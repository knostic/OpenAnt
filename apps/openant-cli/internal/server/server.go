// Package server implements the OpenAnt web UI HTTP server.
package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/knostic/open-ant-cli/internal/report"
	"github.com/knostic/open-ant-cli/internal/types"
	uifiles "github.com/knostic/open-ant-cli/ui"
)

// Job status constants.
const (
	StatusRunning = "running"
	StatusDone    = "done"
	StatusError   = "error"
)

// jobMeta is the on-disk metadata written immediately on job creation.
type jobMeta struct {
	ID        string    `json:"id"`
	Repo      string    `json:"repo"`
	StartedAt time.Time `json:"started_at"`
}

// Job represents a single scan job.
type Job struct {
	mu              sync.Mutex
	ID              string
	Repo            string
	StartedAt       time.Time
	Status          string
	LogBuf          []string
	logBytes        int  // total bytes buffered, to bound memory (see addLog)
	logCapped       bool // true once a line/byte limit was hit; no more appends
	ReportPath      string
	SummaryPath     string
	DisclosurePaths []string
	Cancel          context.CancelFunc

	// Internal scan parameters (not exposed via API)
	apiKey      string
	languages   []string
	libraryMode bool
	verify      bool
	dynamicTest bool
	ctx         context.Context
	done        chan struct{} // closed by runJob after it stops touching the job dir
}

func (j *Job) addLog(line string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.logCapped {
		return
	}
	line = strings.ReplaceAll(line, "\r", " ")
	line = strings.ReplaceAll(line, "\n", " ")
	// Bound memory against a repo that floods stderr — by line count AND total
	// bytes (a few huge lines can blow past a line cap). Cap and stop (rather than
	// trim the front) so SSE replay indices stay stable.
	const maxLogLines = 20000
	const maxLogBytes = 8 << 20 // 8 MiB
	// Check the PROJECTED size so a single line can't overshoot the cap before
	// truncation fires on the next call — the bound stays a hard ceiling.
	if len(j.LogBuf) >= maxLogLines || j.logBytes+len(line) > maxLogBytes {
		j.LogBuf = append(j.LogBuf, "[log truncated: limit reached]")
		j.logCapped = true
		return
	}
	j.logBytes += len(line)
	j.LogBuf = append(j.LogBuf, line)
}

func (j *Job) setDone(reportPath, summaryPath string, disclosurePaths []string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = StatusDone
	j.ReportPath = reportPath
	j.SummaryPath = summaryPath
	j.DisclosurePaths = disclosurePaths
}

func (j *Job) setError() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = StatusError
}

// manager is the in-memory job store.
type manager struct {
	mu     sync.RWMutex
	jobs   map[string]*Job
	outDir string
}

func newManager(outDir string) *manager {
	return &manager{jobs: make(map[string]*Job), outDir: outDir}
}

func (m *manager) add(j *Job) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[j.ID] = j
}

func (m *manager) get(id string) (*Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	return j, ok
}

func (m *manager) remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.jobs, id)
}

func (m *manager) all() []*Job {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		out = append(out, j)
	}
	sort.Slice(out, func(i, k int) bool {
		return out[i].StartedAt.After(out[k].StartedAt)
	})
	return out
}

func (m *manager) cancelAll() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, j := range m.jobs {
		j.mu.Lock()
		if j.Cancel != nil {
			j.Cancel()
		}
		j.mu.Unlock()
	}
}

// Server is the web UI HTTP server.
type Server struct {
	pythonPath     string
	outDir         string
	mgr            *manager
	tmplIndex      *template.Template
	tmplScan       *template.Template
	tmplSum        *template.Template
	tmplDisclosure *template.Template
	sem            chan struct{}
	csrfToken      string
	wg             sync.WaitGroup // tracks in-flight runJob goroutines for shutdown
	shutdownDone   chan struct{}  // closed once cancel+drain completes
	drainMu        sync.Mutex     // guards draining; makes wg.Add happen-before wg.Wait
	draining       bool           // set at shutdown so no new job is added after Wait starts
}

// New creates a new Server.  It parses UI templates and recovers any existing
// jobs from disk at outDir.
func New(pythonPath, outDir string) (*Server, error) {
	tmplIndex, err := template.ParseFS(uifiles.FS, "index.html")
	if err != nil {
		return nil, fmt.Errorf("parse index.html: %w", err)
	}
	tmplScan, err := template.ParseFS(uifiles.FS, "scan.html")
	if err != nil {
		return nil, fmt.Errorf("parse scan.html: %w", err)
	}
	tmplSum, err := template.ParseFS(uifiles.FS, "summary.html")
	if err != nil {
		return nil, fmt.Errorf("parse summary.html: %w", err)
	}
	tmplDisclosure, err := template.ParseFS(uifiles.FS, "disclosure.html")
	if err != nil {
		return nil, fmt.Errorf("parse disclosure.html: %w", err)
	}

	// Per-instance CSRF synchronizer token: 32 hex chars from crypto/rand,
	// stable for the server's lifetime and embedded in served pages.
	tokBytes := make([]byte, 16)
	if _, err := rand.Read(tokBytes); err != nil {
		return nil, fmt.Errorf("generate csrf token: %w", err)
	}

	s := &Server{
		pythonPath:     pythonPath,
		outDir:         outDir,
		mgr:            newManager(outDir),
		tmplIndex:      tmplIndex,
		tmplScan:       tmplScan,
		tmplSum:        tmplSum,
		tmplDisclosure: tmplDisclosure,
		sem:            make(chan struct{}, 4),
		csrfToken:      hex.EncodeToString(tokBytes),
		shutdownDone:   make(chan struct{}),
	}
	s.recoverJobs()
	return s, nil
}

// recoverJobs scans outDir for existing job directories and restores them.
func (s *Server) recoverJobs() {
	entries, err := os.ReadDir(s.outDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		// Only restore dirs whose name is a real job ID; anything else can't be
		// deleted via the API (jobIDRe-gated) and isn't one of our jobs.
		if !jobIDRe.MatchString(id) {
			continue
		}
		jobDir := filepath.Join(s.outDir, id)

		job := &Job{ID: id}

		// Try to read meta.json.
		if data, err := os.ReadFile(filepath.Join(jobDir, "meta.json")); err == nil {
			var m jobMeta
			if json.Unmarshal(data, &m) == nil {
				job.Repo = m.Repo
				job.StartedAt = m.StartedAt
			}
		}

		// Fall back: infer repo from git config and mtime from dir.
		if job.Repo == "" {
			job.Repo = inferRepoURL(jobDir)
		}
		if job.StartedAt.IsZero() {
			if info, err := os.Stat(jobDir); err == nil {
				job.StartedAt = info.ModTime()
			}
		}

		// Determine status from presence of report.html.
		reportPath := filepath.Join(jobDir, "report.html")
		if _, err := os.Stat(reportPath); err == nil {
			job.Status = StatusDone
			job.ReportPath = reportPath
			// Look for summary.
			for _, sp := range []string{
				filepath.Join(jobDir, "report", "SUMMARY_REPORT.md"),
				filepath.Join(jobDir, "SUMMARY_REPORT.md"),
			} {
				if _, err := os.Stat(sp); err == nil {
					job.SummaryPath = sp
					break
				}
			}
			// Look for disclosure reports.
			job.DisclosurePaths = findDisclosures(jobDir)
		} else {
			job.Status = StatusError
		}

		// Load persisted logs if available. Sanitize each line the same way
		// addLog does (a repo can write logs.txt during --dynamic-test) so a bare
		// CR can't inject an SSE field/event on replay, and cap the count.
		if data, err := os.ReadFile(filepath.Join(jobDir, "logs.txt")); err == nil {
			lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
			const maxLogLines = 20000
			if len(lines) > maxLogLines {
				lines = append(lines[:maxLogLines:maxLogLines], "[log truncated: too many lines]")
			}
			for i, l := range lines {
				l = strings.ReplaceAll(l, "\r", " ")
				lines[i] = strings.ReplaceAll(l, "\n", " ")
			}
			job.LogBuf = lines
		}

		s.mgr.add(job)
	}
}

// inferRepoURL tries to read the origin remote URL from repo/.git/config.
func inferRepoURL(jobDir string) string {
	gitConfig := filepath.Join(jobDir, "repo", ".git", "config")
	f, err := os.Open(gitConfig)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	inOrigin := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == `[remote "origin"]` {
			inOrigin = true
			continue
		}
		if inOrigin && strings.HasPrefix(line, "url =") {
			return strings.TrimSpace(strings.TrimPrefix(line, "url ="))
		}
		if strings.HasPrefix(line, "[") {
			inOrigin = false
		}
	}
	return ""
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("POST /scan", s.handleStartScan)
	mux.HandleFunc("GET /assets/{name}", s.handleAsset)
	mux.HandleFunc("GET /scan/{id}", s.handleScanPage)
	mux.HandleFunc("GET /scan/{id}/logs", s.handleScanLogs)
	mux.HandleFunc("GET /report/{id}", s.handleReport)
	mux.HandleFunc("GET /summary/{id}", s.handleSummary)
	mux.HandleFunc("GET /disclosures/{id}", s.handleDisclosureList)
	mux.HandleFunc("GET /disclosure/{id}/{filename}", s.handleDisclosure)
	mux.HandleFunc("DELETE /scan/{id}", s.handleDeleteScan)
	return securityHeaders(mux)
}

// securityHeaders wraps h with defensive response headers on every route. The
// pages render untrusted LLM/scanned-repo content, so we deny framing, stop
// content-type sniffing, and suppress referrer leakage of the local URL.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DNS-rebinding guard for EVERY route (GET included): a non-loopback Host
		// means the request was aimed at another name rebound to 127.0.0.1, so a
		// remote page can't read the index (CSRF token + job list) or any report.
		if !hostHeaderIsLoopback(r) {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()")
		h.ServeHTTP(w, r)
	})
}

// supportedLanguages is the allowlist the scan form's language checkboxes draw
// from; handleStartScan rejects any other value so an attacker-crafted POST
// cannot splice arbitrary tokens into the scanner argv.
var supportedLanguages = map[string]bool{
	"c": true, "go": true, "javascript": true, "php": true, "python": true,
	"ruby": true, "rust": true, "swift": true, "zig": true,
}

// jobIDRe matches the hex job IDs randomID produces; used to reject any other
// shape before an id reaches the filesystem.
var jobIDRe = regexp.MustCompile(`^[a-f0-9]{8,64}$`)

// hostIsLoopback reports whether host binds to loopback ONLY. Fails closed:
// anything not provably loopback (incl. "", 0.0.0.0, ::, hostnames) is false.
func hostIsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Start binds the server and begins serving.  Tries addr first, then falls
// back to any available port on 127.0.0.1.  Returns the bound URL.
func (s *Server) Start(ctx context.Context, addr string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if !hostIsLoopback(host) {
		return "", fmt.Errorf("refusing to bind %q: the OpenAnt web UI is local-only and must listen on a loopback address (127.0.0.1 or localhost)", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// Fall back to OS-assigned port.
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", fmt.Errorf("listen: %w", err)
		}
	}
	url := "http://" + ln.Addr().String()
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}

	go func() {
		<-ctx.Done()
		// Mark draining before Wait so any in-flight handleStartScan either added
		// its job already (happens-before) or is refused — no Add races Wait.
		s.drainMu.Lock()
		s.draining = true
		s.drainMu.Unlock()
		s.mgr.cancelAll() // cancel job ctxs -> killer goroutines SIGKILL process groups
		_ = srv.Close()   // stop listening + drop conns immediately (an open SSE stream
		//                   would make graceful Shutdown block forever)
		// Wait for in-flight runJob goroutines to finish their kill+cleanup, bounded
		// so a wedged job cannot hang process exit.
		done := make(chan struct{})
		go func() { s.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		close(s.shutdownDone)
	}()

	go func() {
		_ = srv.Serve(ln)
	}()

	return url, nil
}

// WaitShutdown blocks until the ctx-triggered shutdown (cancel in-flight scans +
// stop the listener) has completed, so the caller can exit without orphaning
// child scanner process groups. Safe to call after Start returns.
func (s *Server) WaitShutdown() { <-s.shutdownDone }

// ─── Handlers ──────────────────────────────────────────────────────────────

type jobView struct {
	ID         string
	Repo       string
	StartedAt  string
	Status     string
	HasReport  bool
	HasSummary bool
}

type indexData struct {
	Jobs         []*jobView
	HasAPIKey    bool // whether a key is configured; the key VALUE is never sent to the page
	APIKeySource string
	CSRF         string
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	cfg, _ := config.Load()
	apiKey := ""
	apiKeySource := ""
	if cfg != nil && !cfg.HasV2Providers() && cfg.APIKey != "" {
		apiKey = cfg.APIKey
		apiKeySource = "~/.config/openant/config.json"
	}

	jobs := s.mgr.all()
	views := make([]*jobView, 0, len(jobs))
	for _, j := range jobs {
		j.mu.Lock()
		v := &jobView{
			ID:         j.ID,
			Repo:       j.Repo,
			StartedAt:  j.StartedAt.Format("2006-01-02 15:04:05"),
			Status:     j.Status,
			HasReport:  j.ReportPath != "",
			HasSummary: j.SummaryPath != "",
		}
		j.mu.Unlock()
		views = append(views, v)
	}

	d := indexData{
		Jobs:         views,
		HasAPIKey:    apiKey != "",
		APIKeySource: apiKeySource,
		CSRF:         s.csrfToken,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplIndex.Execute(w, d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// hostHeaderIsLoopback reports whether the request's Host is a loopback name.
// The server binds loopback only, so a non-loopback Host means the request was
// aimed at some other name that DNS-rebound to 127.0.0.1 — reject it. Enforced
// for EVERY route by the securityHeaders middleware (not just mutations), so a
// rebinding page can't read the index/reports/logs either.
func hostHeaderIsLoopback(r *http.Request) bool {
	h, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		h = r.Host
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	// Accept ANY loopback IP so a server bound to e.g. 127.0.0.2 (hostIsLoopback
	// allows the whole 127.0.0.0/8 for binding) isn't 403'd by its own Host check.
	// A rebound name like "evil.com" is not an IP literal, so it stays rejected.
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// sameOriginOK guards state-changing requests against CSRF: the Host must be
// loopback (also enforced globally by the middleware) and any Origin/
// Sec-Fetch-Site present must be same-origin.
func sameOriginOK(r *http.Request) bool {
	if !hostHeaderIsLoopback(r) {
		return false
	}
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs == "cross-site" || sfs == "cross-origin" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host {
			return false
		}
	}
	return true
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	switch name {
	case "marked.min.js", "purify.min.js":
	default:
		http.NotFound(w, r)
		return
	}
	data, err := uifiles.FS.ReadFile("vendor/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(data)
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if !sameOriginOK(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrfToken)) != 1 {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	repo := strings.TrimSpace(r.FormValue("repo"))
	if repo == "" {
		http.Error(w, "repo is required", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(repo, "-") {
		http.Error(w, "repository path/URL must not start with '-'", http.StatusBadRequest)
		return
	}
	// Reject credentials embedded in an http(s) URL: the repo string is logged and
	// persisted verbatim (meta.json, logs.txt, SSE, pipeline_output.json, argv), so
	// userinfo would leak. Fail CLOSED on an unparseable URL too — a malformed
	// credential URL (e.g. bad %-escape) must not slip past into the logs before
	// the later clone guard sees it. Use a git credential helper instead.
	if strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "https://") {
		u, err := url.Parse(repo)
		if err != nil || u.User != nil {
			http.Error(w, "invalid repository URL, or credentials in the URL (use a git credential helper instead)", http.StatusBadRequest)
			return
		}
	}

	languages := r.Form["languages"]
	for _, l := range languages {
		if !supportedLanguages[l] {
			http.Error(w, "unsupported language", http.StatusBadRequest)
			return
		}
	}
	libraryMode := r.FormValue("library_mode") == "on"
	apiKey := r.FormValue("api_key")
	if apiKey == "" {
		// Fall back to the configured key, mirroring cmd/root.go: a v2
		// llm_providers config deliberately suppresses the legacy key.
		if cfg, _ := config.Load(); cfg != nil && !cfg.HasV2Providers() {
			apiKey = cfg.APIKey
		}
	}
	verify := r.FormValue("verify") == "on"
	dynamicTest := r.FormValue("dynamic_test") == "on"

	// Gate new work at shutdown BEFORE creating any disk/manager state, and
	// register with the WaitGroup under drainMu so wg.Add can never race the
	// shutdown's wg.Wait (draining is set before Wait). Every return path after
	// this Add MUST call wg.Done; the success path hands the count to runJob's
	// deferred wg.Done.
	s.drainMu.Lock()
	if s.draining {
		s.drainMu.Unlock()
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}
	s.wg.Add(1)
	s.drainMu.Unlock()

	id, err := randomID()
	if err != nil {
		s.wg.Done()
		http.Error(w, "failed to generate ID", http.StatusInternalServerError)
		return
	}

	jobDir := filepath.Join(s.outDir, id)
	if err := os.MkdirAll(jobDir, 0750); err != nil {
		s.wg.Done()
		http.Error(w, "failed to create job dir", http.StatusInternalServerError)
		return
	}

	// Write meta.json immediately.
	meta := jobMeta{ID: id, Repo: repo, StartedAt: time.Now().UTC()}
	if data, err := json.Marshal(meta); err == nil {
		_ = os.WriteFile(filepath.Join(jobDir, "meta.json"), data, 0640)
	}

	ctx, cancel := context.WithCancel(context.Background())
	job := &Job{
		ID:          id,
		Repo:        repo,
		StartedAt:   meta.StartedAt,
		Status:      StatusRunning,
		Cancel:      cancel,
		ctx:         ctx,
		apiKey:      apiKey,
		languages:   languages,
		libraryMode: libraryMode,
		verify:      verify,
		dynamicTest: dynamicTest,
		done:        make(chan struct{}),
	}
	s.mgr.add(job)
	go s.runJob(job)

	http.Redirect(w, r, "/scan/"+id, http.StatusSeeOther)
}

type scanPageData struct {
	ID   string
	Repo string
	CSRF string
}

func (s *Server) handleScanPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	job.mu.Lock()
	repo := job.Repo
	job.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplScan.Execute(w, scanPageData{ID: id, Repo: repo, CSRF: s.csrfToken}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleScanLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}

	flusher, canFlush := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Resume support: on reconnect EventSource replays the Last-Event-ID header
	// (the 0-based index of the last line it received), so we send only newer
	// lines instead of duplicating the whole log. Indices are stable for the
	// buffer's life (addLog/recoverJobs cap-and-stop, never shift).
	start := 0
	if leid := r.Header.Get("Last-Event-ID"); leid != "" {
		if n, err := strconv.Atoi(leid); err == nil && n >= 0 {
			start = n + 1
		}
	}

	job.mu.Lock()
	initial := make([]string, len(job.LogBuf))
	copy(initial, job.LogBuf)
	initStatus := job.Status
	job.mu.Unlock()

	// Clamp both ends: a Last-Event-ID of MaxInt64 makes start=n+1 overflow
	// negative, which would index initial[<0] and panic; past-end just resumes
	// after everything.
	if start < 0 || start > len(initial) {
		start = len(initial)
	}
	for i := start; i < len(initial); i++ {
		fmt.Fprintf(w, "id: %d\ndata: %s\n\n", i, initial[i])
	}
	sent := len(initial)

	if initStatus != StatusRunning {
		fmt.Fprintf(w, "event: done\ndata: %s\n\n", initStatus)
		if canFlush {
			flusher.Flush()
		}
		return
	}
	if canFlush {
		flusher.Flush()
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}

		job.mu.Lock()
		logs := job.LogBuf
		status := job.Status
		job.mu.Unlock()

		for i := sent; i < len(logs); i++ {
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", i, logs[i])
		}
		sent = len(logs)

		if status != StatusRunning {
			fmt.Fprintf(w, "event: done\ndata: %s\n\n", status)
			if canFlush {
				flusher.Flush()
			}
			return
		}
		if canFlush {
			flusher.Flush()
		}
	}
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	job.mu.Lock()
	rp := job.ReportPath
	job.mu.Unlock()
	if rp == "" {
		http.NotFound(w, r)
		return
	}
	f, fi, err := openRegularInRoot(filepath.Join(s.outDir, id), rp)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, filepath.Base(rp), fi.ModTime(), f)
}

type summaryData struct {
	ID           string
	MarkdownJSON template.JS // full JSON-encoded string literal (incl. outer quotes)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	job.mu.Lock()
	sp := job.SummaryPath
	job.mu.Unlock()
	if sp == "" {
		http.NotFound(w, r)
		return
	}
	f, _, err := openRegularInRoot(filepath.Join(s.outDir, id), sp)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// json.Marshal produces a properly-escaped JS string literal including outer quotes.
	mdJSON, _ := json.Marshal(string(data))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplSum.Execute(w, summaryData{
		ID:           id,
		MarkdownJSON: template.JS(mdJSON),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type disclosureInfo struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	URL   string `json:"url"`
}

func (s *Server) handleDisclosureList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	job.mu.Lock()
	paths := make([]string, len(job.DisclosurePaths))
	copy(paths, job.DisclosurePaths)
	job.mu.Unlock()

	infos := make([]disclosureInfo, 0, len(paths))
	for _, p := range paths {
		name := filepath.Base(p)
		label := disclosureTitleFromFile(p)
		if label == "" {
			label = disclosureLabel(name)
		}
		infos = append(infos, disclosureInfo{
			Name:  name,
			Label: label,
			URL:   "/disclosure/" + id + "/" + name,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(infos)
}

type disclosureData struct {
	ID           string
	Name         string
	MarkdownJSON template.JS
}

func (s *Server) handleDisclosure(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	filename := filepath.Base(r.PathValue("filename")) // sanitize: strip any path components
	if filename == "." || filename == "" {
		http.NotFound(w, r)
		return
	}

	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Verify the file is one of the job's known disclosure paths.
	job.mu.Lock()
	var matchedPath string
	for _, p := range job.DisclosurePaths {
		if filepath.Base(p) == filename {
			matchedPath = p
			break
		}
	}
	job.mu.Unlock()

	if matchedPath == "" {
		http.NotFound(w, r)
		return
	}
	// O_NOFOLLOW read: even a known path must be a regular file within the job dir
	// at read time — refuses a symlink atomically (no check-then-read TOCTOU).
	f, _, err := openRegularInRoot(filepath.Join(s.outDir, id), matchedPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		http.NotFound(w, r)
		return
	}

	mdJSON, _ := json.Marshal(string(data))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplDisclosure.Execute(w, disclosureData{
		ID:           id,
		Name:         disclosureLabel(filename),
		MarkdownJSON: template.JS(mdJSON),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// disclosureTitleFromFile reads the first markdown heading from a disclosure
// file and returns the vulnerability title.
// e.g. "# Security Disclosure: Mail Account Credential Theft" → "Mail Account Credential Theft"
// Returns empty string if the title cannot be extracted.
func disclosureTitleFromFile(path string) string {
	// Reject a symlink (Lstat cross-platform; oNoFollow adds unix atomicity) so the
	// title-scan (reached from handleDisclosureList) can't read a symlink target.
	if lfi, err := os.Lstat(path); err != nil || lfi.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			// Strip all leading '#' and whitespace.
			title := strings.TrimSpace(strings.TrimLeft(line, "#"))
			// Strip common "Security Disclosure:" prefix.
			for _, prefix := range []string{
				"Security Disclosure: ",
				"Security Disclosure:",
			} {
				if strings.HasPrefix(title, prefix) {
					return strings.TrimSpace(strings.TrimPrefix(title, prefix))
				}
			}
			return title
		}
	}
	return ""
}

// disclosureLabel converts a disclosure filename to a human-readable label.
// e.g. "DISCLOSURE_01_SQL_INJECTION.md" → "Sql Injection"
var reDisclosurePrefix = regexp.MustCompile(`(?i)^DISCLOSURE_\d+_`)

func disclosureLabel(filename string) string {
	name := strings.TrimSuffix(filename, ".md")
	name = reDisclosurePrefix.ReplaceAllString(name, "")
	words := strings.FieldsFunc(name, func(r rune) bool { return r == '_' || r == '-' })
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
		}
	}
	return strings.Join(words, " ")
}

// findDisclosures returns absolute paths to all .md files in the disclosures
// subdirectory of outDir.
func findDisclosures(outDir string) []string {
	discDir := filepath.Join(outDir, "report", "disclosures")
	entries, err := os.ReadDir(discDir)
	if err != nil {
		return nil
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		p := filepath.Join(discDir, e.Name())
		// Skip symlinks: a disclosure is a scan-produced .md file, never a link
		// out of the job dir (which could point at a host secret).
		if !isRegularNoSymlink(outDir, p) {
			continue
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	if !sameOriginOK(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.csrfToken)) != 1 {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	if !jobIDRe.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	job.mu.Lock()
	if job.Cancel != nil {
		job.Cancel()
	}
	done := job.done
	job.mu.Unlock()

	// Wait (bounded) for the runner to stop touching the job dir before removing
	// it, so a late report/log write can't recreate the deleted directory and
	// resurrect the job on restart. Recovered jobs have no runner (done == nil).
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}

	s.mgr.remove(id)
	_ = os.RemoveAll(filepath.Join(s.outDir, id))
	w.WriteHeader(http.StatusNoContent)
}

// ─── Background job runner ─────────────────────────────────────────────────

func (s *Server) runJob(job *Job) {
	defer s.wg.Done()
	// Closed last (after the cleanup defer below) so handleDeleteScan can wait
	// for this goroutine to stop writing the job dir before it RemoveAll's it —
	// otherwise a late report/log write recreates the deleted directory.
	defer close(job.done)

	outDir := filepath.Join(s.outDir, job.ID)

	defer func() {
		// Panic recovery — log rather than silently dropping the goroutine.
		if r := recover(); r != nil {
			job.addLog(fmt.Sprintf("[error] internal panic: %v", r))
		}
		// Any path that leaves the job still "running" here is a cancellation
		// (delete/shutdown) or a recovered panic; mark it terminal so an open SSE
		// stream receives a done event and stops instead of ticking forever.
		job.mu.Lock()
		if job.Status == StatusRunning {
			job.Status = StatusError
		}
		job.mu.Unlock()
		// Persist full log buffer to logs.txt.
		job.mu.Lock()
		logData := strings.Join(job.LogBuf, "\n") + "\n"
		job.mu.Unlock()
		_ = os.WriteFile(filepath.Join(outDir, "logs.txt"), []byte(logData), 0640)
	}()

	// Acquire a run slot, but abort promptly if the job was cancelled/deleted
	// while queued rather than parking on the semaphore until a slot frees.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-job.ctx.Done():
		return
	}

	job.addLog("→ Starting scan of " + job.Repo)

	// Determine local path: clone if URL, use directly if local path.
	localPath := job.Repo
	isURL := strings.HasPrefix(job.Repo, "https://") ||
		strings.HasPrefix(job.Repo, "http://") ||
		strings.HasPrefix(job.Repo, "git@")

	if isURL {
		cloneDir := filepath.Join(outDir, "repo")
		job.addLog("[clone] Cloning " + job.Repo + "…")
		if err := cloneRepo(job.ctx, job.Repo, cloneDir, job.addLog); err != nil {
			if job.ctx.Err() == nil {
				job.addLog("[clone] Error: " + err.Error())
				job.setError()
			}
			return
		}
		localPath = cloneDir
	}

	// Build scan args.
	args := []string{"scan", "--output", outDir}
	// Language selection mirrors the CLI. No selection = the auto default: every
	// detected language above the size threshold (NOT just the dominant one — see
	// core/language_selection.py select_languages). One selection = --language;
	// several = --languages (a subset). The CLI's --all-languages mode (also scan
	// below-threshold trivial languages) is intentionally not exposed — auto covers
	// the common case.
	if len(job.languages) == 1 {
		args = append(args, "--language", job.languages[0])
	} else if len(job.languages) > 1 {
		args = append(args, "--languages", strings.Join(job.languages, ","))
	}
	if job.verify {
		args = append(args, "--verify")
	}
	if job.dynamicTest {
		args = append(args, "--dynamic-test")
	}
	if job.libraryMode {
		args = append(args, "--library-mode")
	}
	if isURL {
		args = append(args, "--repo-url", job.Repo)
	}
	args = append(args, "--", localPath)

	job.addLog("→ Running: python -m openant " + strings.Join(args, " "))

	stdout, exitCode, err := python.InvokeCtxCapture(job.ctx, s.pythonPath, args, "", job.apiKey, job.addLog)
	if job.ctx.Err() != nil {
		return // cancelled — don't mark error
	}
	if err != nil {
		job.addLog("[error] scan failed to start: " + err.Error())
		job.setError()
		return
	}
	// Exit code 1 means "scan succeeded but found vulnerabilities" (like grep).
	// Exit code 2+ means actual failure. The CLI writes the reason as a JSON
	// envelope on stdout (stderr may be empty), so surface it to the UI.
	if exitCode >= 2 || exitCode < 0 {
		if msgs := envelopeErrors(stdout); len(msgs) > 0 {
			for _, m := range msgs {
				job.addLog("[error] " + m)
			}
		} else {
			job.addLog(fmt.Sprintf("[error] scan exited with code %d", exitCode))
		}
		job.setError()
		return
	}

	// Patch pipeline_output.json with the original repo URL.
	patchPipelineOutput(outDir, job.Repo, job.addLog)

	// Locate or generate report.html.
	reportPath := filepath.Join(outDir, "report.html")
	if !fileExists(reportPath) {
		// Scan step may have placed it in a subdirectory.
		for _, alt := range []string{
			filepath.Join(outDir, "final-reports", "report.html"),
			filepath.Join(outDir, "final-reports", "report-reskin.html"),
		} {
			if fileExists(alt) {
				if data, err := os.ReadFile(alt); err == nil {
					_ = os.WriteFile(reportPath, data, 0640)
				}
				break
			}
		}
	}

	// If still missing, try explicit report generation (non-fatal).
	if !fileExists(reportPath) {
		if err := s.generateHTMLReport(job.ctx, outDir, reportPath, job.apiKey, job.addLog); err != nil {
			if job.ctx.Err() != nil {
				return
			}
			job.addLog("[report] Warning: " + err.Error())
			// Continue — mark done only if we found something.
		}
	}

	if job.ctx.Err() != nil {
		return
	}
	if !fileExists(reportPath) {
		job.addLog("[error] no report.html produced; marking scan as error")
		job.setError()
		return
	}

	// Markdown summary: prefer the one the scan already produced (the pipeline
	// writes report/SUMMARY_REPORT.md by default) to avoid a second LLM-billed
	// summary of the same results. Only generate if the scan produced none.
	summaryPath := ""
	for _, sp := range []string{
		filepath.Join(outDir, "report", "SUMMARY_REPORT.md"),
		filepath.Join(outDir, "SUMMARY_REPORT.md"),
	} {
		if fileExists(sp) {
			summaryPath = sp
			break
		}
	}
	if summaryPath == "" {
		// Non-fatal — requires API key / LLM.
		sp := filepath.Join(outDir, "SUMMARY_REPORT.md")
		if err := s.generateSummary(job.ctx, outDir, sp, job.apiKey, job.addLog); err != nil {
			if job.ctx.Err() != nil {
				return
			}
			job.addLog("[report] Warning: summary not generated: " + err.Error())
		} else {
			summaryPath = sp
		}
	}

	disclosurePaths := findDisclosures(outDir)

	job.setDone(reportPath, summaryPath, disclosurePaths)
}

// envelopeErrors extracts the errors[] from the CLI's JSON result envelope,
// which is printed to stdout on failure (e.g. {"status":"error","errors":[...]}).
// It scans lines bottom-up for the last well-formed envelope carrying errors,
// tolerating non-JSON log noise on the same stream.
func envelopeErrors(stdout string) []string {
	lines := strings.Split(stdout, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var env struct {
			Status string   `json:"status"`
			Errors []string `json:"errors"`
		}
		if err := json.Unmarshal([]byte(line), &env); err == nil && len(env.Errors) > 0 {
			return env.Errors
		}
	}
	return nil
}

// cloneRepo runs git clone --depth 1 and streams stderr to onLog.
// Cloud metadata endpoints that are not otherwise loopback/link-local and so
// need blocking as specific literals: AWS's IPv6 IMDS (a ULA address, and ULA is
// otherwise the IPv6 equivalent of RFC1918 which we allow) and Alibaba Cloud's
// ECS metadata service (a public RFC6598 shared-space address). Both are SSRF
// targets, never a real repository.
var (
	awsIPv6IMDS = net.ParseIP("fd00:ec2::254")
	alibabaIMDS = net.ParseIP("100.100.100.200")
)

// ipBlocked reports whether ip is an SSRF-sensitive target that is never a
// legitimate remote repository: loopback, link-local (which includes the
// 169.254.169.254 IMDS endpoint), unspecified, or a cloud-metadata literal.
// RFC1918 and general IPv6 ULA private ranges stay allowed so internal git
// servers remain scannable (the deliberate policy of the original guard).
func ipBlocked(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() ||
		ip.Equal(awsIPv6IMDS) || ip.Equal(alibabaIMDS)
}

// scpHost extracts the host from an scp-style git address, "[user@]host:path" or
// the bracketed IPv6 form "[user@][::1]:path". ssh connects to the host after the
// LAST userinfo '@', so a smuggled extra userinfo like "git@evil@127.0.0.1" must
// resolve to "127.0.0.1", not "evil@127.0.0.1" (which would dodge the guard and
// let ssh still reach loopback). Returns "" when no host can be determined.
func scpHost(repo string) string {
	s := strings.TrimPrefix(repo, "git@")
	// The host region begins after the last userinfo '@' that precedes the host.
	// Userinfo contains no ':' or '[', so bound the search at the first of those
	// (the path separator, or the start of a bracketed IPv6 literal).
	limit := len(s)
	if c := strings.IndexByte(s, ':'); c >= 0 && c < limit {
		limit = c
	}
	if b := strings.IndexByte(s, '['); b >= 0 && b < limit {
		limit = b
	}
	if a := strings.LastIndexByte(s[:limit], '@'); a >= 0 {
		s = s[a+1:]
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 1 {
			return s[1:i]
		}
		return ""
	}
	return strings.SplitN(s, ":", 2)[0]
}

// fieldCandidates returns EVERY numeric value a resolver might read one
// inet_aton-style field as. Go's net.ParseIP rejects these forms; git/libcurl
// (via the platform resolver) accept them, but the platforms disagree on
// leading-zero fields: glibc reads them as octal, while macOS/BSD getaddrinfo
// reads a leading-zero dotted field as DECIMAL (e.g. "0127" -> 127, not octal
// 87). To match what git could actually dial on ANY platform we must consider
// both. Returns octal AND decimal for a leading-zero field, hex for 0x, decimal
// otherwise; empty slice if the field parses under none of those. Uses big.Int
// so a bare integer larger than 2^64 (which libcurl still wraps mod 2^32) is
// represented rather than overflowing strconv and slipping through.
func fieldCandidates(s string) []*big.Int {
	parse := func(str string, base int) (*big.Int, bool) {
		if str == "" {
			return nil, false
		}
		v, ok := new(big.Int).SetString(str, base)
		return v, ok && v.Sign() >= 0
	}
	switch {
	case len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'):
		if v, ok := parse(s[2:], 16); ok {
			return []*big.Int{v}
		}
		return nil
	case len(s) >= 2 && s[0] == '0':
		var out []*big.Int
		if v, ok := parse(s[1:], 8); ok {
			out = append(out, v) // glibc: octal
		}
		if v, ok := parse(s, 10); ok {
			out = append(out, v) // macOS/BSD: decimal (leading zero ignored)
		}
		return out
	default:
		if v, ok := parse(s, 10); ok {
			return []*big.Int{v}
		}
		return nil
	}
}

// packLegacyIPv4 packs 1–4 inet_aton field values into an IPv4 address, honoring
// the short-form packing (a.b -> a.(24-bit b), etc.) and the bare-integer mod-2^32
// wrap. Returns nil if a multi-part field exceeds its slot.
func packLegacyIPv4(vals []*big.Int) net.IP {
	lim := func(v *big.Int, max uint64) bool { return v.Cmp(new(big.Int).SetUint64(max)) > 0 }
	u := func(v *big.Int) uint64 { return v.Uint64() }
	var n uint64
	switch len(vals) {
	case 1:
		// A bare integer addresses all 32 bits; C inet_aton wraps a too-large
		// value mod 2^32 (e.g. 4294967296 -> 0.0.0.0, or 2^64+X -> X mod 2^32),
		// so take the low 32 bits to match what git resolves.
		n = new(big.Int).And(vals[0], big.NewInt(0xffffffff)).Uint64()
	case 2: // a.b -> a.(24-bit b)
		if lim(vals[0], 0xff) || lim(vals[1], 0xffffff) {
			return nil
		}
		n = u(vals[0])<<24 | u(vals[1])
	case 3: // a.b.c -> a.b.(16-bit c)
		if lim(vals[0], 0xff) || lim(vals[1], 0xff) || lim(vals[2], 0xffff) {
			return nil
		}
		n = u(vals[0])<<24 | u(vals[1])<<16 | u(vals[2])
	case 4:
		if lim(vals[0], 0xff) || lim(vals[1], 0xff) || lim(vals[2], 0xff) || lim(vals[3], 0xff) {
			return nil
		}
		n = u(vals[0])<<24 | u(vals[1])<<16 | u(vals[2])<<8 | u(vals[3])
	default:
		return nil
	}
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// parseLegacyIPv4Candidates parses the non-canonical IPv4 forms that inet_aton
// (and thus git/libcurl) accept but net.ParseIP rejects — bare 32-bit integers
// and dotted 1–4-part forms with decimal/octal/hex fields, incl. short forms like
// "127.1" — and returns EVERY address the host could resolve to across resolver
// platforms (the cross-product of each field's candidate readings). Empty when
// host is not such a legacy numeric address (e.g. a real DNS name), so callers
// fall through to name resolution. Callers must block if ANY candidate is
// sensitive (the reachability-safe superset).
func parseLegacyIPv4Candidates(host string) []net.IP {
	if host == "" {
		return nil
	}
	// Fast reject: a legacy numeric host is only digits, dots, and hex letters.
	// Real hostnames carry other letters/hyphens and fall through to DNS.
	for _, r := range host {
		isDigit := r >= '0' && r <= '9'
		isHex := (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isDigit && !isHex && r != '.' && r != 'x' && r != 'X' {
			return nil
		}
	}
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return nil
	}
	// Per-field candidate values, then cross-product into whole-address vals.
	combos := [][]*big.Int{{}}
	for _, p := range parts {
		cands := fieldCandidates(p)
		if len(cands) == 0 {
			return nil
		}
		var next [][]*big.Int
		for _, combo := range combos {
			for _, v := range cands {
				n := append(append([]*big.Int{}, combo...), v)
				next = append(next, n)
			}
		}
		combos = next
	}
	var ips []net.IP
	for _, vals := range combos {
		if ip := packLegacyIPv4(vals); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// repoHostBlocked reports whether a repo URL points at a loopback, link-local,
// unspecified, or cloud-metadata address — an SSRF target that is never a
// legitimate remote repository. Private (RFC1918 / IPv6 ULA) hosts are allowed
// so internal git servers can still be scanned.
//
// It matches what git/libcurl will actually connect to, not just what
// net.ParseIP recognizes: canonical literals, the legacy numeric IPv4 encodings
// inet_aton accepts (decimal/octal/hex/short forms), the "localhost"/FQDN-root
// spellings, and — for genuine DNS names — every resolved address. A name that
// rebinds to a sensitive address in the window between this check and the clone
// remains out of scope; the redirect vector is closed separately by disabling
// git HTTP redirects in cloneRepo.
func repoHostBlocked(ctx context.Context, repo string) bool {
	var host string
	if strings.HasPrefix(repo, "git@") {
		host = scpHost(repo)
	} else {
		// An http(s) URL we will hand to git. Fail closed on anything git/libcurl
		// parses differently than Go: a backslash libcurl reads as '/', or a
		// malformed userinfo that makes url.Parse error while git salvages a
		// trailing host (e.g. "http://example.com\@127.0.0.1/" reaches 127.0.0.1).
		if strings.Contains(repo, `\`) {
			return true
		}
		u, err := url.Parse(repo)
		if err != nil || u.Host == "" {
			return true
		}
		host = u.Hostname()
	}
	if host == "" {
		return false
	}
	host = strings.TrimSpace(host)       // an scp host like "127.0.0.1 :x" can carry a trailing space
	host = strings.TrimSuffix(host, ".") // FQDN-root form: "localhost.", "127.0.0.1."
	// A non-ASCII host is anomalous for git — real IDN hosts arrive punycode
	// (xn--, ASCII). A libidn2-linked git/libcurl applies UTS-46 mapping
	// (fullwidth digits and the U+3002/FF0E/FF61 label separators -> ASCII), so a
	// raw-unicode host like "127。0。0。1" could dial 127.0.0.1 while Go's resolver
	// NXDOMAINs and the numeric guard never sees ASCII digits. Fail closed.
	for _, r := range host {
		if r > 127 {
			return true
		}
	}
	// "localhost" and, per RFC 6761, any *.localhost name resolve to loopback on
	// common Linux setups (systemd-resolved), while Go's pure-Go resolver may
	// NXDOMAIN it — so block the whole .localhost TLD, not just the bare label.
	if lower := strings.ToLower(host); lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return true
	}
	// Strip an IPv6 zone id before ParseIP, which returns nil for zoned literals
	// (e.g. "fe80::1%eth0", "::1%lo0", "fd00:ec2::254%eth0"). git/libcurl accept
	// the bracketed form "[fe80::1%25eth0]" and dial the address, so the zone must
	// not hide a loopback/link-local/metadata target.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	if ip := net.ParseIP(host); ip != nil {
		return ipBlocked(ip)
	}
	// Non-canonical numeric literal (parseable by inet_aton — decimal/octal/hex/
	// short-form/wrap — but rejected by net.ParseIP): BLOCK unconditionally. No
	// legitimate repository is hosted at a form like 0127.0.0.1 or 2130706433;
	// real hosts are canonical IPs (handled above, incl. RFC1918 internal
	// servers) or DNS names (below). Blocking the whole non-canonical-numeric
	// class is encoding-proof — it does not depend on matching what any resolver
	// reads a given encoding as, which is where each prior round found a bypass.
	if len(parseLegacyIPv4Candidates(host)) > 0 {
		return true
	}
	// A DNS name: resolve and block if ANY resolved address is sensitive.
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(rctx, host)
	if err != nil {
		return false // unresolvable — git will fail on its own; not our block
	}
	for _, a := range addrs {
		if ipBlocked(a.IP) {
			return true
		}
	}
	return false
}

func cloneRepo(ctx context.Context, repo, dest string, onLog func(string)) error {
	if !(strings.HasPrefix(repo, "https://") || strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "git@")) {
		return fmt.Errorf("unsupported repository URL scheme")
	}
	if repoHostBlocked(ctx, repo) {
		return fmt.Errorf("refusing to clone from a loopback, link-local, or metadata address")
	}
	// Bound the clone in time so a hostile remote that streams forever can't hold a
	// scan slot indefinitely (the parent ctx is cancel-only). Disk size is not
	// bounded here — a huge working tree is a documented limitation for a
	// local, user-chosen scan target.
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=user",
		// Do not follow HTTP redirects: an allowed public host could otherwise
		// 302 the clone to a loopback/metadata URL that repoHostBlocked never saw.
		"-c", "http.followRedirects=false",
		"clone", "--depth", "1", "--", repo, dest)
	// Run git in its own process group and SIGKILL the whole group on cancel, so
	// helpers (git-remote-https, ssh) are killed too — matching the python path
	// rather than leaving them to die indirectly on EPIPE. (unix; no-op elsewhere)
	setProcGroupKill(cmd)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stderr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // tolerate long remote: sideband lines
	for sc.Scan() {
		onLog("[clone] " + sc.Text())
	}
	// Drain any remainder (an over-long line stops Scan) so a malicious git
	// server cannot wedge cmd.Wait() by filling the stderr pipe.
	_, _ = io.Copy(io.Discard, stderr)
	return cmd.Wait()
}

// patchPipelineOutput updates the repository.url field in pipeline_output.json.
func patchPipelineOutput(outDir, repo string, onLog func(string)) {
	path := filepath.Join(outDir, "pipeline_output.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return // file doesn't exist, skip silently
	}
	// UseNumber so large integer fields (e.g. a CWE id) round-trip exactly rather
	// than being coerced to float64 and losing precision on rewrite.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return
	}
	if repoField, ok := obj["repository"]; ok {
		if repoMap, ok := repoField.(map[string]any); ok {
			repoMap["url"] = repo
		}
	}
	patched, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(path, patched, 0640); err != nil {
		onLog("[report] Warning: could not patch pipeline_output.json: " + err.Error())
	}
}

// generateHTMLReport uses `python -m openant report-data` to get pre-computed
// report JSON, then renders it with Go's embedded HTML template — the same
// pipeline the `openant report -f html` CLI command uses.
func (s *Server) generateHTMLReport(ctx context.Context, outDir, reportPath, apiKey string, onLog func(string)) error {
	resultsPath := findResultsFile(outDir)
	if resultsPath == "" {
		return fmt.Errorf("no results file found in %s", outDir)
	}

	args := []string{"report-data", resultsPath}
	if ds := findDatasetFile(outDir); ds != "" {
		args = append(args, "--dataset", ds)
	}

	onLog("[report] Generating HTML report…")
	stdout, exitCode, err := python.InvokeCtxCapture(ctx, s.pythonPath, args, "", apiKey, func(line string) {
		onLog("[report] " + line)
	})
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return fmt.Errorf("report-data exited with code %d", exitCode)
	}

	// Parse the JSON envelope that Python writes to stdout.
	var envelope types.Envelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &envelope); err != nil {
		return fmt.Errorf("parse report-data output: %w", err)
	}
	if envelope.Status != "success" {
		if len(envelope.Errors) > 0 {
			return fmt.Errorf("report-data: %s", envelope.Errors[0])
		}
		return fmt.Errorf("report-data returned status %q", envelope.Status)
	}

	// Re-marshal then unmarshal into ReportData (same as report.go does).
	dataBytes, err := json.Marshal(envelope.Data)
	if err != nil {
		return fmt.Errorf("marshal report data: %w", err)
	}
	var reportData report.ReportData
	if err := json.Unmarshal(dataBytes, &reportData); err != nil {
		return fmt.Errorf("parse report data: %w", err)
	}

	return report.GenerateReskin(reportData, reportPath)
}

// generateSummary runs `python -m openant report --format summary` to produce
// SUMMARY_REPORT.md.  This step makes LLM calls so it requires an API key.
func (s *Server) generateSummary(ctx context.Context, outDir, outputPath, apiKey string, onLog func(string)) error {
	resultsPath := findResultsFile(outDir)
	if resultsPath == "" {
		return fmt.Errorf("no results file found in %s", outDir)
	}

	args := []string{"report", resultsPath, "--format", "summary", "--output", outputPath}
	if po := filepath.Join(outDir, "pipeline_output.json"); fileExists(po) {
		args = append(args, "--pipeline-output", po)
	}

	onLog("[report] Generating Markdown summary…")
	exitCode, err := python.InvokeCtx(ctx, s.pythonPath, args, "", apiKey, func(line string) {
		onLog("[report] " + line)
	})
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return fmt.Errorf("summary generation exited with code %d", exitCode)
	}
	if !fileExists(outputPath) {
		return fmt.Errorf("summary file not produced at %s", outputPath)
	}
	return nil
}

// findResultsFile locates the primary results JSON in the output directory.
func findResultsFile(outDir string) string {
	for _, name := range []string{
		"results_verified.json",
		"results_analyzed.json",
		"results.json",
	} {
		p := filepath.Join(outDir, name)
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// findDatasetFile locates the best available dataset JSON in the output directory.
// Prefers the enhanced dataset; falls back to the original parsed dataset.
func findDatasetFile(outDir string) string {
	for _, name := range []string{
		"dataset_enhanced.json",
		"dataset.json",
	} {
		p := filepath.Join(outDir, name)
		if fileExists(p) {
			return p
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// withinRoot reports whether path's fully-resolved location stays inside root's
// fully-resolved location (catches a parent-component symlink or a swapped root).
func withinRoot(root, path string) bool {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(realRoot, realPath)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// isRegularNoSymlink reports whether path is a regular file, not a symlink, whose
// resolved location is within root. Used at ENUMERATION time (findDisclosures) to
// keep symlinks out of the served allowlist.
func isRegularNoSymlink(root, path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return false
	}
	return withinRoot(root, path)
}

// openRegularInRoot opens a file for reading with O_NOFOLLOW so a symlink at the
// final component is refused ATOMICALLY (closing the check-then-read TOCTOU that
// a plain Lstat-then-open leaves open), verifies it's a regular file, and
// confirms containment within root. The job output dir holds files derived from
// an untrusted scanned repo, so no served file may be a symlink to a host secret.
func openRegularInRoot(root, path string) (*os.File, os.FileInfo, error) {
	// Reject a leaf symlink cross-platform (Lstat); on unix oNoFollow also makes
	// the open itself refuse it, closing the check-then-open TOCTOU.
	if lfi, err := os.Lstat(path); err != nil || lfi.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("not a regular file")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("not a regular file")
	}
	if !withinRoot(root, path) {
		f.Close()
		return nil, nil, fmt.Errorf("path escapes job root")
	}
	return f, fi, nil
}

// randomID generates a 16-character cryptographically random hex string.
func randomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
