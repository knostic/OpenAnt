// Package server implements the OpenAnt web UI HTTP server.
package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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
	mu               sync.Mutex
	ID               string
	Repo             string
	StartedAt        time.Time
	Status           string
	LogBuf           []string
	ReportPath       string
	SummaryPath      string
	DisclosurePaths  []string
	Cancel           context.CancelFunc

	// Internal scan parameters (not exposed via API)
	apiKey      string
	language    string
	model       string
	verify      bool
	dynamicTest bool
	ctx         context.Context
}

func (j *Job) addLog(line string) {
	j.mu.Lock()
	defer j.mu.Unlock()
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

func (j *Job) snapshot() (status string, logs []string, reportPath, summaryPath string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	logs = make([]string, len(j.LogBuf))
	copy(logs, j.LogBuf)
	return j.Status, logs, j.ReportPath, j.SummaryPath
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
	pythonPath      string
	outDir          string
	mgr             *manager
	tmplIndex       *template.Template
	tmplScan        *template.Template
	tmplSum         *template.Template
	tmplDisclosure  *template.Template
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

	s := &Server{
		pythonPath:     pythonPath,
		outDir:         outDir,
		mgr:            newManager(outDir),
		tmplIndex:      tmplIndex,
		tmplScan:       tmplScan,
		tmplSum:        tmplSum,
		tmplDisclosure: tmplDisclosure,
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

		// Load persisted logs if available.
		if data, err := os.ReadFile(filepath.Join(jobDir, "logs.txt")); err == nil {
			lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
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
	mux.HandleFunc("GET /scan/{id}", s.handleScanPage)
	mux.HandleFunc("GET /scan/{id}/logs", s.handleScanLogs)
	mux.HandleFunc("GET /report/{id}", s.handleReport)
	mux.HandleFunc("GET /summary/{id}", s.handleSummary)
	mux.HandleFunc("GET /disclosures/{id}", s.handleDisclosureList)
	mux.HandleFunc("GET /disclosure/{id}/{filename}", s.handleDisclosure)
	mux.HandleFunc("DELETE /scan/{id}", s.handleDeleteScan)
	return mux
}

// Start binds the server and begins serving.  Tries addr first, then falls
// back to any available port on 127.0.0.1.  Returns the bound URL.
func (s *Server) Start(ctx context.Context, addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// Fall back to OS-assigned port.
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", fmt.Errorf("listen: %w", err)
		}
	}
	url := "http://" + ln.Addr().String()
	srv := &http.Server{Handler: s.Handler()}

	go func() {
		<-ctx.Done()
		s.mgr.cancelAll()
		_ = srv.Shutdown(context.Background())
	}()

	go func() {
		_ = srv.Serve(ln)
	}()

	return url, nil
}

// ─── Handlers ──────────────────────────────────────────────────────────────

type jobView struct {
	ID          string
	Repo        string
	StartedAt   string
	Status      string
	HasReport   bool
	HasSummary  bool
}

type indexData struct {
	Jobs         []*jobView
	APIKey       string
	HasAPIKey    bool
	APIKeySource string
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	cfg, _ := config.Load()
	apiKey := ""
	apiKeySource := ""
	if cfg != nil && cfg.APIKey != "" {
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
		APIKey:       apiKey,
		HasAPIKey:    apiKey != "",
		APIKeySource: apiKeySource,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplIndex.Execute(w, d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	repo := strings.TrimSpace(r.FormValue("repo"))
	if repo == "" {
		http.Error(w, "repo is required", http.StatusBadRequest)
		return
	}

	language := r.FormValue("language")
	if language == "auto" {
		language = ""
	}
	model := r.FormValue("model")
	apiKey := r.FormValue("api_key")
	if apiKey == "" {
		// Fall back to configured key.
		apiKey = config.ResolveAPIKey("")
	}
	verify := r.FormValue("verify") == "on"
	dynamicTest := r.FormValue("dynamic_test") == "on"

	id, err := randomID()
	if err != nil {
		http.Error(w, "failed to generate ID", http.StatusInternalServerError)
		return
	}

	jobDir := filepath.Join(s.outDir, id)
	if err := os.MkdirAll(jobDir, 0750); err != nil {
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
		language:    language,
		model:       model,
		verify:      verify,
		dynamicTest: dynamicTest,
	}
	s.mgr.add(job)

	go s.runJob(job)

	http.Redirect(w, r, "/scan/"+id, http.StatusSeeOther)
}

type scanPageData struct {
	ID   string
	Repo string
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
	if err := s.tmplScan.Execute(w, scanPageData{ID: id, Repo: repo}); err != nil {
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

	// Send all existing lines immediately, then poll for more.
	job.mu.Lock()
	initial := make([]string, len(job.LogBuf))
	copy(initial, job.LogBuf)
	initStatus := job.Status
	job.mu.Unlock()

	for _, line := range initial {
		fmt.Fprintf(w, "data: %s\n\n", line)
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
			fmt.Fprintf(w, "data: %s\n\n", logs[i])
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
	http.ServeFile(w, r, rp)
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
	data, err := os.ReadFile(sp)
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

	data, err := os.ReadFile(matchedPath)
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
	f, err := os.Open(path)
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
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			paths = append(paths, filepath.Join(discDir, e.Name()))
		}
	}
	sort.Strings(paths)
	return paths
}

func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	job.mu.Lock()
	if job.Cancel != nil {
		job.Cancel()
	}
	job.mu.Unlock()

	s.mgr.remove(id)
	_ = os.RemoveAll(filepath.Join(s.outDir, id))
	w.WriteHeader(http.StatusNoContent)
}

// ─── Background job runner ─────────────────────────────────────────────────

func (s *Server) runJob(job *Job) {
	outDir := filepath.Join(s.outDir, job.ID)

	defer func() {
		// Panic recovery — log and mark error rather than silently dropping the goroutine.
		if r := recover(); r != nil {
			job.addLog(fmt.Sprintf("[error] internal panic: %v", r))
			job.mu.Lock()
			if job.Status == StatusRunning {
				job.Status = StatusError
			}
			job.mu.Unlock()
		}
		// Persist full log buffer to logs.txt.
		job.mu.Lock()
		logData := strings.Join(job.LogBuf, "\n") + "\n"
		job.mu.Unlock()
		_ = os.WriteFile(filepath.Join(outDir, "logs.txt"), []byte(logData), 0640)
	}()

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
	args := []string{"scan", localPath, "--output", outDir}
	if job.language != "" {
		args = append(args, "--language", job.language)
	}
	if job.model != "" && job.model != "opus" {
		args = append(args, "--model", job.model)
	}
	if job.verify {
		args = append(args, "--verify")
	}
	if job.dynamicTest {
		args = append(args, "--dynamic-test")
	}
	if isURL {
		args = append(args, "--repo-url", job.Repo)
	}

	job.addLog("→ Running: python -m openant " + strings.Join(args, " "))

	exitCode, err := python.InvokeCtx(job.ctx, s.pythonPath, args, "", job.apiKey, job.addLog)
	if job.ctx.Err() != nil {
		return // cancelled — don't mark error
	}
	if err != nil {
		job.addLog("[error] scan failed to start: " + err.Error())
		job.setError()
		return
	}
	// Exit code 1 means "scan succeeded but found vulnerabilities" (like grep).
	// Exit code 2+ means actual failure.
	if exitCode >= 2 {
		job.addLog(fmt.Sprintf("[error] scan exited with code %d", exitCode))
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

	// Generate Markdown summary (non-fatal — requires API key / LLM).
	summaryPath := filepath.Join(outDir, "SUMMARY_REPORT.md")
	if err := s.generateSummary(job.ctx, outDir, summaryPath, job.apiKey, job.addLog); err != nil {
		if job.ctx.Err() != nil {
			return
		}
		job.addLog("[report] Warning: summary not generated: " + err.Error())
		summaryPath = "" // leave button disabled
	}
	// Also check pre-existing locations (e.g. from a previous run).
	if summaryPath == "" || !fileExists(summaryPath) {
		summaryPath = ""
		for _, sp := range []string{
			filepath.Join(outDir, "report", "SUMMARY_REPORT.md"),
			filepath.Join(outDir, "SUMMARY_REPORT.md"),
		} {
			if fileExists(sp) {
				summaryPath = sp
				break
			}
		}
	}

	disclosurePaths := findDisclosures(outDir)

	job.setDone(reportPath, summaryPath, disclosurePaths)
}

// cloneRepo runs git clone --depth 1 and streams stderr to onLog.
func cloneRepo(ctx context.Context, repo, dest string, onLog func(string)) error {
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", repo, dest)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stderr)
	for sc.Scan() {
		onLog("[clone] " + sc.Text())
	}
	return cmd.Wait()
}

// patchPipelineOutput updates the repository.url field in pipeline_output.json.
func patchPipelineOutput(outDir, repo string, onLog func(string)) {
	path := filepath.Join(outDir, "pipeline_output.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return // file doesn't exist, skip silently
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
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

// randomID generates a 16-character cryptographically random hex string.
func randomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}


