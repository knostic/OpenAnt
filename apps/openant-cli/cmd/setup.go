package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/x/term"
	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/spf13/cobra"
)

// errStdinClosed surfaces when reader.ReadString hits EOF without any
// input on the current line. The wizard treats that as "user aborted"
// and exits cleanly — without it, every required-prompt loop would
// spin forever in a non-interactive context (no TTY, piped input
// exhausted, etc.).
var errStdinClosed = errors.New("stdin closed before answer provided")

// Pipeline phases that every llm-config must list. Mirrors PHASES in
// “libs/openant-core/utilities/llm/config.py“ — adding a phase requires
// touching both lists. The order here drives the wizard's question flow
// and matches the actual scan execution order in “core/scanner.py“, so
// a user setting up their config walks through phases in the same
// sequence they'll see when they run “openant scan“.
//
// “defaultModels“ maps a provider type to the model the wizard
// pre-fills as the default for THIS phase. Picks reflect the
// project's recommendation: stronger reasoning models for detection /
// verification / reachability review, lighter/faster models for
// generation phases like enhance / report / dynamic_test / app_context.
// Users can always override at the prompt.
var setupLLMPhases = []phaseSpec{
	{
		name:  "app_context",
		short: "Application-context classification (runs first in scan).",
		defaultModels: map[string]string{
			"anthropic": "claude-sonnet-4-20250514",
			"openai":    "gpt-4o-mini",
			"google":    "gemini-2.0-flash",
		},
	},
	{
		name:  "llm_reach",
		short: "LLM-driven reachability review (opt-in stage).",
		defaultModels: map[string]string{
			"anthropic": "claude-opus-4-6",
			"openai":    "gpt-4o",
			"google":    "gemini-1.5-pro",
		},
	},
	{
		name:  "enhance",
		short: "Context enhancement (single-shot + agentic tool calling).",
		defaultModels: map[string]string{
			"anthropic": "claude-sonnet-4-20250514",
			"openai":    "gpt-4o-mini",
			"google":    "gemini-2.0-flash",
		},
	},
	{
		name:  "analyze",
		short: "Stage 1 vulnerability detection.",
		defaultModels: map[string]string{
			"anthropic": "claude-opus-4-6",
			"openai":    "gpt-4o",
			"google":    "gemini-1.5-pro",
		},
	},
	{
		name:  "verify",
		short: "Stage 2 attacker simulation (tool calling).",
		defaultModels: map[string]string{
			"anthropic": "claude-opus-4-6",
			"openai":    "gpt-4o",
			"google":    "gemini-1.5-pro",
		},
	},
	{
		name:  "dynamic_test",
		short: "Docker exploit-test generation.",
		defaultModels: map[string]string{
			"anthropic": "claude-sonnet-4-20250514",
			"openai":    "gpt-4o-mini",
			"google":    "gemini-2.0-flash",
		},
	},
	{
		name:  "report",
		short: "Disclosure + summary + remediation generation.",
		defaultModels: map[string]string{
			"anthropic": "claude-sonnet-4-20250514",
			"openai":    "gpt-4o-mini",
			"google":    "gemini-2.0-flash",
		},
	},
}

// knownModels maps a provider type to a list of well-known model IDs
// shown as a hint to the user when they first configure a provider of
// that type in the session. NOT exhaustive — providers regularly add
// new models, and entries here only include IDs known to exist at the
// provider's main endpoint as of this file's last update. Newer models
// (gpt-5/o3/gemini-2.5/etc.) may also be available — check the
// provider's docs and type the exact ID at the prompt.
var knownModels = map[string][]string{
	"anthropic": {
		"claude-opus-4-6",
		"claude-opus-4-20250514",
		"claude-sonnet-4-20250514",
		"claude-haiku-4-5-20251001",
	},
	"openai": {
		"gpt-4o",
		"gpt-4o-mini",
		"o1",
		"o3-mini",
	},
	"google": {
		"gemini-1.5-pro",
		"gemini-1.5-flash",
		"gemini-2.0-flash",
		"gemini-2.0-flash-lite",
	},
}

// Provider adapter types the wizard offers in the picker. All three
// ship with a Python adapter (anthropic, openai, google) — see
// “libs/openant-core/utilities/llm/providers/__init__.py“ — so a
// completed wizard config runs without further changes. The wizard
// probes each provider+model pair against the real provider API
// before saving, so a typo'd key or model ID surfaces immediately.
var supportedProviderTypes = []string{"anthropic", "openai", "google"}

// apiKeyHints maps a provider type to a one-line reminder shown right
// before the wizard asks for the API key. Used to head off the common
// "I have a ChatGPT/Claude/Gemini subscription, why doesn't it work?"
// confusion — consumer subscriptions are NOT the same product as the
// REST API and don't share quota. Today only OpenAI has a note here
// (the conversation that motivated this came up around Codex/ChatGPT
// subscriptions); the map is keyed by provider so anthropic/google
// can grow their own reminders later without touching the prompt loop.
var apiKeyHints = map[string]string{
	"openai": "Note: ChatGPT/Codex subscriptions do NOT include API access — get an API key at platform.openai.com (separate billing).",
}

type phaseSpec struct {
	name  string
	short string
	// defaultModels: provider type → suggested model for this phase
	// when the provider has no base_url override. A custom base_url
	// short-circuits this map (the user is hitting a proxy, so the
	// provider's stock model list may not apply).
	defaultModels map[string]string
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive configuration wizards",
	Long: `Interactive wizards for first-time OpenAnt setup.

Subcommands ask focused questions and write the answers to
~/.config/openant/config.json. Useful for users who'd rather not
hand-author the v2 config JSON.`,
}

var setupLLMCmd = &cobra.Command{
	Use:   "llm",
	Short: "Walk through creating an llm-config interactively",
	Long: `Interactive wizard for creating an llm-config.

Asks per-phase questions: which provider, which model. Reuses
credentials across phases that share a provider name. Validates each
unique (provider, model) pair with a 1-token probe before writing so
a typo'd key or model ID surfaces here instead of at the next scan.

The built-in ` + "`openant-default`" + ` llm-config is always available without
running this wizard. Use ` + "`setup llm`" + ` when you want a non-default
configuration — e.g. a different model for the analyze phase, or a
separate provider entry for a proxy / Anthropic-compatible endpoint.`,
	Args: cobra.NoArgs,
	Run:  runSetupLLM,
}

func init() {
	setupCmd.AddCommand(setupLLMCmd)
	rootCmd.AddCommand(setupCmd)
}

// ---------------------------------------------------------------------------
// Wizard entry point
// ---------------------------------------------------------------------------

func runSetupLLM(cmd *cobra.Command, args []string) {
	cfg, err := config.Load()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	reader := bufio.NewReader(os.Stdin)
	writeIntro(os.Stderr, cfg)

	// Name + overwrite confirmation.
	configName, ok, err := promptLLMConfigName(reader, cfg)
	if err != nil {
		exitOnInputError(err)
	}
	if !ok {
		return
	}

	// Walk every phase. Provider details collected once per provider
	// name and reused within the session. ``shownModelHints`` tracks
	// which providers have already had their known-models list shown
	// in this session so we don't repeat the hint on every phase.
	sessionProviders := map[string]config.ProviderEntry{}
	shownModelHints := map[string]bool{}
	phaseChoices := map[string]config.LLMPhaseRef{}
	lastProvider := defaultStartingProvider(cfg)

	for _, spec := range setupLLMPhases {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "--- %s phase ---\n", spec.name)
		fmt.Fprintln(os.Stderr, spec.short)

		providerName, err := promptRequired(reader, "Provider name", lastProvider)
		if err != nil {
			exitOnInputError(err)
		}

		// Establish provider details exactly once per name per session.
		if _, alreadyAsked := sessionProviders[providerName]; !alreadyAsked {
			provEntry, provExisted := cfg.GetProvider(providerName)
			if provExisted {
				fmt.Fprintf(os.Stderr, "Using existing provider %q (type=%s)\n", providerName, provEntry.Type)
				sessionProviders[providerName] = provEntry
			} else {
				entry, err := promptNewProvider(reader, providerName)
				if err != nil {
					exitOnInputError(err)
				}
				sessionProviders[providerName] = entry
			}
		}

		prov := sessionProviders[providerName]
		// Show the known-models hint the first time a provider is
		// referenced in this session. Suppressed when a base_url
		// override is set — the user is hitting a proxy with its
		// own model namespace, so the stock list would mislead.
		if !shownModelHints[providerName] {
			shownModelHints[providerName] = true
			if prov.BaseURL == "" {
				if opts, ok := knownModels[prov.Type]; ok && len(opts) > 0 {
					fmt.Fprintf(os.Stderr, "  Known %s models: %s\n", prov.Type, strings.Join(opts, ", "))
				}
			}
		}

		// Per-phase suggested model for the provider type. A custom
		// base_url short-circuits the suggestion (proxy may not host
		// the same model IDs).
		defaultModel := ""
		if prov.BaseURL == "" {
			defaultModel = spec.defaultModels[prov.Type]
		}
		model, err := promptRequired(reader, "Model", defaultModel)
		if err != nil {
			exitOnInputError(err)
		}

		phaseChoices[spec.name] = config.LLMPhaseRef{Provider: providerName, Model: model}
		lastProvider = providerName
	}

	// default_llm flag.
	fmt.Fprintln(os.Stderr)
	makeDefault, err := promptYesNo(reader, fmt.Sprintf("Set %q as default_llm?", configName), true)
	if err != nil {
		exitOnInputError(err)
	}

	// Probe each unique (provider, model) pair.
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Probing providers (1-token request per unique provider+model)...")
	if err := probeAllPhases(sessionProviders, phaseChoices); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	// Commit.
	cfg.WriteLLMConfig(configName, phaseChoices, sessionProviders, makeDefault)
	if err := config.Save(cfg); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr)
	output.PrintSuccess(fmt.Sprintf("llm-config %q written.", configName))
	if makeDefault {
		fmt.Fprintf(os.Stderr, "  default_llm: %s\n", configName)
	}
	path, _ := config.Path()
	fmt.Fprintf(os.Stderr, "  config:      %s\n", path)
}

// ---------------------------------------------------------------------------
// Intro
// ---------------------------------------------------------------------------

func writeIntro(w io.Writer, cfg *config.Config) {
	fmt.Fprintln(w, "OpenAnt LLM setup wizard")
	fmt.Fprintln(w, "Creates a named llm-config in ~/.config/openant/config.json.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The pipeline binds each phase to its configured (provider, model).")
	fmt.Fprintln(w, "Phases:")
	for _, spec := range setupLLMPhases {
		fmt.Fprintf(w, "  - %-13s %s\n", spec.name, spec.short)
	}
	fmt.Fprintln(w)

	existingConfigs := cfg.LLMConfigNames()
	sort.Strings(existingConfigs)
	if len(existingConfigs) > 0 {
		fmt.Fprintln(w, "Existing llm-configs in your file:")
		for _, name := range existingConfigs {
			fmt.Fprintf(w, "  - %s\n", name)
		}
	} else {
		fmt.Fprintln(w, "(No user-authored llm-configs yet — openant-default is always available.)")
	}
	existingProviders := cfg.ProviderNames()
	sort.Strings(existingProviders)
	if len(existingProviders) > 0 {
		fmt.Fprintln(w, "Existing providers (re-using one of these skips the credential questions):")
		for _, name := range existingProviders {
			if p, ok := cfg.GetProvider(name); ok {
				fmt.Fprintf(w, "  - %s (type=%s)\n", name, p.Type)
			}
		}
	}
	fmt.Fprintln(w)
}

// ---------------------------------------------------------------------------
// Prompt helpers
// ---------------------------------------------------------------------------

func promptLLMConfigName(reader *bufio.Reader, cfg *config.Config) (string, bool, error) {
	for {
		name, err := promptString(reader, "Name for this llm-config", "")
		if err != nil {
			return "", false, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			fmt.Fprintln(os.Stderr, "Name cannot be empty.")
			continue
		}
		if name == "openant-default" {
			fmt.Fprintln(os.Stderr, "'openant-default' is the built-in baseline and cannot be redefined. Pick a different name.")
			continue
		}
		if cfg.LLMConfigExists(name) {
			replace, yesErr := promptYesNo(reader, fmt.Sprintf("llm-config %q already exists. Replace?", name), false)
			if yesErr != nil {
				return "", false, yesErr
			}
			if !replace {
				fmt.Fprintln(os.Stderr, "Cancelled.")
				return "", false, nil
			}
		}
		return name, true, nil
	}
}

func promptNewProvider(reader *bufio.Reader, name string) (config.ProviderEntry, error) {
	// When the provider name matches a known type ("anthropic",
	// "openai", "google"), default the type field to that — saves
	// the user a keystroke in the common case where they name the
	// provider after its type. Otherwise no default; the user picks
	// explicitly from the supported list.
	defaultType := ""
	if stringSliceContains(supportedProviderTypes, name) {
		defaultType = name
	}

	for {
		provType, err := promptRequired(reader, fmt.Sprintf("Provider type %v", supportedProviderTypes), defaultType)
		if err != nil {
			return config.ProviderEntry{}, err
		}
		if !stringSliceContains(supportedProviderTypes, provType) {
			fmt.Fprintf(os.Stderr, "Unknown provider type %q. The wizard offers: %v.\n", provType, supportedProviderTypes)
			fmt.Fprintln(os.Stderr, "To use a provider not listed here, contribute an adapter — see docs/features/llm-providers/HOW_TO_ADD_AN_ADAPTER.md.")
			continue
		}
		// Per-provider subscription-vs-API reminder — the wizard needs
		// an API key, not consumer-subscription credentials. ChatGPT /
		// Claude Pro / Gemini Advanced subscriptions are separate
		// billing tiers from each provider's API, and users frequently
		// hit this confusion because it's the same company and login.
		if hint, ok := apiKeyHints[provType]; ok {
			fmt.Fprintln(os.Stderr, hint)
		}
		// No-echo read so the pasted key never lands in the terminal
		// scrollback. Blank input is still allowed (read from env), and
		// on a non-TTY this transparently falls back to a normal line read.
		apiKey, err := promptSecret(reader, "API key (paste; leave blank to read from environment)")
		if err != nil {
			return config.ProviderEntry{}, err
		}
		baseURL, err := promptString(reader, "Base URL (optional — leave blank for the provider's default endpoint)", "")
		if err != nil {
			return config.ProviderEntry{}, err
		}
		return config.ProviderEntry{Type: provType, APIKey: apiKey, BaseURL: baseURL}, nil
	}
}

// exitOnInputError prints a clean message and exits when the wizard
// can't continue because stdin is closed. Used at every prompt
// invocation site so the calling code stays linear.
func exitOnInputError(err error) {
	if errors.Is(err, errStdinClosed) {
		fmt.Fprintln(os.Stderr)
		output.PrintError("Cancelled — no more input.")
		os.Exit(1)
	}
	output.PrintError(err.Error())
	os.Exit(1)
}

// readLine reads one line. Returns “errStdinClosed“ if the reader
// hits EOF on an empty line — which is how non-interactive contexts
// (piped input exhausted, no TTY) surface "no answer". Without this
// signal, every required-prompt loop would spin forever.
func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if errors.Is(err, io.EOF) && line == "" {
		return "", errStdinClosed
	}
	return line, nil
}

// promptString reads a line. Empty input → returns “defaultVal“. The
// prompt is printed to stderr (not stdout) so the wizard composes
// cleanly with shell redirection — a user piping output to a file
// still sees the questions.
func promptString(reader *bufio.Reader, prompt, defaultVal string) (string, error) {
	if defaultVal == "" {
		fmt.Fprintf(os.Stderr, "%s: ", prompt)
	} else {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", prompt, defaultVal)
	}
	line, err := readLine(reader)
	if err != nil {
		return "", err
	}
	if line == "" {
		return defaultVal, nil
	}
	return line, nil
}

// promptSecret reads a single secret line (e.g. an API key) WITHOUT
// echoing it to the terminal — closing the shoulder-surf / scrollback
// leak that the plain ``promptString`` path left open for the API key.
//
// On an interactive terminal it uses term.ReadPassword (no echo) and
// prints a trailing newline to stderr (the no-echo read swallows the
// user's Enter). When stdin is NOT a terminal — piped/scripted input,
// CI, or the test suite — there is no echo to suppress and ReadPassword
// would error on the non-TTY fd, so it falls back to the ordinary
// reader-based ``promptString`` path. This keeps scripted setup and the
// existing tests working while protecting real interactive use.
//
// The prompt is written to stderr (like every other wizard prompt) so
// the secret read composes with shell redirection of stdout.
func promptSecret(reader *bufio.Reader, prompt string) (string, error) {
	if !term.IsTerminal(os.Stdin.Fd()) {
		// Non-interactive: nothing to hide, and ReadPassword can't
		// operate on a pipe — defer to the standard line read.
		return promptString(reader, prompt, "")
	}
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	raw, err := term.ReadPassword(os.Stdin.Fd())
	// ReadPassword consumes the Enter keystroke without echoing it, so
	// emit the newline ourselves to keep subsequent output on its own
	// line — even on the error path.
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// promptRequired loops until the user supplies a non-empty value.
// Required questions like "Model" can't fall back to a blank default
// silently — the resulting config would be malformed.
func promptRequired(reader *bufio.Reader, prompt, defaultVal string) (string, error) {
	for {
		val, err := promptString(reader, prompt, defaultVal)
		if err != nil {
			return "", err
		}
		val = strings.TrimSpace(val)
		if val != "" {
			return val, nil
		}
		fmt.Fprintln(os.Stderr, "  (this field is required)")
	}
}

// promptYesNo accepts y/n/yes/no (case-insensitive). Empty input
// returns “defaultVal“ so the user can mash enter to accept.
func promptYesNo(reader *bufio.Reader, prompt string, defaultVal bool) (bool, error) {
	hint := "[y/N]"
	if defaultVal {
		hint = "[Y/n]"
	}
	for {
		fmt.Fprintf(os.Stderr, "%s %s ", prompt, hint)
		line, err := readLine(reader)
		if err != nil {
			return false, err
		}
		line = strings.TrimSpace(strings.ToLower(line))
		switch line {
		case "":
			return defaultVal, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(os.Stderr, "  Please answer y or n.")
		}
	}
}

// ---------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------

func probeAllPhases(
	providers map[string]config.ProviderEntry,
	phases map[string]config.LLMPhaseRef,
) error {
	seen := map[string]bool{}
	// Sort phase names so the probe order is deterministic — matters
	// when the user is watching output scroll by.
	phaseNames := make([]string, 0, len(phases))
	for p := range phases {
		phaseNames = append(phaseNames, p)
	}
	sort.Strings(phaseNames)

	for _, phase := range phaseNames {
		ref := phases[phase]
		key := ref.Provider + "|" + ref.Model
		if seen[key] {
			continue
		}
		seen[key] = true

		prov, ok := providers[ref.Provider]
		if !ok {
			return fmt.Errorf("internal: provider %q referenced by phase %q but not collected", ref.Provider, phase)
		}
		fmt.Fprintf(os.Stderr, "  %s/%s ... ", ref.Provider, ref.Model)
		if prov.APIKey == "" {
			// Blank key means "read from the environment" (the wizard
			// offers this and WriteLLMConfig persists the env-read shape).
			// The Go probe can't read the provider's env var, so skip it;
			// Python's registry.validate() surfaces a missing/blank env
			// key at scan start instead.
			fmt.Fprintln(os.Stderr, "SKIPPED (key from environment)")
			continue
		}
		var probeErr error
		switch prov.Type {
		case "anthropic":
			probeErr = probeAnthropic(prov.APIKey, prov.BaseURL, ref.Model)
		case "openai":
			probeErr = probeOpenAI(prov.APIKey, prov.BaseURL, ref.Model)
		case "google":
			probeErr = probeGoogle(prov.APIKey, prov.BaseURL, ref.Model)
		default:
			fmt.Fprintln(os.Stderr, "SKIPPED")
			return fmt.Errorf("provider type %q has no probe implementation yet", prov.Type)
		}
		if probeErr != nil {
			fmt.Fprintln(os.Stderr, "FAILED")
			return fmt.Errorf("probe failed for provider %q model %q: %w", ref.Provider, ref.Model, probeErr)
		}
		fmt.Fprintln(os.Stderr, "OK")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

func defaultStartingProvider(cfg *config.Config) string {
	// If the user already has providers on disk, default to the first
	// one alphabetically (most likely "anthropic"). Otherwise default
	// to "anthropic" — the reference adapter and the most common choice.
	names := cfg.ProviderNames()
	sort.Strings(names)
	if len(names) > 0 {
		return names[0]
	}
	return "anthropic"
}

func stringSliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
