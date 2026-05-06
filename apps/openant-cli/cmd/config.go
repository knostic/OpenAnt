package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage CLI configuration",
	Long: `View and update OpenAnt CLI settings.

Configuration is stored in ~/.config/openant/config.json.

Examples:
  openant config set api-key        Set your API key (interactive)
  openant config set base-url       Set LLM endpoint for local AI
  openant config set opus-model     Set model for heavy analysis
  openant config set sonnet-model   Set model for lighter tasks
  openant config show               View current configuration
  openant config unset base-url     Remove a setting
  openant config path               Print the config file path`,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key>",
	Short: "Set a configuration value",
	Long: `Set a configuration value. For sensitive values like api-key,
the value is read from stdin (not echoed) to avoid shell history exposure.

Supported keys: api-key, base-url, default-model, opus-model, sonnet-model, verify-ssl

Examples:
  openant config set api-key              Interactive prompt (recommended)
  openant config set base-url             Set LLM endpoint (e.g. http://localhost:8080)
  openant config set opus-model           Set model name for heavy analysis
  openant config set sonnet-model         Set model name for lighter tasks
  openant config set verify-ssl           Enable/disable SSL certificate verification
  echo "sk-ant-..." | openant config set api-key --stdin   Piped input`,
	Args: cobra.ExactArgs(1),
	Run:  runConfigSet,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Run:   runConfigShow,
}

var configUnsetCmd = &cobra.Command{
	Use:   "unset <key>",
	Short: "Remove a configuration value",
	Args:  cobra.ExactArgs(1),
	Run:   runConfigUnset,
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print the config file path",
	Run:   runConfigPath,
}

var configStdin bool

func init() {
	configSetCmd.Flags().BoolVar(&configStdin, "stdin", false, "Read value from stdin (for piped input)")

	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configUnsetCmd)
	configCmd.AddCommand(configPathCmd)
}

func runConfigSet(cmd *cobra.Command, args []string) {
	key := args[0]

	cfg, err := config.Load()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	var value string

	switch key {
	case "api-key":
		if configStdin {
			// Read from stdin (piped)
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		} else {
			// Interactive prompt
			fmt.Fprint(os.Stderr, "Enter API key: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		}

		if value == "" {
			output.PrintError("No value provided")
			os.Exit(1)
		}

		cfg.APIKey = value

	case "default-model":
		if configStdin {
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		} else {
			fmt.Fprint(os.Stderr, "Enter default model: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		}

		if value == "" {
			output.PrintError("No value provided")
			os.Exit(1)
		}

		cfg.DefaultModel = value

	case "base-url":
		if configStdin {
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		} else {
			fmt.Fprint(os.Stderr, "Enter LLM API base URL (e.g. http://localhost:8080): ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		}

		if value == "" {
			output.PrintError("No value provided")
			os.Exit(1)
		}

		cfg.BaseURL = value

	case "opus-model":
		if configStdin {
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		} else {
			fmt.Fprint(os.Stderr, "Enter opus model name (heavy analysis, e.g. qwen3:32b): ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		}

		if value == "" {
			output.PrintError("No value provided")
			os.Exit(1)
		}

		cfg.OpusModel = value

	case "sonnet-model":
		if configStdin {
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		} else {
			fmt.Fprint(os.Stderr, "Enter sonnet model name (lighter tasks, e.g. qwen3:8b): ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		}

		if value == "" {
			output.PrintError("No value provided")
			os.Exit(1)
		}

		cfg.SonnetModel = value

	case "verify-ssl":
		if configStdin {
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		} else {
			fmt.Fprint(os.Stderr, "Verify SSL certificates? (true/false): ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = strings.TrimSpace(scanner.Text())
			}
		}

		switch strings.ToLower(value) {
		case "true", "yes", "1":
			v := true
			cfg.VerifySSL = &v
		case "false", "no", "0":
			v := false
			cfg.VerifySSL = &v
		default:
			output.PrintError("Value must be true or false")
			os.Exit(1)
		}

	default:
		output.PrintError(fmt.Sprintf("Unknown config key: %s\nSupported keys: api-key, base-url, default-model, opus-model, sonnet-model, verify-ssl", key))
		os.Exit(1)
	}

	if err := config.Save(cfg); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	path, _ := config.Path()
	output.PrintSuccess(fmt.Sprintf("%s saved to %s", key, path))
}

func runConfigShow(cmd *cobra.Command, args []string) {
	cfg, err := config.Load()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	path, _ := config.Path()

	output.PrintHeader("Configuration")
	output.PrintKeyValue("api_key", config.MaskKey(cfg.APIKey))
	if cfg.BaseURL != "" {
		output.PrintKeyValue("base_url", cfg.BaseURL)
	}
	if cfg.DefaultModel != "" {
		output.PrintKeyValue("default_model", cfg.DefaultModel)
	}
	if cfg.OpusModel != "" {
		output.PrintKeyValue("opus_model", cfg.OpusModel)
	}
	if cfg.SonnetModel != "" {
		output.PrintKeyValue("sonnet_model", cfg.SonnetModel)
	}
	if cfg.VerifySSL != nil {
		output.PrintKeyValue("verify_ssl", fmt.Sprintf("%v", *cfg.VerifySSL))
	}
	if cfg.ActiveProject != "" {
		output.PrintKeyValue("active_project", cfg.ActiveProject)
	}
	output.PrintKeyValue("config_file", path)
	fmt.Println()
}

func runConfigUnset(cmd *cobra.Command, args []string) {
	key := args[0]

	cfg, err := config.Load()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	switch key {
	case "api-key":
		cfg.APIKey = ""
	case "base-url":
		cfg.BaseURL = ""
	case "default-model":
		cfg.DefaultModel = ""
	case "opus-model":
		cfg.OpusModel = ""
	case "sonnet-model":
		cfg.SonnetModel = ""
	case "verify-ssl":
		cfg.VerifySSL = nil
	default:
		output.PrintError(fmt.Sprintf("Unknown config key: %s\nSupported keys: api-key, base-url, default-model, opus-model, sonnet-model, verify-ssl", key))
		os.Exit(1)
	}

	if err := config.Save(cfg); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	output.PrintSuccess(fmt.Sprintf("%s removed", key))
}

func runConfigPath(cmd *cobra.Command, args []string) {
	path, err := config.Path()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	fmt.Println(path)
}
