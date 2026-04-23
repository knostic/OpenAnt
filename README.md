<p align="center">
  <img src="assets/open-ant-black.png" alt="OpenAnt" width="180" />
</p>

# OpenAnt

[OpenAnt](https://knostic.ai/openant) from [Knostic](https://knostic.ai) is the leading open source LLM-based vulnerability discovery product, helping defenders proactively find verified security flaws while minimizing both false positives and false negatives. Stage 1 detects. Stage 2 attacks. What survives is real.

We're pretty proud of this product and are in the vulnerability disclosure process for its findings, but do keep in mind that this started as a research project, and some of its features are still in beta. We welcome contributions to make it better.

## Why open source?
Considering the explosion of AI-discovered vulnerabilities, we hope OpenAnt will be the tool helping open source maintainers stay ahead of attackers, where they can use it themselves or submit their repo for scanning at no cost.

While we do provide OpenAnt as a service, you may have heard about Aardvark from OpenAI (now Codex Security) and Claude Code Security from Anthropic, and we have zero intention of competing with them.

## Technical details and free scanning for open source projects
For technical details, limitations, and token costs, check out this blog post:
[https://knostic.ai/blog/openant](https://knostic.ai/blog/openant)

To submit your repo for scanning:
[https://knostic.ai/blog/oss-scan](https://knostic.ai/blog/oss-scan)

## Supported languages
- Go
- Python
- JavaScript/TypeScript (beta)
- C/C++ (beta)
- PHP (beta)
- Ruby (beta)

## Credits
Research and ideation: [Nahum Korda](https://github.com/NahumKorda/).

Productization: Alex Raihelgaus, Daniel Geyshis.

With thanks to: [Michal Kamensky](https://github.com/kamenskymic/), [Imri Goldberg](https://github.com/lorg), [Gadi Evron](https://github.com/gadievron/), Daniel Cuthbert. Josh Grossman, and Avi Douglen.

## Check out Knostic
**If you like our work**, check out what we do at [Knostic](https://knostic.ai) to defend your agents and coding assistants, prevent them from deleting your hard drive and code, and control associated supply chain risks such as MCP servers, extensions, and skills.


## Local setup

Build the CLI binary (requires Go 1.25+):

```bash
cd apps/openant-cli && make build
```

This compiles the Go source and outputs the binary to `apps/openant-cli/bin/openant`.

Symlink it onto your PATH so you can run `openant` from anywhere:

```bash
ln -sf "$(pwd)/apps/openant-cli/bin/openant" /usr/local/bin/openant
```

_Note: run this from the repo root so `$(pwd)` resolves to the correct absolute path._

Set your Anthropic API key (required for analyze, verify, and scan):

```bash
openant set-api-key <your-key>
```

**The key must have access to the Claude Opus 4.6 model.** Get a key at [console.anthropic.com](https://console.anthropic.com/settings/keys).

## Data directories

OpenAnt creates two directories:

- **`~/.config/openant/`** — CLI configuration (`config.json`). Stores your API key, active project, and preferences. File permissions are restricted to `0600`.
- **`~/.openant/`** — Project data. Each initialized project gets a workspace under `~/.openant/projects/<org>/<repo>/` containing `project.json` and a `scans/` directory with per-commit outputs.

## Analyzing a project

### 1. Initialize

Point OpenAnt at a repository. The `-l` flag (language) is required — use `go` or `python`.

```bash
# Remote — clones the repo
openant init <repo-url> -l go

# Remote — pin to a specific commit
openant init <repo-url> -l go --commit <sha>

# Local — references the directory in-place
openant init <path-to-repo> -l go --name <org/repo>
```

This creates a project workspace and sets it as the active project. All subsequent commands operate on the active project automatically — no path arguments needed.

### 2. Run the pipeline

Each step picks up the output of the previous one from the project's scan directory:

```bash
openant parse
openant enhance
openant analyze
openant verify
openant build-output
openant report -f summary
```

Or run the full pipeline in one command:

```bash
openant scan --verify
```

### Working with multiple projects

The pipeline operates on one project at a time. Running `openant init` sets the newly initialized project as the active one, so all subsequent commands target it by default.

If you're working with several projects, you have two options:

```bash
# Option 1: switch the active project
openant project switch org/repo
openant parse

# Option 2: target a project directly with -p
openant parse -p org/repo
```

### Project management

```bash
openant project list              # shows all projects, marks active
openant project show              # details of active project
openant project switch <org/repo> # switch active project
```


## LICENSE
This project is licensed under Apache 2. See the LICENSE file for details.


## Disclaimer and legal notice
This project is intended for defensive and research purposes only. OpenAnt is still in the research phase, use it carefully and at your own risk. Knostic, OpenAnt, and associated developers, researchers, and maintainers assume no responsibility whatsoever for any misuse, damage, or consequences arising from the use of this tool.

Only scan code you own or have explicit permission to test. If you discover a vulnerability in someone else's project through legitimate means, please follow coordinated vulnerability disclosure practices and report it to the maintainers before making it public.
