# Coding agents

agent-sudo needs no cooperation from agents: point an agent's `PATH` at the shim
(`agent-sudo-hostd shim install`, then `~/.agent-tools` first on its `PATH`) and plain
`sudo` goes through the approval service.

The optional **skill** makes requests easier to judge: agents call `agent-sudo`
directly and explain themselves with `--agent-context`. Install it for every agent
found on the machine, as your own user:

```sh
agent-sudo-hostd skill install      # --dry-run to preview, --yes to skip the prompt
agent-sudo-hostd skill status
agent-sudo-hostd skill remove
```

It writes `~/.agents/skills/agent-sudo/SKILL.md`, which most agents read, plus a copy
in the folders of detected agents that only read their own. Re-run after upgrading.

| Agent | Reads the skill from |
| --- | --- |
| Claude Code | `~/.claude/skills` |
| OpenAI Codex | `~/.agents/skills` (and the legacy `~/.codex/skills` if present) |
| Gemini CLI | `~/.agents/skills` |
| GitHub Copilot CLI | `~/.agents/skills` |
| Cursor | `~/.agents/skills` |
| opencode | `~/.agents/skills` |
| Goose | `~/.agents/skills` |
| Amp | `~/.agents/skills` |
| Grok CLI | `~/.grok/skills` |
| Qwen Code | `~/.qwen/skills` |
| Crush | `~/.agents/skills` |
| Factory Droid | `~/.agents/skills` |
| Cline | `~/.cline/skills` |
| Kilo Code | `~/.agents/skills` |
| Devin Desktop / Windsurf | `~/.agents/skills` |
| Kiro | `~/.kiro/skills` |
| Augment (Auggie) | `~/.agents/skills` |
| OpenHands | `~/.agents/skills` |
| Mistral Vibe | `~/.agents/skills` |
| Junie | `~/.agents/skills` |
| Trae | `~/.trae/skills` (`~/.trae-cn/skills` for the China build) |
| Zed | `~/.agents/skills` |
| Google Antigravity | `~/.gemini/config/skills` |

Sources: each agent's skills documentation as of September 2026 (for example
[Codex](https://learn.chatgpt.com/docs/build-skills.md),
[Gemini CLI](https://geminicli.com/docs/cli/skills/),
[Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills),
[Cursor](https://cursor.com/docs/skills), [opencode](https://opencode.ai/docs/skills/),
[Goose](https://goose-docs.ai/docs/guides/context-engineering/using-skills/),
[Amp](https://ampcode.com/docs/customize/skills),
[Qwen Code](https://qwenlm.github.io/qwen-code-docs/en/users/features/skills/),
[Crush](https://github.com/charmbracelet/crush),
[Factory](https://docs.factory.ai/cli/configuration/skills),
[Cline](https://docs.cline.bot/customization/skills),
[Kilo](https://kilo.ai/docs/customize/skills),
[Devin](https://docs.devin.ai/desktop/cascade/skills), [Kiro](https://kiro.dev/docs/skills/),
[Auggie](https://docs.augmentcode.com/cli/skills),
[OpenHands](https://docs.openhands.dev/overview/skills),
[Vibe](https://docs.mistral.ai/vibe/code/cli/skills),
[Junie](https://junie.jetbrains.com/docs/agent-skills.html),
[Trae](https://docs.trae.ai/ide/skills), [Zed](https://zed.dev/docs/ai/skills),
[Antigravity](https://codelabs.developers.google.com/getting-started-with-antigravity-skills)).
Warp also reads `~/.agents/skills` but currently has a bug that skips global skills.
Agents without skill support can still use the PATH shim.
