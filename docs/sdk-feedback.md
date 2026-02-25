# PostureIQ — SDK Feedback Log

> Running log of GitHub Copilot SDK pain points, API gaps, documentation issues, and suggestions.
> This document will be submitted as part of the challenge for **10 bonus points**.

---

## Format

Each entry follows:
```
### [DATE] — [CATEGORY]
**Issue:** Brief description
**Impact:** How it affected development
**Suggestion:** What would improve the experience
```

Categories: `API`, `Documentation`, `DX (Developer Experience)`, `Bug`, `Feature Request`

---

## Entries

### 2026-02-25 — DX

**Issue:** SDK installation and initial setup — documenting first impressions
**Impact:** Starting project scaffolding; evaluating SDK ergonomics
**Suggestion:** TBD — will log setup friction as encountered

---

### 2026-02-25 — DX (Package Name)

**Issue:** The Python package is named `github-copilot-sdk` on PyPI but the import name is just `copilot` (`from copilot import CopilotClient`). The original docs/examples reference `copilot-sdk` which doesn't exist on PyPI. Had to trial-and-error to discover `github-copilot-sdk` as the installable package name and `copilot` as the importable module.
**Impact:** ~15 minutes wasted trying `pip install copilot-sdk` (not found), then guessing `github-copilot-sdk`. Confusion between package name (`github-copilot-sdk`) and import name (`copilot`) is a common Python anti-pattern.
**Suggestion:** Either (1) align the PyPI package name with the import name (e.g., `copilot`), or (2) prominently document the install command in the README/quickstart: `pip install github-copilot-sdk` → `from copilot import CopilotClient`.

---

*Log entries will be added throughout development as issues are encountered.*
