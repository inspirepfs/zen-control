# RALPH recovery map

Recovery is core lifecycle behavior backed by host-associated Git and state. Current evidence includes `.ralph/recovery/<checkpoint>/manifest.json`, `.ralph/state.json.repair-*.bak`, `.ralph/journal.md`, and Git checkpoint references/patches produced by `scripts/ralph.py`.

Core retains integrity/decision rules; ZEN retains Git/worktree behavior, locations, retention, and operator procedures. A non-Git implementation is not designed or implied. See [state ownership](../extraction/STATE_OWNERSHIP.md) and the [dry run](../extraction/DRY_RUN.md).
