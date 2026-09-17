# RALPH architecture map

This navigation layer supports future separation; it is not a second implementation. Embedded behavior remains in `scripts/ralph.py`, which imports `ZEN_PROFILE` from `scripts/ralph_profile.py`.

| View | Current source | Future home | Disposition |
| --- | --- | --- | --- |
| Controller protocol/trust boundary | [architecture](../architecture.md), [core boundary](../extraction/CORE_BOUNDARY.md) | RALPH core | move behavior |
| Lifecycle and approval | [lifecycle map](../lifecycle/README.md) | RALPH core | move behavior |
| Paths, policy, validation, metadata | [ZEN integration](../../zen/ralph-integration/README.md) | ZEN adapter | remain host-owned |
| State/recovery | [state](../state/README.md), [recovery](../recovery/README.md) | core contract + adapter | split |

The duplicate reader-oriented pages (`architecture.md`, `lifecycle.md`, and `concepts.md`) are intentionally retained for ZEN operators while this map seeds future core documentation. Canonicalization waits for approved physical extraction.
