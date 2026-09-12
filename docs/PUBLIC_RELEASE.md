# Public Release Checklist

This checklist is deliberately conservative because ZEN can control a real household network.

## Required before changing repository visibility to public

- [ ] Select an open-source license and add the root `LICENSE` file.
- [ ] Rotate any credential that has ever appeared in chat, terminal captures, support bundles or screenshots.
- [ ] Confirm `.env`, `secrets/`, databases, logs, archives and certificates are ignored and absent from Git history.
- [ ] Run `python3 scripts/public_release_audit.py`.
- [ ] Run the full unit/hostile suite.
- [ ] Run the UX validator and Python compile gate.
- [ ] Validate Compose with safe example configuration.
- [ ] Review `git ls-files` manually for household/device/private deployment material.
- [ ] Check README, docs and screenshots for real names, MAC addresses, private hostnames, public hostnames tied to the household, tokens and activity data.
- [ ] Capture only sanitized screenshots.
- [ ] Confirm GitHub Actions passes from the committed tree.
- [ ] Add a repository description/topics and verify `SECURITY.md` is visible.

## Automated host release path

The supported host-side orchestration helper is `scripts/release_patch.py`. It preserves the manual gates rather than hiding them: patch application rejects fuzz/offset/reversed evidence, source validation must pass, the selected containers must rebuild and become healthy, Git staging must be clean, the pushed commit must pass the selected GitHub Actions workflow, and only then may an annotated release tag be pushed.

Important switches include:

- `--patch NAME.patch` — apply a patch; a relative name also searches `../`.
- `--resume` — continue from an already-applied release tree or an already-committed HEAD; clean committed states do not manufacture an empty commit.
- `--rebuild-service SERVICE` — repeat for additional services; default is `mikrotik-control`.
- `--rebuild-all` — explicitly rebuild/start all Compose services.
- `--expect-version VERSION` — require the live health JSON to expose the expected release.
- `--stage PATH` — repeat to restrict staging; otherwise the intentionally changed tree is staged with `git add -A`.
- `--workflow NAME` — GitHub Actions workflow to wait for; default is `Quality`.
- `--tag TAG` — create and push an annotated tag only after watched CI succeeds.
- `--dry-run` — print the plan and commands without changing state.

The normal flow expects a clean tree before patch application. `--resume` handles three explicit states: a dirty reviewed tree is validated/rebuilt and committed; a clean HEAD ahead of the remote is validated/rebuilt and then published; a clean HEAD already present on the remote reuses the commit-scoped CI evidence instead of rebuilding or attempting an empty commit. An existing release tag that resolves to a different commit is a hard `TAG TARGET MISMATCH` gate.

## License decision

Two sensible options for ZEN are:

- **AGPL-3.0** — strong network copyleft; modifications offered as a network service remain source-available under the license terms.
- **Apache-2.0** — permissive; maximizes reuse, including commercial reuse, with patent/license notices.

The choice is intentionally left to the project owner rather than being silently made by a development patch.

## Git-history check

A clean current tree is not enough if secrets were committed in the past. Before publication inspect the repository history or use a dedicated secret scanner. If a real credential was ever committed, rotate it even if history is later rewritten.

## Publication is not a security boundary

Once a repository is public, assume every committed byte is permanently copied. Do not rely on later deletion to make a credential private again.
