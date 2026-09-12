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

## License decision

Two sensible options for ZEN are:

- **AGPL-3.0** — strong network copyleft; modifications offered as a network service remain source-available under the license terms.
- **Apache-2.0** — permissive; maximizes reuse, including commercial reuse, with patent/license notices.

The choice is intentionally left to the project owner rather than being silently made by a development patch.

## Git-history check

A clean current tree is not enough if secrets were committed in the past. Before publication inspect the repository history or use a dedicated secret scanner. If a real credential was ever committed, rotate it even if history is later rewritten.

## Publication is not a security boundary

Once a repository is public, assume every committed byte is permanently copied. Do not rely on later deletion to make a credential private again.
