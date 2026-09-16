# Supply-Chain Security

ZEN Control treats build and dependency provenance as a release concern, not a background maintenance task. The v0.59.0.12 controls are designed to make dependency drift visible, fail releases on known fixed high-impact vulnerabilities, and retain machine-readable evidence for every Quality run.

## What the automated gate proves

GitHub Quality includes an independent `supply-chain` job after source-quality validation. It:

1. audits the Python dependency graph with `pip-audit`;
2. builds the actual ZEN application image from the candidate source;
3. scans that image with Trivy for **HIGH/CRITICAL vulnerabilities that have a fix available**;
4. emits a full CycloneDX image SBOM;
5. retains the pip-audit report, Trivy report, image ID and build-input hashes as a 30-day workflow artifact;
6. fails the workflow if the Python audit is not clean or the image contains a fixed HIGH/CRITICAL vulnerability.

Unfixed vulnerabilities are still visible to operators through normal scanner output/upstream advisories, but v0.59.0.12 does not make the release gate depend on a fix that does not yet exist. That distinction must not be described as the vulnerability being harmless.

## Immutable GitHub Actions references

Every external `uses:` reference in `.github/workflows/` is pinned to a full 40-character commit SHA. Human-readable version comments remain beside the pins. `scripts/supply_chain_validate.py` fails if a future workflow reintroduces a floating major/version tag.

Current pinned action lines are based on Node 24-capable releases, removing the Node 20 deprecation warning from the existing Quality workflow.

## Dependency update automation

`.github/dependabot.yml` checks weekly for:

- Python package updates;
- GitHub Actions updates;
- Dockerfile base-image updates;
- Docker Compose image updates.

Dependabot opens reviewable pull requests; it does **not** bypass the existing source-quality, runtime-container, fresh-install or supply-chain gates. A dependency PR is evidence to review, not authority to merge automatically.

## Container image policy

The primary application and telemetry-ingest Dockerfiles use the patch-specific `python:3.12.14-slim` base instead of the broad `python:3.12-slim` tag. Dependabot owns later patch/minor proposals and the real candidate image is rescanned before release.

Some auxiliary Compose images are still tag-addressed rather than registry-digest-addressed. Their tags are visible in `docker-compose.yml` and are now covered by Dependabot's Docker Compose monitoring. Digest pinning can be tightened independently when each service's update/recovery behaviour has been qualified; do not claim tag monitoring is equivalent to immutable digest pinning.

## Local validation

The repository-only contract requires no network access:

```bash
python3 scripts/supply_chain_validate.py
```

The vulnerability and SBOM gates require registry/advisory access and therefore run in GitHub Actions. For an ad-hoc connected workstation, use the same tools/versions shown in `.github/workflows/quality.yml` rather than inventing a weaker local policy.

## Release evidence

For a supply-chain-affecting release retain, at minimum:

- exact Git commit/tag;
- Quality workflow result;
- `pip-audit.json`;
- `trivy-vulnerabilities.json`;
- `zen-control-image.cdx.json`;
- image ID and `requirements.txt`/`Dockerfile` hashes.

Do not attach `.env`, live databases, credentials, household telemetry or raw operational logs to supply-chain evidence.
