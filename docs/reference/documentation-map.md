# Documentation Map

This map is the maintained inventory for ZEN Control documentation. It describes the role of each major document rather than replacing the operational instructions in those documents. “Owner” identifies the source of truth for a change; it does not grant authority to change RouterOS, release, or RALPH-controlled files.

## Document inventory

| Document or area | Purpose | Primary audience | Content owner | Intentional duplication | Extraction disposition |
| --- | --- | --- | --- | --- | --- |
| [Project overview](../../README.md) | Product scope, safety model, and capability overview | Future adopters, operators, contributors | Product/project maintainers | High-level authority and version context repeat at entry points | Keep as the concise project entry point; link detailed material instead of expanding it. |
| [ZEN system overview](../ZEN.md) | Implementation-backed system entry point: components, authority, persistence, and RALPH relationship | Operators, developers, future adopters | Application architecture maintainers | Concise boundaries repeat architecture and RouterOS guide | Keep as the cross-role entry point; detailed contracts remain canonical in architecture and RouterOS documentation. |
| [Documentation landing page](../README.md) | Role-based navigation and reference entry point | Everyone | Documentation maintainers | Route summaries intentionally repeat destination descriptions | Keep as navigation only; do not turn it into a second operator guide. |
| [Architecture](../ARCHITECTURE.md) | Authority, persistence, evidence, and failure-boundary design | Developers, reviewers, technical adopters | Application architecture maintainers | Core safety concepts repeat in operator and RouterOS guides | Canonical explanation of system design; extract only concise glossary definitions. |
| [Installation and commissioning](../INSTALL.md) | Supported deployment and first operational acceptance | New operators | Deployment maintainers | Prerequisites and security baseline repeat where an operator acts on them | Keep procedural; link the environment and RouterOS documents for detail. |
| [Environment contract](../ENVIRONMENT.md) | Configuration classes, variables, and lifecycle effects | Operators, developers | Deployment/configuration maintainers | Secret and network cautions repeat in security guidance | Canonical configuration contract; keep secrets out of examples and source control. |
| [Operator guide](../OPERATOR_GUIDE.md) | Day-2 health, diagnostics, recovery, and evidence interpretation | Operators | Operations maintainers | Evidence-state explanations intentionally repeat near diagnostics | Keep operational procedures here; glossary supplies short shared meanings. |
| [RouterOS integration](../../routeros/README.md) | RouterOS authority boundary and supported behavior | Operators, developers | RouterOS contract maintainers | Authority model and baseline repeat in setup/install/security entry points | Canonical integration boundary; link templates rather than duplicate their commands. |
| [RouterOS setup bundle](../../routeros/setup/README.md) | Template inventory, safe order, and verification | Operators changing a router | RouterOS contract maintainers | Baseline, ownership, and failure-closed cautions repeat intentionally before mutation | Keep as the template companion; scripts remain implementation artifacts, not a general tutorial. |
| [RALPH-Lite operator guide](../RALPH-LITE.md) | Supervised autonomous-engineering lifecycle and controller controls | RALPH operators, maintainers | RALPH controller maintainers | Approval and qualification language repeats in controller policy/tooling | Canonical human-facing process guide; glossary supplies short terms only. |
| [RALPH documentation tree](../ralph/README.md) | Navigation for RALPH process material in the ZEN repository | RALPH users, maintainers | RALPH controller maintainers | Route summaries intentionally repeat guide descriptions | Keep as navigation; controller-owned files remain the authority for active execution. |
| [Contributing](../../CONTRIBUTING.md) | Development setup, contribution workflow, and local gates | Contributors | Project maintainers | Safety principles repeat from architecture/security | Keep contribution-specific expectations; refer to canonical operational/security documents. |
| [Security policy](../../SECURITY.md) | Threat model, deployment responsibilities, and vulnerability reporting | Operators, contributors, reporters | Security maintainers | RouterOS and secret-handling warnings repeat at high-risk entry points | Canonical vulnerability-reporting policy; retain short safety reminders elsewhere. |
| [Supply-chain security](../SUPPLY_CHAIN.md) | CI provenance, dependency, image-scan, and SBOM controls | Release maintainers, contributors | Release/security maintainers | Gate summary repeats in contributing and release checklist | Canonical detailed supply-chain evidence reference. |
| [Release and maintenance checklist](../PUBLIC_RELEASE.md) | Release qualification and publication procedure | Release maintainers | Release maintainers | Some gate descriptions intentionally repeat contributing guidance | Keep as the executable release checklist; do not use as product history. |
| [Release history](../../CHANGELOG.md) | Historical changes and compatibility context | Operators, adopters, contributors | Release maintainers | Version references elsewhere point here | Keep historical; do not use it as the current operational contract. |
| [Screenshot guidance](../screenshots/README.md) | Visual-asset policy and evidence limits | Documentation contributors | Documentation maintainers | Text-first/sanitization guidance repeats security cautions | Keep as a focused asset policy. |

## Navigation rules

- The [documentation landing page](../README.md) is the required starting point for ZEN, operator, developer, RALPH, and future-adopter routes.
- A reader reaches every inventory area in one direct link from the landing page or through this map, so no major area is more than two navigation steps away.
- RouterOS scripts are implementation companions. Their documentation route is the RouterOS integration or setup-bundle guide, not a standalone procedural promise.

## Maintenance findings

The bounded audit for this map found no direct factual conflict among the reviewed entry-point documents. The following material is nevertheless duplicated and can become stale independently; retain the record for a later approved documentation-maintenance step.

| ID | Finding | Current disposition | Follow-up needed |
| --- | --- | --- | --- |
| DOC-01 | Runtime-version, maintenance-tag, and “current release” statements appear in the project overview, documentation landing page, installation guide, contributing guide, and security policy. | Consistent in the audited set, but temporal facts have several update points. | Establish a single release/version reference or a release-maintenance checklist for each copy; historical tag claims belong in the changelog. |
| DOC-02 | RouterOS vendor advisory and minimum-version language appears in installation, security, RouterOS integration, and setup documentation. | Intentional safety duplication at each pre-mutation entry point; no conflict found. | Designate exact shared wording and review all copies whenever vendor guidance changes; move superseded advisory detail to historical release notes where appropriate. |
| DOC-03 | RouterOS authority/evidence distinctions appear in the overview, architecture, operator guide, and both RouterOS guides. | Intentional audience-specific duplication; wording is currently aligned. | Keep the glossary as the short shared vocabulary and correct any future semantic drift against architecture and implementation. |
| DOC-04 | The former documentation landing page grouped contributor/security material but did not provide explicit RALPH, developer, or future-adopter routes. | Corrected by this step. | Review route labels when a new major documentation area is added. |

## Audit boundary

This inventory covers repository documentation and the referenced RouterOS companions present at the time of the audit. It does not claim live RouterOS state, release qualification, or external vendor guidance. Those remain operator-, controller-, and release-owned evidence respectively.
