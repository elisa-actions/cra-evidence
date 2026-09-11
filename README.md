# cra-evidence

GitHub Action that generates technical evidence for an application's
dependency inventory. It creates a CycloneDX JSON SBOM, build metadata, an
optional Grype vulnerability report, and an optional GitHub Actions artifact.

This is an initial CRA evidence prototype. The generated artifacts may support
CRA-related processes, but this action does not establish CRA compliance or
produce complete or legally sufficient evidence.

## Prerequisites

- A self-hosted macOS runner with `syft` and `jq` available in `PATH`.
- `cyclonedx` is reported when available for diagnostics.
- `grype` is optional and is never installed by this action.
- The caller must be allowed to upload artifacts when `upload-artifact` is `true`.

Check installed tool versions on the runner, for example:

```bash
syft version
jq --version
grype version   # only needed when vulnerability-scan is enabled
```

## Usage

Add a step to your workflow that references this repository:

```yaml
- name: Generate CRA evidence
  uses: elisa-actions/cra-evidence@main
  with:
    app-name: TarmoTestApp
    app-version: 0.1.0
    platform: ios
    source: .
    vulnerability-scan: 'true'
    fail-on-vulnerabilities: 'false'
```

Use `main` while integrating a change. Once a release tag exists, pin to it
(for example `elisa-actions/cra-evidence@v1.0.0`) so later changes in this
repository don't silently change your workflow.

### Full example

```yaml
name: CRA evidence

on:
  workflow_dispatch:

jobs:
  evidence:
    runs-on: [self-hosted, macos]
    steps:
      - name: Checkout
        uses: actions/checkout@v7

      - name: Generate CRA evidence
        id: cra
        uses: elisa-actions/cra-evidence@main
        with:
          app-name: MyApp
          app-version: 0.1.0
          platform: ios
          source: .
          vulnerability-scan: 'true'
          fail-on-vulnerabilities: 'false'

      - name: Display CRA evidence result
        shell: bash
        run: |
          echo "SBOM: ${{ steps.cra.outputs.sbom-path }}"
          echo "Components: ${{ steps.cra.outputs.component-count }}"
          echo "Vulnerability scan: ${{ steps.cra.outputs.scan-status }}"
```

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `app-name` | Repository name | Human-readable application name. |
| `app-version` | `unknown` | Application version. |
| `platform` | `unknown` | Application platform, such as `ios` or `android`. |
| `source` | `.` | Directory or artifact for Syft to scan. |
| `output-directory` | `cra-evidence` | Directory where evidence files are created. |
| `artifact-name` | `cra-evidence` | Uploaded artifact name. |
| `upload-artifact` | `true` | Whether to upload the evidence directory. |
| `vulnerability-scan` | `false` | Whether to run Grype. |
| `fail-on-vulnerabilities` | `false` | Whether findings or scan failure should fail the action. |
| `fail-on-empty-sbom` | `false` | Whether zero SBOM components should fail the action. |

Boolean inputs are strings and must be exactly `true` or `false`.

## Outputs

- `sbom-path`: Path to the generated CycloneDX JSON SBOM.
- `build-info-path`: Path to the generated build metadata JSON.
- `vulnerability-report-path`: Path to the vulnerability report, when generated (empty otherwise).
- `component-count`: Numeric SBOM component count.
- `vulnerability-count`: Numeric vulnerability count.
- `scan-status`: `disabled`, `tool-unavailable`, `completed`, `completed-with-findings`, or `scan-failed`.
- `evidence-directory`: Directory containing generated evidence.

## Common configurations

Scan a build artifact instead of the checked-out source, for stronger release
evidence:

```yaml
with:
  source: build/Release-iphoneos
  output-directory: build/cra-evidence
```

The default `source: .` is useful for initial adoption, but it can also detect
dependencies used by repository tooling or CI workflows rather than only the
shipped application. A Hello World app with no third-party dependencies can
legitimately have few or zero application dependencies.

Enable non-blocking vulnerability scanning while evaluating results:

```yaml
with:
  vulnerability-scan: 'true'
  fail-on-vulnerabilities: 'false'
```

Make findings or a failed scan block the workflow once you're ready to
enforce it:

```yaml
with:
  vulnerability-scan: 'true'
  fail-on-vulnerabilities: 'true'
```

If Grype is unavailable on the runner, the action continues successfully with
`scan-status: tool-unavailable` and leaves `vulnerability-report-path` empty.
This action never installs Grype automatically.

## Troubleshooting

- **Action not found:** Check the repository name and ref used in `uses`.
- **Required tool missing:** Verify `syft` and `jq` are installed on the
  selected self-hosted runner and available in the non-interactive workflow
  `PATH`.
- **Unexpected dependency count:** Check `source`; scanning `.` includes CI
  and tooling dependencies. Test against an app containing SPM, CocoaPods, or
  other real third-party dependencies.
- **No artifact:** Confirm `upload-artifact` is `true` and the runner has
  permission to use the configured artifact action.

Generated `sbom.json`, `build-info.json`, `vulnerability-report.json`, and
evidence directories should remain workflow artifacts and must not be
committed to this repository.

## CRA prototype disclaimer

This action generates technical evidence that may support CRA-related
processes. It does not by itself establish CRA compliance.
