# cra-evidence

GitHub Action that generates technical evidence for an application's
dependency inventory. It creates a CycloneDX JSON SBOM, build metadata, an
optional Grype vulnerability report, and an optional GitHub Actions artifact.

This is an initial CRA evidence prototype. The generated artifacts may support
CRA-related processes, but this action does not establish CRA compliance or
produce complete or legally sufficient evidence.

## Prerequisites

- A self-hosted macOS runner with `syft`, `jq`, and `zip` available in `PATH`.
- `cyclonedx` is reported when available for diagnostics.
- `grype` is optional and is never installed by this action.
- When `build-artifact` is set, tools matching the artifact type are also required:
  - `.apk`: `apksigner`.
  - `.aab`: `keytool`.
  - `.ipa`: `unzip`, `openssl`, and `codesign`.
- The caller must be allowed to upload artifacts when `upload-artifact` is `true`.

Check installed tool versions on the runner, for example:

```bash
syft version
jq --version
zip --version
grype version       # only needed when vulnerability-scan is enabled
apksigner --version # only needed for .apk build-artifact
keytool -help       # only needed for .aab build-artifact
codesign --version  # only needed for .ipa build-artifact
openssl version     # only needed for .ipa build-artifact
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
    build-artifact: build/MyApp.ipa
    build-number: '42'
    vulnerability-scan: 'true'
    fail-on-vulnerabilities: 'false'
```

For Android, point `build-artifact` at the shipped `.apk` or `.aab`:

```yaml
- name: Generate CRA evidence
  uses: elisa-actions/cra-evidence@main
  with:
    app-name: TarmoTestApp
    app-version: 0.1.0
    platform: android
    source: .
    build-artifact: build/app-release.aab
    build-number: '42'
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
| `build-artifact` | (none) | Shipped `.apk`, `.aab`, or `.ipa` used to generate signing evidence in `build-artifact.json`. |
| `build-number` | (none) | Platform build number recorded in `build-artifact.json`. Required when `build-artifact` is set. |
| `build-time` | artifact modification time | Optional ISO 8601 build time recorded in `build-artifact.json`. |
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
- `build-artifact-path`: Path to the build artifact signing metadata JSON, or empty when `build-artifact` was not set.
- `vulnerability-report-path`: Path to the vulnerability report, when generated (empty otherwise).
- `component-count`: Numeric SBOM component count.
- `vulnerability-count`: Numeric vulnerability count.
- `scan-status`: `disabled`, `tool-unavailable`, `completed`, `completed-with-findings`, or `scan-failed`.
- `evidence-directory`: Directory containing generated evidence.
- `evidence-archive-path`: Path to the timestamped ZIP archive of the evidence directory.
- `evidence-archive-name`: Filename of the timestamped ZIP archive.
- `evidence-version`: Lowercase app, version, platform, and UTC timestamp string, suitable as an artifact registry version.

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

## Android and iOS build artifact signing evidence

Setting `build-artifact` generates `build-artifact.json`, containing the
artifact filename, SHA-256 and SHA-512 digests, byte size, MIME type, build
time, evidence creation time, version, build number, and a `signing` object
extracted from the binary itself:

- **`.apk`**: `apksigner verify --print-certs` reports the signing
  certificate subject and SHA-256 digest, and the public key SHA-256 digest.
- **`.aab`**: `keytool -printcert -jarfile` reports the upload-signing
  certificate subject, issuer, serial number, validity period, and SHA-256
  digest. An AAB identifies its upload-signing certificate, not a distinct
  Google Play app-signing certificate.
- **`.ipa`**: `codesign` and `openssl` report the signing certificate
  subject, issuer, serial number, validity period, SHA-256 fingerprint, and
  the code directory hash (`CDHash`).

`build-number` is required whenever `build-artifact` is set. `build-time`
defaults to the artifact's file modification time; pass it explicitly when
the build system can provide a more authoritative timestamp.

Both `build-info.json` and `build-artifact.json` are validated against an
inline schema (`schema_version: "1.0"`) before the action continues.

## Evidence archive

After evidence files are generated, the action creates a timestamped ZIP
archive of the evidence directory (for example
`MyApp-1.0.0-ios-20260917t120000z.zip`) next to `output-directory`, and
exposes its path, filename, and a normalized `evidence-version` string as
outputs. Use these if you need to publish the evidence archive to your own
artifact storage in addition to, or instead of, the GitHub Actions artifact.

## Troubleshooting

- **Action not found:** Check the repository name and ref used in `uses`.
- **Required tool missing:** Verify `syft`, `jq`, and `zip` are installed on
  the selected self-hosted runner and available in the non-interactive
  workflow `PATH`. When `build-artifact` is set, also verify the matching
  signing tool (`apksigner`, `keytool`, or `unzip`/`openssl`/`codesign`).
- **Unexpected dependency count:** Check `source`; scanning `.` includes CI
  and tooling dependencies. Test against an app containing SPM, CocoaPods, or
  other real third-party dependencies.
- **`build-number is required when build-artifact is set`:** Pass
  `build-number` alongside `build-artifact`.
- **No artifact:** Confirm `upload-artifact` is `true` and the runner has
  permission to use the configured artifact action.

Generated `sbom.json`, `build-info.json`, `build-artifact.json`,
`vulnerability-report.json`, evidence directories, and evidence ZIP archives
should remain workflow artifacts and must not be committed to this
repository.

## CRA prototype disclaimer

This action generates technical evidence that may support CRA-related
processes. It does not by itself establish CRA compliance.
