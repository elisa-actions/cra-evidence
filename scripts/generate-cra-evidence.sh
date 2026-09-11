#!/usr/bin/env bash

set -euo pipefail

APP_NAME="${CRA_APP_NAME:-${GITHUB_REPOSITORY##*/}}"
APP_VERSION="${CRA_APP_VERSION:-unknown}"
PLATFORM="${CRA_PLATFORM:-unknown}"
SOURCE="${CRA_SOURCE:-.}"
OUTPUT_DIRECTORY="${CRA_OUTPUT_DIRECTORY:-cra-evidence}"
ARTIFACT_NAME="${CRA_ARTIFACT_NAME:-cra-evidence}"
UPLOAD_ARTIFACT="${CRA_UPLOAD_ARTIFACT:-true}"
VULNERABILITY_SCAN="${CRA_VULNERABILITY_SCAN:-false}"
FAIL_ON_VULNERABILITIES="${CRA_FAIL_ON_VULNERABILITIES:-false}"
FAIL_ON_EMPTY_SBOM="${CRA_FAIL_ON_EMPTY_SBOM:-false}"

for boolean_name in UPLOAD_ARTIFACT VULNERABILITY_SCAN FAIL_ON_VULNERABILITIES FAIL_ON_EMPTY_SBOM; do
  boolean_value="${!boolean_name}"
  if [[ "$boolean_value" != "true" && "$boolean_value" != "false" ]]; then
    printf '::error::%s must be either true or false, got: %s\n' "$boolean_name" "$boolean_value" >&2
    exit 1
  fi
done

if ! command -v syft >/dev/null 2>&1; then
  printf '::error::syft is required but was not found in PATH.\n' >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  printf '::error::jq is required but was not found in PATH.\n' >&2
  exit 1
fi

syft_version="$(syft version 2>&1 | head -n 1 || true)"
cyclonedx_cli_version="unknown"
if command -v cyclonedx >/dev/null 2>&1; then
  cyclonedx_cli_version="$(cyclonedx --version 2>&1 | head -n 1 || true)"
fi

printf '::group::CRA evidence tools\n'
printf 'Syft: %s\n' "${syft_version:-unknown}"
printf 'CycloneDX CLI: %s\n' "${cyclonedx_cli_version:-unknown}"
if command -v grype >/dev/null 2>&1; then
  grype_version="$(grype version 2>&1 | head -n 1 || true)"
  printf 'Grype: %s\n' "${grype_version:-unknown}"
else
  printf 'Grype: unavailable\n'
fi
printf '::endgroup::\n'

mkdir -p "$OUTPUT_DIRECTORY"
SBOM_PATH="$OUTPUT_DIRECTORY/sbom.json"
BUILD_INFO_PATH="$OUTPUT_DIRECTORY/build-info.json"
VULNERABILITY_REPORT_PATH=""

manifest_names=(
  Package.resolved
  Podfile.lock
  Cartfile.resolved
  Package.swift
  build.gradle
  build.gradle.kts
  gradle.lockfile
  libs.versions.toml
)
manifest_paths=()
for manifest_name in "${manifest_names[@]}"; do
  while IFS= read -r manifest_path; do
    manifest_paths+=("$manifest_path")
  done < <(find "$SOURCE" -type f -name "$manifest_name" -print 2>/dev/null)
done

printf '::group::CRA evidence scan source\n'
printf 'Source: %s\n' "$SOURCE"
if ((${#manifest_paths[@]} == 0)); then
  printf 'No dependency manifests found under %s.\n' "$SOURCE"
else
  printf 'Detected dependency manifests:\n'
  printf '%s\n' "${manifest_paths[@]}"
fi
printf '::endgroup::\n'

printf 'Generating CycloneDX JSON SBOM...\n'
if [[ -d "$SOURCE" ]]; then
  syft "dir:$SOURCE" -o "cyclonedx-json=$SBOM_PATH"
else
  syft "$SOURCE" -o "cyclonedx-json=$SBOM_PATH"
fi

if [[ ! -s "$SBOM_PATH" ]] || ! jq empty "$SBOM_PATH" >/dev/null 2>&1; then
  printf '::error::Generated SBOM is missing, empty, or invalid JSON: %s\n' "$SBOM_PATH" >&2
  exit 1
fi

component_count="$(jq -r 'if (.components? // null) == null then 0 else (.components | length) end' "$SBOM_PATH")"
if [[ ! "$component_count" =~ ^[0-9]+$ ]]; then
  printf '::error::Could not calculate a numeric SBOM component count.\n' >&2
  exit 1
fi
printf 'SBOM component count: %s\n' "$component_count"
jq -r '.components[]? | "- \(.name // "unknown") \(.version // "unknown")"' "$SBOM_PATH" | head -n 100 || true

if [[ "$FAIL_ON_EMPTY_SBOM" == "true" && "$component_count" -eq 0 ]]; then
  empty_sbom_failure=1
else
  empty_sbom_failure=0
fi

workflow_name="${GITHUB_WORKFLOW:-unknown}"
generated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
jq -n \
  --arg schema_version "1.0" \
  --arg app_name "$APP_NAME" \
  --arg app_version "$APP_VERSION" \
  --arg platform "$PLATFORM" \
  --arg repository "${GITHUB_REPOSITORY:-}" \
  --arg commit_sha "${GITHUB_SHA:-}" \
  --arg ref "${GITHUB_REF:-}" \
  --arg workflow "$workflow_name" \
  --arg workflow_run_id "${GITHUB_RUN_ID:-}" \
  --arg workflow_run_number "${GITHUB_RUN_NUMBER:-}" \
  --arg workflow_attempt "${GITHUB_RUN_ATTEMPT:-}" \
  --arg actor "${GITHUB_ACTOR:-}" \
  --arg runner_name "${RUNNER_NAME:-}" \
  --arg runner_os "${RUNNER_OS:-}" \
  --arg generated_at "$generated_at" \
  --arg syft_version "${syft_version:-unknown}" \
  --arg cyclonedx_cli_version "${cyclonedx_cli_version:-unknown}" \
  --arg sbom_format "CycloneDX JSON" \
  --argjson sbom_component_count "$component_count" \
  --arg scanned_source "$SOURCE" \
  '{schema_version, app_name, app_version, platform, repository, commit_sha, ref, workflow, workflow_run_id, workflow_run_number, workflow_attempt, actor, runner_name, runner_os, generated_at, syft_version, cyclonedx_cli_version, sbom_format, sbom_component_count, scanned_source}' \
  > "$BUILD_INFO_PATH"

scan_status="disabled"
vulnerability_count=0
critical_count=0
high_count=0
medium_count=0
low_count=0
negligible_count=0
unknown_count=0
scan_exit_code=0

if [[ "$VULNERABILITY_SCAN" == "true" ]]; then
  if ! command -v grype >/dev/null 2>&1; then
    scan_status="tool-unavailable"
    printf '::warning::Grype is unavailable; vulnerability scanning was not run.\n'
  else
    VULNERABILITY_REPORT_PATH="$OUTPUT_DIRECTORY/vulnerability-report.json"
    temporary_report="$OUTPUT_DIRECTORY/.vulnerability-report.json.tmp"
    set +e
    grype "sbom:$SBOM_PATH" -o json > "$temporary_report"
    scan_exit_code=$?
    set -e
    if [[ -s "$temporary_report" ]] && jq empty "$temporary_report" >/dev/null 2>&1; then
      mv "$temporary_report" "$VULNERABILITY_REPORT_PATH"
      report_valid=1
    else
      jq -n --arg status "scan-failed" --argjson exit_code "$scan_exit_code" \
        '{status: $status, exit_code: $exit_code, matches: []}' > "$VULNERABILITY_REPORT_PATH"
      report_valid=0
    fi
    if [[ "$report_valid" -eq 1 && "$scan_exit_code" -eq 0 ]]; then
      scan_status="completed"
    elif [[ "$report_valid" -eq 1 && "$scan_exit_code" -ne 0 ]] && jq -e '.matches? != null' "$VULNERABILITY_REPORT_PATH" >/dev/null 2>&1; then
      scan_status="completed-with-findings"
    else
      scan_status="scan-failed"
    fi
    vulnerability_count="$(jq '[.matches[]?] | length' "$VULNERABILITY_REPORT_PATH")"
    critical_count="$(jq '[.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase) == "critical")] | length' "$VULNERABILITY_REPORT_PATH")"
    high_count="$(jq '[.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase) == "high")] | length' "$VULNERABILITY_REPORT_PATH")"
    medium_count="$(jq '[.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase) == "medium")] | length' "$VULNERABILITY_REPORT_PATH")"
    low_count="$(jq '[.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase) == "low")] | length' "$VULNERABILITY_REPORT_PATH")"
    negligible_count="$(jq '[.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase) == "negligible")] | length' "$VULNERABILITY_REPORT_PATH")"
    unknown_count="$(jq '[.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase) as $severity | ["critical", "high", "medium", "low", "negligible"] | index($severity) | not)] | length' "$VULNERABILITY_REPORT_PATH")"
    printf 'Vulnerability scan status: %s\n' "$scan_status"
    printf 'Vulnerability counts: critical=%s high=%s medium=%s low=%s negligible=%s unknown=%s total=%s\n' \
      "$critical_count" "$high_count" "$medium_count" "$low_count" "$negligible_count" "$unknown_count" "$vulnerability_count"
  fi
else
  printf 'Vulnerability scanning disabled.\n'
fi

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '# CRA Evidence Summary\n\n'
    printf -- '- Application: %s\n' "$APP_NAME"
    printf -- '- Version: %s\n' "$APP_VERSION"
    printf -- '- Platform: %s\n' "$PLATFORM"
    printf -- '- Repository: %s\n' "${GITHUB_REPOSITORY:-unknown}"
    printf -- '- Commit SHA: %s\n' "${GITHUB_SHA:-unknown}"
    printf -- '- Scanned source: %s\n' "$SOURCE"
    printf -- '- SBOM format: CycloneDX JSON\n'
    printf -- '- Component count: %s\n' "$component_count"
    printf -- '- Dependency manifests detected: %s\n' "${#manifest_paths[@]}"
    printf -- '- Vulnerability scan status: %s\n' "$scan_status"
    printf -- '- Vulnerability counts: critical=%s, high=%s, medium=%s, low=%s, negligible=%s, unknown=%s, total=%s\n' \
      "$critical_count" "$high_count" "$medium_count" "$low_count" "$negligible_count" "$unknown_count" "$vulnerability_count"
    printf -- '- Evidence directory: %s\n' "$OUTPUT_DIRECTORY"
    if [[ "$UPLOAD_ARTIFACT" == "true" ]]; then
      printf -- '- Artifact: %s\n' "$ARTIFACT_NAME"
    else
      printf -- '- Artifact: upload disabled\n'
    fi
    printf '\nThis action generates technical evidence that may support CRA-related processes. It does not by itself establish CRA compliance.\n'
  } >> "$GITHUB_STEP_SUMMARY" || true
fi

printf 'Generated files in %s:\n' "$OUTPUT_DIRECTORY"
find "$OUTPUT_DIRECTORY" -maxdepth 1 -type f -print

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'sbom-path=%s\n' "$SBOM_PATH"
    printf 'build-info-path=%s\n' "$BUILD_INFO_PATH"
    printf 'vulnerability-report-path=%s\n' "$VULNERABILITY_REPORT_PATH"
    printf 'component-count=%s\n' "$component_count"
    printf 'vulnerability-count=%s\n' "$vulnerability_count"
    printf 'scan-status=%s\n' "$scan_status"
    printf 'evidence-directory=%s\n' "$OUTPUT_DIRECTORY"
  } >> "$GITHUB_OUTPUT"
fi

if [[ "$empty_sbom_failure" -eq 1 ]]; then
  printf '::error::SBOM contains zero components and fail-on-empty-sbom is enabled.\n' >&2
  exit 1
fi
if [[ "$FAIL_ON_VULNERABILITIES" == "true" && ( "$scan_status" == "completed-with-findings" || "$scan_status" == "scan-failed" ) && "$vulnerability_count" -gt 0 ]]; then
  printf '::error::Vulnerabilities were found and fail-on-vulnerabilities is enabled.\n' >&2
  exit 1
fi
if [[ "$FAIL_ON_VULNERABILITIES" == "true" && "$scan_status" == "scan-failed" ]]; then
  printf '::error::The vulnerability scan failed and fail-on-vulnerabilities is enabled.\n' >&2
  exit 1
fi

printf 'CRA evidence generated successfully.\n'
