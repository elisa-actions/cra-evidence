#!/usr/bin/env bash

set -euo pipefail

APP_NAME="${CRA_APP_NAME:-${GITHUB_REPOSITORY##*/}}"
APP_VERSION="${CRA_APP_VERSION:-unknown}"
PLATFORM="${CRA_PLATFORM:-unknown}"
SOURCE="${CRA_SOURCE:-.}"
BUILD_ARTIFACT="${CRA_BUILD_ARTIFACT:-}"
BUILD_NUMBER="${CRA_BUILD_NUMBER:-}"
BUILD_TIME="${CRA_BUILD_TIME:-}"
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

if [[ -n "$BUILD_ARTIFACT" && -z "$BUILD_NUMBER" ]]; then
  printf '::error::build-number is required when build-artifact is set.\n' >&2
  exit 1
fi

if ! command -v syft >/dev/null 2>&1; then
  printf '::error::syft is required but was not found in PATH.\n' >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  printf '::error::jq is required but was not found in PATH.\n' >&2
  exit 1
fi
if ! command -v zip >/dev/null 2>&1; then
  printf '::error::zip is required but was not found in PATH.\n' >&2
  exit 1
fi
if [[ -n "$BUILD_ARTIFACT" ]]; then
  case "$BUILD_ARTIFACT" in
    *.ipa)
      if ! command -v unzip >/dev/null 2>&1; then
        printf '::error::unzip is required to inspect an .ipa build artifact.\n' >&2
        exit 1
      fi
      if ! command -v openssl >/dev/null 2>&1; then
        printf '::error::openssl is required to inspect an .ipa build artifact.\n' >&2
        exit 1
      fi
      if ! command -v codesign >/dev/null 2>&1; then
        printf '::error::codesign is required to inspect an .ipa build artifact.\n' >&2
        exit 1
      fi
      ;;
    *.apk)
      if ! command -v apksigner >/dev/null 2>&1; then
        printf '::error::apksigner is required to inspect an .apk build artifact.\n' >&2
        exit 1
      fi
      ;;
    *.aab)
      if ! command -v keytool >/dev/null 2>&1; then
        printf '::error::keytool is required to inspect an .aab build artifact.\n' >&2
        exit 1
      fi
      ;;
    *)
      printf '::error::build-artifact must have an .apk, .aab, or .ipa extension: %s\n' "$BUILD_ARTIFACT" >&2
      exit 1
      ;;
  esac
fi

validate_build_info() {
  jq -e '
    type == "object" and
    .schema_version == "1.0" and
    (. as $document | ["app_name", "app_version", "platform", "repository", "commit_sha", "ref", "workflow", "workflow_url", "event_name", "workflow_run_id", "workflow_run_number", "workflow_attempt", "actor", "runner_name", "runner_os", "generated_at", "source_sha256", "syft_version", "cyclonedx_cli_version", "sbom_format", "sbom_component_count", "scanned_source"] | all(.[]; . as $key | $document | has($key))) and
    (.source_sha256 | test("^[a-f0-9]{64}$")) and
    (.sbom_component_count | type == "number" and floor == . and . >= 0)
  ' "$1" >/dev/null || {
    printf '::error::Generated build-info.json does not match schema 1.0: %s\n' "$1" >&2
    exit 1
  }
}

validate_build_artifact() {
  jq -e '
    type == "object" and
    .schema_version == "1.0" and
    (. as $document | ["file", "sha256", "sha512", "size", "mime_type", "build_time", "recorded_at", "version", "build_number", "signing"] | all(.[]; . as $key | $document | has($key))) and
    (.sha256 | test("^[a-f0-9]{64}$")) and
    (.sha512 | test("^[a-f0-9]{128}$")) and
    (.size | type == "number" and floor == . and . > 0) and
    (.signing | type == "object")
  ' "$1" >/dev/null || {
    printf '::error::Generated build-artifact.json does not match schema 1.0: %s\n' "$1" >&2
    exit 1
  }
}

extract_android_apk_signing() {
  local verification
  verification="$(apksigner verify --print-certs "$BUILD_ARTIFACT" 2>&1)" || {
    printf '::error::Could not verify APK signing: %s\n' "$verification" >&2
    exit 1
  }

  local subject sha256 public_key_sha256
  subject="$(printf '%s\n' "$verification" | awk 'tolower($0) ~ /certificate dn:/ {sub(/^.*certificate DN:[[:space:]]*/, ""); print; exit}')"
  sha256="$(printf '%s\n' "$verification" | awk 'tolower($0) ~ /certificate[[:space:]]+sha-256 digest:/ {sub(/^.*digest:[[:space:]]*/, ""); gsub(":", ""); gsub(/[[:space:]]/, ""); print tolower($0); exit}')"
  public_key_sha256="$(printf '%s\n' "$verification" | awk 'tolower($0) ~ /certificate public key sha-256 digest:/ {sub(/^.*digest:[[:space:]]*/, ""); gsub(":", ""); gsub(/[[:space:]]/, ""); print tolower($0); exit}')"
  if [[ ! "$sha256" =~ ^[[:xdigit:]]{64}$ ]]; then
    printf '::error::APK signing certificate SHA-256 digest was not reported in a recognized format.\n%s\n' "$verification" >&2
    exit 1
  fi

  jq -n \
    --arg method "apksigner" \
    --arg certificate_subject "$subject" \
    --arg certificate_sha256 "$sha256" \
    --arg public_key_sha256 "$public_key_sha256" \
    '{
      verification_method: $method,
      certificate_subject: $certificate_subject,
      certificate_sha256: $certificate_sha256,
      public_key_sha256: $public_key_sha256
    }'
}

extract_android_aab_signing() {
  local verification
  verification="$(keytool -printcert -jarfile "$BUILD_ARTIFACT" 2>&1)" || {
    printf '::error::Could not verify AAB signing: %s\n' "$verification" >&2
    exit 1
  }

  local subject issuer serial_number validity valid_from valid_to sha256
  subject="$(printf '%s\n' "$verification" | sed -n 's/^Owner: //p' | head -n 1)"
  issuer="$(printf '%s\n' "$verification" | sed -n 's/^Issuer: //p' | head -n 1)"
  serial_number="$(printf '%s\n' "$verification" | sed -n 's/^Serial number: //p' | head -n 1)"
  validity="$(printf '%s\n' "$verification" | sed -n 's/^Valid from: //p' | head -n 1)"
  valid_from="${validity%% until: *}"
  valid_to="${validity#* until: }"
  [[ "$valid_to" == "$validity" ]] && valid_to=""
  sha256="$(printf '%s\n' "$verification" | sed -n 's/^[[:space:]]*SHA256: //p' | head -n 1)"
  if [[ -z "$sha256" ]]; then
    printf '::error::AAB signing certificate SHA-256 digest was not reported.\n' >&2
    exit 1
  fi

  jq -n \
    --arg method "keytool -printcert -jarfile" \
    --arg certificate_subject "$subject" \
    --arg certificate_issuer "$issuer" \
    --arg certificate_serial_number "$serial_number" \
    --arg certificate_valid_from "$valid_from" \
    --arg certificate_valid_to "$valid_to" \
    --arg certificate_sha256 "$sha256" \
    '{
      verification_method: $method,
      certificate_subject: $certificate_subject,
      certificate_issuer: $certificate_issuer,
      certificate_serial_number: $certificate_serial_number,
      certificate_valid_from: $certificate_valid_from,
      certificate_valid_to: $certificate_valid_to,
      certificate_sha256: $certificate_sha256
    }'
}

extract_ios_ipa_signing() {
  local extract_directory ipa_app certificate_path certificate_details certificate_fingerprint code_signature_details
  extract_directory="$(mktemp -d)"
  unzip -qq "$BUILD_ARTIFACT" 'Payload/*.app/*' -d "$extract_directory" || {
    rm -rf "$extract_directory"
    printf '::error::Could not extract an app bundle from IPA: %s\n' "$BUILD_ARTIFACT" >&2
    exit 1
  }
  ipa_app="$(find "$extract_directory/Payload" -maxdepth 1 -type d -name '*.app' -print -quit)"
  if [[ -z "$ipa_app" ]]; then
    rm -rf "$extract_directory"
    printf '::error::IPA does not contain an app bundle: %s\n' "$BUILD_ARTIFACT" >&2
    exit 1
  fi
  (
    cd "$extract_directory"
    codesign -d --extract-certificates "$ipa_app" >/dev/null 2>&1
  ) || {
    rm -rf "$extract_directory"
    printf '::error::Could not extract IPA signing certificate: %s\n' "$BUILD_ARTIFACT" >&2
    exit 1
  }
  certificate_path="$extract_directory/codesign0"
  certificate_details="$(openssl x509 -inform der -in "$certificate_path" -noout -subject -issuer -serial -startdate -enddate)" || {
    rm -rf "$extract_directory"
    printf '::error::Could not inspect IPA signing certificate: %s\n' "$BUILD_ARTIFACT" >&2
    exit 1
  }
  certificate_fingerprint="$(openssl x509 -inform der -in "$certificate_path" -noout -fingerprint -sha256)" || {
    rm -rf "$extract_directory"
    printf '::error::Could not calculate IPA signing certificate SHA-256 digest: %s\n' "$BUILD_ARTIFACT" >&2
    exit 1
  }
  code_signature_details="$(codesign -d --verbose=4 "$ipa_app" 2>&1)"

  local subject issuer serial_number sha256 valid_from valid_to code_directory_hash
  subject="$(printf '%s\n' "$certificate_details" | sed -n 's/^subject=//p' | head -n 1)"
  issuer="$(printf '%s\n' "$certificate_details" | sed -n 's/^issuer=//p' | head -n 1)"
  serial_number="$(printf '%s\n' "$certificate_details" | sed -n 's/^serial=//p' | head -n 1)"
  sha256="$(printf '%s' "$certificate_fingerprint" | sed 's/^[^=]*=//' | tr -d '[:space:]')"
  valid_from="$(printf '%s\n' "$certificate_details" | sed -n 's/^notBefore=//p' | head -n 1)"
  valid_to="$(printf '%s\n' "$certificate_details" | sed -n 's/^notAfter=//p' | head -n 1)"
  code_directory_hash="$(printf '%s\n' "$code_signature_details" | sed -n 's/^CDHash=//p' | head -n 1)"
  rm -rf "$extract_directory"
  if [[ ! "$sha256" =~ ^([[:xdigit:]]{2}:){31}[[:xdigit:]]{2}$ ]]; then
    printf '::error::IPA signing certificate SHA-256 digest was not reported in a recognized format.\n%s\n' "$certificate_fingerprint" >&2
    exit 1
  fi

  jq -n \
    --arg method "codesign --extract-certificates" \
    --arg certificate_subject "$subject" \
    --arg certificate_issuer "$issuer" \
    --arg certificate_serial_number "$serial_number" \
    --arg certificate_sha256 "$sha256" \
    --arg certificate_valid_from "$valid_from" \
    --arg certificate_valid_to "$valid_to" \
    --arg code_directory_hash "$code_directory_hash" \
    '{
      verification_method: $method,
      certificate_subject: $certificate_subject,
      certificate_issuer: $certificate_issuer,
      certificate_serial_number: $certificate_serial_number,
      certificate_sha256: $certificate_sha256,
      certificate_valid_from: $certificate_valid_from,
      certificate_valid_to: $certificate_valid_to,
      code_directory_hash: $code_directory_hash
    }'
}

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
BUILD_ARTIFACT_PATH=""
VULNERABILITY_REPORT_PATH=""

if [[ -n "$BUILD_ARTIFACT" ]]; then
  if [[ ! -f "$BUILD_ARTIFACT" ]]; then
    printf '::error::build-artifact must be a regular file: %s\n' "$BUILD_ARTIFACT" >&2
    exit 1
  fi

  BUILD_ARTIFACT_PATH="$OUTPUT_DIRECTORY/build-artifact.json"
  artifact_sha256="$(shasum -a 256 "$BUILD_ARTIFACT" | awk '{print $1}')"
  artifact_sha512="$(shasum -a 512 "$BUILD_ARTIFACT" | awk '{print $1}')"
  artifact_size="$(stat -f '%z' "$BUILD_ARTIFACT")"
  artifact_mime_type="$(file -b --mime-type "$BUILD_ARTIFACT")"
  artifact_recorded_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  artifact_build_time="$BUILD_TIME"
  if [[ -z "$artifact_build_time" ]]; then
    artifact_build_time="$(date -r "$(stat -f '%m' "$BUILD_ARTIFACT")" -u +'%Y-%m-%dT%H:%M:%SZ')"
  fi
  case "$BUILD_ARTIFACT" in
    *.apk) signing_json="$(extract_android_apk_signing)" ;;
    *.aab) signing_json="$(extract_android_aab_signing)" ;;
    *.ipa) signing_json="$(extract_ios_ipa_signing)" ;;
  esac

  jq -n \
    --arg schema_version "1.0" \
    --arg file "$(basename "$BUILD_ARTIFACT")" \
    --arg sha256 "$artifact_sha256" \
    --arg sha512 "$artifact_sha512" \
    --arg mime_type "$artifact_mime_type" \
    --arg build_time "$artifact_build_time" \
    --arg recorded_at "$artifact_recorded_at" \
    --arg version "$APP_VERSION" \
    --arg build_number "$BUILD_NUMBER" \
    --argjson size "$artifact_size" \
    --argjson signing "$signing_json" \
    '{
      schema_version: $schema_version,
      file: $file,
      sha256: $sha256,
      sha512: $sha512,
      size: $size,
      mime_type: $mime_type,
      build_time: $build_time,
      recorded_at: $recorded_at,
      version: $version,
      build_number: $build_number,
      signing: $signing
    }' \
    > "$BUILD_ARTIFACT_PATH"
  validate_build_artifact "$BUILD_ARTIFACT_PATH"
fi

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
event_name="${GITHUB_EVENT_NAME:-unknown}"
workflow_url=""
if [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" && -n "${GITHUB_RUN_ID:-}" ]]; then
  workflow_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
fi
source_manifest="$(mktemp)"
if [[ -d "$SOURCE" ]]; then
  source_root="$(cd "$SOURCE" && pwd)"
  output_root="$(cd "$(dirname "$OUTPUT_DIRECTORY")" && pwd)/$(basename "$OUTPUT_DIRECTORY")"
  while IFS= read -r source_file; do
    [[ "$source_file" == "$output_root"/* ]] && continue
    relative_file="${source_file#"$source_root"/}"
    printf '%s  %s\n' "$(shasum -a 256 "$source_file" | awk '{print $1}')" "$relative_file" >> "$source_manifest"
  done < <(find "$source_root" -type f -print | sort)
else
  printf '%s  %s\n' "$(shasum -a 256 "$SOURCE" | awk '{print $1}')" "$(basename "$SOURCE")" > "$source_manifest"
fi
source_sha256="$(shasum -a 256 "$source_manifest" | awk '{print $1}')"
rm -f "$source_manifest"
jq -n \
  --arg schema_version "1.0" \
  --arg app_name "$APP_NAME" \
  --arg app_version "$APP_VERSION" \
  --arg platform "$PLATFORM" \
  --arg repository "${GITHUB_REPOSITORY:-}" \
  --arg commit_sha "${GITHUB_SHA:-}" \
  --arg ref "${GITHUB_REF:-}" \
  --arg workflow "$workflow_name" \
  --arg workflow_url "$workflow_url" \
  --arg event_name "$event_name" \
  --arg workflow_run_id "${GITHUB_RUN_ID:-}" \
  --arg workflow_run_number "${GITHUB_RUN_NUMBER:-}" \
  --arg workflow_attempt "${GITHUB_RUN_ATTEMPT:-}" \
  --arg actor "${GITHUB_ACTOR:-}" \
  --arg runner_name "${RUNNER_NAME:-}" \
  --arg runner_os "${RUNNER_OS:-}" \
  --arg generated_at "$generated_at" \
  --arg source_sha256 "$source_sha256" \
  --arg syft_version "${syft_version:-unknown}" \
  --arg cyclonedx_cli_version "${cyclonedx_cli_version:-unknown}" \
  --arg sbom_format "CycloneDX JSON" \
  --argjson sbom_component_count "$component_count" \
  --arg scanned_source "$SOURCE" \
  '{
    schema_version: $schema_version,
    app_name: $app_name,
    app_version: $app_version,
    platform: $platform,
    repository: $repository,
    commit_sha: $commit_sha,
    ref: $ref,
    workflow: $workflow,
    workflow_url: $workflow_url,
    event_name: $event_name,
    workflow_run_id: $workflow_run_id,
    workflow_run_number: $workflow_run_number,
    workflow_attempt: $workflow_attempt,
    actor: $actor,
    runner_name: $runner_name,
    runner_os: $runner_os,
    generated_at: $generated_at,
    source_sha256: $source_sha256,
    syft_version: $syft_version,
    cyclonedx_cli_version: $cyclonedx_cli_version,
    sbom_format: $sbom_format,
    sbom_component_count: $sbom_component_count,
    scanned_source: $scanned_source
  }' \
  > "$BUILD_INFO_PATH"
validate_build_info "$BUILD_INFO_PATH"

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
    if [[ -n "$BUILD_ARTIFACT_PATH" ]]; then
      printf -- '- Build artifact metadata: %s\n' "$BUILD_ARTIFACT_PATH"
    fi
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

archive_timestamp="$(date -u +'%Y%m%dt%H%M%Sz')"
archive_stem="${APP_NAME}-${APP_VERSION}-${PLATFORM}"
archive_stem="$(printf '%s' "$archive_stem" | tr '[:space:]/' '--' | tr -cd '[:alnum:]._+-')"
evidence_version_stem="${GITHUB_REPOSITORY:-local}-${archive_stem}-${GITHUB_RUN_ID:-$archive_timestamp}-${GITHUB_RUN_ATTEMPT:-1}"
evidence_version="$(printf '%s' "$evidence_version_stem" \
  | tr '[:upper:]' '[:lower:]' \
  | sed -E 's/[^a-z0-9.+~:-]+/-/g; s/-+/-/g; s/^[^a-z0-9]+//; s/[^a-z0-9]+$//')"
archive_directory="$(cd "$(dirname "$OUTPUT_DIRECTORY")" && pwd)"
EVIDENCE_ARCHIVE_PATH="$archive_directory/$archive_stem.zip"

printf 'Creating CRA evidence archive: %s\n' "$EVIDENCE_ARCHIVE_PATH"
(
  cd "$OUTPUT_DIRECTORY"
  zip -qr "$EVIDENCE_ARCHIVE_PATH" .
)
if [[ ! -s "$EVIDENCE_ARCHIVE_PATH" ]]; then
  printf '::error::CRA evidence archive was not created: %s\n' "$EVIDENCE_ARCHIVE_PATH" >&2
  exit 1
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'sbom-path=%s\n' "$SBOM_PATH"
    printf 'build-info-path=%s\n' "$BUILD_INFO_PATH"
    printf 'build-artifact-path=%s\n' "$BUILD_ARTIFACT_PATH"
    printf 'vulnerability-report-path=%s\n' "$VULNERABILITY_REPORT_PATH"
    printf 'component-count=%s\n' "$component_count"
    printf 'vulnerability-count=%s\n' "$vulnerability_count"
    printf 'scan-status=%s\n' "$scan_status"
    printf 'evidence-directory=%s\n' "$OUTPUT_DIRECTORY"
    printf 'evidence-archive-path=%s\n' "$EVIDENCE_ARCHIVE_PATH"
    printf 'evidence-archive-name=%s\n' "$(basename "$EVIDENCE_ARCHIVE_PATH")"
    printf 'evidence-version=%s\n' "$evidence_version"
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
