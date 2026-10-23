#!/bin/sh
# Stand-in for the grype binary used by CLI tests. FIXTURES points at
# internal/grype/testdata.
set -e
case "$1" in
  version)
    echo '{"application":"grype","version":"0.100.0"}'
    ;;
  db)
    case "$2" in
      update) echo "Vulnerability database updated to latest version" ;;
      status) echo "Built: 2026-10-22" ;;
      search) echo '[{"id":"'"$4"'","provider":"nvd","severity":"high"}]' ;;
      *) echo "unknown db command" >&2; exit 1 ;;
    esac
    ;;
  *)
    shift
    while [ $# -gt 0 ]; do
      case "$1" in
        -o)
          shift
          case "$1" in
            json=*) cp "$FIXTURES/grype.json" "${1#json=}" ;;
            cyclonedx-json=*) cp "$FIXTURES/sbom.cdx.json" "${1#cyclonedx-json=}" ;;
          esac
          ;;
      esac
      shift
    done
    ;;
esac
