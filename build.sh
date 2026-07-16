#!/usr/bin/env sh
set -eu
mkdir -p dist
case "$(uname -s)" in
  Darwin) out="dist/grok-sso-importer.dylib" ;;
  *) out="dist/grok-sso-importer.so" ;;
esac
CGO_ENABLED=1 go build -buildmode=c-shared -trimpath -ldflags='-s -w' -o "$out" .
