$ErrorActionPreference = 'Stop'
$env:CGO_ENABLED = '1'
New-Item -ItemType Directory -Force -Path dist | Out-Null
go build -buildmode=c-shared -trimpath -ldflags '-s -w' -o dist/grok-sso-importer.dll .
