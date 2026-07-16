# Grok SSO Importer

Native CLIProxyAPI plugin that converts x.ai/Grok SSO cookies through the official OAuth device flow and immediately imports the resulting xAI OAuth JSON files into the CPA auth directory.

## Features

- Paste one SSO per line in the CPA management UI.
- Upload a TXT file; the browser reads it locally and fills the same import box.
- Accepts either raw SSO lines or `email----password----sso` lines.
- Uses a Chrome TLS fingerprint for the x.ai verification flow.
- Saves CPA-compatible `type: xai`, `auth_kind: oauth`, `using_api: true` credentials through `host.auth.save`.
- Does not return SSO values or OAuth tokens in status responses.

## Input

```text
<sso-token-1>
<sso-token-2>
email@example.com----password----<sso-token-3>
```

## Install

Add this URL to CPA plugin store sources and install it from the web management panel:

```text
https://raw.githubusercontent.com/Sakuralaaa/grok-sso-importer/main/registry.json
```

## Notes

- Conversion contacts `accounts.x.ai` and `auth.x.ai` from the CPA server.
- Use the optional proxy field when the CPA server cannot directly reach x.ai.
- Keep worker count low to reduce x.ai rate limiting.
- Failed rows can be copied from the original input and retried later.
