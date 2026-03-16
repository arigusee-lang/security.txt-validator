# security.txt Validator

A web tool for validating, generating, and auto-correcting `security.txt` files per [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).

`security.txt` is a standard that allows website owners to describe their vulnerability disclosure practices. Learn more at [securitytxt.org](https://securitytxt.org/).

## Features

- **Validate** — paste content or drag-and-drop a `.txt` file to get line-by-line errors and warnings with RFC references
- **Fetch by domain** — enter a domain name and the tool fetches `security.txt` via an SSRF-protected proxy, checking both content and hosting configuration (Content-Type, location, redirects)
- **Generate** — fill in a form to build a valid file with live preview, copy, and download
- **Auto-correct** — a corrected version is generated automatically (missing fields inserted, URI schemes fixed, expired dates replaced)
- **PGP ClearSign** — correctly detects signed files and extracts content from the PGP wrapper
- **Dark / light theme**

## Validation Rules

| Rule | Severity | Description |
|---|---|---|
| Required fields | error | Contact and Expires must be present |
| Expires format | error | Must be a valid RFC 3339 date-time, not in the past |
| URI schemes | error | Contact: `mailto:` / `https:` / `tel:`, others: `https:` |
| Line syntax | error | Every line must be a field, comment, or blank |
| Preferred-Languages | error | Must contain valid BCP 47 tags |
| Unknown fields | warning | Fields not defined by RFC 9116 |
| Expiry window | warning | Less than 30 days or more than 365 days until expiry |
| Content-Type | warning | Must be `text/plain` (fetch mode) |
| File location | warning | `/.well-known/security.txt` is recommended (fetch mode) |
| PGP signature | info | ClearSign wrapper detection and structure check |

## Tech Stack

- **Frontend**: Svelte 4, TypeScript, Vite
- **Backend**: Express, Node.js (SSRF-protected proxy)
- **Tests**: Vitest (124 tests)

## Getting Started

```bash
# Install dependencies
npm install

# Development (frontend + backend)
npm run dev      # Vite dev server on :5173
npm run server   # Express proxy on :3001

# Run tests
npm test

# Production
npm run build
npm start        # Serves built frontend + API on :3001
```

## Links

- [RFC 9116 — A File Format to Aid in Security Vulnerability Disclosure](https://www.rfc-editor.org/rfc/rfc9116)
- [securitytxt.org](https://securitytxt.org/)
- [RFC 4880 — OpenPGP (ClearSign)](https://www.rfc-editor.org/rfc/rfc4880#section-7)

## License

MIT
