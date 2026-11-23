# Rasid · راصد — suspicious link & website checker

Paste any public website address. Rasid:

1. **URL rules**: look-alike UAE and global brands, fake `.gov.ae` addresses, punycode, raw IPs, link shorteners, risky endings, lure words, and domain age from the public RDAP registry.
2. **Threat lists**: OpenPhish community feed, URLhaus online URLs, Phishing Army blocklist (downloaded server-side, cached 30 min).
3. **Safe page inspection** (`netlify/functions/check.mts`): GET only, ports 80/443, no cookies, never submits forms. Every hostname and every redirect hop is resolved and must be a public IP, and the socket connects to that exact IP. Limits: 9 s, 1 MB, 5 redirects.
4. **AI**: Claude Haiku via Netlify AI Gateway (OpenAI `gpt-4o-mini` fallback). It receives only the redacted evidence and must cite evidence ids. Page content is treated as untrusted.

A confirmed threat-list match is always **Dangerous**: the AI can't clear it. If the AI is unavailable, the rule checks still answer. Private or internal addresses are never sent to the AI.

## Run locally

Install Node.js and npm. From the repository root run:

```sh
npm ci
npx netlify-cli dev
```

Open the local URL printed by the CLI. Submit https://example.com and inspect the verdict, page-inspection status, feed availability and AI status. The checker falls back to rules if model credentials are unavailable. Configure provider access in your own server-side environment for development.

## Working together

The competition checker is at https://rasid-link-checker.netlify.app/. The mobile warning screens in the videos illustrate planned functionality. Start each feature on a branch and open a pull request for review. Use the existing production site only when the project owner is ready to release.

**First suggested contributor task: compare an advert with a payment request.** Implement a local comparison function and a small bilingual test set first. “Free delivery” followed by “pay AED 5 for delivery” should flag a mismatch. “Free delivery” with an AED 5 product price should pass that check. If the fee type is unclear, return insufficient information. In your PR, show the input, the reason and the result for each example. The owner can continue the automatic link-blocking prototype independently.

## API

`POST /api/check` with `{"url":"https://example.com"}`, or `GET /api/check?url=...`. `{"sample":"feed"}` checks a random live OpenPhish entry.
