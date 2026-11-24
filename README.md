# RASID | راصّد

RASID is a bilingual phishing and fraudulent-checkout detector for web users in the UAE. [Open the hosted checker](https://rasid-link-checker.netlify.app/) on a phone or computer, choose **Continue as guest**, enter `https://example.com`, and tap **Check now**. Review the verdict and the evidence underneath it. Judges can use this route without installing software, paying, or providing account credentials.

The competition source snapshot is **RASID-competition-source.zip** in this repository. Download and extract it, then open the extracted folder before following the build instructions below. It contains the matching backend, website, Xcode project and this README.

## Problem and solution

A video, search result, or message can send someone to a convincing imitation of a bank or payment page. A familiar logo gives the user little evidence about who controls the destination. RASID checks the actual address, follows redirects where inspection is possible, and explains the warning signs in English or Arabic.

The website checks links on demand. The included iPhone app adds automatic checks in Safari once the user enables the extension. Installing the website on a home screen provides a shortcut to the checker. Automatic Safari protection requires the native extension.

## Technical choices, tools and APIs

| Component | How and why it is used |
| --- | --- |
| Browser interface | HTML, CSS and JavaScript provide a bilingual interface that judges can open directly. |
| Detection backend | TypeScript Netlify Functions implement the checker. The server can inspect public HTTP(S) destinations without opening a suspect page on the user's device. It limits redirects, rejects private destinations and inspects returned HTML without executing page scripts. |
| Detection rules and optional AI | URL patterns, threat-list matches, page observations and domain age supply evidence. The backend can ask Claude to interpret the evidence, with an OpenAI fallback when configured. Rules can return a verdict when model access is unavailable. Look at the AI status in a full scan to see whether a model actually ran. |
| iPhone and Safari | SwiftUI hosts the app. A Safari Web Extension uses JavaScript and native messaging to read the protection preference. The extension can warn, block, or offer a one-time continuation for a suspicious result. The Safari card-form guard recognizes standard card-number and security-code fields and checks for an insecure page or submission destination without reading their values. |
| Accounts and storage | Netlify Blobs stores account records, site review records and cached verdicts. Registered accounts use salted scrypt password hashes. The server signs guest and account sessions. |

## Data and scope

- The backend consults the OpenPhish community URL feed, Phishing Army domain blocklist and public RDAP registration data. Feed availability and registration dates can vary. The repository contains the application and rules. It does not require a downloadable training dataset.
- The checker uses the submitted URL, public page and redirect evidence when available. Optional model calls receive selected, redacted evidence. Site review records can include a hostname, a redacted example and the reason for a flag. Use public test URLs without private tokens.
- A safe verdict means the checks found insufficient evidence of a threat. A checkout can use HTTPS and still be fraudulent. RASID cannot validate a seller or reverse a payment.
- This submission covers the web checker and Safari extension. Automatic protection inside Instagram and Snapchat is under development. The UAE PASS profile flow and automatic police reporting in this build are demonstrations.

## Build and run the web project

Use Node.js 22.12+ and npm. From the repository root, in a macOS or Linux shell:

```sh
npm ci
export RASID_SECRET="$(openssl rand -hex 32)"
npx netlify-cli dev
```

Open the local address printed by the CLI. Run through Netlify Dev so that both the interface and the functions are available. Keep the same development secret across restarts to preserve sessions. Guest access and the rules-based checker do not require a paid AI key. Network access is needed to inspect public websites, retrieve threat feeds and query RDAP. Optional model access uses server-side provider configuration such as `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`. Keep credentials out of Git.

For an API smoke test with the local server running, use the address printed by Netlify Dev in place of port 8888 if needed:

```sh
base=http://localhost:8888
token=$(curl -fsS -X POST "$base/api/auth/guest" | node -pe 'JSON.parse(require("fs").readFileSync(0,"utf8")).token')
curl -fsS "$base/api/check" -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","mode":"scan"}'
```

A completed full check returns a verdict and evidence sections. The result identifies unavailable checks. The automatic Safari flow uses the same endpoint with `mode: "gate"` for a browsing decision.

## Build and run the iPhone project

1. On a Mac with Xcode, open **ios/Rasid.xcodeproj**, choose the **Rasid** scheme, select an iPhone simulator, and press **Run**. The competition build was prepared using Xcode 27.2. The native client points to the hosted RASID backend by default.
2. Continue as a guest and enable protection in RASID. In iPhone **Settings → Apps → Safari → Extensions**, enable RASID and grant it access to the sites you intend to test. Older iOS versions put Safari directly under Settings.
3. Open a harmless public URL in Safari. Check that the extension responds with protection enabled. Disable protection in the app and repeat to compare.
4. A physical-device build needs signing configured for the app and extension under **Signing & Capabilities**. Teams using different identifiers must keep the extension identifier and shared App Group consistent in the entitlements and Swift code. The hosted web checker is the simplest free option for judges without a Mac.

## Repository map

| Path | Contents |
| --- | --- |
| `public/` | Web interface, app manifest, service worker and icons |
| `netlify/functions/` | Authentication, checking, site lists and policy endpoints |
| `netlify/lib/engine.mts` | URL rules, feeds, RDAP, page inspection and AI decision logic |
| `netlify/lib/auth.mts`, `netlify/lib/sites.mts` | Session signing, accounts and site records |
| `ios/Rasid/` | Native iPhone app, preferences and guest sign-in |
| `ios/Rasid Extension/` | Safari extension, navigation checks and warning screen |
