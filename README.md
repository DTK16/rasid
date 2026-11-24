# RASID | راصّد

RASID checks links for signs of phishing and fraudulent UAE payment pages. The hosted checker works in Arabic and English.

**Competition MVP · 25 November 2026**  
[Open the live checker](https://rasid-link-checker.netlify.app/) · [Watch the 40-second Safari test](https://github.com/DTK16/rasid/blob/main/RASID-Safari-Link-Recheck.mp4) · [Download the buildable source](https://github.com/DTK16/rasid/blob/main/RASID-competition-source.zip)

For a source build, download and extract **RASID-competition-source.zip** from this repository. Run the commands below from the extracted folder containing `package.json` and `ios/`. The live web checker can be tried immediately as a guest.

## Try RASID as a judge

1. Open the [live checker](https://rasid-link-checker.netlify.app/) on your phone or laptop. Select **English** if needed and choose **Continue as guest** (المتابعة كضيف). On a computer, choose **Continue** on the device screen. This walkthrough requires only a browser.
2. On **Protect**, choose **Example: TAMM impersonation** (مثال تجريبي: انتحال منصة تم). RASID inspects a controlled sample that uses the TAMM name and requests card details on a different domain. Expect **Dangerous** and a reason identifying the domain mismatch.
3. Choose **Official TAMM fines** (منصة تم الرسمية). Expect **Safe** for the official domain. Both examples run a check when tapped.
4. For a separate map example, open the [server globe for example.com](https://rasid-link-checker.netlify.app/server-map.html?host=example.com&lang=en). Drag to rotate and select **Center on server** to return to the estimated hosting location. The fictional TAMM sample has no public IP or coordinates.

For automatic checks while browsing Safari, use the native iPhone installation instructions below. Guest access covers the checker. The hosted administration tools require the appropriate account.

## Problem and solution

A video, search result, or message can send someone to a convincing imitation of a bank or payment page. A familiar logo gives the user little evidence about who controls the destination. RASID checks the actual address, follows redirects where inspection is possible, and explains the warning signs in English or Arabic.

The website checks links on demand. The included iPhone app adds automatic checks in Safari once the user enables the extension. Installing the website on a home screen provides a shortcut to the checker. Automatic Safari protection requires the native extension.

## Recorded Safari test

On 25 November 2026 we opened two links directly in Safari on an iPhone 18 Pro simulator running iOS 27.2. RASID showed **Safe** for the Loro Piana UAE storefront and **Suspicious** for the SwitchROMs game-download page. The warning offered **Listen**, **Close this page** and **Open anyway**. These are observations from two visits. Classification depends on the evidence available at scan time.

The recording shows a repeat visit to Loro Piana. During the first visit, its cookie notice appeared briefly before the checking screen. Safari protection can intervene after content first appears. The two examples do not measure precision or recall on the competition's hidden test set.

## Features to explore

| Where | What to try |
| --- | --- |
| Protect | Scan a URL or a message. On iPhone, **Paste and check** reads the clipboard after a user tap and iOS may ask for confirmation. Results include a verdict, score and reasons. |
| Safari | Enable the extension, open a link, and read or listen to the verdict. Suspicious links offer a temporary override. On supported Google search pages the extension flags some UAE payment links with a brand/domain mismatch. |
| Accessibility | The app uses labels, icons, spoken results, VoiceOver announcements and distinct haptics for completed scans. Test vibration on a physical iPhone. Safari warnings include a **Listen** button. |
| UAE banking | Compare a claimed helpline with the selected bank’s official number, including a number found in a Maps listing. The report directory offers bank websites, domestic and international call options, and official reporting channels including TDRA. |
| Threats and evidence | Search confirmed threats and sites awaiting review. Admins can confirm, clear or return a site for review. Open the server map for an approximate hosting location. Use the report button to request an evidence PDF with a screenshot, timestamp and available registration and hosting details. |
| Account and Settings | Use guest or email sign-in, view privacy and terms, switch Arabic/English, choose system/light/dark appearance, toggle protection and check Safari permissions. Seasonal scam reminders follow the selected language. |

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
- This submission covers the web checker and Safari extension. For a link opened in an app’s own embedded browser, use its Open in Safari action to enter the supported protection path. The UAE PASS profile flow and automatic police reporting in this build are demonstrations.

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
4. For a quick diagnostic, open the [extension status page](https://rasid-link-checker.netlify.app/safari-check.html?lang=en) in Safari on the device. It reports whether the extension responds on that page.
5. A physical-device build needs signing configured for the app and extension under **Signing & Capabilities**. Teams using different identifiers must keep the extension identifier and shared App Group consistent in the entitlements and Swift code. The hosted web checker is the simplest free option for judges without a Mac.

## Repository map

| Path | Contents |
| --- | --- |
| `public/` | Web interface, app manifest, service worker and icons |
| `netlify/functions/` | Authentication, checking, site lists and policy endpoints |
| `netlify/lib/engine.mts` | URL rules, feeds, RDAP, page inspection and AI decision logic |
| `netlify/lib/auth.mts`, `netlify/lib/sites.mts` | Session signing, accounts and site records |
| `ios/Rasid/` | Native iPhone app, preferences and guest sign-in |
| `ios/Rasid Extension/` | Safari extension, navigation checks and warning screen |

### Demo report email

The report button sends a screenshot of the RASID warning and the flagged URL to the authenticated report endpoint. The server rechecks the verdict, builds an evidence PDF, and sends the same time-limited report preview link to the RASID support inbox and the configured demo contact. It confirms submission after the email provider accepts both deliveries. Opening a red warning by itself does not send email.

Configure the following Netlify Functions environment variables before deploying the one-tap email flow:

- `RASID_GMAIL_APP_PASSWORD` enables Gmail SMTP from the support mailbox. Store the Google app password as a private Functions secret.
- Alternatively, `RESEND_API_KEY` holds a Resend sending key.
- `RASID_REPORT_FROM` identifies a sender authorized by Resend.
- `RASID_REPORT_TO` identifies the competition test inbox. Keep personal addresses in deployment settings.

Report PDFs and email receipts use the existing Netlify Blobs store. Signed links expire seven days from the start of the UTC report date. Expiry limits downloads; stored files remain until deleted. Retries within one report dialog reuse its submission ID. Opening a fresh report starts a new submission.
