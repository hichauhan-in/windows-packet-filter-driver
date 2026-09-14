# Windows Packet Filter

A **C11 Windows WFP callout driver**, administrator-only command-line controller, and technical project site explaining the design.

The driver monitors **IPv4 TCP/UDP connection authorizations** and can block one configured endpoint rule. It is a systems-programming learning project, not a production firewall or raw packet sniffer.

**[Read the project site](https://hichauhan-in.github.io/windows-packet-filter-driver/)** · **[Native project guide](NetworkDriver/README.md)** · **[Build, VM testing & rollback](NetworkDriver/docs/TESTING.md)**

> The site link becomes available after GitHub Pages is enabled and the first deployment succeeds. The local page is [`index.html`](index.html). Driver loading belongs only in an isolated, authorized Windows VM.

## What is here

| Area | Contents |
| --- | --- |
| [`NetworkDriver/`](NetworkDriver/) | C11 WDM driver, WFP callouts, secured buffered IOCTLs, shared policy and tests |
| [`NetworkDriver/NetworkCtl/`](NetworkDriver/NetworkCtl/) | C controller: `monitor`, `block`, `stats`, `events`, `watch` |
| [`index.html`](index.html) | Architecture, lifetime, worked decisions, permissions, tradeoffs, validation and source map |
| [`assets/`](assets/) | Responsive navy/cyan theme and an original project favicon |
| [`.github/workflows/pages.yml`](.github/workflows/pages.yml) | Curated static GitHub Pages deployment |

The website matches the visual language of the companion heap-manager project: dark navy, cyan accents, monospace panels and a numbered technical write-up. It has no framework, production JavaScript, external fonts, analytics, live driver access or third-party runtime requests. Native `<details>` elements provide keyboard-accessible worked examples. Assets use relative paths so the page works at a GitHub project URL and when opened locally.

Examples are labeled as **illustrations**, not captured network events. Native test results are a documented snapshot, not a live CI status. The website workflow does not build or test the Windows driver.

## Publish with GitHub Pages

1. Commit and push the intended source/site files to `main`. Review `git status` first; do not commit binaries, private keys, certificates or VM logs.
2. In this repository on GitHub, open **Settings → Pages → Build and deployment**.
3. Set **Source** to **GitHub Actions**. No Jekyll theme or branch-based `/docs` configuration is needed.
4. Open **Actions → Publish project site → Run workflow** on `main` for the first deployment. Later pushes affecting `index.html`, `assets/`, `.nojekyll` or the Pages workflow trigger it automatically.
5. Wait for the build and `github-pages` deployment to succeed. The environment link gives the deployed URL, normally `https://hichauhan-in.github.io/windows-packet-filter-driver/`.

Pull requests stage the static artifact but do **not** deploy. The deployment job alone receives Pages-write and OIDC permissions. Repository or organization policy may require approval of the `github-pages` environment.

Only these files are staged for public hosting:

- `index.html`
- `assets/site.css`
- `assets/favicon.svg`
- `.nojekyll`

The artifact does not include the native workspace, binaries, test captures, certificates or local configuration. Source/documentation links point to GitHub rather than publishing the whole repository as site content. No GitHub settings, pushes or deployments are performed merely by adding these files locally.

## Preview the site

For a quick preview, open `index.html` in a browser. All content and native disclosures work without JavaScript or a server.

For an HTTP preview, from the repository root with Python available:

```powershell
python -m http.server 8000 --bind 127.0.0.1
```

Open `http://127.0.0.1:8000/` and press Ctrl+C in the terminal when finished. This development server exposes the repository files to your local machine; it is not the curated deployment artifact. Keep it bound to loopback and do not use it to serve a working directory publicly.

The page supports narrow layouts, visible keyboard focus, a skip link, semantic headings, reduced motion, horizontally scrollable code/tables and native expandable examples. No npm install, bundler or network font download is required.

### Local site validation

Headless Microsoft Edge checks passed at widths of 320, 390, 768, 1024 and 1440 pixels with no page-wide horizontal overflow. Keyboard expansion of the native examples, visible focus, skip-link tab order, reduced-motion behavior and accessibility landmarks were checked. HTML nesting, SVG syntax, local anchors/assets and linked repository source paths also passed checks. This is not a full WCAG audit or a validation of external sites.

The four-file public artifact is approximately 54 KB before compression. Desktop/mobile screenshots and local check results, if retained, are in the ignored `.pages-preview/` directory and are not deployed. The native solution also built successfully after the website additions. GitHub-hosted deployment itself still requires repository settings and a workflow run.

## Native project status

The recorded local validation covers:

- Debug and Release x64 builds, including WDK INF/catalog checks.
- **45 C rule/ABI checks** per configuration.
- **13 driver-free CLI validation cases**.
- TCP and UDP loopback echo fixtures **without the driver loaded**.

Driver loading, actual blocking, device ACL enforcement, concurrent kernel behavior, unload, BFE lifecycle and Driver Verifier remain **VM tests to perform**. ARM64 configurations exist but are unvalidated. Builds are unsigned by default; follow the [manual signing and VM guide](NetworkDriver/docs/TESTING.md) before deployment.

## Keep the presentation accurate

When behavior changes, update the native documentation and the matching sections in `index.html`. The page is intentionally hand-authored, not a generated live view of driver state. Do not add benchmark claims or mark kernel scenarios as passed without corresponding evidence. For a portfolio demo, record a narrow monitor → block → recover sequence in an authorized VM and redact sensitive metadata before publishing.
