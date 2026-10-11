# Frontend source scope

Use when planning React, Vue, Angular or related JS/TS application reviews.
The scanner skips conventional dependency, build and cache trees before parsing.
These artifacts belong in neither ordinary Value nor Comprehensive queues:
review the authored behavior once, rather than its bundled copies or tool caches.
Comprehensive expands credible security questions in the selected source scope;
it does not automatically reopen generated artifacts.

## Built-in boundaries

Names match directory components, case-insensitively, at any project depth.
For paths containing `/`, only that immediate parent/child combination is skipped.
This is a conventional source-scope policy, not a proof of generation or safety.

| Stack/tool | Excluded directories | Authored locations to retain |
| --- | --- | --- |
| Shared JS/TS tooling | `node_modules`, `bower_components`, `jspm_packages`, `.pnpm-store`, `.cache`, `.parcel-cache`, `.turbo`, `dist`, `build`, `out`, `coverage` | Application packages, configuration, scripts and shared implementations |
| React/Next.js | `.next`, `_next/static` | `app`, `pages`, components, server code; other `_next` children |
| Vue/Nuxt and Nitro output | `.nuxt`, `_nuxt`, `.nitro`, `.output` | Pages, components, plugins, middleware, server/API implementations |
| Vite: React/Vue/Solid and other JS/TS | `.vite`, `.vite-temp` | Original Vite config, imports, aliases, plugins and source |
| Angular | `.angular`, `dist` | `src`, `projects`, libraries, templates and Angular config |
| Quasar/Vue | `.quasar`, `dist` | `src`, `src-ssr`, `src-pwa`, `src-electron`, boot files and config |
| React Router | `.react-router`, `build` | Actual routes, loaders/actions, components and server code |
| SolidStart v1 | `.vinxi`, `.nitro`, `.output` | Source routes, middleware and server functions |
| VuePress | `.vuepress/.temp`, `.cache`, `dist` | `.vuepress` config, components, themes, templates and public files |
| VitePress | `.vitepress/cache`, `dist`, `.vite` | `.vitepress` config, custom themes and plugins |
| Docusaurus/React | `.docusaurus`, `build` | Authored themes, swizzled components, config and plugins |
| SvelteKit / Astro tooling | `.svelte-kit`, `.astro`, `_astro`, `dist`, `build` | Source, routes, components, actions and config; component parser coverage remains separate |
| Yarn | `.yarn/cache`, `.yarn/unplugged`, `.yarn/sdks`, `.yarn/releases` | Local plugins, patches, workspace packages and configuration |
| Nx | `.nx/cache`, `.nx/workspace-data` | Local generators/plugins and project configuration |
| Storybook / Playwright | `storybook-static`, `playwright-report`, `blob-report` | `.storybook` config, stories, test source and application components |

## Keep ambiguous source and deployment folders

Do not add blanket exclusions for `public`, `static`, `assets`, `lib`, `www`,
`generated`, `cache`, `.temp`, tests, fixtures, docs or directories containing
`dist` as a substring. These names can contain authored runtime code or useful
research controls. Existing nonproduction classification remains a separate
selection policy. Do not exclude an entire `.vuepress`, `.vitepress`, `.yarn`,
`.nx`, `.storybook`, `.vercel` or `.netlify` directory.

Custom output paths need repository ignore rules or confirmed provenance during
preassessment; do not evaluate framework configuration or build plugins to guess
them. Retain unresolved mixed ownership. Vercel's `.vercel/output` can be populated
by hand, so its name alone does not establish duplicated generated source.

Check `excluded_subtrees` through `mehscan investigate provenance` and report
source coverage gaps. Excluded descendants are not individual deferred IDs or safe
verdicts. For compiled-only targets or a concrete deployed/dependency lead, scan
the relevant excluded directory as an explicit root and follow its actual source.
Do not claim original/output equivalence from a source map alone. Read served
assets, service workers and authored server code when relevant; none are dismissed
merely because they are frontend files.

## Frontend review buckets

| Value | Comprehensive-only | Outside application scope |
| --- | --- | --- |
| Raw markup and meaningful writer-to-consumer relationships; unsafe URL construction or connected browser input; credentials sent to an unresolved destination; consequential uploads/executable content. | Unresolved stored link writers/scheme controls; raw stylesheet ownership/SSR breakout; auth redirects and meaningful CSRF/credential-in-URL questions. Name the missing edge. | Source-confirmed local asset/document generators, vendor/generated copies, ordinary fixed-destination client reads and complete positive URL controls without another consequential effect. |

Standalone intrinsic JSX link writers, owned Angular ordinary URL bypasses and
literal stylesheet insertions (React JSX/createElement, Vue `h`, Solid JSX) start
Comprehensive-only. Constructed URLs, connected input, represented native caller
facts, active resources and raw HTML keep stronger admission. A style tag is not
a sanitizer; inspect SSR breakout. These hints retain exact IDs, not safe verdicts.

| Supported consumer | Value question | Comprehensive / scope check |
| --- | --- | --- |
| React JSX / createElement | `dangerouslySetInnerHTML` producer, escaping and consumer; unsafe link construction | Known intrinsic stylesheet or standalone stored link writer; custom props are not native URL sinks. |
| Vue SFC / render `h` | `v-html` / intrinsic `innerHTML` writer and final control | Known `h('style', ...)`; group source-confirmed theme/frontmatter writers before packaging repeated views. Plain interpolation / `v-text` is not raw HTML. |
| Angular | Owned HTML, script or resource-URL bypass; connected input or constructed ordinary URL | Standalone `bypassSecurityTrustUrl` writer/scheme/consumer question. Ordinary framework HTML binding is not itself a bypass. |
| Solid JSX | Intrinsic `innerHTML`, writer and output control | Known intrinsic `style`; do not infer native sinks from custom component props. |
| Lit | Imported `unsafeHTML` producer and final markup | Raw strings remain Value; a tagged template or CSS-looking string does not establish its output container. |
| jQuery | Owned HTML insertion receiver, operand and prior controls | Resolve actual `.html` / `.append` consumer; do not infer stylesheet context from a selector or variable name. |
| Plain DOM / executable EJS client code | Raw insertion, unsafe URL/resource consumers, credentials and meaningful browser effects | Unknown element kinds stay prioritized. Source-confirmed ordinary navigation, controls and tooling use the shared scope criteria. |

Do not classify a prop as trusted from its TypeScript type or a `theme`, `admin`,
`icon` or `config` name. Read its writer chain. Repeated authored-site config
consumers can share one publishing-authority question in Comprehensive after
preassessment; a runtime editor, external feed or less-trusted writer reopens Value.
Positive sanitizer controls must cover the exact final operand and configuration;
post-sanitization interpolation reopens the question.
For a framework/theme library without its host integration, group expected raw
rendering APIs and authored-site content under a Comprehensive integration/writer
contract. Keep actual lower-trust flows, unsafe construction and protection
bypasses in Value; missing deployment policy alone is not another priority job.

The scanner excludes direct imported DOMPurify sanitization with explicit literal
text-markup tag/attribute allowlists at the final HTML insertion. Dynamic or wider
options, shadowed/replaced receivers, later construction and source-visible hook/
global configuration retain review work. This bounded slice does not infer safe
wrappers, stylesheets or other interpretation contexts.

Coverage remains bounded: Vue dynamic-tag `h`, template URL bindings and Angular
style bypass are not fully inventoried. Svelte/Astro component templates are not
supported parsers. Next/Nuxt/SolidStart server handlers remain separate runtime
surfaces; frontend source scoping must not discard their server-side effects.

Use short source reads to record exact IDs, ownership/control evidence and reasons
in the review plan before packaging. Source-confirmed ordinary tooling/copies can
leave both application queues; explicit build/dependency scope or a consequential
lead reopens them. Do not remove authored wrappers, dismiss every worker, assume
client runtime from a folder, or treat a POST as SSRF. Server actions and credential
destinations retain their own questions. Scanner hints alone do not establish
these scope exclusions or safe verdicts.

## Sources behind the conventions

- [Next.js compiled assets](https://nextjs.org/docs/14/pages/api-reference/next-config-js/assetPrefix), [Nuxt generated output](https://nuxt.com/docs/guide/concepts/server-engine/), [Nuxt defaults](https://nuxt.com/docs/4.x/directory-structure/gitignore) and [Nuxt asset directory](https://nuxt.com/docs/api/configuration/nuxt-config?from=20423&from_column=20423).
- [Vite cache](https://vite.dev/config/shared-options#cachedir), [Vite temporary config](https://vite.dev/config/), [Angular cache](https://angular.dev/cli/cache) and [Quasar generated files](https://quasar.dev/start/vs-code-configuration/).
- [VuePress config](https://vuepress.vuejs.org/reference/config), [VitePress layout](https://github.com/vuejs/vitepress/blob/main/docs/en/guide/getting-started.md), [Docusaurus ignore policy](https://github.com/facebook/docusaurus/blob/main/.gitignore), [React Router generated types](https://reactrouter.com/how-to/route-module-type-safety) and [SolidStart template](https://github.com/solidjs/templates/blob/main/solid-start-v1/basic/.gitignore).
- [Astro generated types](https://docs.astro.build/en/reference/cli-reference/#astro-sync) and [built assets](https://docs.astro.build/en/reference/configuration-reference/#buildassets), [Yarn folders](https://yarnpkg.com/getting-started/qa), [Nx cache](https://nx.dev/docs/kb/change-cache-location) and [workspace data](https://nx.dev/docs/reference/environment-variables).
- [Storybook output](https://storybook.js.org/docs/sharing/publish-storybook), [Playwright reports](https://playwright.dev/docs/test-reporters), and [Vercel's manually authored output option](https://vercel.com/docs/build-output-api).
