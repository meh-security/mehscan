# ast-grep source attribution

The `core`, `config`, `language`, and `outline` directories originate from the
local `ast-grep-main/` source snapshot, version 0.45.1.

Upstream project: <https://github.com/ast-grep/ast-grep>

These copied crates are MIT licensed. See [LICENSE](LICENSE).

The scanner intentionally does not copy or use ast-grep's CLI, LSP, bindings,
editor integration, or other workspace crates.

Local modifications: `language` adds a separately named `PhpMixed` grammar
adapter backed by Tree-sitter's `LANGUAGE_PHP`. The upstream `Php` adapter keeps
its PHP-only grammar; mixed PHP/HTML parsing does not alter other languages.
