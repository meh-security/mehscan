# Go grammar

Based on [tree-sitter-go 0.25.0](https://github.com/tree-sitter/tree-sitter-go/tree/1547678a9da59885853f5f5cc8a99cc203fa2e2c),
under its original MIT license. The Rust binding and queries retain the upstream
API. The local grammar adds method type parameters and expression arguments to
the special `new`/`make` call syntax, including calls that shadow those builtins.
An identifier argument can denote either a type or a value; the syntax tree does
not resolve that semantic ambiguity.

`src/parser.c`, `src/grammar.json`, `src/node-types.json` and the parser headers
are generated with tree-sitter CLI 0.26.3, ABI 15. To regenerate, run
`tree-sitter generate --abi 15` in this directory with Node.js available.
Normal builds compile the checked-in C parser and require neither generator nor
Node.js. `grammar.js` contains the maintained grammar changes; source text is
parsed directly without rewriting.
