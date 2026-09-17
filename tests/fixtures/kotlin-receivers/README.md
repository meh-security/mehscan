# Explicit receiver controls

These original source controls exercise `this.field` when a local variable has
the same name and a different type. They are parsed but are not a runnable app.

- `memberQuery`: request text reaches the real EntityManager query and execution.
- `memberRead`: request text selects the real Path read target.
- `lookalikeQuery`: the actual member ignores the input and returns fixed data.
- `lookalikeRead`: the actual member returns a fixed read path.

The local variable's type must not replace the explicit member's identity.
Receiver lambdas and extension functions remain unresolved conservatively.
