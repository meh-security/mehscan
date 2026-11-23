# Ruby and Rails source review

Read the original Ruby and template source. Establish the actual class,
receiver, call shape and Rails or gem version before applying an API contract.
A source-level class or call binding leaves routing, effective dispatch and
deployment configuration open.

## Requests and authority

- Find the route and owning controller action. Check inherited callbacks,
  callback exceptions, included concerns and resource lookup before deciding
  whether the actor can reach the effect.
- Bind the exact parameter and the consumer. Parameter presence checks and
  strong parameter allowlists answer different questions from authorization.
  Trace ownership or tenant constraints to the actual selected record and write.
- A missing route, dynamic receiver, local replacement or unresolved policy
  remains an evidence gap.

## Data and output

- For Active Record, identify the exact query method and argument slot.
  Distinguish a structured predicate or a bound value from text that determines
  grammar, identifiers, ordering or fragments. Follow wrappers where the source
  establishes passing the same operand.
- For HTML, identify the template or render mode and the exact output context.
  Check where a string acquires explicit HTML trust. Follow it to the consumer
  and inspect any intervening escaping or sanitization.
- Treat dynamic template text separately from data passed to a fixed template.
  ERB, Haml and Slim sources can supply caller and output context for a named
  check.

## Resource and interpretation boundaries

- For redirects, record the destination form and effective Rails host policy,
  including version, configuration and any explicit host-policy option. For
  file operations, establish path
  construction, intended directory and the actor authorized to select the file.
- For process and HTTP operations, resolve the actual overload, operand roles
  and runtime configuration. Distinguish an explicit command string from
  separate arguments and a URL parser from destination authorization.
- For Ruby object loading, identify the actual Marshal, YAML or Psych method
  and where the bytes originate. Review class and alias policy in the effective
  version and caller context.

Use the smallest exact source ranges that answer the named question. Keep
independent policy, runtime and caller limitations visible in the result.
