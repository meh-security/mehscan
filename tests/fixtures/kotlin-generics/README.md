# Generic JVM identity controls

Original Kotlin controls distinguish type parameters named `Statement`, an
import alias `SQL`, and `URL` from the JVM APIs they shadow. The custom receivers
return fixed text; they perform no SQL or network access. These four lookalike
operations must not enter the JDBC or URL review inventory.

The two real JDBC controls use a fully qualified type within a generic function
and an imported type outside the generic owner. They remain inventory candidates;
their source alone does not establish request exposure or an exploitable issue.

The file compiles with Kotlin 2.4.10 and JDK 17. Its `main` performs four harmless
lookalike checks. With the Kotlin compiler installed, run:

```powershell
kotlinc app.kt -include-runtime -d controls.jar
java -jar controls.jar
```

Generic identity is handled conservatively within its syntactic declaration.
This is not compiler-backed resolution of inherited bounds, nested class scope,
or generic dispatch.
