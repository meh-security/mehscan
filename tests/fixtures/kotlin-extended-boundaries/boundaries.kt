import groovy.lang.GroovyShell
import javax.naming.directory.DirContext
import javax.naming.directory.SearchControls

fun extendedBoundaries(
    shell: GroovyShell,
    directory: DirContext,
    expression: String,
    filter: String,
    controls: SearchControls,
) {
    shell.evaluate(expression)
    directory.search("ou=people", filter, controls)
}
