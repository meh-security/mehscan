package quality.generics
import java.sql.Statement
import java.sql.Statement as SQL
import java.net.URL
open class Other { fun executeQuery(q: String) = "fixed" }
open class OtherURL { fun openStream() = "fixed" }
class C<Statement : Other>(val db: Statement) { fun query(q: String) = db.executeQuery(q) }
fun <Statement : Other> generic(db: Statement, q: String) = db.executeQuery(q)
fun <SQL : Other> aliased(db: SQL, q: String) = db.executeQuery(q)
fun <URL : OtherURL> network(url: URL) = url.openStream()
fun <Statement : Other> qualified(db: java.sql.Statement, q: String) = db.executeQuery(q)
fun ordinary(db: Statement, q: String) = db.executeQuery(q)
fun main() {
 check(C(Other()).query("user text") == "fixed")
 check(generic(Other(), "user text") == "fixed")
 check(aliased(Other(), "user text") == "fixed")
 check(network(OtherURL()) == "fixed")
 println("4 generic lookalike runtime checks passed")
}
