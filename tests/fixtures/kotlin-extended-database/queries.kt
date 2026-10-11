import com.mongodb.client.MongoCollection
import org.bson.Document
import org.hibernate.Session

fun queryBoundaries(store: MongoCollection<Document>, session: Session, filter: String, selector: Document, sql: String) {
    store.find(selector)
    store.find(Document.parse(filter))
    session.createNativeQuery(sql)
}
