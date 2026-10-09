use mehscan_core::{EvidenceKind, ScanResult};
use mehscan_engine::investigation::{ReviewInventory, build_review_inventory};

fn inventory(label: &str, files: &[(&str, &str)]) -> ReviewInventory {
    let root =
        std::env::temp_dir().join(format!("mehscan-db-cleanup-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    for (path, source) in files {
        std::fs::write(root.join(path), source).unwrap();
    }
    let result = build_review_inventory(&root, false).unwrap();
    std::fs::remove_dir_all(root).unwrap();
    assert_eq!(result.scan.coverage.totals.parse_failed, 0);
    result
}

fn sinks<'a>(scan: &'a ScanResult, path: &str, cwe: &str) -> Vec<&'a mehscan_core::Evidence> {
    scan.evidence
        .iter()
        .filter(|e| {
            e.location.path == path && e.kind == EvidenceKind::Sink && e.cwe_candidates == [cwe]
        })
        .collect()
}

#[test]
fn unused_sql_builders_leave_both_queues_but_executed_and_escaped_stay() {
    let result = inventory(
        "builders",
        &[
            (
                "app.php",
                r#"<?php
use Illuminate\Support\Facades\DB;
function ignored($sql) { DB::raw($sql); $unused = DB::raw($sql); }
function escaped($sql) { return DB::raw($sql); }
function embedded($sql) { return DB::table('users')->select(DB::raw($sql))->get(); }
function executed($sql) { return DB::select($sql); }
"#,
            ),
            (
                "app.js",
                r#"
const knex = require('knex'); const db = knex({client:'pg'});
function ignored(sql) { db.raw(sql); const unused = db.raw(sql); }
function escaped(sql) { return db.raw(sql); }
async function awaited(sql) { const unused = await db.raw(sql); }
function executed(sql) { return db.raw(sql).then(rows => rows); }
"#,
            ),
            (
                "App.java",
                r#"
import org.hibernate.Session;
class App {
void ignored(Session session, String sql) { session.createNativeQuery(sql); var unused = session.createNativeQuery(sql); }
Object escaped(Session session, String sql) { return session.createNativeQuery(sql); }
Object executed(Session session, String sql) { var q = session.createNativeQuery(sql); return q.getResultList(); }
}
"#,
            ),
            (
                "app.kt",
                "import org.hibernate.Session\nfun ignored(session: Session, sql: String) { val unused = session.createNativeQuery(sql) }\nfun escaped(session: Session, sql: String) = session.createNativeQuery(sql)\nfun executed(session: Session, sql: String) = session.createNativeQuery(sql).list()\n",
            ),
        ],
    );
    for (path, expected) in [
        ("app.php", 3),
        ("app.js", 3),
        ("App.java", 2),
        ("app.kt", 2),
    ] {
        let hits = sinks(&result.scan, path, "CWE-89");
        assert_eq!(hits.len(), expected, "{path}: {hits:#?}");
        assert!(
            !hits
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some("ignored"))
        );
        assert!(
            !result
                .entries
                .iter()
                .any(|e| e.path == path && e.symbol.as_deref() == Some("ignored"))
        );
    }
    for path in ["app.js", "App.java", "app.kt"] {
        assert!(
            sinks(&result.scan, path, "CWE-89")
                .iter()
                .any(|e| e.captures.contains_key("query_execution")),
            "missing terminal {path}"
        );
    }
}

#[test]
fn sql_construction_is_consumer_context_without_transferring_unknown_sdk_contracts() {
    let result = inventory(
        "consumer",
        &[(
            "app.php",
            r#"<?php
use Illuminate\Support\Facades\DB;
function consumed($sql) { return DB::select(DB::raw($sql)); }
"#,
        )],
    );
    let hits = sinks(&result.scan, "app.php", "CWE-89");
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].captures["query"].text, "DB::raw($sql)");
    assert_eq!(hits[0].related_evidence.len(), 1);
    let construction = result
        .scan
        .evidence
        .iter()
        .find(|e| hits[0].related_evidence.contains(&e.id))
        .unwrap();
    assert_eq!(construction.kind, EvidenceKind::Resource);
    assert_eq!(construction.captures["query"].text, "$sql");
    assert_eq!(
        result
            .entries
            .iter()
            .filter(|e| e.cwe_candidates == ["CWE-89"])
            .count(),
        1
    );
}

#[test]
fn mongo_equality_closes_scalar_data_but_not_object_operators_or_shadowed_casts() {
    let result = inventory(
        "scalar",
        &[
            (
                "app.js",
                r#"
const {MongoClient}=require('mongodb'); const mongo=new MongoClient('uri'); const store=mongo.db('app').collection('users');
function fixed(req) { store.findOne({id: String(req.body.id)}); store.findOne({id: {$eq: Number(req.body.id)}}); }
function aliases(req) { const id=String(req.body.id); store.findOne({id: id}); store.findOne({id: id}); }
function unknown(req) { store.findOne({id: req.body.id}); store.findOne(req.body); store.findOne({[req.body.field]: 'x'}); store.findOne({$where: req.body.code}); }
function shadow(req,String) { store.findOne({id:String(req.body.id)}); }
function mutated(req) { let id=String(req.body.id); id=req.body.id; store.findOne({id:id}); }
"#,
            ),
            (
                "app.ts",
                "import {MongoClient} from 'mongodb'; const mongo=new MongoClient('uri'); const store=mongo.db('app').collection('users'); function fixed(id:string) { store.findOne({id:String(id)}); } function unknown(id:string) { store.findOne({id:id}); }",
            ),
            (
                "app.tsx",
                "import {MongoClient} from 'mongodb'; const mongo=new MongoClient('uri'); const store=mongo.db('app').collection('users'); function fixed(id:string) { store.findOne({id:String(id)}); } function unknown(id:string) { store.findOne({id:id}); }",
            ),
            (
                "app.py",
                "from pymongo import MongoClient\nstore=MongoClient('uri')['app']['users']\ndef fixed(req):\n    store.find_one({'id':str(req['id'])})\ndef unknown(req):\n    store.find_one({'id':req['id']})\ndef shadow(req,str):\n    store.find_one({'id':str(req['id'])})\n",
            ),
            (
                "App.java",
                "import com.mongodb.client.MongoCollection; import com.mongodb.client.model.Filters; import org.bson.Document; class App { void fixed(MongoCollection<Document> store,String id) { store.find(Filters.eq(\"id\",id)); store.find(new Document(\"id\",id)); } void unknown(MongoCollection<Document> store,Object id,String field) { store.find(Filters.eq(\"id\",id)); store.find(Filters.eq(field,\"fixed\")); } }",
            ),
            (
                "App.cs",
                "using MongoDB.Driver; using MongoDB.Bson; class App { void Fixed(IMongoCollection<BsonDocument> store,string id) { store.Find(Builders<BsonDocument>.Filter.Eq(\"id\",id)); store.Find(new BsonDocument(\"id\",id)); } void Unknown(IMongoCollection<BsonDocument> store,object id) { store.Find(Builders<BsonDocument>.Filter.Eq(\"id\",id)); } }",
            ),
            (
                "app.php",
                "<?php use MongoDB\\Driver\\Manager; use MongoDB\\Driver\\Query; function fixed(Manager $store,$id) { $store->executeQuery('a.b',new Query(['id'=>(string)$id])); } function unknown(Manager $store,$id) { $store->executeQuery('a.b',new Query(['id'=>$id])); }",
            ),
        ],
    );
    for (path, expected) in [
        ("app.js", 6),
        ("app.ts", 1),
        ("app.tsx", 1),
        ("app.py", 2),
        ("App.java", 2),
        ("App.cs", 1),
        ("app.php", 1),
    ] {
        let hits = sinks(&result.scan, path, "CWE-943");
        assert_eq!(hits.len(), expected, "{path}: {hits:#?}");
        assert!(hits.iter().all(|e| !matches!(
            e.enclosing_symbol.as_deref(),
            Some("fixed" | "Fixed" | "aliases")
        )));
        assert!(!result.entries.iter().any(|e| e.path == path
            && matches!(e.symbol.as_deref(), Some("fixed" | "Fixed" | "aliases"))));
    }
    assert!(result.scan.security_paths.iter().all(|p| {
        result
            .scan
            .evidence
            .iter()
            .any(|e| e.id == p.sink_evidence_id)
    }));
}

#[test]
fn string_expression_text_and_executable_predicates_are_not_equality_data() {
    let result = inventory(
        "expressions",
        &[(
            "app.ts",
            r#"
import {DynamoDBClient} from '@aws-sdk/client-dynamodb'; import {QueryCommand} from '@aws-sdk/lib-dynamodb';
import {MongoClient} from 'mongodb';
const client=new DynamoDBClient({}); const mongo=new MongoClient('uri'); const store=mongo.db('app').collection('users');
function run(req:any) { client.send(new QueryCommand({TableName:'users',KeyConditionExpression:String(req.body.expression)})); store.findOne({$where:String(req.body.code)}); }
"#,
        )],
    );
    assert_eq!(sinks(&result.scan, "app.ts", "CWE-943").len(), 2);
}

#[test]
fn equality_supports_kotlin_and_practical_dotnet_scalar_types() {
    let result = inventory(
        "typed-equality",
        &[
            (
                "app.kt",
                "import com.mongodb.client.MongoCollection\nimport com.mongodb.client.model.Filters\nimport org.bson.Document\nfun fixed(store: MongoCollection<Document>, id: String) { store.find(Filters.eq(\"id\",id)) }\nfun unknown(store: MongoCollection<Document>, id: Any) { store.find(Filters.eq(\"id\",id)) }\n",
            ),
            (
                "App.cs",
                r#"
using System; using MongoDB.Driver; using MongoDB.Bson;
class Row { public string Name {get;set;} }
class App {
void Fixed(IMongoCollection<Row> store,Guid id,DateTime date,char letter) {
store.Find(Builders<Row>.Filter.Eq("id",id));
store.Find(Builders<Row>.Filter.Eq("date",date));
store.Find(Builders<Row>.Filter.Eq("letter",letter));
store.Find(Builders<Row>.Filter.Eq("idText",id.ToString()));
store.Find(Builders<Row>.Filter.Eq("dateText",date.ToString("yyyy-MM-dd")));
store.Find(Builders<Row>.Filter.Eq(x=>x.Name,"name"));
}
void Unknown(IMongoCollection<Row> store,object value) {store.Find(Builders<Row>.Filter.Eq("id",value));}
}
"#,
            ),
        ],
    );
    for path in ["app.kt", "App.cs"] {
        let hits = sinks(&result.scan, path, "CWE-943");
        assert_eq!(hits.len(), 1, "{path}: {hits:#?}");
    }
}

#[test]
fn mutated_escaped_and_ambiguous_document_origins_still_require_research() {
    let result = inventory(
        "map-controls",
        &[(
            "app.js",
            r#"
const {MongoClient}=require('mongodb'); const mongo=new MongoClient('uri'); const store=mongo.db('app').collection('users');
function local(req) {const filter={id:String(req.body.id)}; store.findOne(filter);}
function mutated(req) {const filter={id:'fixed'}; filter.id=req.body.id; store.findOne(filter);}
function escaped(req) {const filter={id:'fixed'}; replace(filter,req.body); store.findOne(filter);}
function duplicate(req) {store.findOne({id:'fixed',id:req.body.id});}
function spread(req) {store.findOne({id:'fixed',...req.body});}
function helper(req) {store.findOne(makeFilter(req.body));}
function shadow(req) {function String(v) {return v;} store.findOne({id:String(req.body.id)});}
"#,
        )],
    );
    let hits = sinks(&result.scan, "app.js", "CWE-943");
    assert_eq!(hits.len(), 6, "{hits:#?}");
    assert!(
        !hits
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("local"))
    );
}

#[test]
fn ref_replacement_and_shadowed_scalar_types_do_not_inherit_data_proof() {
    let result = inventory(
        "type-controls",
        &[
            (
                "App.cs",
                "using MongoDB.Driver; using MongoDB.Bson; class App { void Run(IMongoCollection<BsonDocument> store) { object value=5; Replace(out value); store.Find(Builders<BsonDocument>.Filter.Eq(\"id\",value)); } }",
            ),
            (
                "App.java",
                "import com.mongodb.client.MongoCollection; import com.mongodb.client.model.Filters; import org.bson.Document; import custom.String; class App { void run(MongoCollection<Document> store,String id) {store.find(Filters.eq(\"id\",id));} }",
            ),
            (
                "app.kt",
                "import com.mongodb.client.MongoCollection\nimport com.mongodb.client.model.Filters\nimport org.bson.Document\nclass String\nfun run(store:MongoCollection<Document>,id:String) {store.find(Filters.eq(\"id\",id))}\n",
            ),
        ],
    );
    for path in ["App.cs", "App.java", "app.kt"] {
        assert_eq!(sinks(&result.scan, path, "CWE-943").len(), 1, "{path}");
    }
}

#[test]
fn node_reload_groups_only_the_same_adjacent_stable_selector() {
    let result = inventory(
        "node-reload",
        &[(
            "app.ts",
            r#"
function reload(value:any) {const id=String(value); const selected=Rows.findOne({where:{id:id}}); return Rows.findOne({where:{id:id}});}
function changed(value:any) {const id=String(value); const selected=Rows.findOne({where:{id:id}}); return Rows.findOne({where:{id:'other'}});}
function options(value:any) {const id=String(value); const selected=Rows.findOne({where:{id:id}}); return Rows.findOne({where:{id:id},paranoid:false});}
function mutated(value:any) {let id=String(value); const selected=Rows.findOne({where:{id:id}}); id='other'; return Rows.findOne({where:{id:id}});}
function deleted(value:any) {const id=String(value); const selected=Rows.findOne({where:{id:id}}); return Rows.destroy({where:{id:id}});}
"#,
        )],
    );
    let hits = sinks(&result.scan, "app.ts", "CWE-639");
    assert_eq!(hits.len(), 9, "{hits:#?}");
    assert_eq!(
        hits.iter()
            .filter(|e| e.captures.contains_key("resource_reload"))
            .count(),
        1
    );
}

#[test]
fn adjacent_same_key_reload_retains_one_unknown_authority_question() {
    let result = inventory(
        "reload",
        &[
            (
                "App.cs",
                r#"
using Microsoft.EntityFrameworkCore;
class Row {public int Id {get;set;}}
class AppDb:DbContext {public DbSet<Row> Rows {get;set;}}
class App {
object Reload(AppDb db,int id) { var selected=db.Rows.Find(id); return db.Rows.Find(id); }
object Changed(AppDb db,int id,int next) { var selected=db.Rows.Find(id); return db.Rows.Find(next); }
object Separated(AppDb db,int id) { var selected=db.Rows.Find(id); Check(selected); return db.Rows.Find(id); }
object Context(AppDb db,AppDb other,int id) { var selected=db.Rows.Find(id); return other.Rows.Find(id); }
}
"#,
            ),
            (
                "app.py",
                "from django.db import models\nclass Row(models.Model):\n    pass\ndef reload(value):\n    key=int(value)\n    selected=Row.objects.get(pk=key)\n    return Row.objects.get(pk=key)\ndef changed(value):\n    selected=Row.objects.get(pk=int(value))\n    return Row.objects.get(pk=2)\n",
            ),
        ],
    );
    let csharp = sinks(&result.scan, "App.cs", "CWE-639");
    assert_eq!(csharp.len(), 7, "{csharp:#?}");
    let python = sinks(&result.scan, "app.py", "CWE-639");
    assert_eq!(python.len(), 3, "{python:#?}");
    for path in ["App.cs", "app.py"] {
        let hits = sinks(&result.scan, path, "CWE-639");
        let original = hits
            .iter()
            .find(|e| e.captures.contains_key("resource_reload"))
            .expect("original authority retained");
        assert!(original.context.operand_facts.iter().any(|f| {
            f.value == "identity_preserving_adjacent_reload"
                && f.remaining_checks
                    .contains(&"original_resource_authority".into())
        }));
        assert!(
            result
                .scan
                .evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::Resource
                    && original.related_evidence.contains(&e.id))
        );
    }
}
