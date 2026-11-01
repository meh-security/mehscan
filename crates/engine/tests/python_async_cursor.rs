use mehscan_core::Capability;
use std::fs;

#[test]
fn typed_context_cursors_keep_query_and_parameter_identity_without_flask() {
    let root = std::env::temp_dir().join(format!("mehscan-async-cursor-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    for (name, code) in [
        (
            "aiopg",
            "from aiopg.connection import Connection as Conn\nasync def save(db: Conn, value):\n    async with db.cursor() as statement:\n        await statement.execute('SELECT ' + value)\n",
        ),
        (
            "psycopg",
            "from psycopg import AsyncConnection\nasync def save(db: AsyncConnection, value):\n    async with db.cursor() as statement:\n        await statement.execute('SELECT %s', (value,))\n",
        ),
        (
            "untyped",
            "async def save(db, value):\n    async with db.cursor() as statement:\n        await statement.execute('SELECT ' + value)\n",
        ),
        (
            "foreign",
            "from other_driver import Connection\nasync def save(db: Connection, value):\n    async with db.cursor() as statement:\n        await statement.execute('SELECT ' + value)\n",
        ),
        (
            "reassigned",
            "from aiopg import Connection\nasync def save(db: Connection, value):\n    db = other()\n    async with db.cursor() as statement:\n        await statement.execute('SELECT ' + value)\n",
        ),
        (
            "shadowed",
            "from aiopg import Connection\nclass Connection: pass\nasync def save(db: Connection, value):\n    async with db.cursor() as statement:\n        await statement.execute('SELECT ' + value)\n",
        ),
        (
            "rebound",
            "from aiopg import Connection\nasync def save(db: Connection, value):\n    async with db.cursor() as statement:\n        statement = other()\n        await statement.execute('SELECT ' + value)\n",
        ),
        (
            "outside",
            "from aiopg import Connection\nasync def save(db: Connection, value):\n    async with db.cursor() as statement:\n        pass\n    await statement.execute('SELECT ' + value)\n",
        ),
        (
            "reimport",
            "from aiopg import Connection\nfrom other_driver import Connection\nasync def save(db: Connection, value):\n    async with db.cursor() as statement:\n        await statement.execute('SELECT ' + value)\n",
        ),
        (
            "nested",
            "from aiopg import Connection\nasync def save(db: Connection, value):\n    async with db.cursor() as statement:\n        async with other.cursor() as statement:\n            await statement.execute('SELECT ' + value)\n",
        ),
        (
            "mutation",
            "from aiopg import Connection\nasync def save(db: Connection, value):\n    db.cursor = custom\n    async with db.cursor() as statement:\n        await statement.execute('SELECT ' + value)\n",
        ),
        (
            "wrong_method",
            "from aiopg import Connection\nasync def save(db: Connection, value):\n    async with db.cursor() as statement:\n        await statement.executescript('SELECT ' + value)\n",
        ),
    ] {
        fs::write(root.join(format!("{name}.py")), code).unwrap();
    }
    let result = mehscan_engine::scan_path(&root).unwrap();
    fs::remove_dir_all(&root).unwrap();
    let queries: Vec<_> = result
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::DatabaseQuery)
        .collect();
    assert!(queries.iter().any(|e| e.location.path == "aiopg.py"));
    assert!(queries.iter().any(|e| e.location.path == "psycopg.py"));
    assert!(
        queries
            .iter()
            .all(|e| matches!(e.location.path.as_str(), "aiopg.py" | "psycopg.py")),
        "{queries:#?}"
    );
    assert!(result.evidence.iter().any(
        |e| e.location.path == "psycopg.py" && e.capability == Capability::SqlParameterization
    ));
    assert!(
        !result
            .evidence
            .iter()
            .any(|e| e.location.path == "aiopg.py"
                && e.capability == Capability::SqlParameterization)
    );
}
