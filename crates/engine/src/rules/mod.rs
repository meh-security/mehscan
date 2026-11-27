mod compiler;
mod loader;
mod relations;
mod validate;

pub(crate) use compiler::{CompiledRule, compile_for_language, parser_language};
pub use loader::load_builtin_rules;
pub use relations::load_builtin_relations;

/// Only embedded metadata is shared. Each scan still prepares its own source and scope.
pub(crate) struct BuiltinCatalog {
    pub rules: Vec<mehscan_core::Rule>,
    pub relations: Vec<mehscan_core::RelationContract>,
}

pub(crate) fn builtin_catalog() -> Result<&'static BuiltinCatalog, crate::EngineError> {
    static CATALOG: std::sync::OnceLock<Result<BuiltinCatalog, crate::EngineError>> =
        std::sync::OnceLock::new();
    CATALOG
        .get_or_init(|| {
            let rules = load_builtin_rules()?;
            let relations = load_builtin_relations(&rules)?;
            Ok(BuiltinCatalog { rules, relations })
        })
        .as_ref()
        .map_err(|error| crate::EngineError(error.0.clone()))
}
