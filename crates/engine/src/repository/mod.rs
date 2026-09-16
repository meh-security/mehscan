mod build_profile;
mod classify;
mod discover;

pub(crate) use classify::{FileClass, is_generated_javascript_source, is_sast_excluded_source};
pub(crate) use discover::{DiscoveredFile, discover, discover_with_options};
