use std::fs;
use std::path::Path;

#[test]
fn manifest_depends_on_the_public_tag_without_magnetar_or_paths() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest_text = fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
    let manifest: toml::Value = toml::from_str(&manifest_text).expect("parse Cargo.toml");
    let dependencies = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .expect("dependencies table");

    assert!(!dependencies.contains_key("suprnova-magnetar"));
    assert!(!dependencies.contains_key("magnetar"));
    let suprnova = dependencies
        .get("suprnova")
        .and_then(toml::Value::as_table)
        .expect("public Suprnova dependency");
    assert_eq!(
        suprnova.get("git").and_then(toml::Value::as_str),
        Some("https://github.com/eas4ai/suprnova.git")
    );
    assert_eq!(
        suprnova.get("tag").and_then(toml::Value::as_str),
        Some("v2.0.2")
    );
    assert!(!suprnova.contains_key("path"));
}

#[test]
fn library_source_uses_only_the_suprnova_sdk_surface() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for name in ["lib.rs", "provider.rs", "transport.rs"] {
        let source = fs::read_to_string(root.join(name)).expect("read library source");
        assert!(
            !source.contains("magnetar::") && !source.contains("suprnova_magnetar"),
            "{name} bypasses the public Suprnova SDK"
        );
    }
}
