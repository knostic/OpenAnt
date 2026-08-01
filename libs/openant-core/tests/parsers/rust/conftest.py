"""Skip the Rust parser tests (don't ERROR) on a runner without tree-sitter-rust.

Every test here loads the Rust parser stages, which `import tree_sitter` /
`tree_sitter_rust`. Without the wheel the module import raises at COLLECTION time,
which pytest reports as an error that fails the whole job. Guard it the same way
the swift/zig/javascript parser tests guard their native grammars (importorskip
precedent), once for the whole directory via collect_ignore_glob.
"""
import importlib.util

if importlib.util.find_spec("tree_sitter_rust") is None:
    collect_ignore_glob = ["test_*.py"]
