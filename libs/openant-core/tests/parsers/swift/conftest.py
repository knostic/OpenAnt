"""Skip the Swift parser tests (don't ERROR) on a runner without tree-sitter-swift.

Every test here loads the Swift parser stages, which `import tree_sitter` /
`tree_sitter_swift`. Without the wheel the module import raises at COLLECTION time,
which pytest reports as an error that fails the whole job — on the CI matrix
(macos/windows) that would take down the Python suite. Guard it the same way the
zig/javascript parser tests guard their native grammars (importorskip precedent),
but once for the whole directory via collect_ignore_glob.
"""
import importlib.util

if importlib.util.find_spec("tree_sitter_swift") is None:
    collect_ignore_glob = ["test_*.py"]
