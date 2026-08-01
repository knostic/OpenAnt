"""a receiver bound from a free-function call
`let c = load()` where `load() -> Cfg` must type `c` as Cfg, so `c.validate()`
resolves PRECISELY to Cfg.validate -- recovering the unknown-receiver blackout the
unknown-receiver decline gate would otherwise cause, with NO phantom to a same-named method on an
unrelated type. This makes the receiver KNOWN rather than relaxing the gate."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import build, edges  # noqa: E402


def test_free_fn_return_type_types_the_binding(tmp_path):
    repo = {
        "a.rs": "pub struct Cfg; impl Cfg { fn validate(&self) {} }\n"
                "pub struct Form; impl Form { fn validate(&self) {} }\n"
                "pub fn load() -> Cfg { Cfg }\n",
        "b.rs": "use crate::a::{Cfg, Form, load};\npub fn run() { let c = load(); c.validate(); }\n",
    }
    e = edges(build(tmp_path, repo)[1])
    assert ("run", "Cfg.validate") in e, e        # recovered precisely via load() -> Cfg
    assert ("run", "Form.validate") not in e, e   # no phantom to the other same-named type
