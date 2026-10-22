"""#852: the InvokeModel body's ``anthropic_version`` stays pinned to
``bedrock-2023-05-31`` across the anthropic 2.x bump.

WHY THIS TEST IS AT THE WIRE AND NOT AT THE MOCK. The SDK injects the field
itself, in ``anthropic/lib/bedrock/_client.py::_prepare_options``:

    options.json_data.setdefault("anthropic_version", ANTHROPIC_API_VERSION)

``ANTHROPIC_API_VERSION`` moved ``2023-06-01`` -> ``2026-10-21`` in anthropic
2.0.0 and ``DEFAULT_VERSION = "bedrock-2023-05-31"`` was deleted outright (both
files are byte-identical in 2.1.0). Because the injection is the SDK's and the
key is a ``setdefault``, a test that asserted the adapter's ``create(**kwargs)`` would
pass even if the SDK ignored the override entirely -- it would be checking our
intent, not the outcome. So this drives a REAL ``AnthropicBedrock`` over an
``httpx2.MockTransport`` and reads the bytes that would leave the process.

THE VENDOR DOCUMENTS THE BREAK AND BLESSES THIS EXACT MITIGATION. The Bedrock
(Opus 4.6 and earlier) page warns that the ARN-versioned models in its table
"don't support 2026-10-21 on Bedrock, and requests to them that send it can
return a 400 error", and closes: "The Boto3 example sets anthropic_version in
its request body and isn't affected." This repo ships FOUR such models as
``status: current`` in config/models.json -- {global,us}.anthropic.claude-haiku-4-5-20251001-v1:0
and {global,us}.anthropic.claude-sonnet-4-6 -- and names ``anthropic_version``
nowhere, so nothing in CI could observe the flip. This test is that observer.

BOTH CALL SITES ARE COVERED DELIBERATELY: ``complete()`` and ``validate()`` each
issue their own ``messages.create``, and ``validate()`` is the FIRST call a scan
makes (registry.validate at startup). A pin applied only in ``complete()`` would
leave every scan's preflight 400-ing on those four records while the scan body
worked -- the worst available failure shape.
"""
from __future__ import annotations

import json

import httpx2
import pytest

import anthropic

from utilities.llm.adapter import Message, TextBlock
from utilities.llm.providers.bedrock import BedrockAdapter

BEDROCK_BODY_API_VERSION = "bedrock-2023-05-31"

# the two ARN-versioned families this repo ships as status: current
ARN_VERSIONED_CURRENT = [
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "global.anthropic.claude-haiku-4-5-20251001-v1:0",
    "us.anthropic.claude-sonnet-4-6",
    "global.anthropic.claude-sonnet-4-6",
]


def _user(text: str) -> Message:
    """The adapter takes TYPED Message/ContentBlock objects, not raw dicts — the
    first cut of this test passed dicts and every case died with AttributeError at
    providers/anthropic.py:334 (`message.role`), i.e. RED FOR THE WRONG REASON. A
    test that fails before reaching its assertion proves nothing, so it is fixed
    here rather than read as a pass-by-failure."""
    return Message(role="user", content=[TextBlock(text=text)])


def _client_capturing(seen):
    def handler(request: httpx2.Request) -> httpx2.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content.decode())
        return httpx2.Response(
            200,
            json={
                "id": "msg_1", "type": "message", "role": "assistant",
                "model": "m", "content": [{"type": "text", "text": "hi"}],
                "stop_reason": "end_turn", "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )

    return anthropic.AnthropicBedrock(
        aws_access_key="AKIAIOSFODNN7EXAMPLE",
        aws_secret_key="x" * 40,
        aws_region="us-east-1",
        http_client=httpx2.Client(transport=httpx2.MockTransport(handler)),
    )


@pytest.mark.parametrize("model", ARN_VERSIONED_CURRENT)
def test_complete_pins_the_body_api_version(model):
    seen: dict = {}
    adapter = BedrockAdapter(_client=_client_capturing(seen))
    adapter.complete(model=model, system=None,
                     messages=[_user("hi")], max_tokens=16)
    assert seen["body"]["anthropic_version"] == BEDROCK_BODY_API_VERSION, (
        f"complete() sent anthropic_version={seen['body'].get('anthropic_version')!r} "
        f"for the ARN-versioned model {model}; the vendor documents 2026-10-21 as "
        f"unsupported for it on Bedrock (400)"
    )


@pytest.mark.parametrize("model", ARN_VERSIONED_CURRENT)
def test_validate_pins_the_body_api_version(model):
    """validate() is the FIRST call a scan makes — it needs the pin too."""
    seen: dict = {}
    adapter = BedrockAdapter(_client=_client_capturing(seen))
    adapter.validate(model)
    assert seen["body"]["anthropic_version"] == BEDROCK_BODY_API_VERSION, (
        f"validate() sent anthropic_version={seen['body'].get('anthropic_version')!r} "
        f"for {model} — a scan's preflight would 400 while complete() succeeded"
    )


def test_the_pin_does_not_disturb_the_rest_of_the_body():
    """The pin adds exactly one key and changes nothing else on the wire."""
    seen: dict = {}
    adapter = BedrockAdapter(_client=_client_capturing(seen))
    adapter.complete(model="anthropic.claude-opus-4-8", system="sys",
                     messages=[_user("hi")], max_tokens=16)
    assert set(seen["body"]) == {"anthropic_version", "max_tokens", "messages", "system"}
    assert seen["body"]["max_tokens"] == 16
    assert seen["body"]["system"] == "sys"
    assert seen["body"]["messages"] == [
        {"role": "user", "content": [{"type": "text", "text": "hi"}]}]
    # the model goes in the URL, never the body (the SDK pops it)
    assert "model" not in seen["body"]
    assert seen["url"].endswith("/model/anthropic.claude-opus-4-8/invoke")
