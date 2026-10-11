import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fixtures import (
    archive_destination,
    parse_document,
    profile_label,
    render_text,
)


def run_assertions():
    assert render_text("hello") == "<p>hello</p>"
    assert render_text('<script>alert("x")</script>') == "<p>&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;</p>"
    assert archive_destination("a/b.txt") == "/approved/uploads/a/b.txt"
    for name in ["../../outside", "/outside", "..\\outside", "a\0b"]:
        try:
            archive_destination(name)
        except ValueError:
            pass
        else:
            raise AssertionError("Traversal not denied")
    assert parse_document("<root>hello</root>") == "hello"
    try:
        parse_document('<!DOCTYPE root [<!ENTITY e SYSTEM "file:///nonexistent">]><root>&e;</root>')
    except ValueError:
        pass
    else:
        raise AssertionError("DTD not denied")
    assert render_text("still available") == "<p>still available</p>"
    assert archive_destination("after.txt").endswith("/after.txt")
    assert parse_document("<root>after</root>") == "after"
    assert profile_label("Alice") == "Hello Alice"
    expression = "__import__('os').system('untrusted')"
    assert profile_label(expression) == "Hello " + expression
    assert profile_label("Bob") == "Hello Bob"
    return dict.fromkeys(["html_text", "archive_path", "xml_no_dtd", "profile_literal"], True)


if __name__ == "__main__":
    print(json.dumps(run_assertions(), sort_keys=True))
