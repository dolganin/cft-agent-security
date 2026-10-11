"""Minimal text, archive-name, XML and profile formatting functions."""
import html
import posixpath
import xml.etree.ElementTree as ET


def render_text(value):
    return "<p>" + html.escape(value, quote=True) + "</p>"


def archive_destination(name):
    if not isinstance(name, str) or "\\" in name or "\0" in name or name.startswith("/"):
        raise ValueError("Invalid archive name")
    root = "/approved/uploads"
    path = posixpath.normpath(posixpath.join(root, name))
    if not path.startswith(root + "/"):
        raise ValueError("Archive traversal denied")
    return path


def parse_document(value):
    # This intentionally accepts a small DTD-free XML subset, not arbitrary XML.
    if "<!DOCTYPE" in value.upper() or "<!ENTITY" in value.upper():
        raise ValueError("DTD/entities denied")
    return ET.fromstring(value).text


def profile_label(value):
    if not isinstance(value, str):
        raise TypeError("Profile name must be text")
    return "Hello " + value
