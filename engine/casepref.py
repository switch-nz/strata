"""Preferences that belong to a case rather than to an examiner's machine.

They are stored in the case's own metadata, so whoever opens the case sees the
same folder columns; anything an examiner sets for themselves alone lives in
engine.prefs. Each value is checked here before it is stored, and what is read
back is checked again, so a damaged or hand-edited case cannot hand the
interface something it does not understand."""

import json

from .text import t as _t

# The columns the folder listing can show, besides the name, which is always
# first. "path" is only drawn in a listing of everything below a folder.
FOLDER_COLUMNS = ("size", "extension", "signature", "created", "modified",
                  "accessed", "md5", "sha", "path")

DEFAULT_FOLDER_COLUMNS = ("path", "size", "extension", "signature", "created",
                          "modified", "accessed", "md5", "sha")

_KEY = "pref."


def clean_folder_columns(value):
    """The columns to show, in order, or None to go back to the default."""
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError(_t("casepref.columns_not_list"))
    out = []
    for c in value:
        if c not in FOLDER_COLUMNS:
            raise ValueError(_t("casepref.column_unknown") % (c,))
        if c not in out:
            out.append(c)
    return out


def load_folder_columns(raw):
    """What a case has stored, or None if it holds nothing usable."""
    if not raw:
        return None
    try:
        return clean_folder_columns(json.loads(raw))
    except (ValueError, TypeError):
        return None


def meta_key(name):
    return _KEY + name
