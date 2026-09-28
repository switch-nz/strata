import datetime
import html
import os

from . import version as version_mod
from .text import t as _t

def _e(v):
    return html.escape("" if v is None else str(v), quote=True)

def _bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024 or unit == "PB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024
    return "—"

def _has_zone(iso):
    s = str(iso)
    return s.endswith("Z") or (len(s) > 6 and s[-6] in "+-" and s[-3] == ":")

def _when(iso, tz=None):
    if not iso:
        return "—"
    utc = str(iso).replace("T", " ").replace("Z", "")
    if not _has_zone(iso):
        return utc   # recorded with no zone: shown as-is, not converted
    if not tz or tz.get("offset_minutes") is None:
        return "%s UTC" % utc
    try:
        base = datetime.datetime.fromisoformat(str(iso).replace("Z", ""))
        local = base + datetime.timedelta(minutes=tz["offset_minutes"])
    except ValueError:
        return "%s UTC" % utc
    mins = tz["offset_minutes"]
    sign = "+" if mins >= 0 else "-"
    label = "%s%02d:%02d" % (sign, abs(mins) // 60, abs(mins) % 60)
    return "%s %s &middot; %s UTC" % (
        local.isoformat(" ", "seconds"), label, utc)

CSS = """
:root { --ink:#14181c; --dim:#5a6672; --line:#d7dde3; --accent:#8a5a12;
        --bad:#a23a28; --good:#2f6b5f; --panel:#f6f8fa; }
* { box-sizing: border-box; }
body { font: 13px/1.6 ui-monospace, "SF Mono", Consolas, monospace;
       color: var(--ink); margin: 0; padding: 32px; background: #fff;
       max-width: 60rem; }
h1 { font-size: 20px; font-weight: 600; margin: 0 0 4px; }
h2 { font-size: 14px; font-weight: 600; margin: 32px 0 8px;
     padding-bottom: 5px; border-bottom: 2px solid var(--ink); }
h3 { font-size: 12px; font-weight: 600; margin: 18px 0 6px; color: var(--dim);
     text-transform: uppercase; letter-spacing: .08em; }
.sub { color: var(--dim); margin: 0 0 20px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 4px;
        font-size: 12px; }
th { text-align: left; font-weight: 600; border-bottom: 1px solid var(--ink);
     padding: 5px 8px 5px 0; white-space: nowrap; }
td { border-bottom: 1px solid var(--line); padding: 5px 8px 5px 0;
     vertical-align: top; word-break: break-word; }
tr:last-child td { border-bottom: 0; }
.num { text-align: right; white-space: nowrap; }
.pre { white-space: pre-wrap; overflow-wrap: anywhere; }
.note { color: var(--dim); font-size: 11px; line-height: 1.5;
        margin: 4px 0 14px; }
.panel { background: var(--panel); border: 1px solid var(--line);
         padding: 12px 14px; margin: 10px 0 18px; }
.verdict { display: flex; gap: 10px; align-items: baseline;
           border-left: 4px solid var(--good); padding-left: 12px;
           margin: 14px 0; }
.verdict.is-bad { border-left-color: var(--bad); }
.verdict b { font-size: 14px; }
.is-bad b, .bad { color: var(--bad); }
.good { color: var(--good); }
.tag { display: inline-block; border: 1px solid var(--accent);
       color: var(--accent); padding: 0 6px; margin: 0 4px 3px 0;
       font-size: 11px; }
.del { color: var(--bad); }
.kv { display: grid; grid-template-columns: 12rem 1fr; gap: 2px 14px;
      font-size: 12px; margin: 6px 0 14px; }
.kv dt { color: var(--dim); }
.kv dd { margin: 0; word-break: break-all; }
footer { margin-top: 40px; padding-top: 12px; border-top: 1px solid var(--line);
         color: var(--dim); font-size: 11px; }
.empty { color: var(--dim); font-style: italic; }
@media print {
  body { padding: 0; max-width: none; font-size: 11px; }
  h2 { page-break-after: avoid; }
  table, .panel, .verdict { page-break-inside: avoid; }
  a[href]::after { content: ""; }
}
"""

def _table(headers, rows, empty):
    if not rows:
        return '<p class="empty">%s</p>' % _e(empty)
    head = "".join("<th%s>%s</th>" % (' class="num"' if h.startswith("#") else "",
                                      _e(h.lstrip("#"))) for h in headers)
    body = []
    for r in rows:
        cells = []
        for h, v in zip(headers, r):
            cls = ' class="num"' if h.startswith("#") else ""
            cells.append("<td%s>%s</td>" % (cls, v))
        body.append("<tr>%s</tr>" % "".join(cells))
    return "<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>" % (
        head, "".join(body))

def render(data, evidence_detail=None, tz=None, index_status=None):
    case = data or {}
    name = case.get("name") or _t("report.untitled_case")
    integ = case.get("audit_integrity") or {}
    intact = bool(integ.get("intact"))
    tagged = case.get("tagged") or []
    marks = case.get("bookmarks") or []
    audit = case.get("audit") or []
    items = case.get("evidence") or []

    out = ["<!doctype html><html lang=en><head><meta charset=utf-8>",
           "<title>%s</title>" % _t("report.doc_title", _e(name)),
           "<style>%s</style></head><body>" % CSS]

    out.append("<h1>%s</h1>" % _e(name))
    out.append('<p class="sub">%s</p>'
               % _t("report.subtitle", _when(case.get("generated_at"), tz)))

    out.append('<div class="verdict%s">' % ("" if intact else " is-bad"))
    if intact:
        out.append("<b class=good>%s</b><span>%s</span>"
                   % (_t("report.audit.intact"),
                      _t("report.audit.intact_detail", len(audit))))
    else:
        out.append("<b>%s</b><span>%s%s</span>"
                   % (_t("report.audit.broken"),
                      _t("report.audit.broken_detail",
                         _e(integ.get("broken_at"))),
                      (" " + _e(integ["detail"])) if integ.get("detail")
                      else ""))
    out.append("</div>")

    out.append("<dl class=kv>")
    for label, val in ((_t("report.kv.case"), _e(name)),
                       (_t("report.kv.case_file"), _e(case.get("path"))),
                       (_t("report.kv.examiner"), _e(case.get("examiner"))),
                       (_t("report.kv.created"),
                        _when(case.get("created_at"), tz)),
                       (_t("report.kv.created_by"),
                        _e(case.get("created_by"))),
                       (_t("report.kv.evidence_items"), str(len(items))),
                       (_t("report.kv.tagged_items"), str(len(tagged))),
                       (_t("report.kv.attack_attributions"),
                        str(len([a for a in (case.get("attack") or [])
                                 if a.get("asserted")]))),
                       (_t("report.kv.bookmarks"), str(len(marks)))):
        out.append("<dt>%s</dt><dd>%s</dd>" % (label, val))
    if tz and tz.get("offset_minutes") is not None:
        mins = tz["offset_minutes"]
        sign = "+" if mins >= 0 else "-"
        out.append("<dt>%s</dt><dd>%s</dd>"
                   % (_t("report.kv.local_time"),
                      _t("report.local_time_value",
                         _e(tz.get("name") or _t("report.an_offset")), sign,
                         abs(mins) // 60, abs(mins) % 60,
                         _e(tz.get("source") or _t("report.the_examiner")))))
    out.append("</dl>")

    out.append("<h2>%s</h2>" % _t("report.h.evidence"))
    rows = []
    for it in items:
        stored = it.get("stored_md5") or ""
        verified = it.get("verified_md5") or ""
        if stored and verified:
            mark = ('<span class=good>%s</span>' % _t(
                "report.ev.verified",
                _when(it.get("verified_at"), tz))) if stored == verified else \
                '<span class=bad>%s</span>' % _t("report.ev.mismatch")
        elif stored:
            mark = '<span class="empty">%s</span>' % _t(
                "report.ev.not_reverified")
        else:
            mark = '<span class="empty">%s</span>' % _t(
                "report.ev.no_stored_hash")
        rows.append([
            "<b>%s</b><br><span class=note>%s</span>"
            % (_e(it.get("label")), _e(it.get("path"))),
            _e(it.get("format")), _bytes(it.get("size")),
            "%s<br><span class=note>%s</span>"
            % (mark, _t("report.ev.md5", _e(stored or "—"))),
            _when(it.get("added_at"), tz),
        ])
    out.append(_table([_t("report.col.item"), _t("report.col.format"),
                       "#" + _t("report.col.size"),
                       _t("report.col.acquisition_hash"),
                       _t("report.col.added")],
                      rows, _t("report.empty.evidence")))
    out.append('<p class="note">%s</p>' % _t("report.note.hashes"))

    if evidence_detail:
        for ev in evidence_detail:
            out.append("<h3>%s</h3>"
                       % _t("report.h.volumes", _e(ev.get("label"))))
            vrows = []
            for p in ev.get("partitions") or []:
                note = p.get("note") or ""
                vrows.append([
                    _e(p.get("slot")), _e(p.get("detected") or p.get("type")),
                    "%d" % (p.get("offset") or 0), _bytes(p.get("size")),
                    ('<span class=note>%s</span>' % _e(note)) if note else "",
                ])
            out.append(_table(
                [_t("report.col.slot"), _t("report.col.filesystem"),
                 "#" + _t("report.col.offset"), "#" + _t("report.col.size"),
                 _t("report.col.notes")],
                vrows, _t("report.empty.volumes")))

    out.append("<h2>%s</h2>" % _t("report.h.coverage"))
    if index_status:
        out.append('<div class=panel>%s</div>' % index_status)
    else:
        out.append('<p class="note">%s</p>' % _t("report.note.no_index"))

    out.append("<h2>%s</h2>" % _t("report.h.tagged"))
    counts = case.get("tag_counts") or {}
    if counts:
        out.append("<p>" + "".join(
            '<span class=tag>%s &middot; %d</span>' % (_e(k), v)
            for k, v in sorted(counts.items())) + "</p>")
    rows = []
    for item in tagged:
        rows.append([
            "<span class=tag>%s</span>" % _e(item.get("tag")),
            "%s%s<br><span class=note>%s</span>" % (
                _e(item.get("name")),
                (' <span class=del>%s</span>' % _t("report.deleted"))
                if item.get("deleted") else "",
                _e(item.get("path"))),
            _bytes(item.get("size")),
            _when(item.get("modified"), tz),
            "%s<br><span class=note>%s</span>" % (
                _e(item.get("examiner")), _when(item.get("created_at"), tz)),
            _e(item.get("note") or ""),
        ])
    out.append(_table(
        [_t("report.col.tag"), _t("report.col.file"),
         "#" + _t("report.col.size"), _t("report.col.modified"),
         _t("report.col.tagged_by"), _t("report.col.note")],
        rows, _t("report.empty.tagged")))

    attack = case.get("attack") or []
    if attack:
        out.append("<h2>%s</h2>" % _t("report.h.attack"))
        cat = case.get("attack_catalogue") or {}
        out.append("<p>%s</p>" % _t(
            "report.attack.intro",
            _e(cat.get("source") or _t("report.attack.builtin")),
            _t("report.attack.version", _e(cat.get("version")))
            if cat.get("version") else ""))

        asserted = [a for a in attack if a.get("asserted")]
        proposed = [a for a in attack if not a.get("asserted")]

        rows = []
        for a in asserted:
            rows.append([
                _e(a.get("technique")), _e(a.get("technique_name") or ""),
                _e(a.get("tactic") or ""),
                "%s %s" % (_e(a.get("target_kind") or ""),
                           _e(a.get("target_ref") or "")),
                _e(a.get("examiner") or _t("report.unattributed")),
                _e(a.get("note") or ""),
            ])
        out.append(_table(
            [_t("report.col.technique"), _t("report.col.name"),
             _t("report.col.tactic"), _t("report.col.applies_to"),
             _t("report.col.attributed_by"), _t("report.col.note")],
            rows, _t("report.empty.attack")))

        if proposed:
            out.append("<h3>%s</h3>" % _t("report.h.proposed"))
            out.append("<p>%s</p>" % (
                _t("report.attack.proposed_one")
                if len(proposed) == 1 else
                _t("report.attack.proposed_many", len(proposed))))
            out.append(_table(
                [_t("report.col.technique"), _t("report.col.name"),
                 _t("report.col.applies_to")],
                [[_e(a.get("technique")), _e(a.get("technique_name") or ""),
                  "%s %s" % (_e(a.get("target_kind") or ""),
                             _e(a.get("target_ref") or ""))]
                 for a in proposed],
                _t("report.empty.proposed")))

    shown = [b for b in marks if b.get("in_report", True)]
    held = len(marks) - len(shown)
    out.append("<h2>%s</h2>" % _t("report.h.bookmarks"))
    rows = [[
        _e(b.get("label") or "—"),
        _e(b.get("category") or "—"),
        (_t("report.mark.in_file", b.get("offset") or 0,
            _e(b.get("mark_in") or _t("report.a_file")))
         if b.get("frame") == "file" else "0x%X" % (b.get("offset") or 0)),
        str(b.get("length") or 1),
        _e(b.get("source") or ""),
        "%s<br><span class=note>%s</span>" % (_e(b.get("examiner")),
                                              _when(b.get("created_at"), tz)),
        _e(b.get("note") or ""),
    ] for b in shown]
    out.append(_table([_t("report.col.label"), _t("report.col.category"),
                       "#" + _t("report.col.offset"),
                       "#" + _t("report.col.length"),
                       _t("report.col.origin"), _t("report.col.marked_by"),
                       _t("report.col.note")], rows,
                      _t("report.empty.bookmarks")))
    if held:
        out.append("<p class=note>%s</p>" % (
            _t("report.held.one") if held == 1
            else _t("report.held.many", held)))

    notes = case.get("notes") or []
    out.append("<h2>%s</h2>" % _t("report.h.notes"))
    out.append('<p class="note">%s</p>' % _t("report.note.notes"))
    rows = []
    for n in notes:
        text = '<div class="pre">%s</div>' % _e(n.get("body") or "")
        history = n.get("history") or []
        if history:
            text += '<p class=note>%s</p>' % _t("report.note.edited") + "".join(
                '<p class=note>%s, %s: %s</p>' % (
                    _e(h.get("examiner")), _when(h.get("at"), tz),
                    _e(h.get("body") or ""))
                for h in history)
        if n.get("retracted_at"):
            text = ('<p class=note><b>%s</b></p>' % _t(
                "report.note.retracted", _e(n.get("retracted_by")),
                _when(n.get("retracted_at"), tz))) + text
        who = _e(n.get("author"))
        if n.get("examiner") != n.get("author"):
            who += "<br><span class=note>%s %s</span>" % (
                "&rarr;", _e(n.get("examiner")))
        rows.append(["%s<br><span class=note>%s</span>" % (
                         who, _when(n.get("created_at"), tz)),
                     text])
    out.append(_table([_t("report.col.written_by"), _t("report.col.text")],
                      rows, _t("report.empty.notes")))

    out.append("<h2>%s</h2>" % _t("report.h.audit"))
    out.append('<p class="note">%s</p>' % _t("report.note.audit"))
    rows = [[
        str(a.get("seq")),
        _when(a.get("at"), tz),
        _e(a.get("examiner")),
        _e(a.get("action")),
        '<span class=note>%s</span>' % _e((a.get("detail") or "")[:400]),
    ] for a in audit]
    out.append(_table(["#" + _t("report.col.seq"), _t("report.col.when"),
                       _t("report.col.examiner"), _t("report.col.action"),
                       _t("report.col.detail")], rows,
                      _t("report.empty.audit")))

    out.append("<footer>%s</footer>" % _t(
        "report.footer",
        _e(version_mod.label()),
        _t("report.footer_local") if tz else "",
        _when(case.get("generated_at"), tz)))
    out.append("</body></html>")
    return "".join(out)

def write(path, html_text):
    path = os.path.abspath(path)
    if os.path.exists(path):
        with open(path, "rb") as f:
            head = f.read(200).lower()
        if b"<!doctype html" not in head:
            raise ValueError(_t("report.refuse_overwrite", path))
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_text)
    return {"path": path, "bytes": len(html_text.encode("utf-8"))}
