from .nodes import node_of as _node_of

def _safe_listdir(fs, node, path):
    try:
        return fs.listdir(node, path)
    except Exception:
        return []

def _find_dir(fs, root, *names):
    """Walks a fixed chain of case-insensitive directory names from root,
    one listdir() per level -- the "one directory read" an instant
    presence check is allowed, not a walk of the tree. Returns
    (node, path) for the last name found, or (None, None) as soon as one
    is missing."""
    node, path = root, "/"
    for name in names:
        low = name.lower()
        found = next((e for e in _safe_listdir(fs, node, path)
                     if e.get("is_dir") and (e.get("name") or "").lower() == low),
                    None)
        if found is None:
            return None, None
        node = _node_of(found)
        path = path.rstrip("/") + "/" + found["name"]
    return node, path

def presence_recyclebin(fs, root):
    """A count of distinct deleted items under $Recycle.Bin (or its
    legacy names), without reading a single $I/$R file's content."""
    node = path = None
    for name in ("$Recycle.Bin", "RECYCLER", "RECYCLED"):
        node, path = _find_dir(fs, root, name)
        if node is not None:
            break
    if node is None:
        return {"found": False, "count": 0}
    keys = set()
    for sid in _safe_listdir(fs, node, path):
        if not sid.get("is_dir"):
            continue
        sid_path = path.rstrip("/") + "/" + sid["name"]
        for e in _safe_listdir(fs, _node_of(sid), sid_path):
            nm = e.get("name") or ""
            if len(nm) > 2 and nm[0] == "$" and nm[1] in "IiRr":
                keys.add((sid["name"], nm[2:]))
    return {"found": bool(keys), "count": len(keys)}

def presence_prefetch(fs, root):
    """A count of .pf files in the default Windows\\Prefetch location --
    not the recursive whole-volume search the real prefetch artefact
    does, so a relocated prefetch folder will not be counted here."""
    node, path = _find_dir(fs, root, "Windows", "Prefetch")
    if node is None:
        return {"found": False, "count": 0}
    count = sum(1 for e in _safe_listdir(fs, node, path)
               if not e.get("is_dir") and (e.get("name") or "").lower()
               .endswith(".pf"))
    return {"found": count > 0, "count": count}

BROWSER_PROFILE_PATHS = (
    ("AppData", "Local", "Google", "Chrome", "User Data"),
    ("AppData", "Local", "Microsoft", "Edge", "User Data"),
    ("AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
    ("AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
)

_NON_USER_DIRS = ("public", "default", "default user", "all users")

def presence_browser(fs, root):
    """Which local user profiles have a known browser's data folder --
    existence only, not the schema-matching walk the real browser
    artefact does to find every history database."""
    users_node, users_path = _find_dir(fs, root, "Users")
    if users_node is None:
        return {"found": False, "profiles": []}
    profiles = []
    for u in _safe_listdir(fs, users_node, users_path):
        if not u.get("is_dir") or (u.get("name") or "").lower() in _NON_USER_DIRS:
            continue
        for segs in BROWSER_PROFILE_PATHS:
            node, path = _find_dir(fs, _node_of(u), *segs)
            if node is not None:
                profiles.append({"user": u["name"], "browser": segs[-2],
                                 "path": path})
    return {"found": bool(profiles), "profiles": profiles}

def presence(fs, root):
    """Instant, non-recursive presence checks -- one or two directory
    reads each -- for artefacts an examiner would otherwise only find out
    about by running the real (recursive or parsing) thing. A count or
    "found" here is a reason to run the real artefact, not a substitute
    for it: a relocated prefetch folder or an unrecognised browser still
    needs the real scan to be found."""
    return {
        "recyclebin": presence_recyclebin(fs, root),
        "prefetch": presence_prefetch(fs, root),
        "browser": presence_browser(fs, root),
    }

INSTANT, QUICK, MINUTES, LONG = "instant", "quick", "minutes", "long"

COST_ORDER = {INSTANT: 0, QUICK: 1, MINUTES: 2, LONG: 3}

COST_NOTE = {
    INSTANT: "Already known, or one directory read.",
    QUICK: "Seconds. Reads a handful of files.",
    MINUTES: "A minute or two. Walks the filesystem.",
    LONG: "A full pass over the media. Start it and work elsewhere.",
}

CATALOGUE = [
    {
        "id": "volumes", "label": "Volume layout", "cost": INSTANT,
        "scope": "image", "method": None, "route": None, "per_volume": False,
        "answers": "What partitions exist, what filesystem each really holds, "
                   "and what space no partition claims.",
        "needs": [],
    },
    {
        "id": "encryption", "label": "Encrypted volumes", "cost": INSTANT,
        "scope": "image", "method": "GET", "route": "encryption", "per_volume": True,
        "answers": "Which volumes are locked, and which key protectors could "
                   "be attempted at all.",
        "needs": [],
    },
    {
        "id": "usn", "label": "Change journal", "cost": QUICK,
        "scope": "volume", "method": "POST", "route": "usn", "per_volume": True,
        "answers": "What happened to files — creations, renames, moves and "
                   "deletions — including for files whose MFT records have "
                   "since been reused. Often the only surviving record of a "
                   "deleted file's name.",
        "needs": ["NTFS"],
    },
    {
        "id": "logfile", "label": "NTFS log ($LogFile)", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "logfile",
        "per_volume": True,
        "answers": "What NTFS's crash-recovery log still holds: recent "
                   "transactions, the operations they performed and, where "
                   "an entry carries one, a file name and its timestamps. "
                   "Read as recorded; it is a ring, not a full history.",
        "needs": ["NTFS"],
    },
    {
        "id": "registry", "label": "Well-known registry keys", "cost": MINUTES,
        "scope": "image", "method": "POST", "route": "registry/report", "per_volume": False,
        "answers": "Machine identity, USB devices attached, networks joined, "
                   "auto-start programs, installed software, local accounts "
                   "and user activity.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "prefetch", "label": "Prefetch", "cost": QUICK,
        "scope": "volume", "method": "POST", "route": "prefetch", "per_volume": True,
        "answers": "What was executed, when, how often, and which files each "
                   "program opened at startup.",
        "needs": ["Windows volume"],
    },
    {
        "id": "lnk", "label": "Shortcuts and Jump Lists", "cost": QUICK,
        "scope": "volume", "method": "GET", "route": "lnk", "per_volume": True,
        "answers": "What was opened and from where, including from removable "
                   "media that is no longer present.",
        "needs": ["Windows volume"],
    },
    {
        "id": "recyclebin", "label": "Recycle Bin", "cost": QUICK,
        "scope": "volume", "method": "GET", "route": "recyclebin", "per_volume": True,
        "answers": "What was deleted through the shell, by whom, when, and "
                   "from what original path.",
        "needs": ["Windows volume"],
    },
    {
        "id": "shellbags", "label": "Shellbags", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "shellbags", "per_volume": True,
        "answers": "Folders opened in Explorer — including folders that no "
                   "longer exist and drives no longer attached.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "appcompat", "label": "Amcache and ShimCache", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "appcompat", "per_volume": True,
        "answers": "Executables the system recorded, with SHA-1 hashes that "
                   "survive the binary being deleted.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "browser", "label": "Browser history", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "browser", "per_volume": True,
        "answers": "Sites visited, downloads, searches and form entries, "
                   "including rows deleted from the databases.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "evtx", "label": "Windows event logs", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "evtx", "per_volume": True,
        "answers": "Logons, process creation, service installation and system "
                   "state changes.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "filetypes", "label": "File-type verification", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "filetypes/scan", "per_volume": False,
        "answers": "Files whose extension disagrees with their content — the "
                   "cheap way to find something deliberately misnamed.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "timeline", "label": "Timeline", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "timeline", "per_volume": True,
        "answers": "Every parser's timestamps in one ordered sequence, with "
                   "timestomping checks against the $FILE_NAME set.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "hash", "label": "Hash every file", "cost": LONG,
        "scope": "volume", "method": "POST", "route": "hash", "per_volume": True,
        "answers": "MD5, SHA-1 and SHA-256 for matching against known-good "
                   "and known-bad sets. Bounded by read speed.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "carve", "label": "Signature carving", "cost": LONG,
        "scope": "image", "method": "POST", "route": "carve", "per_volume": True,
        "answers": "Files recoverable from unallocated space by signature, "
                   "with no filesystem involvement.",
        "needs": [],
    },
    {
        "id": "index", "label": "Content index", "cost": LONG,
        "scope": "image", "method": "POST", "route": "search/index", "per_volume": False,
        "answers": "Full-text search across files and, optionally, the whole "
                   "medium including unpartitioned space. The most expensive "
                   "thing here and rarely the first thing needed.",
        "needs": [],
    },
]

TRIAGE = [a["id"] for a in CATALOGUE if a["cost"] in (INSTANT, QUICK)]

def catalogue(available=None):
    out = []
    for a in sorted(CATALOGUE, key=lambda x: (COST_ORDER[x["cost"]],
                                              x["label"])):
        row = dict(a)
        row["cost_note"] = COST_NOTE[a["cost"]]
        row["in_triage"] = a["id"] in TRIAGE
        if available is not None:
            row["available"] = a["id"] in available
        out.append(row)
    return out
