# belay-receipt.awk -- the one line a receipt is shown as (belay-hook).
#
#   awk -f belay-receipt.awk -v mode=call -v where=TEXT -v sens=FILE \
#       -v dont=FILE -v json=FILE -v text=FILE -v flagout=FILE
#
#       json: `belay diff --json` of one interval; text: the same interval's
#       `belay diff --all`. Prints the number of changed entries, then the
#       line: "belay: ", a red circle when anything is flagged, `where`
#       ("" or "outside tool calls: "), then what changed. Appends what it flagged to flagout, one a line:
#       what <TAB> label.
#
#   awk -f belay-receipt.awk -v mode=turn -v flagged=FILE -v calls=N \
#       -v incalls=N -v outside=N -v receipt=1
#
#       Prints the turn's lines: what was flagged, if anything, then the
#       totals, ending (with receipt set) in the command that opens the
#       long layer. Every line starts "belay: ", the red circle right
#       after it: always in the same place.
#
# Flagged, so leading the line: a path the built-in list (sens) or the
# project's .belay-donttouch (dont) matches, whatever happened to it; every
# line of the receipt's privilege section; a file replaced by a symlink; a
# symlink retargeted to an absolute path or through `..`; git history
# rewritten. Everything else is counted: nothing is left out of the count.
#
# A diff.v1 record is one line, and a quote inside a JSON string is always
# escaped, so `"outcome":"` and the other keys looked for here can only be
# keys: no string a tool wrote can pass for one.

function g2r(p,    anch, pre, out, i, c) {
    sub(/\/+$/, "", p)
    anch = (substr(p, 1, 1) == "/")
    sub(/^\/+/, "", p)
    pre = (!anch && index(p, "/") == 0) ? "(^|.*/)" : "^"
    out = ""
    for (i = 1; i <= length(p); ) {
        c = substr(p, i, 1)
        if (substr(p, i, 3) == "**/") { out = out "(.*/)?"; i += 3 }
        else if (substr(p, i, 2) == "**") { out = out ".*"; i += 2 }
        else if (c == "*") { out = out "[^/]*"; i++ }
        else if (index("][\\.^$+?(){}|", c)) { out = out "\\" c; i++ }
        else { out = out c; i++ }
    }
    return pre out "(/.*)?$"
}

function load(file, fixed,    l, t) {
    while ((getline l < file) > 0) {
        sub(/\r$/, "", l)
        if (l ~ /^[ \t]*(#|$)/) continue
        if (fixed == "") {                      # label <TAB> pattern
            t = index(l, "\t")
            if (t == 0) continue
            np++; lab[np] = substr(l, 1, t - 1); re[np] = g2r(substr(l, t + 1))
        } else {
            np++; lab[np] = fixed; re[np] = g2r(l)
        }
    }
    close(file)
}

# The label of the first pattern that matches, or "".
function label(path,    i) {
    if (path ~ /(^|\/)\.git\/hooks\/[^\/]*\.sample$/) return ""
    for (i = 1; i <= np; i++) if (path ~ re[i]) return lab[i]
    return ""
}

# A JSON string's text from position i (just past its opening quote) of s:
# \" \\ \/ undone, other escapes left as they are written. Sets ENDPOS.
function jstr(s, i,    out, c, n) {
    out = ""
    for (;;) {
        c = substr(s, i, 1)
        if (c == "" || c == "\"") break
        if (c == "\\") {
            n = substr(s, i + 1, 1)
            out = out ((n == "\"" || n == "\\" || n == "/") ? n : "\\" n)
            i += 2
        } else { out = out c; i++ }
    }
    ENDPOS = i
    return out
}

function field(s, key,    k) {
    k = index(s, "\"" key "\":\"")
    return k ? jstr(s, k + length(key) + 4) : ""
}

# For one line: no bidi controls (a name could reorder the line around
# it), and long names cut at the front.
function shown(p,    st) {
    gsub(/\342\200[\216\217\252-\256]|\342\201[\246-\251]|\330\234/, "?", p)
    if (length(p) > 80) {                   # bytes (LC_ALL=C): never cut inside a character
        st = length(p) - 76
        while (substr(p, st, 1) ~ /[\200-\277]/) st++
        p = "..." substr(p, st)
    }
    return p
}

function word(o) {
    return o == "type_changed" ? "type changed" : o == "metadata_only" ? "metadata changed" : o
}

function flag(what, lb) {
    nf++; fwhat[nf] = what; flab[nf] = lb
    if (flagout != "") print what "\t" lb >> flagout
}

function plural(n, s) { return n " " s (n == 1 ? "" : "s") }

# "a (x); b (y); and 2 more flagged"
function flags(    i, s, show) {
    show = nf > 3 ? 3 : nf
    s = ""
    for (i = 1; i <= show; i++) s = s (i > 1 ? "; " : "") fwhat[i] " (" flab[i] ")"
    if (nf > show) s = s "; and " (nf - show) " more flagged"
    return s
}

BEGIN {
    RED = "\360\237\224\264"         # U+1F534, a red circle: what was flagged
    if (mode == "turn") {
        while ((getline l < flagged) > 0) {
            t = index(l, "\t")
            nf++; fwhat[nf] = substr(l, 1, t - 1); flab[nf] = substr(l, t + 1)
        }
        total = incalls + outside
        if (total == 0 && nf == 0) { print "belay: nothing changed this turn"; exit }
        if (nf) print "belay: " RED " " nf " flagged: " flags()
        if (incalls > 0 && outside > 0)
            s = total " changed this turn: " incalls " in " plural(calls, "tool call") ", " outside " outside tool calls"
        else if (outside > 0) s = total " changed this turn outside tool calls"
        else s = total " changed this turn in " plural(calls, "tool call")
        print "belay: " s (receipt != "" ? " · full receipt: /belay:receipt" : "")
        exit
    }

    load(sens, "")
    if (dont != "") load(dont, "don't-touch")

    order = "modified added removed type_changed metadata_only unknown"
    while ((getline l < json) > 0) {
        if (substr(l, 1, 9) == "{\"path\":\"") { path = jstr(l, 10); rest = substr(l, ENDPOS + 1); named = 1 }
        else if (substr(l, 1, 13) == "{\"path_b64\":\"") {
            jstr(l, 14); rest = substr(l, ENDPOS + 1); path = "(a name that is not UTF-8)"; named = 0
        } else if (substr(l, 1, 10) == "{\"event\":\"") {
            if (jstr(l, 11) == "git_history_rewritten") flag(shown(field(l, "text")), "git history rewritten")
            continue
        } else continue
        o = field(rest, "outcome")
        ty = field(rest, "type")
        total++
        lb = named ? label(path) : ""
        # a directory made or removed: its files are records of their own
        if (ty == "dir" && (o == "added" || o == "removed")) lb = ""
        if (lb == "" && ty == "lnk" && o == "type_changed") lb = "replaced by a symlink"
        if (lb == "" && ty == "lnk" && o == "modified" && (k = index(rest, "\"after\":{"))) {
            tg = field(substr(rest, k), "link_target")
            if (tg ~ /^\// || tg ~ /(^|\/)\.\.(\/|$)/) lb = "symlink now points to " shown(tg)
        }
        if (lb != "") { flag(shown(path) " " word(o), lb); continue }
        nrest++
        cnt[o]++
        if (nrest <= 3) few[nrest] = shown(path) " " word(o)
        top = path; if ((k = index(top, "/"))) top = substr(top, 1, k); else top = ""
        if (top != "") under[top]++
    }
    close(json)

    # the receipt's privilege section: every line of it
    while ((getline l < text) > 0) {
        if (l == "privilege") { inpriv = 1; continue }
        if (inpriv && l !~ /^  /) inpriv = 0
        if (inpriv) { sub(/^ +/, "", l); gsub(/  +/, " ", l); flag(shown(l), "privilege") }
    }
    close(text)

    s = "belay: " (nf ? RED " " : "") where (nf ? flags() : "")
    if (nrest > 0) {
        if (nf) s = s " · " nrest " more: "
        else s = s plural(nrest, "change") ": "
        if (nrest <= 3 && !nf) {
            for (i = 1; i <= nrest; i++) s = s (i > 1 ? ", " : "") few[i]
        } else {
            n = split(order, ord, " "); first = 1
            for (i = 1; i <= n; i++) if (cnt[ord[i]] > 0) {
                s = s (first ? "" : ", ") cnt[ord[i]] " " word(ord[i]); first = 0
            }
            for (t in under) if (under[t] * 2 > nrest && nrest > 3) s = s " (" under[t] " under " shown(t) ")"
        }
    }
    print total + 0
    print s
}
