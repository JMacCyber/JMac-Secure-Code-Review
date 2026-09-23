"""The HTML report.

One self-contained page. No network, no fonts to fetch, no framework: the
file opens from disk, from a repository view, or from an artefact store and
renders the same way in each.

It carries the same honesty as the text report. The first screen shows what
ran, what did not run, and what policy refused, because a reader who does
not know the dependency scanner never ran will read an empty dependency
section as good news.
"""

from __future__ import annotations

import html as _html
import json
from typing import Any, List

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

_TIP = {
    "Critical": "Exploitable now, or a credential already exposed. Fix before merge.",
    "High": "A real defect with a plausible path to harm. Fix before merge.",
    "Medium": "A defect worth fixing. Not proven exploitable in this code.",
    "Low": "Minor, or dependent on conditions that may not hold here.",
    "Info": "Not a defect. Stated so the reader knows it was looked at.",
}

CSS = """
:root{--bg:#020617;--card:#0E1223;--muted:#1A1E2F;--border:#334155;--fg:#F8FAFC;
--dim:#94A3B8;--Critical:#F87171;--High:#FB923C;--Medium:#FBBF24;--Low:#38BDF8;
--Info:#94A3B8;--Green:#22C55E;--Amber:#F59E0B;--Red:#EF4444}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:24px;margin:0 0 4px}
h2{font-size:16px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);
margin:36px 0 12px}
.sub{color:var(--dim);font-size:13px;margin:0 0 24px}
.verdict{padding:14px 18px;border-radius:10px;font-weight:600;margin:0 0 24px;
border:1px solid var(--border);background:var(--card)}
.verdict b{font-size:18px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--border);border-radius:10px;
padding:14px 16px;cursor:pointer;text-align:left;color:inherit;font:inherit;
transition:border-color .15s,transform .15s}
.tile:hover,.tile:focus-visible{border-color:var(--fg);transform:translateY(-2px)}
.tile.on{border-color:var(--fg);background:var(--muted)}
.tile .n{font-size:30px;font-weight:700;line-height:1.1}
.tile .k{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em}
.panel{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:4px 18px}
.row{display:flex;gap:14px;padding:9px 0;border-bottom:1px solid var(--muted);font-size:14px}
.row:last-child{border-bottom:0}
.row .lbl{color:var(--dim);min-width:150px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--dim);font-size:12px;text-transform:uppercase;
letter-spacing:.08em;padding:8px 10px;border-bottom:1px solid var(--border)}
td{padding:10px;border-bottom:1px solid var(--muted);vertical-align:top}
tbody tr{cursor:pointer}
tbody tr:hover{background:var(--muted)}
tbody tr:focus-visible{outline:2px solid var(--fg);outline-offset:-2px}
.sev{font-weight:700;white-space:nowrap}
.path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;color:var(--dim);
word-break:break-all}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:#05070F;border:1px solid var(--border);border-radius:8px;padding:12px;
overflow:auto;font-size:13px;margin:8px 0 0;white-space:pre-wrap;word-break:break-word}
input[type=search]{width:100%;margin:12px 0 0;padding:10px 12px;border-radius:8px;
border:1px solid var(--border);background:var(--card);color:var(--fg);font:inherit}
.note{color:var(--dim);font-size:13px}
.overlay{position:fixed;inset:0;background:rgba(2,6,23,.78);display:none;padding:40px 16px;
overflow:auto;z-index:20}
.overlay.on{display:block}
.modal{max-width:840px;margin:0 auto;background:var(--card);border:1px solid var(--border);
border-radius:12px;padding:24px 26px 30px;position:relative}
.x{position:absolute;top:12px;right:14px;background:none;border:0;color:var(--dim);
font-size:26px;line-height:1;cursor:pointer}
.x:hover{color:var(--fg)}
.empty{color:var(--dim);padding:18px 0}
.btn{background:var(--muted);border:1px solid var(--border);border-radius:8px;color:var(--fg);
font:inherit;padding:9px 14px;cursor:pointer;margin:12px 0 0}
.btn:hover,.btn:focus-visible{border-color:var(--fg)}
#fixprompt{max-height:440px}
"""

JS = """
(function(){
var data=JSON.parse(document.getElementById('jscr-data').textContent);
var rows=[].slice.call(document.querySelectorAll('tbody tr[data-i]'));
var overlay=document.getElementById('overlay');
var body=document.getElementById('modal-body');
var filter='';var sev='';
function esc(s){var d=document.createElement('div');d.textContent=s==null?'':String(s);
return d.innerHTML;}
function show(i){
  var f=data[i];if(!f)return;
  var h='<h1 style="margin-right:30px">'+esc(f.title)+'</h1>';
  h+='<p class="sub"><span class="sev" style="color:var(--'+esc(f.severity)+')">'
    +esc(f.severity)+'</span> &middot; <span class="path">'+esc(f.path)+':'
    +esc(f.line||'?')+'</span></p>';
  if(f.evidence){h+='<h2>Evidence</h2><pre>'+esc(f.evidence)+'</pre>';}
  if(f.detail){h+='<h2>Why It Is Reported</h2><p>'+esc(f.detail)+'</p>';}
  if(f.recommendation){h+='<h2>How To Fix It</h2><p>'+esc(f.recommendation)+'</p>';}
  h+='<h2>Provenance</h2><div class="panel">';
  var meta=[['Found By',f.source],['Rule',f.rule_id||'none'],['CWE',f.cwe||'none'],
    ['Confidence',f.confidence],['In The Diff',f.in_diff?'Yes':'No'],
    ['Verification',f.verification_note||'not recorded']];
  for(var m=0;m<meta.length;m++){
    h+='<div class="row"><span class="lbl">'+esc(meta[m][0])+'</span><span>'
      +esc(meta[m][1])+'</span></div>';}
  h+='</div>';
  body.innerHTML=h;overlay.classList.add('on');document.body.style.overflow='hidden';
  document.getElementById('x').focus();
}
function close(){overlay.classList.remove('on');document.body.style.overflow='';}
rows.forEach(function(tr){
  tr.setAttribute('tabindex','0');
  tr.addEventListener('click',function(){show(+tr.getAttribute('data-i'));});
  tr.addEventListener('keydown',function(e){
    if(e.key==='Enter'||e.key===' '){e.preventDefault();show(+tr.getAttribute('data-i'));}});
});
document.getElementById('x').addEventListener('click',close);
overlay.addEventListener('click',function(e){if(e.target===overlay)close();});
document.addEventListener('keydown',function(e){if(e.key==='Escape')close();});
function apply(){
  var shown=0;
  rows.forEach(function(tr){
    var okSev=!sev||tr.getAttribute('data-sev')===sev;
    var okTxt=!filter||tr.textContent.toLowerCase().indexOf(filter)>=0;
    var on=okSev&&okTxt;tr.style.display=on?'':'none';if(on)shown++;});
  document.getElementById('empty').style.display=shown?'none':'block';
}
var box=document.getElementById('q');
if(box){box.addEventListener('input',function(){filter=box.value.toLowerCase();apply();});}
[].slice.call(document.querySelectorAll('.tile[data-sev]')).forEach(function(b){
  b.addEventListener('click',function(){
    sev=(sev===b.getAttribute('data-sev'))?'':b.getAttribute('data-sev');
    [].slice.call(document.querySelectorAll('.tile')).forEach(function(o){
      o.classList.toggle('on',o===b&&sev!=='');});
    apply();});
});
var copy=document.getElementById('copyfix');
if(copy){copy.addEventListener('click',function(){
  var text=document.getElementById('fixprompt').textContent;
  function done(ok){copy.textContent=ok?'Copied':'Copy failed. Select the text and press Cmd+C.';
    setTimeout(function(){copy.textContent='Copy The Prompt';},4000);}
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(function(){done(true);},function(){done(false);});
  }else{
    var t=document.createElement('textarea');t.value=text;document.body.appendChild(t);t.select();
    var ok=false;try{ok=document.execCommand('copy');}catch(e){ok=false;}
    document.body.removeChild(t);done(ok);}
});}
})();
"""


def _esc(value: Any) -> str:
    return _html.escape("" if value is None else str(value), quote=True)


def _verdict(result: Any) -> str:
    worst = result.worst_severity()
    blocking = sum(1 for f in result.findings if f.severity in ("Critical", "High"))
    if worst in ("Critical", "High"):
        colour, word = "Red", "Red"
        text = "{0} finding(s) need attention before merge.".format(blocking)
    elif worst in ("Medium", "Low"):
        colour, word = "Amber", "Amber"
        text = "Nothing blocking, but there are issues worth reading."
    elif result.errors:
        colour, word = "Amber", "Amber"
        text = "The review completed with errors. Read What Ran below."
    else:
        colour, word = "Green", "Green"
        text = "Nothing found. This is not proof the change is safe."
    return (
        '<div class="verdict" style="border-left:5px solid var(--{0})">'
        '<b style="color:var(--{0})">Result: {1}</b> &nbsp; {2}</div>'
    ).format(colour, word, _esc(text))


def _tiles(result: Any) -> str:
    counts = result.counts()
    parts = [
        '<button class="tile" type="button" title="Every finding the engine kept after '
        'verification. Rejected claims are listed separately.">'
        '<div class="n">{0}</div><div class="k">Findings</div></button>'.format(
            len(result.findings)
        )
    ]
    for name in SEVERITIES:
        parts.append(
            '<button class="tile" type="button" data-sev="{0}" title="{1} Click to show only '
            'these rows; click again to clear."><div class="n" style="color:var(--{0})">{2}</div>'
            '<div class="k">{0}</div></button>'.format(name, _esc(_TIP[name]), counts.get(name, 0))
        )
    return '<div class="tiles">{0}</div>'.format("".join(parts))


def _line(label: str, value: str) -> str:
    return '<div class="row"><span class="lbl">{0}</span><span>{1}</span></div>'.format(
        _esc(label), value
    )


def _what_ran(result: Any) -> str:
    out: List[str] = []
    provider = result.provider or {}
    used = provider.get("used")
    if used and used != "null":
        out.append(
            _line("AI Review", "{0} ({1})".format(_esc(used), _esc(provider.get("model") or "?")))
        )
    elif used == "null":
        out.append(_line("AI Review", "Did not run: the null provider is configured"))
    else:
        out.append(_line("AI Review", "Did not run"))

    for row in result.scanners:
        if row.get("ran"):
            out.append(
                _line(
                    str(row.get("name")),
                    "{0} finding(s) in {1:.1f}s".format(
                        row.get("findings", 0), row.get("duration_seconds", 0.0)
                    ),
                )
            )
        else:
            out.append(
                _line(
                    str(row.get("name")),
                    "Did not run: {0}".format(_esc(row.get("error") or "unknown")),
                )
            )

    redaction = result.redaction or {}
    if redaction.get("applied"):
        out.append(
            _line(
                "Redaction",
                "{0} probable secret(s) removed before egress".format(redaction.get("hits")),
            )
        )
    for entry in (result.policy or {}).get("denied") or []:
        out.append(
            _line(
                "Refused By Policy",
                "{0} {1}: {2}".format(
                    _esc(entry.get("action")), _esc(entry.get("subject")), _esc(entry.get("reason"))
                ),
            )
        )
    for text in result.errors:
        out.append(_line("Error", _esc(text)))
    for text in result.warnings:
        out.append(_line("Note", _esc(text)))
    return '<div class="panel">{0}</div>'.format("".join(out))


def _table(result: Any) -> str:
    if not result.findings:
        return '<p class="empty">No findings above the confidence floor.</p>'
    rows: List[str] = []
    for index, finding in enumerate(result.findings):
        rows.append(
            '<tr data-i="{0}" data-sev="{1}">'
            '<td class="sev" style="color:var(--{1})">{1}</td>'
            "<td>{2}</td>"
            '<td class="path">{3}:{4}</td>'
            '<td class="path">{5}</td>'
            "</tr>".format(
                index,
                _esc(finding.severity),
                _esc(finding.title),
                _esc(finding.path),
                _esc(finding.line or "?"),
                _esc(finding.rule_id or finding.source),
            )
        )
    return (
        '<input type="search" id="q" placeholder="Filter by file, rule or words in the title">'
        "<table><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Rule</th>"
        "</tr></thead><tbody>{0}</tbody></table>"
        '<p class="empty" id="empty" style="display:none">No row matches that filter.</p>'
    ).format("".join(rows))


def _not_covered_text(result: Any) -> str:
    """The limits of the run, in one paragraph, used by the page and by the prompt."""
    missing = [str(r.get("name")) for r in result.scanners if not r.get("ran")]
    lines = [
        "This report covers the code in the range named above, read by the scanners and the "
        "reviewer listed in What Ran. It is not a statement that the repository is safe.",
    ]
    if missing:
        lines.append(
            "These scanners did not run, so their whole class of defect was never looked "
            "for: {0}.".format(", ".join(missing))
        )
    provider = result.provider or {}
    if not provider.get("used") or provider.get("used") == "null":
        lines.append("No AI review ran. Every finding here came from a deterministic rule.")
    lines.append(
        "Findings the engine could not anchor to a real line were rejected, not hidden. "
        "They are counted in the summary."
    )
    return " ".join(lines)


def _not_covered(result: Any) -> str:
    return '<div class="panel"><div class="row"><span class="note">{0}</span></div></div>'.format(
        _esc(_not_covered_text(result))
    )


def _fix_prompt(result: Any) -> str:
    """The instructions a reader hands to their own AI, as plain text.

    The report is read by someone whose next move is to ask an agent to fix
    this. Without an order of work that agent edits straight into the working
    tree and there is nothing to roll back to. The four steps are the order:
    marker, branch, machine test, human QA.
    """
    run = result.run or {}
    lines = [
        "You are fixing findings from a JMac Secure Code Review.",
        "",
        "Target: {0}".format(result.target),
        "Repository: {0}".format((run.get("repository") or {}).get("root") or result.root),
    ]
    if run.get("run_id"):
        lines.append("Run: {0}".format(run.get("run_id")))
    if run.get("finished_at"):
        lines.append("Scanned: {0}".format(run.get("finished_at")))
    lines += [
        "",
        "Work in this order. Do not skip a step, and do not reorder them.",
        "",
        "1. Save a major save marker.",
        "   Commit or tag the tree exactly as it is now, before any edit.",
        "   Tell me the marker id and the one command that returns to it.",
        "",
        "2. Branch, then fix.",
        "   Cut a branch from that marker. Never fix on the main line.",
        "   One commit per finding, naming the finding in the message.",
        "   Change only what the finding names. No unrelated refactoring.",
        "   If a finding is wrong for this code, say so and leave the code alone.",
        "",
        "3. Test before you hand over.",
        "   Run this project's own tests and linters.",
        "   Re-run the scanner over the branch and show that each finding is gone.",
        "   Report what passed, what failed, and what you could not run.",
        "",
        "4. Hand to a human for QA.",
        "   List every file changed, what to run or click to see each fix,",
        "   and anything you could not verify yourself.",
        "   Do not merge. A person approves.",
        "",
        "Findings to fix ({0}):".format(len(result.findings)),
    ]
    order = {name: i for i, name in enumerate(SEVERITIES)}
    for f in sorted(result.findings, key=lambda x: (order.get(x.severity, 9), str(x.path))):
        lines.append("")
        lines.append("[{0}] {1}:{2} - {3}".format(f.severity, f.path, f.line or "?", f.title))
        if f.detail:
            lines.append("    Why: {0}".format(f.detail))
        if f.recommendation:
            lines.append("    Fix: {0}".format(f.recommendation))
        source = [str(v) for v in (f.source, f.rule_id, f.cwe) if v]
        if source:
            lines.append("    From: {0}".format(" / ".join(source)))
    if not result.findings:
        lines.append("")
        lines.append("None. Nothing to fix. This is not proof the code is safe.")
    lines += [
        "",
        "What this report does not cover, so do not report it as clean:",
        "  " + _not_covered_text(result),
    ]
    return "\n".join(lines)


def _handover(result: Any) -> str:
    return (
        "<h2>Hand This To Your AI</h2>"
        '<div class="panel"><div class="row"><span class="note">Paste this into your own '
        "coding agent. It names the findings and the order of work: save a marker, branch, "
        "test, then hand to a person. Nothing here is sent anywhere; the text is already in "
        "this file.</span></div></div>"
        '<button class="btn" type="button" id="copyfix">Copy The Prompt</button>'
        '<pre id="fixprompt">{0}</pre>'
    ).format(_esc(_fix_prompt(result)))


def _payload(result: Any) -> str:
    """The findings, as JSON the page can read but the parser cannot mistake for markup.

    json.dumps leaves angle brackets raw. Inside a script element a raw ``<script``
    or ``<!--`` shifts the HTML parser into a state where the closing tag no longer
    closes, which is how a finding title from an untrusted repository would escape
    the data block. Escaping every bracket as a unicode sequence removes the
    question: JSON.parse restores the exact characters, the parser never sees one.
    """
    findings = [f.as_dict() for f in result.findings]
    text = json.dumps(findings, default=str)
    for raw, escaped in (
        ("<", "\\u003c"),
        (">", "\\u003e"),
        ("&", "\\u0026"),
        ("\u2028", "\\u2028"),
        ("\u2029", "\\u2029"),
    ):
        text = text.replace(raw, escaped)
    return text


def render_html(result: Any, title: str = "JMac Secure Code Review") -> str:
    run = result.run or {}
    repo = run.get("repository") or {}
    meta = " &middot; ".join(
        _esc(part)
        for part in (
            repo.get("root") or result.root,
            "run {0}".format(run.get("run_id", "")) if run.get("run_id") else "",
            run.get("finished_at") or "",
        )
        if part
    )
    rejected = ""
    if result.rejected:
        items = [
            _line(
                "{0}:{1}".format(_esc(f.path), _esc(f.line or "?")),
                "{0} &mdash; {1}".format(
                    _esc(f.title), _esc(f.verification_note or "no reason recorded")
                ),
            )
            for f in result.rejected
        ]
        rejected = '<h2>Rejected Before Reporting ({0})</h2><div class="panel">{1}</div>'.format(
            len(result.rejected), "".join(items)
        )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>{title} &mdash; {target}</title><style>{css}</style></head><body>"
        '<div class="wrap"><h1>{title}</h1>'
        '<p class="sub">{target}<br>{meta}</p>{verdict}{tiles}'
        "<h2>What Ran</h2>{ran}"
        "<h2>Findings</h2>{table}"
        "{rejected}"
        "{handover}"
        "<h2>What This Report Does Not Cover</h2>{notcovered}"
        "</div>"
        '<div class="overlay" id="overlay" role="dialog" aria-modal="true">'
        '<div class="modal"><button class="x" id="x" type="button" '
        'aria-label="Close">&times;</button><div id="modal-body"></div></div></div>'
        '<script type="application/json" id="jscr-data">{data}</script>'
        "<script>{js}</script></body></html>"
    ).format(
        title=_esc(title),
        target=_esc(result.target),
        meta=meta,
        css=CSS,
        verdict=_verdict(result),
        tiles=_tiles(result),
        ran=_what_ran(result),
        table=_table(result),
        rejected=rejected,
        handover=_handover(result),
        notcovered=_not_covered(result),
        data=_payload(result),
        js=JS,
    )
