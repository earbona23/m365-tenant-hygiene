<#
.SYNOPSIS
    The report's stylesheet, inlined into the HTML file.
.DESCRIPTION
    Kept in one place so the renderer stays about structure and this stays about
    appearance. Colours are defined as custom properties and redefined once for dark
    mode, so a reader's system preference is respected without a second stylesheet.

    Severity colours are chosen for contrast against both surfaces rather than for
    vividness: a report that is unreadable in dark mode is a report that gets
    screenshotted badly into an incident ticket.
#>
function Get-HygieneReportStyle {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
:root {
  color-scheme: light dark;
  --bg: #f5f6f8;
  --surface: #ffffff;
  --surface-alt: #fafbfc;
  --ink: #10151d;
  --muted: #5b6675;
  --line: #e2e6eb;
  --accent: #0f6e6e;
  --sev-critical: #a81f14;
  --sev-high: #b4530a;
  --sev-medium: #8a6100;
  --sev-low: #14539a;
  --sev-informational: #5b6675;
  --radius: 10px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117;
    --surface: #151b23;
    --surface-alt: #1b222b;
    --ink: #e6edf3;
    --muted: #93a0ae;
    --line: #262e38;
    --accent: #2dd4bf;
    --sev-critical: #ff6b6b;
    --sev-high: #ffa04d;
    --sev-medium: #f2c744;
    --sev-low: #6aa9f5;
    --sev-informational: #93a0ae;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.6 ui-sans-serif, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 1120px; margin: 0 auto; padding: 0 24px; }
.mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; font-size: 0.9em; }

/* Masthead */
.masthead {
  background: var(--surface);
  border-bottom: 1px solid var(--line);
  padding: 36px 0 28px;
}
.eyebrow {
  margin: 0 0 6px;
  font-size: 12px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--accent);
  font-weight: 600;
}
.masthead h1 { margin: 0 0 20px; font-size: 30px; line-height: 1.2; font-weight: 650; letter-spacing: -0.02em; }
dl.meta { display: flex; flex-wrap: wrap; gap: 8px 36px; margin: 0; }
dl.meta div { min-width: 0; }
dl.meta dt { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
dl.meta dd { margin: 2px 0 0; font-size: 14px; overflow-wrap: anywhere; }

main { padding-bottom: 72px; }
section { margin-top: 40px; }
h2 { font-size: 19px; margin: 0 0 14px; font-weight: 650; letter-spacing: -0.01em; }
h3 { font-size: 15px; margin: 32px 0 10px; font-weight: 650; }

/* Incomplete-audit notice */
.notice {
  background: var(--surface);
  border: 1px solid var(--line);
  border-left: 4px solid var(--sev-medium);
  border-radius: var(--radius);
  padding: 18px 22px;
}
.notice h2 { margin: 0 0 6px; font-size: 16px; color: var(--sev-medium); }
.notice p { margin: 0 0 10px; color: var(--muted); }
.notice ul { margin: 0; padding-left: 20px; }
.notice li { margin-bottom: 8px; font-size: 14px; }

/* Severity cards */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
.card {
  background: var(--surface);
  border: 1px solid var(--line);
  border-top: 3px solid var(--sev-informational);
  border-radius: var(--radius);
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.card .count { font-size: 30px; font-weight: 650; line-height: 1.1; letter-spacing: -0.02em; }
.card .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }
.card.sev-critical { border-top-color: var(--sev-critical); }
.card.sev-critical .count { color: var(--sev-critical); }
.card.sev-high { border-top-color: var(--sev-high); }
.card.sev-high .count { color: var(--sev-high); }
.card.sev-medium { border-top-color: var(--sev-medium); }
.card.sev-medium .count { color: var(--sev-medium); }
.card.sev-low { border-top-color: var(--sev-low); }
.card.sev-low .count { color: var(--sev-low); }
.card.neutral { border-top-color: var(--accent); }

/* Coverage table */
table.grid { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden; }
table.grid th, table.grid td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--line); font-size: 14px; vertical-align: top; }
table.grid thead th { background: var(--surface-alt); font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; color: var(--muted); font-weight: 600; }
table.grid tbody tr:last-child td { border-bottom: 0; }
table.grid .num { text-align: right; font-variant-numeric: tabular-nums; }
table.grid .note { color: var(--muted); font-size: 13px; max-width: 420px; }

.status { font-size: 11px; font-weight: 650; text-transform: uppercase; letter-spacing: 0.06em; padding: 2px 8px; border-radius: 999px; border: 1px solid currentColor; white-space: nowrap; }
.status-completed { color: var(--accent); }
.status-skipped { color: var(--sev-medium); }
.status-failed { color: var(--sev-critical); }

/* Filters */
.filters { display: flex; flex-wrap: wrap; align-items: center; gap: 14px; margin-bottom: 8px; }
.search { display: flex; flex-direction: column; gap: 4px; }
.search span { font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; color: var(--muted); }
.search input {
  min-width: 260px; padding: 8px 12px; font: inherit; font-size: 14px;
  color: var(--ink); background: var(--surface);
  border: 1px solid var(--line); border-radius: 8px;
}
.search input:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.chips { display: flex; flex-wrap: wrap; gap: 8px; }
.chip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 5px 11px; border-radius: 999px; cursor: pointer;
  font-size: 12px; font-weight: 600;
  border: 1px solid var(--line); background: var(--surface); color: var(--muted);
  user-select: none;
}
.chip input { accent-color: currentColor; margin: 0; }
.chip.sev-critical { color: var(--sev-critical); }
.chip.sev-high { color: var(--sev-high); }
.chip.sev-medium { color: var(--sev-medium); }
.chip.sev-low { color: var(--sev-low); }
.result-count { margin: 0; margin-left: auto; font-size: 13px; color: var(--muted); }

.check-heading { display: flex; align-items: center; gap: 10px; }
.badge { font-size: 12px; font-weight: 600; color: var(--muted); background: var(--surface-alt); border: 1px solid var(--line); border-radius: 999px; padding: 1px 9px; }

/* Findings */
.finding {
  background: var(--surface);
  border: 1px solid var(--line);
  border-left: 3px solid var(--sev-informational);
  border-radius: var(--radius);
  margin-bottom: 8px;
}
.finding.sev-critical { border-left-color: var(--sev-critical); }
.finding.sev-high { border-left-color: var(--sev-high); }
.finding.sev-medium { border-left-color: var(--sev-medium); }
.finding.sev-low { border-left-color: var(--sev-low); }
.finding[hidden] { display: none; }
.finding > summary {
  cursor: pointer; padding: 12px 16px; display: flex; flex-wrap: wrap;
  align-items: center; gap: 10px; list-style: none;
}
.finding > summary::-webkit-details-marker { display: none; }
.finding > summary:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; border-radius: var(--radius); }
.pill { font-size: 10px; font-weight: 700; letter-spacing: 0.07em; text-transform: uppercase; padding: 3px 8px; border-radius: 4px; border: 1px solid currentColor; white-space: nowrap; }
.pill.sev-critical { color: var(--sev-critical); }
.pill.sev-high { color: var(--sev-high); }
.pill.sev-medium { color: var(--sev-medium); }
.pill.sev-low { color: var(--sev-low); }
.pill.sev-informational { color: var(--sev-informational); }
.object { font-weight: 600; overflow-wrap: anywhere; }
.headline { color: var(--muted); font-size: 14px; }
.finding .body { padding: 0 16px 16px 16px; border-top: 1px solid var(--line); }
.detail { margin: 14px 0 0; }
.recommendation { margin: 12px 0 0; padding: 12px 14px; background: var(--surface-alt); border-radius: 8px; font-size: 14px; }
.recommendation strong { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; color: var(--accent); margin-bottom: 4px; }
dl.facts { display: flex; flex-wrap: wrap; gap: 6px 28px; margin: 14px 0 0; }
dl.facts dt { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
dl.facts dd { margin: 1px 0 0; font-size: 13px; overflow-wrap: anywhere; }
.evidence-label { margin: 16px 0 4px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; color: var(--muted); }
pre.evidence {
  margin: 0; padding: 12px 14px; overflow-x: auto;
  background: var(--surface-alt); border: 1px solid var(--line); border-radius: 8px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; line-height: 1.5;
}
.reference { margin: 12px 0 0; font-size: 13px; }
.reference a { color: var(--accent); }
.empty { color: var(--muted); background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); padding: 18px 22px; margin: 0; }

footer { margin-top: 48px; padding-top: 20px; border-top: 1px solid var(--line); color: var(--muted); font-size: 13px; }
footer p { margin: 0 0 4px; }

@media print {
  :root { --bg: #fff; --surface: #fff; --surface-alt: #fff; --ink: #000; --line: #bbb; }
  body { font-size: 11pt; }
  .no-print { display: none !important; }
  .masthead { padding: 0 0 16px; }
  .finding { break-inside: avoid; page-break-inside: avoid; }
  .finding > .body { display: block !important; }
  a { text-decoration: none; color: inherit; }
}
'@
}

<#
.SYNOPSIS
    The report's client-side behaviour, inlined into the HTML file.
.DESCRIPTION
    Deliberately small and dependency-free: severity filtering, a text filter over
    pre-computed haystacks, a live count of what is shown, and expanding every finding
    before printing so a printed report is not a page of collapsed summaries.

    The filter reads from a data attribute rather than the rendered DOM, so filtering a
    large report does not walk the tree on every keystroke.
#>
function Get-HygieneReportScript {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
(function () {
  "use strict";

  var findings = Array.prototype.slice.call(document.querySelectorAll(".finding"));
  if (!findings.length) { return; }

  var search  = document.getElementById("q");
  var chips   = Array.prototype.slice.call(document.querySelectorAll("#sev-filters input"));
  var counter = document.getElementById("shown");

  function apply() {
    var term = (search && search.value || "").trim().toLowerCase();
    var allowed = {};
    chips.forEach(function (c) { allowed[c.value] = c.checked; });

    var shown = 0;
    findings.forEach(function (el) {
      var okSeverity = allowed[el.getAttribute("data-severity")] !== false;
      var okTerm = !term || (el.getAttribute("data-search") || "").indexOf(term) !== -1;
      var visible = okSeverity && okTerm;
      el.hidden = !visible;
      if (visible) { shown++; }
    });

    // Hide a check heading whose findings are all filtered out, so the report
    // never shows a section header above nothing.
    Array.prototype.slice.call(document.querySelectorAll(".check-heading")).forEach(function (h) {
      var any = false, node = h.nextElementSibling;
      while (node && node.classList && node.classList.contains("finding")) {
        if (!node.hidden) { any = true; break; }
        node = node.nextElementSibling;
      }
      h.hidden = !any;
    });

    if (counter) {
      counter.textContent = shown === findings.length
        ? findings.length + " findings"
        : shown + " of " + findings.length + " findings";
    }
  }

  if (search) { search.addEventListener("input", apply); }
  chips.forEach(function (c) { c.addEventListener("change", apply); });

  window.addEventListener("beforeprint", function () {
    findings.forEach(function (el) { if (!el.hidden) { el.open = true; } });
  });

  apply();
})();
'@
}
