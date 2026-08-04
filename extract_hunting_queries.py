#!/usr/bin/env python3
"""
extract_hunting_queries.py — Extract Microsoft Defender XDR Advanced Hunting
queries (KQL) from the public MicrosoftDocs/defender-docs repository and write
them to a single static HTML file.

For every query found, the page shows:
  - title   : the heading the query appears under (its name)
  - context : the sentence/paragraph right before the query (usually
              "Use the following query to ..."), when present
  - the KQL code block (with a copy-to-clipboard button)
  - a link back to the source document on GitHub

UNOFFICIAL tool. All content is sourced from the public
MicrosoftDocs/defender-docs repository (branch: public) and remains the
property of Microsoft.

Requires Python 3.11+ and the packages in requirements.txt.
"""

from __future__ import annotations

import argparse
import html
import logging
import os
import re
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    import frontmatter
except ImportError:  # pragma: no cover - friendly message for missing deps
    sys.stderr.write(
        "ERROR: missing dependency. Install it with:\n"
        "    pip install -r requirements.txt\n"
    )
    raise SystemExit(2)

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

REPO_URL = "https://github.com/MicrosoftDocs/defender-docs.git"
DEFAULT_BRANCH = "public"
DOCS_SUBDIR = "defender-xdr"

GITHUB_REPO = "https://github.com/MicrosoftDocs/defender-docs"
GITHUB_BLOB_BASE = f"{GITHUB_REPO}/blob/{DEFAULT_BRANCH}"

DISCLAIMER = (
    "Unofficial extraction from public Microsoft documentation. "
    "Not affiliated with, endorsed by, or maintained by Microsoft. "
    "All content is sourced from the MicrosoftDocs/defender-docs repository "
    "(https://github.com/MicrosoftDocs/defender-docs/tree/public/defender-xdr) "
    "and remains the property of Microsoft. Always verify queries against the "
    "official Microsoft Learn documentation before use."
)

log = logging.getLogger("extract_hunting_queries")


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class Query:
    title: str        # heading the query appears under (its name)
    context: str      # prose immediately before the query (may be "")
    kql: str          # the KQL code block
    doc_title: str    # title of the source document
    doc_path: str     # path of the source file relative to the repo root
    doc_url: str      # GitHub URL of the source file


@dataclass
class SourceDoc:
    path: Path
    rel_path: str
    title: str
    ah_tagged: bool               # carries Microsoft's advanced-hunting metadata
    queries: list[Query] = field(default_factory=list)


# --------------------------------------------------------------------------
# Source acquisition
# --------------------------------------------------------------------------


def run_git(args: list[str], cwd: Path | None = None) -> None:
    """Run a git command, raising RuntimeError on failure."""
    cmd = ["git", *args]
    log.debug("Running: %s", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"git command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}"
        )


def clone_repo(dest: Path, repo_url: str, branch: str) -> None:
    """Shallow sparse-clone the repo, checking out only the docs folder."""
    log.info("Cloning %s (branch=%s, shallow, sparse: %s/) ...", repo_url, branch, DOCS_SUBDIR)
    try:
        run_git([
            "clone", "--depth", "1", "--branch", branch,
            "--filter=blob:none", "--sparse", repo_url, str(dest),
        ])
        run_git(["sparse-checkout", "set", DOCS_SUBDIR], cwd=dest)
    except RuntimeError as exc:
        log.warning("Sparse clone failed (%s). Falling back to a plain shallow clone.", exc)
        shutil.rmtree(dest, ignore_errors=True)
        run_git(["clone", "--depth", "1", "--branch", branch, repo_url, str(dest)])


def update_repo(dest: Path, branch: str) -> bool:
    """Try to fast-forward an existing clone. Returns True on success."""
    try:
        run_git(["fetch", "--depth", "1", "origin", branch], cwd=dest)
        run_git(["reset", "--hard", f"origin/{branch}"], cwd=dest)
        return True
    except RuntimeError as exc:
        log.warning("Could not update existing clone: %s", exc)
        return False


def repo_head(dest: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=dest, capture_output=True, text=True,
    )
    return proc.stdout.strip()


def ensure_source(args: argparse.Namespace) -> Path:
    """
    Resolve the local directory that contains the source repo checkout.

    Priority:
      1. --source-dir / DEFENDER_DOCS_DIR (an existing checkout, used as-is)
      2. --work-dir cache (cloned on first run, updated on later runs)
    """
    explicit = args.source_dir or os.environ.get("DEFENDER_DOCS_DIR")
    if explicit:
        src = Path(explicit).expanduser().resolve()
        if not (src / DOCS_SUBDIR).is_dir():
            raise SystemExit(
                f"ERROR: --source-dir {src} does not contain a '{DOCS_SUBDIR}/' folder."
            )
        log.info("Using existing source checkout: %s", src)
        return src

    cache = Path(args.work_dir).expanduser().resolve()
    if (cache / ".git").is_dir():
        log.info("Found cached clone at %s; updating ...", cache)
        if not update_repo(cache, args.branch):
            log.info("Re-cloning from scratch ...")
            shutil.rmtree(cache, ignore_errors=True)
            clone_repo(cache, args.repo_url, args.branch)
    else:
        cache.parent.mkdir(parents=True, exist_ok=True)
        clone_repo(cache, args.repo_url, args.branch)

    log.info("Source ready at %s (commit %s)", cache, repo_head(cache) or "unknown")
    return cache


# --------------------------------------------------------------------------
# Document selection
# --------------------------------------------------------------------------


def is_advanced_hunting_doc(path: Path, metadata: dict) -> bool:
    """
    Decide whether a Markdown file carries Microsoft's Advanced Hunting
    metadata. Any of these signals qualifies it:

      1. Frontmatter ``ms.subservice: adv-hunting``
      2. Frontmatter ``ms.custom`` contains ``cx-ah``
      3. Filename starts with ``advanced-hunting`` or ``api-advanced-hunting``
    """
    name = path.name.lower()
    if not name.endswith(".md"):
        return False

    subservice = str(metadata.get("ms.subservice", "") or "").strip().lower()
    if subservice == "adv-hunting":
        return True

    custom = metadata.get("ms.custom") or []
    if isinstance(custom, str):
        custom = [custom]
    if any(str(c).strip().lower() == "cx-ah" for c in custom):
        return True

    return name.startswith(("advanced-hunting", "api-advanced-hunting"))


# --------------------------------------------------------------------------
# Query extraction
# --------------------------------------------------------------------------

HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
FENCE_OPEN_RE = re.compile(r"^(\s*)```([A-Za-z0-9_+-]*)\s*$")
KQL_LANGS = {"kusto", "kql"}


def clean_inline(text: str) -> str:
    """Strip Markdown inline markup, leaving plain text."""
    text = re.sub(r"<a\s+name=[^>]*></a>", "", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)   # [text](url) -> text
    text = re.sub(r"\[([^\]]+)\]\[[^\]]*\]", r"\1", text)  # [text][ref] -> text
    text = re.sub(r"(\*\*|__)(.*?)\1", r"\2", text)        # bold
    text = re.sub(r"(\*|_)(.*?)\1", r"\2", text)           # italic
    text = text.replace("`", "")
    return re.sub(r"\s+", " ", text).strip()


def clean_heading(text: str) -> str:
    return clean_inline(text)


# Lines that should NOT be treated as a "context" paragraph.
NON_PROSE_RE = re.compile(
    r"^\s*(#{1,6}\s|>|```|:::|\[!|-\s|\*\s|\+\s|\d+[.)]\s|\||<)"
)


def preceding_context(lines: list[str], fence_line: int, max_chars: int = 400) -> str:
    """
    Return the plain-text paragraph immediately above the fence (typically
    "Use the following query to ..." / "Run this query to ..."), or "" if
    there isn't one. Blank lines between the prose and the fence are skipped.
    """
    i = fence_line - 1
    while i >= 0 and not lines[i].strip():
        i -= 1  # skip blank lines directly above the fence

    block: list[str] = []
    while i >= 0:
        line = lines[i]
        if not line.strip():
            break  # paragraph boundary
        if NON_PROSE_RE.match(line):
            break  # heading / list / alert / table / code / html
        block.append(line.strip())
        i -= 1
    block.reverse()
    text = clean_inline(" ".join(block))
    return text[:max_chars].rstrip()


def extract_queries(body: str, doc_title: str) -> list[Query]:
    """
    Extract every ```kusto / ```kql fenced block from a Markdown body.

    - Works for fences at any indentation (e.g. inside list items) and for
      any language-tag casing (```Kusto, ```kusto, ```kql).
    - Code is de-indented by the opening fence's indentation.
    - The query title is the nearest heading above the fence; duplicates
      within one document get a " (2)", " (3)", ... suffix.
    """
    lines = body.splitlines()
    headings: list[tuple[int, str]] = [
        (i, clean_heading(m.group(2)))
        for i, line in enumerate(lines)
        if (m := HEADING_RE.match(line))
    ]

    queries: list[Query] = []
    title_counts: dict[str, int] = {}

    i = 0
    while i < len(lines):
        m = FENCE_OPEN_RE.match(lines[i])
        if not m or m.group(2).lower() not in KQL_LANGS:
            i += 1
            continue

        indent = len(m.group(1))
        code_lines: list[str] = []
        j = i + 1
        while j < len(lines) and lines[j].strip() != "```":
            cl = lines[j]
            # De-indent by the opening fence's indentation where possible.
            if indent and cl[:indent].strip() == "":
                cl = cl[indent:]
            code_lines.append(cl)
            j += 1

        open_line = i  # index of the opening fence line
        code = "\n".join(code_lines).strip("\n")
        i = j + 1  # skip past the closing fence (or EOF if unbalanced)

        if not code.strip():
            continue

        # Title = nearest heading above the opening fence.
        title = doc_title
        for line_no, heading in headings:
            if line_no < open_line:
                title = heading
            else:
                break

        title_counts[title] = title_counts.get(title, 0) + 1
        if title_counts[title] > 1:
            title = f"{title} ({title_counts[title]})"

        queries.append(
            Query(
                title=title,
                context=preceding_context(lines, open_line),
                kql=code,
                doc_title=doc_title,
                doc_path="",   # filled in by caller
                doc_url="",    # filled in by caller
            )
        )

    return queries


# --------------------------------------------------------------------------
# Document loading
# --------------------------------------------------------------------------


def load_documents(docs_dir: Path, repo_root: Path) -> list[SourceDoc]:
    """
    Scan the docs folder and keep every document that contains at least one
    KQL query block.

    A document is included when EITHER:
      - it is tagged as Advanced Hunting content (is_advanced_hunting_doc), OR
      - it simply contains ```kusto/```kql code blocks (this catches docs such
        as alert-grading playbooks and response guides whose hunting queries
        are not tagged with the adv-hunting subservice).
    Documents without any KQL blocks are ignored entirely.
    """
    md_files = sorted(docs_dir.rglob("*.md"))
    log.info("Scanning %d Markdown files under %s ...", len(md_files), docs_dir)

    docs: list[SourceDoc] = []
    for path in md_files:
        try:
            post = frontmatter.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("Skipping %s: could not parse (%s)", path.name, exc)
            continue

        rel_path = path.relative_to(repo_root).as_posix()
        title = str(post.metadata.get("title") or path.stem)
        ah_tagged = is_advanced_hunting_doc(path, post.metadata)

        queries = extract_queries(post.content, title)
        if not queries:
            log.debug("Ignoring (no KQL blocks): %s", path.name)
            continue

        for q in queries:
            q.doc_path = rel_path
            q.doc_url = f"{GITHUB_BLOB_BASE}/{rel_path}"

        doc = SourceDoc(
            path=path,
            rel_path=rel_path,
            title=title,
            ah_tagged=ah_tagged,
            queries=queries,
        )
        docs.append(doc)
        log.debug(
            "%-58s queries=%2d  ah-tagged=%s", path.name, len(queries), ah_tagged
        )

    tagged = sum(1 for d in docs if d.ah_tagged)
    log.info(
        "Kept %d documents containing queries (%d advanced-hunting tagged, "
        "%d additional docs that contain KQL blocks; %d files ignored).",
        len(docs), tagged, len(docs) - tagged, len(md_files) - len(docs),
    )
    return docs


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

STYLE_CSS = """
* { box-sizing: border-box; }
body {
  margin: 0; background: #f6f8fa; color: #1f2328; line-height: 1.6;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
a { color: #0f6cbd; text-decoration: none; }
a:hover { text-decoration: underline; }
.container { max-width: 960px; margin: 0 auto; padding: 0 20px; }
header.site-header {
  background: linear-gradient(135deg, #0b2e4f 0%, #0f6cbd 100%);
  color: #fff; padding: 26px 0 20px; margin-bottom: 24px;
}
header.site-header h1 { margin: 0 0 6px; font-size: 1.5rem; }
header.site-header p { margin: 4px 0; color: #dbe7f3; font-size: 0.92rem; }
header.site-header a { color: #cfe6ff; }
section.doc { margin-bottom: 34px; }
section.doc > h2 {
  font-size: 1.2rem; border-bottom: 2px solid #0f6cbd; padding-bottom: 6px;
}
div.query {
  background: #fff; border: 1px solid #d1d9e0; border-radius: 8px;
  padding: 14px 18px; margin: 14px 0;
}
div.query h3 { margin: 0 0 6px; font-size: 1.02rem; }
p.context { margin: 0 0 10px; color: #59636e; font-size: 0.92rem; }
div.code-block { position: relative; }
pre {
  margin: 0; background: #0d1117; color: #e6edf3; border-radius: 8px;
  padding: 14px 16px; overflow-x: auto; font-size: 0.85rem; line-height: 1.5;
}
pre code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  white-space: pre;
}
button.copy-btn {
  position: absolute; top: 8px; right: 8px; cursor: pointer;
  background: #21262d; color: #c9d1d9; border: 1px solid #444c56;
  border-radius: 6px; font-size: 0.75rem; padding: 4px 10px;
}
button.copy-btn:hover { background: #30363d; }
button.copy-btn.copied { background: #1a7f37; border-color: #1a7f37; color: #fff; }
footer.site-footer {
  border-top: 1px solid #d1d9e0; margin-top: 30px; padding: 20px 0 32px;
  font-size: 0.82rem; color: #59636e;
}
footer.site-footer p { margin: 6px 0; }
@media (max-width: 640px) {
  header.site-header h1 { font-size: 1.2rem; }
}
""".strip()

COPY_JS = """
document.querySelectorAll("pre").forEach(function (pre) {
  var wrapper = document.createElement("div");
  wrapper.className = "code-block";
  pre.parentNode.insertBefore(wrapper, pre);
  wrapper.appendChild(pre);
  var btn = document.createElement("button");
  btn.type = "button";
  btn.className = "copy-btn";
  btn.textContent = "Copy";
  btn.addEventListener("click", function () {
    var text = pre.innerText;
    function done() {
      btn.textContent = "Copied!";
      btn.classList.add("copied");
      setTimeout(function () {
        btn.textContent = "Copy";
        btn.classList.remove("copied");
      }, 1600);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {
        var ta = document.createElement("textarea");
        ta.value = text; document.body.appendChild(ta); ta.select();
        try { document.execCommand("copy"); } catch (e) {}
        document.body.removeChild(ta); done();
      });
    } else {
      var ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); } catch (e) {}
      document.body.removeChild(ta); done();
    }
  });
  wrapper.appendChild(btn);
});
""".strip()


def esc(text: str) -> str:
    return html.escape(text, quote=True)


def write_html(docs: list[SourceDoc], out_file: Path, commit: str) -> int:
    """Write all extracted queries to a single HTML file. Returns query count."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    sections: list[str] = []
    total = 0
    for doc in sorted(docs, key=lambda d: d.title.lower()):
        blocks: list[str] = []
        for q in doc.queries:
            total += 1
            context = (
                f'<p class="context">{esc(q.context)}</p>' if q.context else ""
            )
            blocks.append(f"""    <div class="query">
      <h3>{esc(q.title)}</h3>
      {context}
      <pre><code>{esc(q.kql)}</code></pre>
    </div>""")
        sections.append(f"""  <section class="doc">
    <h2><a href="{esc(doc.queries[0].doc_url)}">{esc(doc.title)}</a></h2>
{chr(10).join(blocks)}
  </section>""")

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Defender XDR Advanced Hunting Queries (Unofficial)</title>
<style>
{STYLE_CSS}
</style>
</head>
<body>
<header class="site-header">
  <div class="container">
    <h1>Microsoft Defender XDR — Advanced Hunting Queries</h1>
    <p>{total} queries extracted from {len(docs)} documents in
       <a href="{GITHUB_REPO}/tree/{DEFAULT_BRANCH}/{DOCS_SUBDIR}">MicrosoftDocs/defender-docs</a>
       (branch <code>{DEFAULT_BRANCH}</code>, commit <code>{esc(commit or "unknown")}</code>).</p>
    <p>Generated at {esc(generated_at)}.</p>
  </div>
</header>
<main class="container">
{chr(10).join(sections)}
</main>
<footer class="site-footer">
  <div class="container">
    <p><strong>Disclaimer:</strong> {DISCLAIMER}</p>
    <p>Generated at {esc(generated_at)} by an automated, unofficial script.</p>
  </div>
</footer>
<script>
{COPY_JS}
</script>
</body>
</html>
"""

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(page, encoding="utf-8")
    log.info("Wrote %d queries from %d documents -> %s", total, len(docs), out_file)
    return total


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract Defender XDR Advanced Hunting (KQL) queries to a single HTML file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              python scripts/extract_hunting_queries.py
              python scripts/extract_hunting_queries.py --output output/queries.html --verbose
              DEFENDER_DOCS_DIR=/path/to/defender-docs python scripts/extract_hunting_queries.py
        """),
    )
    parser.add_argument("--repo-url", default=REPO_URL, help="Git URL of the source repository.")
    parser.add_argument("--branch", default=DEFAULT_BRANCH, help="Branch to read (default: public).")
    parser.add_argument("--work-dir", default=".cache/defender-docs",
                        help="Cache directory for the cloned repository (default: .cache/defender-docs).")
    parser.add_argument("--source-dir", default=None,
                        help="Use an existing local checkout instead of cloning "
                             "(env var DEFENDER_DOCS_DIR is also honored).")
    parser.add_argument("--output", default="output/advanced-hunting-queries.html",
                        help="HTML output file (default: output/advanced-hunting-queries.html).")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        repo_root = ensure_source(args)
    except (RuntimeError, SystemExit) as exc:
        log.error("Could not obtain source repository: %s", exc)
        return 1

    docs_dir = repo_root / DOCS_SUBDIR
    if not docs_dir.is_dir():
        log.error("Expected folder %s not found in the source checkout.", docs_dir)
        return 1

    try:
        docs = load_documents(docs_dir, repo_root)
    except Exception:
        log.exception("Failed while scanning documents.")
        return 1

    if not docs:
        log.error("No documents with hunting queries were found — nothing to write.")
        return 1

    out_file = Path(args.output).expanduser().resolve()
    try:
        count = write_html(docs, out_file, repo_head(repo_root))
    except Exception:
        log.exception("Failed while writing output.")
        return 1

    log.info("Done. %d queries extracted.", count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
