#!/usr/bin/env python3
"""cti-cli — Command-line threat intelligence powered by pranithjain.qzz.io.

Configuration (env vars or global flags):
  --base-url / CTI_API_BASE   API base (default https://pranithjain.qzz.io/api/v1)
  --api-key  / CTI_API_KEY     bearer token for auth-gated endpoints (e.g. investigate)

Exit codes: 0 ok · 1 API error · 2 network error · 3 auth required
"""

import json
import re
import sys

import click
import requests
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table
from rich.panel import Panel
from rich import box

DEFAULT_BASE = "https://pranithjain.qzz.io/api/v1"
console = Console()

# Resolved from the CLI group (flags / env) before any command runs.
BASE = DEFAULT_BASE
API_KEY = None

EXIT_API = 1
EXIT_NETWORK = 2
EXIT_AUTH = 3


def _headers(extra=None):
    h = {"Accept": "application/json"}
    if API_KEY:
        h["Authorization"] = f"Bearer {API_KEY}"
    if extra:
        h.update(extra)
    return h


def api(method, path, *, stream=False, timeout=60, **kwargs):
    """Call the API. Returns parsed JSON (or the raw Response when stream=True)."""
    url = BASE + path
    headers = _headers(kwargs.pop("headers", None))
    try:
        r = requests.request(method, url, headers=headers, timeout=timeout, stream=stream, **kwargs)
    except requests.exceptions.ConnectionError:
        console.print(f"[red]Cannot reach {BASE}[/red] — check your connection or --base-url.")
        sys.exit(EXIT_NETWORK)
    except requests.exceptions.Timeout:
        console.print(f"[red]Request timed out ({timeout}s).[/red] The server may be busy.")
        sys.exit(EXIT_NETWORK)
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request failed:[/red] {e}")
        sys.exit(EXIT_NETWORK)

    if r.status_code in (401, 403):
        console.print(
            "[red]Authentication required[/red] for this endpoint. "
            "Set an API key via [bold]--api-key[/bold] or the [bold]CTI_API_KEY[/bold] env var."
        )
        sys.exit(EXIT_AUTH)
    if not r.ok:
        detail = ""
        try:
            detail = r.json().get("message") or r.json().get("error") or ""
        except ValueError:
            detail = (r.text or "")[:200]
        console.print(f"[red]API error ({r.status_code}):[/red] {detail}")
        sys.exit(EXIT_API)

    if stream:
        return r
    try:
        return r.json()
    except ValueError:
        console.print("[red]Server returned a non-JSON response.[/red]")
        sys.exit(EXIT_API)


def detect_indicator_type(value):
    """Detect if value is an IP, domain, hash, CVE, URL, or keyword."""
    v = value.strip()
    if re.match(r"^CVE-\d{4}-\d{4,}$", v, re.I):
        return "cve"
    if re.match(r"^https?://", v, re.I):
        return "url"
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", v):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32,64}$", v):
        return "hash"
    if re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", v):
        return "domain"
    return "keyword"


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--base-url", envvar="CTI_API_BASE", default=DEFAULT_BASE,
              help="API base URL (env: CTI_API_BASE).")
@click.option("--api-key", envvar="CTI_API_KEY", default=None,
              help="Bearer token for auth-gated endpoints (env: CTI_API_KEY).")
@click.version_option("1.1.0", prog_name="cti")
def cli(base_url, api_key):
    """cti-cli — Threat Intelligence from the command line.

    Powered by pranithjain.qzz.io — live feeds, IOC checker, CVE/actor lookups.
    """
    global BASE, API_KEY
    BASE = base_url.rstrip("/")
    API_KEY = api_key


@cli.command()
@click.argument("indicator")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def investigate(indicator, as_json):
    """Run an AI investigation on any indicator (auth-gated; needs --api-key).

    Accepts: IP, domain, hash (MD5/SHA1/SHA256), CVE ID, actor name, or keyword.
    """
    console.print(f"[dim]Investigating:[/dim] {indicator}")
    with console.status("[bold cyan]Running investigation pipeline..."):
        data = api("GET", "/copilot/investigate", params={"q": indicator})

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    qtype = data.get("query_type", "unknown")
    model = data.get("model_used", "unknown")
    console.print()
    console.print(Panel(
        f"[bold]{indicator}[/bold]  ·  [dim]{qtype}[/dim]  ·  [dim]{model}[/dim]",
        title="Investigation Report",
        border_style="cyan",
    ))

    sources = data.get("sources", [])
    if sources:
        tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        tbl.add_column("Source", style="cyan")
        tbl.add_column("Results", justify="right")
        for s in sources:
            tbl.add_row(str(s.get("name", "?")), str(s.get("items", 0)))
        console.print(tbl)
        console.print()

    console.print(Markdown(data.get("narrative", "No narrative generated.")))


@cli.command()
@click.argument("query")
@click.option("--limit", "-n", default=50, help="Max results per section")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def search(query, limit, as_json):
    """Search across live threat-intel sources (ransomware, IOCs, actors, CVEs...)."""
    console.print(f"[dim]Searching:[/dim] {query}")
    with console.status("[bold cyan]Searching all sources..."):
        data = api("GET", "/unified-search", params={"q": query})

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    total = data.get("total", 0)
    sections = data.get("sections", [])
    console.print(f"\n[bold]{total}[/bold] results for [cyan]{query}[/cyan]\n")

    for sec in sections:
        items = sec.get("items", [])
        if not items:
            continue
        label = sec.get("label", "Unknown")
        console.print(f"[bold cyan]{label}[/bold cyan] ({sec.get('total', len(items))})")
        for item in items[:limit]:
            name = item.get("label", "")
            desc = item.get("description", "")
            url = item.get("url", "")
            line = f"  • {name}"
            if desc:
                line += f"  [dim]{desc[:80]}[/dim]"
            console.print(line)
            if url:
                console.print(f"    [dim]{url}[/dim]")
        console.print()


@cli.command()
@click.argument("cve_id")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def cve(cve_id, as_json):
    """Look up a CVE — CVSS, CWE, KEV status, PoCs, references.

    Example: cti cve CVE-2024-1709
    """
    console.print(f"[dim]Looking up:[/dim] {cve_id}")
    with console.status("[bold cyan]Querying CVE data..."):
        data = api("GET", "/cve/lookup", params={"id": cve_id})

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    d = data.get("cve", data)
    cvss = d.get("cvss") or {}
    kev = d.get("kev") or {}

    console.print()
    console.print(Panel(
        f"[bold]{d.get('cve_id', cve_id)}[/bold]\n"
        f"Severity: [bold]{cvss.get('severity', 'N/A')}[/bold]  ·  "
        f"CVSS {cvss.get('version', '')}: {cvss.get('base_score', 'N/A')}  ·  "
        f"KEV: {'[red]Yes[/red]' if kev.get('in_kev') else 'No'}",
        title="CVE Lookup",
        border_style="red" if kev.get("in_kev") else "cyan",
    ))

    console.print(f"\n{(d.get('description') or 'No description.')[:600]}\n")

    cwe = d.get("cwe")
    if cwe:
        console.print(f"CWE: {cwe if isinstance(cwe, str) else ', '.join(cwe)}")
    if cvss.get("vector"):
        console.print(f"Vector: [dim]{cvss['vector']}[/dim]")

    if kev.get("in_kev"):
        extra = " · [red]known ransomware[/red]" if kev.get("known_ransomware") else ""
        console.print(
            f"[red]CISA KEV:[/red] added {kev.get('date_added', 'N/A')} — "
            f"{kev.get('vulnerability_name', '')}{extra}"
        )

    poc = d.get("poc")
    poc_urls = poc.get("urls", []) if isinstance(poc, dict) else (poc or [])
    if poc_urls:
        console.print(f"\n[yellow]Public PoCs ({len(poc_urls)}):[/yellow]")
        for p in poc_urls[:5]:
            console.print(f"  {p if isinstance(p, str) else p.get('url', p)}")

    refs = d.get("references") or []
    if refs:
        console.print(f"\n[dim]References ({len(refs)}):[/dim]")
        for ref in refs[:5]:
            console.print(f"  {ref if isinstance(ref, str) else ref.get('url', ref)}")


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
@click.option("--group", "-g", default=None, help="Filter by group name")
def ransomware(as_json, group):
    """Show recent ransomware activity — victims, groups, sectors."""
    with console.status("[bold cyan]Loading ransomware activity..."):
        data = api("GET", "/ransomware-recent")

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    victims = data.get("victims", [])
    groups = data.get("groups", [])
    if group:
        victims = [v for v in victims if group.lower() in v.get("group", "").lower()]

    console.print(f"\n[bold]{len(victims)}[/bold] victims  ·  [bold]{len(groups)}[/bold] groups\n")

    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    tbl.add_column("Group", style="red")
    tbl.add_column("Victim")
    tbl.add_column("Sector", style="dim")
    tbl.add_column("Discovered", style="dim")
    for v in victims[:30]:
        tbl.add_row(
            v.get("group", "?"),
            v.get("victim", "?"),
            v.get("sector", "—"),
            (v.get("discovered", "") or "")[:10],
        )
    console.print(tbl)

    if groups:
        console.print("\n[bold]Most active groups:[/bold]")
        for g in sorted(groups, key=lambda x: x.get("count", 0), reverse=True)[:10]:
            console.print(f"  • {g.get('group', '?')} — {g.get('count', 0)} victims")


@cli.command()
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def actor(name, as_json):
    """Look up a threat actor (auth-gated; needs --api-key).

    Example: cti actor LockBit
    """
    console.print(f"[dim]Looking up actor:[/dim] {name}")
    with console.status("[bold cyan]Searching actor data..."):
        data = api("GET", "/copilot/investigate", params={"q": name})

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    console.print()
    console.print(Panel(
        f"[bold]{name}[/bold]  ·  [dim]{data.get('query_type', 'unknown')}[/dim]",
        title="Threat Actor Report",
        border_style="red",
    ))

    for s in data.get("sources", []):
        if s.get("items", 0) > 0:
            console.print(f"\n[bold cyan]{s.get('name')}[/bold cyan] ({s['items']} results)")
            items = s.get("data", [])
            if isinstance(items, list):
                for item in items[:5]:
                    if isinstance(item, dict):
                        nm = (item.get("display_name") or item.get("victim")
                              or item.get("title") or item.get("id", ""))
                        desc = (item.get("description", "") or "")[:80]
                        console.print(f"  • {nm}  [dim]{desc}[/dim]")

    console.print()
    console.print(Markdown(data.get("narrative", "")))


@cli.command()
@click.argument("indicator")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def check(indicator, as_json):
    """Check an IOC against live providers (streaming verdict).

    Accepts: IP, domain, URL, or hash.
    """
    itype = detect_indicator_type(indicator)
    if itype not in ("ip", "domain", "hash", "url"):
        console.print(f"[red]Cannot determine a checkable indicator type for:[/red] {indicator}")
        sys.exit(EXIT_API)

    console.print(f"[dim]Checking {itype}:[/dim] {indicator}")
    results = []
    overall = None

    with console.status("[bold cyan]Streaming from providers..."):
        r = api("GET", "/ioc/check", params={"indicator": indicator}, stream=True, timeout=120)
        for line in r.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data:"):
                continue
            try:
                payload = json.loads(line[5:].strip())
            except json.JSONDecodeError:
                continue
            # Stream shape: a meta line (has "type"+"providers"), then one line per
            # provider (has "source"), then a final summary line (has "contributing").
            if "source" in payload:
                results.append(payload)
            elif "contributing" in payload or "confidence" in payload:
                overall = payload

    if as_json:
        click.echo(json.dumps({"results": results, "overall": overall}, indent=2))
        return

    color_for = {"clean": "green", "malicious": "red", "suspicious": "yellow"}
    if overall:
        v = overall.get("verdict", "unknown")
        adm = overall.get("admiralty", {}).get("label", "")
        console.print()
        console.print(Panel(
            f"[bold]{indicator}[/bold]  ·  verdict "
            f"[{color_for.get(v, 'dim')}]{v.upper()}[/{color_for.get(v, 'dim')}]  ·  "
            f"score {overall.get('score', 0)}  ·  confidence {overall.get('confidence', '?')}"
            + (f"  ·  {adm}" if adm else ""),
            title=f"IOC Check: {indicator}",
            border_style=color_for.get(v, "cyan"),
        ))

    reported = [r for r in results if r.get("status") not in ("unsupported", "error")]
    tbl = Table(box=box.ROUNDED, title=f"{len(reported)} providers reporting", show_header=True)
    tbl.add_column("Provider", style="cyan")
    tbl.add_column("Verdict")
    tbl.add_column("Score", justify="right")
    tbl.add_column("Tags")
    for d in reported:
        verdict = d.get("verdict", "unknown")
        tags = ", ".join((d.get("tags") or [])[:3])
        tbl.add_row(
            d.get("source", "?"),
            f"[{color_for.get(verdict, 'dim')}]{verdict}[/{color_for.get(verdict, 'dim')}]",
            str(d.get("score", 0)),
            tags,
        )
    console.print(tbl)


@cli.command("hash-lookup")
@click.argument("hash_value")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
@click.pass_context
def hash_lookup(ctx, hash_value, as_json):
    """Look up a file hash across live enrichment providers.

    Runs the public IOC checker (VirusTotal, MalwareBazaar, OTX, and more) —
    no API key required.
    """
    if not re.fullmatch(r"[a-fA-F0-9]{32,64}", hash_value.strip()):
        console.print("[red]Not a valid MD5/SHA1/SHA256 hash.[/red]")
        sys.exit(EXIT_API)
    ctx.invoke(check, indicator=hash_value.strip(), as_json=as_json)


@cli.command()
@click.argument("ip_addr")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def ip(ip_addr, as_json):
    """Geolocate an IP — country, city, reverse DNS, proxy/VPN/Tor flags."""
    console.print(f"[dim]Looking up:[/dim] {ip_addr}")
    with console.status("[bold cyan]Querying..."):
        data = api("GET", "/ip-geo", params={"ip": ip_addr})

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    geo = data.get("geo") or {}
    priv = data.get("privacy") or {}
    flags = [k for k in ("vpn", "proxy", "tor", "relay", "hosting") if priv.get(k)]
    console.print()
    console.print(Panel(
        f"[bold]{data.get('ip', ip_addr)}[/bold]  ·  [dim]{data.get('detected_kind', '')}[/dim]\n"
        f"Location: {geo.get('city', 'N/A')}, {geo.get('region', '')} {geo.get('country', 'N/A')}\n"
        f"Reverse DNS: {geo.get('reverse_dns', 'N/A')}\n"
        f"Privacy flags: "
        + ("[red]" + ", ".join(flags) + "[/red]" if flags else "[green]none[/green]"),
        title="IP Geolocation",
        border_style="red" if flags else "cyan",
    ))


@cli.command()
@click.argument("domain_name")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def domain(domain_name, as_json):
    """Domain lookup — verdict, DNS, email auth, RDAP, certificates."""
    console.print(f"[dim]Looking up:[/dim] {domain_name}")
    with console.status("[bold cyan]Querying..."):
        data = api("GET", "/domain/lookup", params={"domain": domain_name})

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    verdict = data.get("verdict", "unknown")
    color = {"clean": "green", "malicious": "red", "suspicious": "yellow"}.get(verdict, "cyan")
    console.print()
    console.print(Panel(
        f"[bold]{data.get('domain', domain_name)}[/bold]  ·  "
        f"verdict [{color}]{verdict}[/{color}]  ·  score {data.get('score', 'N/A')}",
        title="Domain Lookup",
        border_style=color,
    ))

    for section in ("dns", "email_auth", "rdap", "certificates", "threat_intel"):
        sd = data.get(section)
        if isinstance(sd, dict) and sd:
            console.print(f"\n[bold cyan]{section}[/bold cyan]")
            for k, v in sd.items():
                if v in (None, "", [], {}):
                    continue
                if isinstance(v, (list, dict)):
                    v = json.dumps(v)[:120]
                console.print(f"  {k}: {v}")


@cli.command()
@click.argument("text", required=False)
@click.option("--file", "-f", type=click.Path(exists=True), help="Read from file")
def extract(text, file):
    """Extract IOCs (IPs, domains, hashes, URLs, CVEs) from text, file, or stdin."""
    if file:
        with open(file) as fh:
            raw = fh.read()
    elif text:
        raw = text
    else:
        raw = sys.stdin.read()

    if not raw.strip():
        console.print("[red]No input provided.[/red]")
        sys.exit(EXIT_API)

    iocs = {
        "ipv4": sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw))),
        "domain": sorted(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", raw))),
        "sha256": sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b", raw))),
        "sha1": sorted(set(re.findall(r"\b[a-fA-F0-9]{40}\b", raw))),
        "md5": sorted(set(re.findall(r"\b[a-fA-F0-9]{32}\b", raw))),
        "url": sorted(set(re.findall(r"https?://[^\s<>\"']+", raw))),
        "cve": sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", raw, re.I))),
    }

    total = sum(len(v) for v in iocs.values())
    console.print(f"\n[bold]{total}[/bold] IOCs extracted:\n")
    for kind, values in iocs.items():
        if values:
            console.print(f"[bold cyan]{kind}[/bold cyan] ({len(values)})")
            for v in values[:20]:
                console.print(f"  {v}")
            if len(values) > 20:
                console.print(f"  [dim]... and {len(values) - 20} more[/dim]")
            console.print()


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def briefings(as_json):
    """Show recent threat briefings."""
    with console.status("[bold cyan]Loading briefings..."):
        data = api("GET", "/briefings/list")

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    items = data.get("items", data.get("briefings", []))
    console.print(f"\n[bold]{data.get('total', len(items))}[/bold] briefings\n")
    for b in items[:10]:
        meta = b.get("metadata", b)
        slug = b.get("slug", "")
        title = meta.get("title", slug)
        date = (meta.get("date") or meta.get("published_at", ""))[:10]
        stats = meta.get("stats", {})
        console.print(f"  [cyan]{date}[/cyan]  {title}")
        console.print(
            f"    [dim]{stats.get('findings', 0)} findings · "
            f"{stats.get('cves', 0)} CVEs · {stats.get('iocs', 0)} IOCs[/dim]   [dim]{slug}[/dim]"
        )


@cli.command()
def feed_status():
    """Show health status of all live threat-intel feeds."""
    with console.status("[bold cyan]Checking feeds..."):
        data = api("GET", "/feed-status")

    rows = data.get("rows", data.get("sources", []))
    overall = data.get("overall", "?")
    console.print(
        f"\nOverall: [bold]{overall}[/bold]  ·  "
        f"{data.get('total_sources', len(rows))} sources  ·  "
        f"[green]{data.get('healthy', 0)} healthy[/green] · "
        f"[yellow]{data.get('degraded', 0)} degraded[/yellow] · "
        f"[red]{data.get('down', 0)} down[/red] · {data.get('cold', 0)} cold\n"
    )

    status_color = {"healthy": "green", "degraded": "yellow", "down": "red", "cold": "dim"}
    tbl = Table(box=box.SIMPLE, title="Feed Status", show_header=True)
    tbl.add_column("Feed", style="cyan")
    tbl.add_column("Status")
    tbl.add_column("Grade", justify="center")
    for s in rows:
        st = s.get("status", "?")
        c = status_color.get(st, "dim")
        tbl.add_row(
            s.get("label", s.get("id", "?")),
            f"[{c}]{st}[/{c}]",
            s.get("admiralty_grade", s.get("reliability", "—")),
        )
    console.print(tbl)


@cli.command()
@click.argument("query")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
@click.pass_context
def copilot(ctx, query, as_json):
    """Alias for `investigate` — run the AI copilot on any query (auth-gated)."""
    ctx.invoke(investigate, indicator=query, as_json=as_json)


if __name__ == "__main__":
    cli()
