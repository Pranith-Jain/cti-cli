#!/usr/bin/env python3
"""cti-cli — Command-line threat intelligence powered by pranithjain.qzz.io"""

import json
import sys
import textwrap
import click
import requests
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table
from rich.panel import Panel
from rich import box

BASE = "https://pranithjain.qzz.io/api/v1"
console = Console()


def api(method, path, **kwargs):
    """Make an API call. Returns parsed JSON or raises."""
    url = BASE + path
    try:
        r = requests.request(method, url, timeout=60, **kwargs)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.HTTPError as e:
        body = e.response.text[:300] if e.response else ""
        console.print(f"[red]API error ({e.response.status_code}):[/red] {body}")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        console.print("[red]Cannot reach pranithjain.qzz.io — check your connection.[/red]")
        sys.exit(1)
    except requests.exceptions.Timeout:
        console.print("[red]Request timed out (60s). The server may be busy.[/red]")
        sys.exit(1)


def api_get_query(path, **kwargs):
    """Make a GET API call with query params. Returns parsed JSON or raises."""
    return api("GET", path, **kwargs)


def detect_indicator_type(value):
    """Detect if value is an IP, domain, hash, CVE, or keyword."""
    import re
    v = value.strip()
    if re.match(r'^CVE-\d{4}-\d{4,}$', v, re.I):
        return "cve"
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', v):
        return "ip"
    if re.match(r'^[a-fA-F0-9]{32,64}$', v):
        return "hash"
    if re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', v):
        return "domain"
    return "keyword"


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="cti")
def cli():
    """cti-cli — Threat Intelligence from the command line.

    Powered by pranithjain.qzz.io — 13+ live feeds, AI copilot, IOC checker.
    """
    pass


@cli.command()
@click.argument("indicator")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def investigate(indicator, as_json):
    """Run an AI investigation on any indicator.

    Accepts: IP, domain, hash (MD5/SHA1/SHA256), CVE ID, actor name, or keyword.
    """
    console.print(f"[dim]Investigating:[/dim] {indicator}")
    with console.status("[bold cyan]Running investigation pipeline..."):
        data = api("GET", "/copilot/investigate", params={"q": indicator})

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    # Header
    qtype = data.get("query_type", "unknown")
    model = data.get("model_used", "unknown")
    console.print()
    console.print(Panel(
        f"[bold]{indicator}[/bold]  ·  [dim]{qtype}[/dim]  ·  [dim]{model}[/dim]",
        title="Investigation Report",
        border_style="cyan",
    ))

    # Sources summary
    sources = data.get("sources", [])
    if sources:
        tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        tbl.add_column("Source", style="cyan")
        tbl.add_column("Results", justify="right")
        for s in sources:
            tbl.add_row(s["name"], str(s["items"]))
        console.print(tbl)
        console.print()

    # Narrative
    narrative = data.get("narrative", "No narrative generated.")
    console.print(Markdown(narrative))


@cli.command()
@click.argument("query")
@click.option("--limit", "-n", default=50, help="Max results per section")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def search(query, limit, as_json):
    """Search across 12+ threat intel sources.

    Searches ransomware victims, C2 IPs, live IOCs, detections, actors, CVEs,
    writeups, cybercrime, IOC correlation, breaches, malware samples, malpedia.
    """
    console.print(f"[dim]Searching:[/dim] {query}")
    with console.status("[bold cyan]Searching 12+ sources..."):
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
        kind = sec.get("kind", "")
        console.print(f"[bold cyan]{label}[/bold cyan] ({len(items)})")
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
@click.argument("hash_value")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def hash_lookup(hash_value, as_json):
    """Look up a file hash across live enrichment providers.

    Checks VirusTotal, MalwareBazaar, MalShare, OTX, and more.
    """
    console.print(f"[dim]Looking up hash:[/dim] {hash_value}")
    with console.status("[bold cyan]Querying providers..."):
        data = api("GET", "/copilot/investigate", params={"q": hash_value})

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    # Extract enrichment data
    enrichment = None
    for s in data.get("sources", []):
        if s["name"] == "Live Enrichment":
            enrichment = s.get("data", {})
            break

    if enrichment:
        providers = enrichment.get("providers", [])
        tbl = Table(box=box.ROUNDED, title="Hash Enrichment", show_header=True)
        tbl.add_column("Provider", style="cyan")
        tbl.add_column("Verdict")
        tbl.add_column("Score", justify="right")
        tbl.add_column("Tags")
        for p in providers:
            verdict = p.get("verdict", "unknown")
            score = p.get("score", 0)
            color = {"clean": "green", "malicious": "red", "suspicious": "yellow"}.get(verdict, "dim")
            tags = ", ".join(p.get("tags", [])[:3])
            tbl.add_row(
                p.get("source", "?"),
                f"[{color}]{verdict}[/{color}]",
                str(score),
                tags,
            )
        console.print(tbl)
    else:
        console.print("[yellow]No enrichment data found.[/yellow]")

    # Narrative
    console.print()
    console.print(Markdown(data.get("narrative", "")))


@cli.command()
@click.argument("cve_id")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def cve(cve_id, as_json):
    """Look up a CVE — CVSS, EPSS, KEV status, related writeups.

    Example: cti cve CVE-2024-1709
    """
    console.print(f"[dim]Looking up:[/dim] {cve_id}")
    with console.status("[bold cyan]Querying CVE data..."):
        data = api("GET", "/cve/lookup", params={"id": cve_id})

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    cve_data = data.get("cve", data)
    console.print()
    console.print(Panel(
        f"[bold]{cve_data.get('id', cve_id)}[/bold]\n"
        f"Severity: [bold]{cve_data.get('severity', 'N/A')}[/bold]  ·  "
        f"CVSS: {cve_data.get('cvss', {}).get('base_score', 'N/A')}  ·  "
        f"KEV: {'Yes' if cve_data.get('kev', {}).get('in_kev') else 'No'}",
        title="CVE Lookup",
        border_style="cyan",
    ))

    desc = cve_data.get("description", "No description.")
    console.print(f"\n{desc[:500]}\n")

    epss = cve_data.get("epss", {})
    if epss:
        console.print(f"EPSS: [bold]{epss.get('score', 'N/A')}[/bold] (percentile: {epss.get('percentile', 'N/A')})")

    kev = cve_data.get("kev", {})
    if kev and kev.get("in_kev"):
        console.print(f"[red]CISA KEV:[/red] Added {kev.get('date_added', 'N/A')} — {kev.get('vulnerability_name', '')}")

    refs = cve_data.get("references", [])
    if refs:
        console.print(f"\n[dim]References ({len(refs)}):[/dim]")
        for ref in refs[:5]:
            console.print(f"  {ref}")


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
@click.option("--group", "-g", default=None, help="Filter by group name")
def ransomware(as_json, group):
    """Show recent ransomware activity — victims, groups, sectors."""
    console.print("[dim]Fetching ransomware data...[/dim]")
    with console.status("[bold cyan]Loading..."):
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
            v.get("discovered", "")[:10],
        )
    console.print(tbl)

    if groups:
        console.print(f"\n[bold]Active groups:[/bold]")
        for g in sorted(groups, key=lambda x: x.get("count", 0), reverse=True)[:10]:
            console.print(f"  • {g['group']} — {g['count']} victims")


@cli.command()
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def actor(name, as_json):
    """Look up a threat actor — timeline, TTPs, victims, CVEs.

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

    sources = data.get("sources", [])
    for s in sources:
        if s["items"] > 0:
            console.print(f"\n[bold cyan]{s['name']}[/bold cyan] ({s['items']} results)")
            items = s.get("data", [])
            if isinstance(items, list):
                for item in items[:5]:
                    if isinstance(item, dict):
                        name_val = item.get("display_name") or item.get("victim") or item.get("title") or item.get("id", "")
                        desc = item.get("description", "")[:80]
                        console.print(f"  • {name_val}  [dim]{desc}[/dim]")

    console.print()
    console.print(Markdown(data.get("narrative", "")))


@cli.command()
@click.argument("indicator")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def check(indicator, as_json):
    """Check an IOC against 24+ providers (streaming verdict).

    Accepts: IP, domain, URL, or hash.
    """
    itype = detect_indicator_type(indicator)
    kind_map = {"ip": "ipv4", "domain": "domain", "hash": "hash", "url": "url"}
    kind = kind_map.get(itype)
    if not kind:
        console.print(f"[red]Cannot determine indicator type for: {indicator}[/red]")
        sys.exit(1)

    console.print(f"[dim]Checking {kind}:[/dim] {indicator}")
    results = []

    with console.status("[bold cyan]Streaming from 24+ providers..."):
        r = requests.get(f"{BASE}/ioc/check", params={"indicator": indicator}, stream=True, timeout=120)
        for line in r.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data:"):
                continue
            try:
                payload = json.loads(line[5:].strip())
                if payload.get("type") == "result":
                    results.append(payload)
                elif payload.get("type") == "done":
                    break
            except json.JSONDecodeError:
                continue

    if as_json:
        click.echo(json.dumps(results, indent=2))
        return

    tbl = Table(box=box.ROUNDED, title=f"IOC Check: {indicator}", show_header=True)
    tbl.add_column("Provider", style="cyan")
    tbl.add_column("Verdict")
    tbl.add_column("Score", justify="right")
    tbl.add_column("Tags")
    for r in results:
        d = r.get("data", {})
        verdict = d.get("verdict", "unknown")
        score = d.get("score", 0)
        color = {"clean": "green", "malicious": "red", "suspicious": "yellow"}.get(verdict, "dim")
        tags = ", ".join(d.get("tags", [])[:3])
        tbl.add_row(
            d.get("source", r.get("provider", "?")),
            f"[{color}]{verdict}[/{color}]",
            str(score),
            tags,
        )
    console.print(tbl)


@cli.command()
@click.argument("ip")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def ip(ip, as_json):
    """Geolocate an IP — country, ASN, ISP, proxy/VPN flags."""
    console.print(f"[dim]Looking up:[/dim] {ip}")
    with console.status("[bold cyan]Querying..."):
        data = api("GET", "/ip-geo", params={"ip": ip})

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    console.print()
    console.print(Panel(
        f"[bold]{ip}[/bold]\n"
        f"Country: {data.get('country', 'N/A')}  ·  "
        f"ASN: {data.get('asn', 'N/A')}  ·  "
        f"ISP: {data.get('isp', 'N/A')}\n"
        f"Proxy: {data.get('proxy', 'N/A')}  ·  "
        f"Hosting: {data.get('hosting', 'N/A')}",
        title="IP Geolocation",
        border_style="cyan",
    ))


@cli.command()
@click.argument("domain_name")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def domain(domain_name, as_json):
    """Domain lookup — WHOIS, DNS, email auth, CT logs."""
    console.print(f"[dim]Looking up:[/dim] {domain_name}")
    with console.status("[bold cyan]Querying..."):
        data = api("GET", "/domain/lookup", params={"domain": domain_name})

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    console.print()
    for section_name, section_data in data.items():
        if isinstance(section_data, dict) and section_data:
            console.print(f"[bold cyan]{section_name}[/bold cyan]")
            for k, v in section_data.items():
                if v:
                    console.print(f"  {k}: {v}")
            console.print()


@cli.command()
@click.argument("text", required=False)
@click.option("--file", "-f", type=click.Path(exists=True), help="Read from file")
def extract(text, file):
    """Extract IOCs (IPs, domains, hashes, URLs, CVEs) from text or file."""
    if file:
        with open(file) as fh:
            raw = fh.read()
    elif text:
        raw = text
    else:
        raw = sys.stdin.read()

    if not raw.strip():
        console.print("[red]No input provided.[/red]")
        sys.exit(1)

    import re
    iocs = {
        "ipv4": list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw))),
        "domain": list(set(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', raw))),
        "sha256": list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', raw))),
        "sha1": list(set(re.findall(r'\b[a-fA-F0-9]{40}\b', raw))),
        "md5": list(set(re.findall(r'\b[a-fA-F0-9]{32}\b', raw))),
        "url": list(set(re.findall(r'https?://[^\s<>"\']+', raw))),
        "cve": list(set(re.findall(r'CVE-\d{4}-\d{4,}', raw, re.I))),
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
@click.option("--days", "-d", default=7, help="Number of days")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def briefings(as_json, days):
    """Show recent threat briefings."""
    with console.status("[bold cyan]Loading briefings..."):
        data = api("GET", "/briefings/list")

    if as_json:
        click.echo(json.dumps(data, indent=2))
        return

    items = data.get("briefings", [])
    console.print(f"\n[bold]{len(items)}[/bold] briefings\n")
    for b in items[:10]:
        slug = b.get("slug", "")
        title = b.get("title", slug)
        date = b.get("published_at", "")[:10]
        findings = b.get("stats", {}).get("findings", 0)
        iocs = b.get("stats", {}).get("iocs", 0)
        console.print(f"  [cyan]{date}[/cyan]  {title}")
        console.print(f"    [dim]{findings} findings · {iocs} IOCs[/dim]")


@cli.command()
def feed_status():
    """Show health status of all live threat intel feeds."""
    with console.status("[bold cyan]Checking feeds..."):
        data = api("GET", "/feed-status")

    sources = data.get("sources", [])
    tbl = Table(box=box.SIMPLE, title="Feed Status", show_header=True)
    tbl.add_column("Feed", style="cyan")
    tbl.add_column("Status")
    tbl.add_column("Items", justify="right")
    tbl.add_column("Age", style="dim")
    for s in sources:
        ok = s.get("ok", False)
        status = "[green]OK[/green]" if ok else "[red]DOWN[/red]"
        tbl.add_row(
            s.get("id", "?"),
            status,
            str(s.get("count", "—")),
            s.get("age", "—"),
        )
    console.print(tbl)


@cli.command()
@click.argument("query")
@click.option("--json", "as_json", is_flag=True, help="Raw JSON output")
def copilot(query, as_json):
    """Alias for investigate — run AI copilot on any query."""
    ctx = click.get_current_context()
    ctx.invoke(investigate, indicator=query, as_json=as_json)


if __name__ == "__main__":
    cli()
