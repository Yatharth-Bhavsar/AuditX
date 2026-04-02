import click
import os
import time
import sys
from datetime import datetime
from rich.console import Console
import questionary
import pyfiglet

from auditx.scanner.ast_extractor import ASTExtractor
from auditx.analyzer.gemini_client import GeminiClient
from auditx.reporter.report_builder import ReportBuilder
from auditx.rules import evaluate_rules
from auditx.missing_controls import check_missing_controls
from auditx.taint import extract_taint_findings
from auditx.vuln_db import scan_dependencies
from auditx.owasp import enrich_with_owasp, get_owasp_coverage
from auditx.scoring import calculate_score, calculate_custom_score
from auditx.policy_reader import extract_pdf_text, extract_controls_from_policy
from auditx.policy_matcher import match_controls

console = Console()

def _run_pipeline(target_dir, profile, output_path, api_key, custom_policy_path, interactive=False):
    start_time = time.time()
    
    if not output_path:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        output_path = f"auditx_report_{timestamp}.html"
        
    if interactive:
        console.print("\n[bold cyan]Initializing AuditX...[/bold cyan]\n")
        
    # Step 1: AST Extraction
    status_msg = "[bold cyan]Extracting AST representations...[/bold cyan]" if interactive else "[1/6] Running AST Extraction"
    with console.status(status_msg, spinner="dots") if interactive else open(os.devnull, 'w') as _:
        try:
            extractor = ASTExtractor(target_dir)
            summary = extractor.scan()
            metadata = summary.to_flat_dict()
            if interactive: time.sleep(1.2)
        except Exception as e:
            console.print(f"[red]Error during AST parsing: {e}[/red]")
            sys.exit(1)
            
    if interactive:
        console.print("  [green]✔ AST Parsing Complete[/green]")
    else:
        click.echo("[1/6] AST Parsing Complete")

    # Step 2: Static Rules
    status_msg = "[bold cyan]Evaluating Compliance Static Rules...[/bold cyan]" if interactive else "[2/6] Evaluating Rules"
    with console.status(status_msg, spinner="dots") if interactive else open(os.devnull, 'w') as _:
        static_findings = evaluate_rules(metadata)
        missing_controls = check_missing_controls(metadata)
        if interactive: time.sleep(1.2)
    
    # Step 3: Shallow Taint
    status_msg = "[bold cyan]Running Surface Taint Analysis...[/bold cyan]" if interactive else "[3/6] Taint Analysis"
    with console.status(status_msg, spinner="dots") if interactive else open(os.devnull, 'w') as _:
        taint_findings = extract_taint_findings(metadata)
        if interactive: time.sleep(1.2)
        
    if interactive:
        console.print("  [green]✔ Taint Analysis Complete[/green]")
    else:
        click.echo("[2/6] Taint Analysis Complete")
        
    # Step 4: CVE Detection
    status_msg = "[bold cyan]Resolving Dependency CVEs...[/bold cyan]" if interactive else "[3/6] Scan Dependencies"
    with console.status(status_msg, spinner="dots") if interactive else open(os.devnull, 'w') as _:
        cve_findings = scan_dependencies(target_dir)
        if interactive: time.sleep(2.0)
        
    if interactive:
        console.print("  [green]✔ CVE Scan Complete[/green]")
    else:
        click.echo("[3/6] CVE Scan Complete")
        
    # Step 5: Merge & Deduplicate
    all_findings = static_findings + taint_findings + cve_findings
    seen = set()
    deduped_findings = []
    status_msg = "[bold cyan]Mapping Discoveries...[/bold cyan]" if interactive else "[4/6] Mapping Configs"
    with console.status(status_msg, spinner="dots") if interactive else open(os.devnull, 'w') as _:
        for f in all_findings:
            rid = f.get('rule_id')
            loc = f.get('location')
            key = f"{rid}_{loc}"
            if key not in seen:
                seen.add(key)
                deduped_findings.append(f)
                
        deduped_findings = enrich_with_owasp(deduped_findings)
        owasp_coverage = get_owasp_coverage(deduped_findings)
        if interactive: time.sleep(1.5)
        
    if not interactive:
        click.echo("[4/6] Deduplication & Mapping Complete")

    # Step 6: AI Translation
    status_msg = "[bold cyan]Building Executive Context...[/bold cyan]" if interactive else "[5/6] AI Processing"
    with console.status(status_msg, spinner="dots") if interactive else open(os.devnull, 'w') as _:
        gemini = GeminiClient(api_key)
        translation_dict = gemini.translate_findings(deduped_findings)
        top_risk_sentence = gemini.get_top_risk(deduped_findings)
        
        for f in deduped_findings:
            f['behavior_observed'] = translation_dict.get(f.get('rule_id', ''), '')
            
    if interactive:
         console.print("  [green]✔ AI Reasoning Complete[/green]")
    else:
         click.echo("[5/6] AI Reasoning Complete")
         
    # Optional Custom Policy Handling
    custom_policy_results = None
    custom_policy_score = None
    if custom_policy_path:
        status_msg = "[bold cyan]Analyzing Custom Policy Definitions...[/bold cyan]" if interactive else "[Policy] Analyzing"
        with console.status(status_msg, spinner="dots") if interactive else open(os.devnull, 'w') as _:
            if interactive: console.print(f"  📄 Processing Custom Policy: {custom_policy_path}")
            pdf_text = extract_pdf_text(custom_policy_path)
            controls = extract_controls_from_policy(pdf_text, gemini)
            custom_policy_results = match_controls(controls, metadata)
            custom_policy_score = calculate_custom_score(custom_policy_results)

    status_msg = "[bold cyan]Generating Comprehensive Audit Report...[/bold cyan]" if interactive else "[6/6] Building Report"
    with console.status(status_msg, spinner="dots") if interactive else open(os.devnull, 'w') as _:
        score_data = calculate_score(deduped_findings, missing_controls, profile)
        duration = time.time() - start_time
        
        reporter = ReportBuilder()
        reporter.build_report(
            findings=deduped_findings, 
            summary_obj=summary, 
            profile=profile, 
            duration=duration, 
            output_path=output_path,
            score_data=score_data,
            top_risk_sentence=top_risk_sentence,
            missing_controls=missing_controls,
            custom_policy_results=custom_policy_results,
            custom_policy_score=custom_policy_score,
            owasp_coverage=owasp_coverage,
            cve_findings=cve_findings
        )
    
    if interactive:
        console.print("  [green]✔ Report Generated[/green]\n")
        console.print(f"  📊 Compliance Score: [{score_data['color']}]{score_data['score']}/100 - {score_data['label']}[/{score_data['color']}]")
        console.print(f"  📉 Top Risk: {top_risk_sentence}")
        console.print(f"\n[bold]Report saved successfully at:[/bold] [cyan]{output_path}[/cyan]\n")
    else:
        click.echo("[6/6] Report Generated")
        click.echo(f"Report Output: {output_path}")

@click.group()
def cli():
    """AuditX — AI Compliance Gap Scanner"""
    pass

@cli.command()
def start():
    """Interactive CLI mode for AuditX"""
    banner = pyfiglet.figlet_format("AuditX", font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    
    action = questionary.select(
        "Select an action:",
        choices=["Auto Audit", "Upload Custom Policy (PDF)", "Exit"]
    ).ask()
    
    if action == "Exit":
        sys.exit(0)
        
    profile = questionary.select(
        "Select compliance profile:",
        choices=["fintech", "saas", "healthcare"]
    ).ask()
    
    target_dir = questionary.path("Enter target codebase directory:", default="./demo_repo").ask()
    
    custom_policy_path = None
    if action == "Upload Custom Policy (PDF)":
        custom_policy_path = questionary.path("Enter path to Custom Policy PDF:").ask()
        if not os.path.exists(custom_policy_path):
             console.print("[red]Invalid PDF path.[/red]")
             sys.exit(1)
             
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        api_key = questionary.password("Enter Gemini API Key (Hidden):").ask()
        if not api_key:
            console.print("[red]API Key required.[/red]")
            sys.exit(1)
            
    _run_pipeline(target_dir, profile, None, api_key, custom_policy_path, interactive=True)


@cli.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--profile', type=click.Choice(['fintech', 'saas', 'healthcare']), default='saas', help="Compliance profile to use")
@click.option('--output', type=click.Path(), default=None, help="Output file path for HTML report")
@click.option('--api-key', type=str, default=None, help="Gemini API key")
@click.option('--custom-policy', type=click.Path(exists=False), default=None, help="Path to a custom compliance policy PDF to assess against.")
def scan(directory, profile, output, api_key, custom_policy):
    """Scan a target codebase directory for compliance gaps"""
    key = api_key or os.environ.get("GEMINI_API_KEY")
    if not key:
        click.echo("Error: GEMINI_API_KEY is not set.", err=True)
        sys.exit(1)
        
    if custom_policy and not os.path.exists(custom_policy):
        click.echo(f"❌ Error: File not found: {custom_policy}")
        sys.exit(1)
        
    _run_pipeline(directory, profile, output, key, custom_policy, interactive=False)

if __name__ == '__main__':
    cli()
