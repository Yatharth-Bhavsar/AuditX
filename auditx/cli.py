import click
import os
import time
import sys
from datetime import datetime
from auditx.scanner.ast_extractor import ASTExtractor
from auditx.analyzer.gemini_client import GeminiClient
from auditx.reporter.report_builder import ReportBuilder

@click.group()
def cli():
    """AuditX — AI Compliance Gap Scanner for Indian Startups"""
    pass

@cli.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--profile', type=click.Choice(['fintech', 'saas']), default='saas', help="Compliance profile to use")
@click.option('--output', type=click.Path(), default=None, help="Output file path for HTML report")
@click.option('--api-key', type=str, default=None, help="Gemini API key")
@click.option('--verbose', is_flag=True, help="Print stage-by-stage progress to stdout")
def scan(directory, profile, output, api_key, verbose):
    """Scan a target codebase directory for compliance gaps"""
    start_time = time.time()
    
    # Check API key
    key = api_key or os.environ.get("GEMINI_API_KEY")
    if not key:
        click.echo("Error: GEMINI_API_KEY is not set.", err=True)
        click.echo("Please set it via environment variable or use the --api-key option.", err=True)
        click.echo("Example: export GEMINI_API_KEY='your_key' or auditx scan . --api-key 'key'", err=True)
        sys.exit(1)

    if not output:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        output = f"./auditx_report_{timestamp}.html"

    # Stage 1: AST Extraction
    click.echo("[1/3] Scanning codebase...")
    extractor = ASTExtractor(directory)
    summary = extractor.scan()
    
    if summary.file_count == 0:
        click.echo(f"Warning: No valid source files (Python/JS) found in {directory}.", err=True)
        sys.exit(0)
    
    click.echo(f"      Found {summary.file_count} files.")

    # Stage 2: Gemini Analysis
    click.echo("[2/3] Analyzing compliance...")
    analyzer = GeminiClient(api_key=key)
    
    try:
        findings = analyzer.run_analysis(summary, profile)
        click.echo(f"      {len(findings)} findings identified.")
    except Exception as e:
        click.echo(f"Warning: API analysis failed: {str(e)}", err=True)
        findings = [] # Fallback, generate report anyway
        
    # Stage 3/4: Report Generation & Ruleset Enrichment
    click.echo("[3/3] Generating report...")
    duration = time.time() - start_time
    
    reporter = ReportBuilder()
    
    # Calculate metadata values before passing to reporter
    # We do a quick pre-calc to display results in CLI
    from auditx.compliance.ruleset import enrich_finding
    
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    enriched = []
    for f in findings:
        enf = enrich_finding(f)
        enriched.append(enf)
        sev = str(enf.get('severity', '')).upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
            
    # Calculate effort for CLI text
    days = (severity_counts['CRITICAL'] * 1.0) + (severity_counts['HIGH'] * 0.5) + (severity_counts['MEDIUM'] * 0.25)

    reporter.build_report(findings, summary, profile, duration, output)
    
    click.echo(f"\n  ✓ Scan complete. Report: {output}")
    click.echo(f"  Summary: {severity_counts['CRITICAL']} CRITICAL | {severity_counts['HIGH']} HIGH | {severity_counts['MEDIUM']} MEDIUM | {severity_counts['LOW']} LOW")
    click.echo(f"  Estimated remediation: ~{days:.1f} engineering days")

if __name__ == '__main__':
    cli()
