import os
from jinja2 import Environment, FileSystemLoader
from auditx.compliance.ruleset import enrich_finding
import datetime

class ReportBuilder:
    def __init__(self):
        templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(loader=FileSystemLoader(templates_dir))
        self.template = self.env.get_template('report.html')
        
    def _calculate_effort(self, summary) -> str:
        # CRITICAL×1day + HIGH×0.5day + MEDIUM×0.25day
        days = (summary['critical'] * 1.0) + (summary['high'] * 0.5) + (summary['medium'] * 0.25)
        return f"~{days:.1f} engineering days"

    def build_report(self, findings: list, codebase_summary, profile: str, duration: float, output_path: str):
        # 1. Enrich findings with ruleset match
        enriched_findings = []
        for finding in findings:
            enriched = enrich_finding(finding)
            enriched_findings.append(enriched)
            
        # 2. Calculate summary metrics
        severity_counts = {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0
        }
        for f in enriched_findings:
            sev = str(f.get('severity', '')).lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
                
        # 3. Prepare metadata
        effort = self._calculate_effort(severity_counts)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        metadata = {
            'version': "1.0.0",
            'directory': "Target Codebase", # Could be passed in specifically
            'profile': profile,
            'files_count': codebase_summary.file_count,
            'duration': f"{duration:.1f}",
            'timestamp': timestamp,
            'effort_days': effort
        }
        
        # 4. Render HTML
        html_content = self.template.render(
            findings=enriched_findings,
            summary=severity_counts,
            metadata=metadata
        )
        
        # 5. Write to output
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return output_path
