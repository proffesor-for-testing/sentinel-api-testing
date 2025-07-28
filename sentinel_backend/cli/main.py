#!/usr/bin/env python3
"""
Sentinel CLI - Command Line Interface for CI/CD Integration

This CLI tool provides command-line access to the Sentinel API testing platform,
enabling seamless integration with CI/CD pipelines like GitHub Actions, GitLab CI, and Jenkins.
"""

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import click
import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

# Import configuration
from config.settings import get_network_settings, get_application_settings

# Get configuration
network_settings = get_network_settings()
app_settings = get_application_settings()

console = Console()

class SentinelClient:
    """HTTP client for interacting with Sentinel API Gateway"""
    
    def __init__(self, base_url: str = "http://localhost:8000", timeout: int = 300):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout)
    
    async def upload_specification(self, spec_path: Path) -> Dict:
        """Upload API specification to Sentinel"""
        with open(spec_path, 'r') as f:
            spec_content = f.read()
        
        response = await self.client.post(
            f"{self.base_url}/specifications/",
            json={
                "name": spec_path.stem,
                "content": spec_content,
                "format": "openapi" if spec_path.suffix in ['.yaml', '.yml', '.json'] else "unknown"
            }
        )
        response.raise_for_status()
        return response.json()
    
    async def create_test_run(self, spec_id: str, test_types: List[str], config: Dict = None) -> Dict:
        """Create a new test run"""
        payload = {
            "specification_id": spec_id,
            "test_types": test_types,
            "config": config or {}
        }
        
        response = await self.client.post(
            f"{self.base_url}/test-runs/",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    async def get_test_run_status(self, run_id: str) -> Dict:
        """Get test run status and results"""
        response = await self.client.get(f"{self.base_url}/test-runs/{run_id}")
        response.raise_for_status()
        return response.json()
    
    async def wait_for_completion(self, run_id: str, poll_interval: int = 5) -> Dict:
        """Wait for test run to complete"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Running tests...", total=None)
            
            while True:
                result = await self.get_test_run_status(run_id)
                status = result.get('status', 'unknown')
                
                if status in ['completed', 'failed', 'error']:
                    progress.update(task, description=f"Test run {status}")
                    break
                
                progress.update(task, description=f"Test run {status}...")
                await asyncio.sleep(poll_interval)
        
        return result
    
    async def generate_mock_data(self, spec_id: str, strategy: str = "realistic", count: int = 10, seed: int = None) -> Dict:
        """Generate mock data using the Data Mocking Agent"""
        payload = {
            "spec_id": int(spec_id),
            "strategy": strategy,
            "count": count
        }
        
        if seed is not None:
            payload["seed"] = seed
        
        response = await self.client.post(
            f"{self.base_url}/generate-data",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()

@click.group()
@click.option('--base-url', default=f"http://localhost:{network_settings.api_gateway_port}", help='Sentinel API base URL')
@click.option('--timeout', default=app_settings.test_execution_timeout, help='Request timeout in seconds')
@click.pass_context
def cli(ctx, base_url, timeout):
    """Sentinel CLI - AI-powered API testing platform"""
    ctx.ensure_object(dict)
    ctx.obj['client'] = SentinelClient(base_url, timeout)

@cli.command()
@click.argument('spec_path', type=click.Path(exists=True, path_type=Path))
@click.option('--test-types', '-t', multiple=True, 
              type=click.Choice(['functional', 'security', 'performance']),
              default=['functional'], help='Types of tests to run')
@click.option('--wait/--no-wait', default=True, help='Wait for test completion')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output results to file')
@click.option('--format', type=click.Choice(['json', 'junit', 'html']), default='json', help='Output format')
@click.option('--fail-on-issues/--no-fail-on-issues', default=True, help='Exit with error code if issues found')
@click.pass_context
async def test(ctx, spec_path, test_types, wait, output, format, fail_on_issues):
    """Run API tests against a specification"""
    client = ctx.obj['client']
    
    try:
        # Upload specification
        console.print(f"📄 Uploading specification: {spec_path}")
        spec_result = await client.upload_specification(spec_path)
        spec_id = spec_result['id']
        console.print(f"✅ Specification uploaded with ID: {spec_id}")
        
        # Create test run
        console.print(f"🚀 Creating test run with types: {', '.join(test_types)}")
        run_result = await client.create_test_run(spec_id, list(test_types))
        run_id = run_result['id']
        console.print(f"✅ Test run created with ID: {run_id}")
        
        if wait:
            # Wait for completion
            final_result = await client.wait_for_completion(run_id)
            
            # Display results
            await display_results(final_result, format, output)
            
            # Exit with appropriate code
            if fail_on_issues and has_issues(final_result):
                console.print("❌ Tests completed with issues", style="red")
                sys.exit(1)
            else:
                console.print("✅ Tests completed successfully", style="green")
        else:
            console.print(f"🔄 Test run started. Check status with: sentinel status {run_id}")
            
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        sys.exit(1)
    finally:
        await client.close()

@cli.command()
@click.argument('run_id')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output results to file')
@click.option('--format', type=click.Choice(['json', 'junit', 'html']), default='json', help='Output format')
@click.pass_context
async def status(ctx, run_id, output, format):
    """Check status of a test run"""
    client = ctx.obj['client']
    
    try:
        result = await client.get_test_run_status(run_id)
        await display_results(result, format, output)
        
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        sys.exit(1)
    finally:
        await client.close()

@cli.command()
@click.argument('spec_path', type=click.Path(exists=True, path_type=Path))
@click.pass_context
async def validate(ctx, spec_path):
    """Validate an API specification"""
    client = ctx.obj['client']
    
    try:
        console.print(f"🔍 Validating specification: {spec_path}")
        spec_result = await client.upload_specification(spec_path)
        
        # Display validation results
        validation = spec_result.get('validation', {})
        if validation.get('valid', True):
            console.print("✅ Specification is valid", style="green")
        else:
            console.print("❌ Specification has issues:", style="red")
            for issue in validation.get('issues', []):
                console.print(f"  • {issue}")
                
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        sys.exit(1)
    finally:
        await client.close()

@cli.command()
@click.argument('spec_path', type=click.Path(exists=True, path_type=Path))
@click.option('--strategy', type=click.Choice(['realistic', 'edge_cases', 'invalid', 'boundary']), 
              default='realistic', help='Data generation strategy')
@click.option('--count', default=10, help='Number of data samples to generate')
@click.option('--seed', type=int, help='Random seed for reproducible data generation')
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file for generated data')
@click.pass_context
async def generate_data(ctx, spec_path, strategy, count, seed, output):
    """Generate mock data from API specification"""
    client = ctx.obj['client']
    
    try:
        # Upload specification
        console.print(f"📄 Uploading specification: {spec_path}")
        spec_result = await client.upload_specification(spec_path)
        spec_id = spec_result['id']
        console.print(f"✅ Specification uploaded with ID: {spec_id}")
        
        # Generate mock data
        console.print(f"🎲 Generating mock data with strategy: {strategy}")
        data_result = await client.generate_mock_data(spec_id, strategy, count, seed)
        
        # Display summary
        metadata = data_result.get('metadata', {})
        console.print(f"✅ Mock data generated successfully")
        console.print(f"  • Total endpoints: {metadata.get('total_endpoints', 0)}")
        console.print(f"  • Schemas analyzed: {metadata.get('schemas_analyzed', 0)}")
        console.print(f"  • Data relationships: {metadata.get('data_relationships', 0)}")
        
        # Save to file if requested
        if output:
            with open(output, 'w') as f:
                json.dump(data_result, f, indent=2)
            console.print(f"📄 Mock data saved to: {output}")
        else:
            # Display sample data
            mock_data = data_result.get('mock_data', {})
            if mock_data:
                console.print("\n📊 Sample Generated Data:")
                for path, methods in list(mock_data.items())[:3]:  # Show first 3 endpoints
                    console.print(f"  {path}:")
                    for method, data in methods.items():
                        if data.get('request_bodies'):
                            sample = data['request_bodies'][0]['data']
                            console.print(f"    {method.upper()}: {json.dumps(sample, indent=2)[:100]}...")
                            break
                
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        sys.exit(1)
    finally:
        await client.close()

async def display_results(result: Dict, format: str, output: Optional[Path]):
    """Display test results in the specified format"""
    status = result.get('status', 'unknown')
    
    # Create summary table
    table = Table(title=f"Test Run Results - Status: {status.upper()}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    # Add basic metrics
    table.add_row("Run ID", result.get('id', 'N/A'))
    table.add_row("Status", status)
    table.add_row("Total Tests", str(result.get('total_tests', 0)))
    table.add_row("Passed", str(result.get('passed_tests', 0)))
    table.add_row("Failed", str(result.get('failed_tests', 0)))
    table.add_row("Duration", f"{result.get('duration', 0):.2f}s")
    
    console.print(table)
    
    # Show issues if any
    issues = result.get('issues', [])
    if issues:
        console.print("\n🚨 Issues Found:")
        for issue in issues[:10]:  # Show first 10 issues
            severity = issue.get('severity', 'unknown')
            color = {'high': 'red', 'medium': 'yellow', 'low': 'blue'}.get(severity, 'white')
            console.print(f"  • [{color}]{severity.upper()}[/{color}]: {issue.get('message', 'No message')}")
        
        if len(issues) > 10:
            console.print(f"  ... and {len(issues) - 10} more issues")
    
    # Output to file if requested
    if output:
        if format == 'json':
            with open(output, 'w') as f:
                json.dump(result, f, indent=2)
        elif format == 'junit':
            junit_xml = generate_junit_xml(result)
            with open(output, 'w') as f:
                f.write(junit_xml)
        elif format == 'html':
            html_report = generate_html_report(result)
            with open(output, 'w') as f:
                f.write(html_report)
        
        console.print(f"📄 Results saved to: {output}")

def has_issues(result: Dict) -> bool:
    """Check if test results contain any issues"""
    return (
        result.get('failed_tests', 0) > 0 or
        len(result.get('issues', [])) > 0 or
        result.get('status') in ['failed', 'error']
    )

def generate_junit_xml(result: Dict) -> str:
    """Generate JUnit XML format for CI/CD integration"""
    total_tests = result.get('total_tests', 0)
    failed_tests = result.get('failed_tests', 0)
    duration = result.get('duration', 0)
    
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="Sentinel API Tests" tests="{total_tests}" failures="{failed_tests}" time="{duration}">
'''
    
    # Add test cases
    for issue in result.get('issues', []):
        test_name = issue.get('test_case', 'Unknown Test')
        xml += f'  <testcase name="{test_name}" classname="SentinelTest">\n'
        if issue.get('severity') in ['high', 'medium']:
            xml += f'    <failure message="{issue.get("message", "")}">{issue.get("details", "")}</failure>\n'
        xml += '  </testcase>\n'
    
    xml += '</testsuite>'
    return xml

def generate_html_report(result: Dict) -> str:
    """Generate HTML report for human-readable results"""
    status = result.get('status', 'unknown')
    status_color = {'completed': 'green', 'failed': 'red', 'error': 'orange'}.get(status, 'gray')
    
    html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Sentinel Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .status {{ color: {status_color}; font-weight: bold; }}
        .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .metric {{ background: #f9f9f9; padding: 15px; border-radius: 5px; text-align: center; }}
        .issues {{ margin-top: 20px; }}
        .issue {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }}
        .high {{ border-color: red; }}
        .medium {{ border-color: orange; }}
        .low {{ border-color: blue; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Sentinel API Test Report</h1>
        <p>Status: <span class="status">{status.upper()}</span></p>
        <p>Run ID: {result.get('id', 'N/A')}</p>
    </div>
    
    <div class="metrics">
        <div class="metric">
            <h3>{result.get('total_tests', 0)}</h3>
            <p>Total Tests</p>
        </div>
        <div class="metric">
            <h3>{result.get('passed_tests', 0)}</h3>
            <p>Passed</p>
        </div>
        <div class="metric">
            <h3>{result.get('failed_tests', 0)}</h3>
            <p>Failed</p>
        </div>
    </div>
'''
    
    issues = result.get('issues', [])
    if issues:
        html += '<div class="issues"><h2>Issues Found</h2>'
        for issue in issues:
            severity = issue.get('severity', 'unknown')
            html += f'''
            <div class="issue {severity}">
                <strong>{severity.upper()}</strong>: {issue.get('message', 'No message')}
                <br><small>{issue.get('details', '')}</small>
            </div>
            '''
        html += '</div>'
    
    html += '</body></html>'
    return html

def main():
    """Main entry point for the CLI"""
    # Convert sync click to async
    import asyncio
    
    def async_cli():
        return asyncio.run(cli(standalone_mode=False))
    
    try:
        cli()
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"❌ Unexpected error: {e}", style="red")
        sys.exit(1)

if __name__ == '__main__':
    main()
