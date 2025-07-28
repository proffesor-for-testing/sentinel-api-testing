#!/usr/bin/env python3
"""
Configuration management CLI tool for Sentinel.

This tool provides utilities for managing configuration files,
validating settings, migrating configurations, and troubleshooting
configuration issues.
"""

import os
import sys
import json
import shutil
import argparse
from pathlib import Path
from typing import Dict, Any, Optional
import tempfile
from datetime import datetime

from .validation import ConfigurationValidator, ConfigurationReporter, validate_startup_configuration
from .settings import get_database_settings, get_service_settings, get_application_settings

class ConfigurationManager:
    """Configuration management utilities."""
    
    def __init__(self):
        """Initialize configuration manager."""
        self.config_dir = Path(__file__).parent
        self.backup_dir = self.config_dir / "backups"
        self.backup_dir.mkdir(exist_ok=True)
    
    def validate_config(self, environment: Optional[str] = None) -> bool:
        """Validate configuration for specified environment."""
        if environment:
            os.environ["SENTINEL_ENVIRONMENT"] = environment
        
        print(f"🔍 Validating configuration for environment: {os.getenv('SENTINEL_ENVIRONMENT', 'development')}")
        return validate_startup_configuration()
    
    def generate_report(self, output_format: str = "text", output_file: Optional[str] = None) -> bool:
        """Generate configuration report."""
        print("📊 Generating configuration report...")
        
        report = ConfigurationReporter.generate_report()
        
        if output_format == "json":
            content = json.dumps(report, indent=2)
        else:
            # Capture text report
            import io
            from contextlib import redirect_stdout
            
            f = io.StringIO()
            with redirect_stdout(f):
                ConfigurationReporter.print_report(report)
            content = f.getvalue()
        
        if output_file:
            Path(output_file).write_text(content)
            print(f"✅ Report saved to: {output_file}")
        else:
            print(content)
        
        return True
    
    def backup_config(self, name: Optional[str] = None) -> str:
        """Create backup of current configuration."""
        if not name:
            name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        backup_path = self.backup_dir / name
        backup_path.mkdir(exist_ok=True)
        
        print(f"💾 Creating configuration backup: {name}")
        
        # Backup all environment files
        env_files = ["development.env", "testing.env", "production.env", "docker.env"]
        
        for env_file in env_files:
            source = self.config_dir / env_file
            if source.exists():
                destination = backup_path / env_file
                shutil.copy2(source, destination)
                print(f"  ✅ Backed up: {env_file}")
        
        # Backup settings.py
        settings_source = self.config_dir / "settings.py"
        if settings_source.exists():
            settings_dest = backup_path / "settings.py"
            shutil.copy2(settings_source, settings_dest)
            print(f"  ✅ Backed up: settings.py")
        
        # Create backup metadata
        metadata = {
            "name": name,
            "timestamp": datetime.now().isoformat(),
            "environment": os.getenv("SENTINEL_ENVIRONMENT", "development"),
            "files": env_files + ["settings.py"]
        }
        
        metadata_file = backup_path / "metadata.json"
        metadata_file.write_text(json.dumps(metadata, indent=2))
        
        print(f"✅ Configuration backup created: {backup_path}")
        return str(backup_path)
    
    def restore_config(self, backup_name: str) -> bool:
        """Restore configuration from backup."""
        backup_path = self.backup_dir / backup_name
        
        if not backup_path.exists():
            print(f"❌ Backup not found: {backup_name}")
            return False
        
        print(f"🔄 Restoring configuration from backup: {backup_name}")
        
        # Read backup metadata
        metadata_file = backup_path / "metadata.json"
        if metadata_file.exists():
            metadata = json.loads(metadata_file.read_text())
            print(f"  📅 Backup created: {metadata.get('timestamp', 'unknown')}")
            print(f"  🌍 Environment: {metadata.get('environment', 'unknown')}")
        
        # Restore files
        for file_path in backup_path.glob("*.env"):
            destination = self.config_dir / file_path.name
            shutil.copy2(file_path, destination)
            print(f"  ✅ Restored: {file_path.name}")
        
        # Restore settings.py if it exists
        settings_backup = backup_path / "settings.py"
        if settings_backup.exists():
            settings_dest = self.config_dir / "settings.py"
            shutil.copy2(settings_backup, settings_dest)
            print(f"  ✅ Restored: settings.py")
        
        print("✅ Configuration restored successfully")
        return True
    
    def list_backups(self) -> None:
        """List available configuration backups."""
        print("📋 Available configuration backups:")
        
        if not self.backup_dir.exists() or not any(self.backup_dir.iterdir()):
            print("  No backups found")
            return
        
        for backup_dir in sorted(self.backup_dir.iterdir()):
            if backup_dir.is_dir():
                metadata_file = backup_dir / "metadata.json"
                if metadata_file.exists():
                    try:
                        metadata = json.loads(metadata_file.read_text())
                        timestamp = metadata.get('timestamp', 'unknown')
                        environment = metadata.get('environment', 'unknown')
                        print(f"  📁 {backup_dir.name}")
                        print(f"    📅 Created: {timestamp}")
                        print(f"    🌍 Environment: {environment}")
                    except Exception:
                        print(f"  📁 {backup_dir.name} (metadata corrupted)")
                else:
                    print(f"  📁 {backup_dir.name} (no metadata)")
    
    def migrate_config(self, from_version: str, to_version: str) -> bool:
        """Migrate configuration between versions."""
        print(f"🔄 Migrating configuration from {from_version} to {to_version}")
        
        # Create backup before migration
        backup_name = f"pre_migration_{from_version}_to_{to_version}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.backup_config(backup_name)
        
        # Perform migration based on version
        if from_version == "1.0" and to_version == "1.1":
            return self._migrate_1_0_to_1_1()
        else:
            print(f"❌ Migration path from {from_version} to {to_version} not supported")
            return False
    
    def _migrate_1_0_to_1_1(self) -> bool:
        """Migrate from version 1.0 to 1.1."""
        print("  🔧 Applying migration 1.0 -> 1.1")
        
        # Example migration: add new configuration keys
        for env_file in ["development.env", "testing.env", "production.env", "docker.env"]:
            file_path = self.config_dir / env_file
            if file_path.exists():
                content = file_path.read_text()
                
                # Add new configuration keys if they don't exist
                new_keys = [
                    "# New in v1.1",
                    "SENTINEL_APP_CACHE_ENABLED=true",
                    "SENTINEL_APP_CACHE_TTL_SECONDS=300",
                    "SENTINEL_APP_METRICS_ENABLED=true",
                    "SENTINEL_APP_TRACING_ENABLED=false"
                ]
                
                for key in new_keys:
                    if key not in content:
                        content += f"\n{key}"
                
                file_path.write_text(content)
                print(f"    ✅ Updated: {env_file}")
        
        print("  ✅ Migration completed successfully")
        return True
    
    def check_environment_consistency(self) -> bool:
        """Check consistency across environment files."""
        print("🔍 Checking environment consistency...")
        
        env_files = ["development.env", "testing.env", "production.env", "docker.env"]
        all_keys = set()
        file_keys = {}
        
        # Collect all keys from all files
        for env_file in env_files:
            file_path = self.config_dir / env_file
            if file_path.exists():
                keys = set()
                for line in file_path.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key = line.split('=')[0]
                        keys.add(key)
                        all_keys.add(key)
                file_keys[env_file] = keys
        
        # Check for missing keys
        inconsistencies = []
        for env_file, keys in file_keys.items():
            missing_keys = all_keys - keys
            if missing_keys:
                inconsistencies.append(f"{env_file} missing keys: {', '.join(sorted(missing_keys))}")
        
        if inconsistencies:
            print("❌ Environment inconsistencies found:")
            for inconsistency in inconsistencies:
                print(f"  • {inconsistency}")
            return False
        else:
            print("✅ All environment files are consistent")
            return True
    
    def generate_template(self, environment: str, output_file: Optional[str] = None) -> bool:
        """Generate configuration template for specified environment."""
        print(f"📝 Generating configuration template for: {environment}")
        
        template_content = f"""# Sentinel {environment.title()} Environment Configuration
# Generated on {datetime.now().isoformat()}

# Environment
SENTINEL_ENVIRONMENT={environment}

# Database Settings
SENTINEL_DB_URL=postgresql+asyncpg://sentinel_user:sentinel_password@localhost:5432/sentinel_db
SENTINEL_DB_POOL_SIZE=10
SENTINEL_DB_MAX_OVERFLOW=20
SENTINEL_DB_POOL_TIMEOUT=30
SENTINEL_DB_POOL_RECYCLE=3600
SENTINEL_DB_AUTO_MIGRATE=true
SENTINEL_DB_MIGRATION_TIMEOUT=120

# Service URLs
SENTINEL_SERVICE_AUTH_SERVICE_URL=http://auth_service:8000
SENTINEL_SERVICE_SPEC_SERVICE_URL=http://spec_service:8000
SENTINEL_SERVICE_ORCHESTRATION_SERVICE_URL=http://orchestration_service:8000
SENTINEL_SERVICE_DATA_SERVICE_URL=http://data_service:8000
SENTINEL_SERVICE_EXECUTION_SERVICE_URL=http://execution_service:8000

# Service Timeouts
SENTINEL_SERVICE_SERVICE_TIMEOUT=30
SENTINEL_SERVICE_HEALTH_CHECK_TIMEOUT=5
SENTINEL_SERVICE_HEALTH_CHECK_INTERVAL=30

# Security Settings
SENTINEL_SECURITY_JWT_SECRET_KEY=your-secret-key-here-must-be-at-least-32-characters-long
SENTINEL_SECURITY_JWT_ALGORITHM=HS256
SENTINEL_SECURITY_JWT_EXPIRATION_HOURS=24

# Password Policy
SENTINEL_SECURITY_PASSWORD_MIN_LENGTH=8
SENTINEL_SECURITY_PASSWORD_REQUIRE_UPPERCASE=true
SENTINEL_SECURITY_PASSWORD_REQUIRE_LOWERCASE=true
SENTINEL_SECURITY_PASSWORD_REQUIRE_NUMBERS=true
SENTINEL_SECURITY_PASSWORD_REQUIRE_SPECIAL=true

# Session Settings
SENTINEL_SECURITY_SESSION_TIMEOUT_MINUTES=30
SENTINEL_SECURITY_MAX_LOGIN_ATTEMPTS=5
SENTINEL_SECURITY_LOCKOUT_DURATION_MINUTES=15

# CORS Settings
SENTINEL_SECURITY_CORS_ORIGINS=["http://localhost:3000"]
SENTINEL_SECURITY_CORS_ALLOW_CREDENTIALS=true

# Rate Limiting
SENTINEL_SECURITY_RATE_LIMIT_REQUESTS=100
SENTINEL_SECURITY_RATE_LIMIT_WINDOW_SECONDS=60

# Default Admin User
SENTINEL_SECURITY_DEFAULT_ADMIN_EMAIL=admin@sentinel.local
SENTINEL_SECURITY_DEFAULT_ADMIN_PASSWORD=change-this-password

# Network Settings
SENTINEL_NETWORK_API_GATEWAY_PORT=8000
SENTINEL_NETWORK_AUTH_SERVICE_PORT=8005
SENTINEL_NETWORK_SPEC_SERVICE_PORT=8001
SENTINEL_NETWORK_ORCHESTRATION_SERVICE_PORT=8002
SENTINEL_NETWORK_EXECUTION_SERVICE_PORT=8003
SENTINEL_NETWORK_DATA_SERVICE_PORT=8004
SENTINEL_NETWORK_DATABASE_PORT=5432
SENTINEL_NETWORK_HOST=0.0.0.0

# Timeout Settings
SENTINEL_NETWORK_HTTP_TIMEOUT=30
SENTINEL_NETWORK_WEBSOCKET_TIMEOUT=60

# Application Settings
SENTINEL_APP_DEBUG={"true" if environment == "development" else "false"}
SENTINEL_APP_LOG_LEVEL={"DEBUG" if environment == "development" else "INFO"}
SENTINEL_APP_LOG_FILE=null

# Pagination
SENTINEL_APP_DEFAULT_PAGE_SIZE=20
SENTINEL_APP_MAX_PAGE_SIZE=100

# Feature Flags
SENTINEL_APP_ENABLE_ANALYTICS=true
SENTINEL_APP_ENABLE_PERFORMANCE_TESTING=true
SENTINEL_APP_ENABLE_SECURITY_TESTING=true
SENTINEL_APP_ENABLE_DATA_MOCKING=true

# Agent Settings
SENTINEL_APP_MAX_CONCURRENT_AGENTS=5
SENTINEL_APP_AGENT_TIMEOUT_SECONDS=300

# Test Settings
SENTINEL_APP_MAX_TEST_CASES_PER_SPEC=1000
SENTINEL_APP_TEST_EXECUTION_TIMEOUT=300

# LLM Settings
SENTINEL_APP_LLM_PROVIDER=openai
SENTINEL_APP_LLM_API_KEY=your-llm-api-key-here
SENTINEL_APP_LLM_MODEL=gpt-3.5-turbo
SENTINEL_APP_LLM_MAX_TOKENS=2000
SENTINEL_APP_LLM_TEMPERATURE=0.7

# Cache Settings
SENTINEL_APP_CACHE_ENABLED=true
SENTINEL_APP_CACHE_TTL_SECONDS=300

# Monitoring Settings
SENTINEL_APP_METRICS_ENABLED={"true" if environment == "production" else "false"}
SENTINEL_APP_TRACING_ENABLED={"true" if environment == "production" else "false"}

# Application Info
SENTINEL_APP_APP_NAME=Sentinel API Testing Platform
SENTINEL_APP_APP_VERSION=1.0.0
"""
        
        if output_file:
            Path(output_file).write_text(template_content)
            print(f"✅ Template saved to: {output_file}")
        else:
            output_file = self.config_dir / f"{environment}_template.env"
            output_file.write_text(template_content)
            print(f"✅ Template saved to: {output_file}")
        
        return True

def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="Sentinel Configuration Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m config.manage validate --environment production
  python -m config.manage report --format json --output config_report.json
  python -m config.manage backup --name pre_deployment
  python -m config.manage restore pre_deployment
  python -m config.manage template --environment production --output prod.env
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate configuration')
    validate_parser.add_argument('--environment', help='Environment to validate')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate configuration report')
    report_parser.add_argument('--format', choices=['text', 'json'], default='text', help='Output format')
    report_parser.add_argument('--output', help='Output file path')
    
    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Create configuration backup')
    backup_parser.add_argument('--name', help='Backup name')
    
    # Restore command
    restore_parser = subparsers.add_parser('restore', help='Restore configuration from backup')
    restore_parser.add_argument('backup_name', help='Name of backup to restore')
    
    # List backups command
    subparsers.add_parser('list-backups', help='List available backups')
    
    # Migrate command
    migrate_parser = subparsers.add_parser('migrate', help='Migrate configuration between versions')
    migrate_parser.add_argument('--from-version', required=True, help='Source version')
    migrate_parser.add_argument('--to-version', required=True, help='Target version')
    
    # Check consistency command
    subparsers.add_parser('check-consistency', help='Check environment file consistency')
    
    # Generate template command
    template_parser = subparsers.add_parser('template', help='Generate configuration template')
    template_parser.add_argument('--environment', required=True, help='Environment name')
    template_parser.add_argument('--output', help='Output file path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    manager = ConfigurationManager()
    
    try:
        if args.command == 'validate':
            success = manager.validate_config(args.environment)
            sys.exit(0 if success else 1)
        
        elif args.command == 'report':
            manager.generate_report(args.format, args.output)
        
        elif args.command == 'backup':
            manager.backup_config(args.name)
        
        elif args.command == 'restore':
            success = manager.restore_config(args.backup_name)
            sys.exit(0 if success else 1)
        
        elif args.command == 'list-backups':
            manager.list_backups()
        
        elif args.command == 'migrate':
            success = manager.migrate_config(args.from_version, args.to_version)
            sys.exit(0 if success else 1)
        
        elif args.command == 'check-consistency':
            success = manager.check_environment_consistency()
            sys.exit(0 if success else 1)
        
        elif args.command == 'template':
            manager.generate_template(args.environment, args.output)
    
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
