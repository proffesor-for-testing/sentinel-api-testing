#!/usr/bin/env python3
"""
Database Diagnostics Tool for Sentinel
Comprehensive diagnostics and troubleshooting for PostgreSQL issues

This script provides:
- Detailed connection diagnostics
- Table and index analysis
- Vector operation testing
- Performance profiling
- Lock detection
- Replication status (if applicable)
- Recovery recommendations
"""

import os
import sys
import time
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'database': os.getenv('DB_NAME', 'sentinel_db'),
    'user': os.getenv('DB_USER', 'sentinel'),
    'password': os.getenv('DB_PASSWORD', 'sentinel_password'),
    'connect_timeout': 5
}


class DatabaseDiagnostics:
    """Comprehensive database diagnostics"""

    def __init__(self):
        self.conn = None
        self.diagnostics = {
            'timestamp': datetime.utcnow().isoformat(),
            'connection': {},
            'extensions': {},
            'tables': {},
            'indexes': {},
            'performance': {},
            'locks': {},
            'issues': [],
            'recommendations': []
        }

    def connect(self) -> bool:
        """Establish database connection"""
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            self.conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            logger.info("✓ Connected to database")
            return True
        except Exception as e:
            logger.error(f"✗ Connection failed: {e}")
            self.diagnostics['connection']['error'] = str(e)
            self.diagnostics['issues'].append({
                'severity': 'critical',
                'category': 'connection',
                'message': f"Cannot connect to database: {e}"
            })
            return False

    def check_connection_info(self):
        """Gather connection and server information"""
        logger.info("\n" + "=" * 60)
        logger.info("CONNECTION DIAGNOSTICS")
        logger.info("=" * 60)

        try:
            cursor = self.conn.cursor()

            # Server version
            cursor.execute("SELECT version();")
            version = cursor.fetchone()[0]
            logger.info(f"PostgreSQL Version: {version.split(',')[0]}")
            self.diagnostics['connection']['version'] = version

            # Current database
            cursor.execute("SELECT current_database(), current_user, inet_server_addr(), inet_server_port();")
            db, user, host, port = cursor.fetchone()
            logger.info(f"Database: {db}")
            logger.info(f"User: {user}")
            logger.info(f"Host: {host}:{port}")

            self.diagnostics['connection'].update({
                'database': db,
                'user': user,
                'host': str(host) if host else 'unix_socket',
                'port': port
            })

            # Connection count
            cursor.execute("""
                SELECT count(*), state
                FROM pg_stat_activity
                WHERE datname = current_database()
                GROUP BY state;
            """)
            connections = dict(cursor.fetchall())
            logger.info(f"Active connections: {connections}")
            self.diagnostics['connection']['active_connections'] = connections

            cursor.close()

        except Exception as e:
            logger.error(f"Connection info check failed: {e}")
            self.diagnostics['issues'].append({
                'severity': 'high',
                'category': 'connection',
                'message': f"Failed to gather connection info: {e}"
            })

    def check_extensions(self):
        """Check installed extensions"""
        logger.info("\n" + "=" * 60)
        logger.info("EXTENSION DIAGNOSTICS")
        logger.info("=" * 60)

        try:
            cursor = self.conn.cursor()

            # List all extensions
            cursor.execute("""
                SELECT extname, extversion, extrelocatable
                FROM pg_extension
                ORDER BY extname;
            """)

            extensions = {}
            for name, version, relocatable in cursor.fetchall():
                logger.info(f"✓ {name} v{version}")
                extensions[name] = {
                    'version': version,
                    'relocatable': relocatable
                }

            self.diagnostics['extensions'] = extensions

            # Check pgvector specifically
            if 'vector' not in extensions:
                logger.error("✗ pgvector extension NOT installed")
                self.diagnostics['issues'].append({
                    'severity': 'critical',
                    'category': 'extensions',
                    'message': 'pgvector extension is not installed'
                })
                self.diagnostics['recommendations'].append(
                    "Install pgvector: CREATE EXTENSION vector;"
                )
            else:
                # Test vector operations
                try:
                    cursor.execute("SELECT '[1,2,3]'::vector <-> '[4,5,6]'::vector;")
                    distance = cursor.fetchone()[0]
                    logger.info(f"✓ pgvector functional (test distance: {distance})")
                except Exception as e:
                    logger.error(f"✗ pgvector test failed: {e}")
                    self.diagnostics['issues'].append({
                        'severity': 'high',
                        'category': 'extensions',
                        'message': f'pgvector not functional: {e}'
                    })

            cursor.close()

        except Exception as e:
            logger.error(f"Extension check failed: {e}")
            self.diagnostics['issues'].append({
                'severity': 'high',
                'category': 'extensions',
                'message': f"Failed to check extensions: {e}"
            })

    def check_tables(self):
        """Analyze table structure and data"""
        logger.info("\n" + "=" * 60)
        logger.info("TABLE DIAGNOSTICS")
        logger.info("=" * 60)

        try:
            cursor = self.conn.cursor()

            # Get all tables with row counts and sizes
            cursor.execute("""
                SELECT
                    schemaname || '.' || tablename as table_name,
                    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                    pg_total_relation_size(schemaname||'.'||tablename) as bytes,
                    n_live_tup as row_count,
                    n_dead_tup as dead_rows,
                    last_vacuum,
                    last_autovacuum
                FROM pg_stat_user_tables
                ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
            """)

            tables = {}
            for row in cursor.fetchall():
                table, size, bytes_val, rows, dead, vacuum, autovacuum = row

                logger.info(f"\nTable: {table}")
                logger.info(f"  Size: {size}")
                logger.info(f"  Rows: {rows:,} (dead: {dead:,})")

                tables[table] = {
                    'size': size,
                    'bytes': bytes_val,
                    'row_count': rows,
                    'dead_rows': dead,
                    'last_vacuum': str(vacuum) if vacuum else None,
                    'last_autovacuum': str(autovacuum) if autovacuum else None
                }

                # Check for issues
                if dead and rows and (dead / rows) > 0.2:
                    logger.warning(f"  ⚠️  High dead row ratio: {dead}/{rows}")
                    self.diagnostics['issues'].append({
                        'severity': 'medium',
                        'category': 'tables',
                        'message': f'Table {table} has high dead row ratio'
                    })
                    self.diagnostics['recommendations'].append(
                        f"Consider VACUUM ANALYZE {table};"
                    )

            self.diagnostics['tables'] = tables

            # Check for missing required tables
            required_tables = [
                'public.users', 'public.projects', 'public.api_specifications',
                'public.test_cases', 'public.test_suites', 'public.test_runs',
                'public.test_results'
            ]

            missing = set(required_tables) - set(tables.keys())
            if missing:
                logger.error(f"\n✗ Missing required tables: {missing}")
                self.diagnostics['issues'].append({
                    'severity': 'critical',
                    'category': 'tables',
                    'message': f'Missing tables: {", ".join(missing)}'
                })
                self.diagnostics['recommendations'].append(
                    "Run initialization script: python3 sentinel_backend/init_database.py"
                )

            cursor.close()

        except Exception as e:
            logger.error(f"Table check failed: {e}")
            self.diagnostics['issues'].append({
                'severity': 'high',
                'category': 'tables',
                'message': f"Failed to analyze tables: {e}"
            })

    def check_indexes(self):
        """Analyze index health and usage"""
        logger.info("\n" + "=" * 60)
        logger.info("INDEX DIAGNOSTICS")
        logger.info("=" * 60)

        try:
            cursor = self.conn.cursor()

            # Get index statistics
            cursor.execute("""
                SELECT
                    schemaname || '.' || tablename as table_name,
                    indexname,
                    pg_size_pretty(pg_relation_size(schemaname||'.'||indexname)) as size,
                    idx_scan as scans,
                    idx_tup_read as tuples_read,
                    idx_tup_fetch as tuples_fetched
                FROM pg_stat_user_indexes
                ORDER BY pg_relation_size(schemaname||'.'||indexname) DESC;
            """)

            indexes = {}
            unused_indexes = []

            for row in cursor.fetchall():
                table, idx_name, size, scans, reads, fetches = row

                logger.info(f"\nIndex: {idx_name}")
                logger.info(f"  Table: {table}")
                logger.info(f"  Size: {size}")
                logger.info(f"  Scans: {scans:,}")

                indexes[idx_name] = {
                    'table': table,
                    'size': size,
                    'scans': scans,
                    'tuples_read': reads,
                    'tuples_fetched': fetches
                }

                # Warn about unused indexes
                if scans == 0:
                    logger.warning(f"  ⚠️  Index never used")
                    unused_indexes.append(idx_name)

            self.diagnostics['indexes'] = indexes

            if unused_indexes:
                self.diagnostics['recommendations'].append(
                    f"Consider dropping unused indexes: {', '.join(unused_indexes)}"
                )

            cursor.close()

        except Exception as e:
            logger.error(f"Index check failed: {e}")
            self.diagnostics['issues'].append({
                'severity': 'medium',
                'category': 'indexes',
                'message': f"Failed to analyze indexes: {e}"
            })

    def check_performance(self):
        """Profile query performance"""
        logger.info("\n" + "=" * 60)
        logger.info("PERFORMANCE DIAGNOSTICS")
        logger.info("=" * 60)

        try:
            cursor = self.conn.cursor()

            # Check cache hit ratio
            cursor.execute("""
                SELECT
                    sum(heap_blks_read) as heap_read,
                    sum(heap_blks_hit)  as heap_hit,
                    sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read)) * 100 as ratio
                FROM pg_statio_user_tables;
            """)

            heap_read, heap_hit, ratio = cursor.fetchone()
            if ratio:
                logger.info(f"Cache hit ratio: {ratio:.2f}%")
                self.diagnostics['performance']['cache_hit_ratio'] = round(ratio, 2)

                if ratio < 90:
                    logger.warning("⚠️  Low cache hit ratio")
                    self.diagnostics['issues'].append({
                        'severity': 'medium',
                        'category': 'performance',
                        'message': f'Low cache hit ratio: {ratio:.2f}%'
                    })
                    self.diagnostics['recommendations'].append(
                        "Consider increasing shared_buffers configuration"
                    )

            # Check for slow queries (if pg_stat_statements available)
            try:
                cursor.execute("""
                    SELECT
                        query,
                        calls,
                        total_exec_time,
                        mean_exec_time,
                        max_exec_time
                    FROM pg_stat_statements
                    ORDER BY mean_exec_time DESC
                    LIMIT 5;
                """)

                slow_queries = []
                for query, calls, total, mean, max_time in cursor.fetchall():
                    slow_queries.append({
                        'query': query[:100],
                        'calls': calls,
                        'mean_time_ms': round(mean, 2),
                        'max_time_ms': round(max_time, 2)
                    })

                if slow_queries:
                    logger.info("\nTop slow queries:")
                    for q in slow_queries:
                        logger.info(f"  {q['query'][:50]}... (mean: {q['mean_time_ms']}ms)")

                    self.diagnostics['performance']['slow_queries'] = slow_queries

            except:
                logger.info("pg_stat_statements not available (optional)")

            # Simple query performance test
            start = time.time()
            cursor.execute("SELECT 1;")
            cursor.fetchone()
            simple_latency = (time.time() - start) * 1000

            logger.info(f"Simple query latency: {simple_latency:.2f}ms")
            self.diagnostics['performance']['simple_query_ms'] = round(simple_latency, 2)

            if simple_latency > 100:
                logger.warning("⚠️  High query latency")
                self.diagnostics['issues'].append({
                    'severity': 'high',
                    'category': 'performance',
                    'message': f'High query latency: {simple_latency:.2f}ms'
                })

            cursor.close()

        except Exception as e:
            logger.error(f"Performance check failed: {e}")
            self.diagnostics['issues'].append({
                'severity': 'medium',
                'category': 'performance',
                'message': f"Failed to check performance: {e}"
            })

    def check_locks(self):
        """Check for blocking locks"""
        logger.info("\n" + "=" * 60)
        logger.info("LOCK DIAGNOSTICS")
        logger.info("=" * 60)

        try:
            cursor = self.conn.cursor()

            cursor.execute("""
                SELECT
                    l.pid,
                    l.mode,
                    l.granted,
                    a.query,
                    a.state,
                    age(now(), a.query_start) as duration
                FROM pg_locks l
                JOIN pg_stat_activity a ON l.pid = a.pid
                WHERE l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
                AND a.pid != pg_backend_pid()
                ORDER BY a.query_start;
            """)

            locks = []
            blocked = []

            for pid, mode, granted, query, state, duration in cursor.fetchall():
                lock_info = {
                    'pid': pid,
                    'mode': mode,
                    'granted': granted,
                    'query': query[:100] if query else None,
                    'state': state,
                    'duration': str(duration)
                }
                locks.append(lock_info)

                if not granted:
                    logger.warning(f"⚠️  Blocked lock: PID {pid}, mode {mode}")
                    blocked.append(lock_info)

            if locks:
                logger.info(f"Total locks: {len(locks)} (blocked: {len(blocked)})")
                self.diagnostics['locks'] = {
                    'total': len(locks),
                    'blocked': len(blocked),
                    'details': locks[:10]  # Limit to first 10
                }

                if blocked:
                    self.diagnostics['issues'].append({
                        'severity': 'high',
                        'category': 'locks',
                        'message': f'{len(blocked)} blocked queries detected'
                    })
            else:
                logger.info("No problematic locks detected")

            cursor.close()

        except Exception as e:
            logger.error(f"Lock check failed: {e}")
            self.diagnostics['issues'].append({
                'severity': 'low',
                'category': 'locks',
                'message': f"Failed to check locks: {e}"
            })

    def run_full_diagnostics(self) -> dict:
        """Run all diagnostic checks"""
        logger.info("\n" + "=" * 60)
        logger.info("SENTINEL DATABASE DIAGNOSTICS")
        logger.info("=" * 60)

        if not self.connect():
            return self.diagnostics

        try:
            self.check_connection_info()
            self.check_extensions()
            self.check_tables()
            self.check_indexes()
            self.check_performance()
            self.check_locks()

        finally:
            if self.conn:
                self.conn.close()

        # Summarize
        logger.info("\n" + "=" * 60)
        logger.info("DIAGNOSTIC SUMMARY")
        logger.info("=" * 60)

        if not self.diagnostics['issues']:
            logger.info("✅ No issues detected")
        else:
            critical = sum(1 for i in self.diagnostics['issues'] if i['severity'] == 'critical')
            high = sum(1 for i in self.diagnostics['issues'] if i['severity'] == 'high')
            medium = sum(1 for i in self.diagnostics['issues'] if i['severity'] == 'medium')

            logger.info(f"Issues found: {len(self.diagnostics['issues'])}")
            logger.info(f"  Critical: {critical}")
            logger.info(f"  High: {high}")
            logger.info(f"  Medium: {medium}")

            logger.info("\nIssues:")
            for issue in self.diagnostics['issues']:
                logger.info(f"  [{issue['severity'].upper()}] {issue['category']}: {issue['message']}")

        if self.diagnostics['recommendations']:
            logger.info("\nRecommendations:")
            for rec in self.diagnostics['recommendations']:
                logger.info(f"  • {rec}")

        return self.diagnostics


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Sentinel Database Diagnostics'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )

    args = parser.parse_args()

    diag = DatabaseDiagnostics()
    results = diag.run_full_diagnostics()

    if args.json:
        print(json.dumps(results, indent=2, default=str))

    # Exit with error code if critical issues found
    critical_issues = [i for i in results['issues'] if i['severity'] == 'critical']
    sys.exit(1 if critical_issues else 0)


if __name__ == "__main__":
    main()
