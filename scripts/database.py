"""
Database module for OpenMRS Security Testing CVSS Score Tracking

This module implements SQLite-based historical tracking of CVSS vulnerability scores
for continuous security testing. It supports baseline score management and relative
scoring to track security improvements/regressions over time.

Design Decisions:
- SQLite for simplicity (stored in GitHub Artifacts)
- Auto-set baseline on first run
- Keep last 100 runs per test
- Relative score = baseline_score - current_score (positive = improvement)
- JSON storage for dynamic parameters and test observations

Author: David Yin (NSF Research Project)
Date: 2025
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
import os


class SecurityTestDatabase:
    """
    Manages SQLite database for security test results and CVSS score tracking.
    
    The database tracks:
    1. Baseline scores (first run or manually set) - test_baseline table
    2. Historical test runs - test_history table
    
    Relative scoring allows tracking security improvements:
    - Positive improvement = vulnerability severity decreased (good!)
    - Negative improvement = vulnerability severity increased (regression)
    """
    
    def __init__(self, db_path: str = 'test_results.db'):
        """
        Initialize database connection and create tables if needed.
        
        Args:
            db_path: Path to SQLite database file (default: test_results.db)
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row  # Enable column access by name
        self._create_tables()
    
    def _create_tables(self):
        """
        Create database schema if tables don't exist.
        
        Tables:
        - test_baseline: Stores baseline CVSS scores for comparison
        - test_history: Stores every test run with relative scoring
        """
        cursor = self.conn.cursor()
        
        # Baseline scores table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_baseline (
                test_name TEXT PRIMARY KEY,
                baseline_cvss_score REAL NOT NULL,
                baseline_vector TEXT NOT NULL,
                baseline_date DATETIME NOT NULL,
                baseline_commit_sha TEXT,
                notes TEXT
            )
        ''')
        
        # Historical test runs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_name TEXT NOT NULL,
                run_date DATETIME NOT NULL,
                commit_sha TEXT,
                cvss_score REAL NOT NULL,
                cvss_vector TEXT NOT NULL,
                relative_score REAL NOT NULL,
                test_status TEXT NOT NULL,
                execution_time_seconds REAL,
                details JSON,
                FOREIGN KEY (test_name) REFERENCES test_baseline(test_name)
            )
        ''')
        
        # Create index for faster queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_test_history_name_date 
            ON test_history(test_name, run_date DESC)
        ''')
        
        self.conn.commit()
    
    def set_baseline(
        self, 
        test_name: str, 
        cvss_score: float, 
        cvss_vector: str,
        commit_sha: Optional[str] = None,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Set or update baseline CVSS score for a test.
        
        The baseline is used to calculate relative scores (improvement/regression).
        Typically set on first run or manually reset when security changes are made.
        
        Args:
            test_name: Unique identifier for the test
            cvss_score: CVSS 4.0 score (0.0 - 10.0)
            cvss_vector: Full CVSS 4.0 vector string
            commit_sha: Git commit hash (optional)
            notes: Human-readable notes about this baseline (optional)
        
        Returns:
            Dictionary with baseline information
        """
        cursor = self.conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO test_baseline 
            (test_name, baseline_cvss_score, baseline_vector, baseline_date, baseline_commit_sha, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (test_name, cvss_score, cvss_vector, datetime.now().isoformat(), commit_sha, notes))
        
        self.conn.commit()
        
        return {
            'test_name': test_name,
            'baseline_score': cvss_score,
            'baseline_vector': cvss_vector,
            'baseline_date': datetime.now().isoformat(),
            'commit_sha': commit_sha
        }
    
    def save_test_result(
        self,
        test_name: str,
        cvss_score: float,
        cvss_vector: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
        execution_time_seconds: Optional[float] = None,
        commit_sha: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Save a test run result and calculate relative score against baseline.
        
        If no baseline exists, automatically sets current run as baseline.
        Maintains last 100 runs per test to keep database size manageable.
        
        Args:
            test_name: Unique identifier for the test
            cvss_score: CVSS 4.0 score from this run
            cvss_vector: Full CVSS 4.0 vector string
            status: Test status (PASS, FAIL, etc.)
            details: JSON-serializable dict with dynamic params, observations, etc.
            execution_time_seconds: Test duration
            commit_sha: Git commit hash (optional)
        
        Returns:
            Dictionary containing:
            - baseline_score: The baseline CVSS score
            - current_score: Current run's CVSS score
            - relative_score: baseline - current (positive = improvement)
            - test_name, status, etc.
        """
        cursor = self.conn.cursor()
        
        # Check if baseline exists, if not, set current run as baseline
        cursor.execute('SELECT baseline_cvss_score FROM test_baseline WHERE test_name = ?', (test_name,))
        baseline_row = cursor.fetchone()
        
        if baseline_row is None:
            # Auto-set baseline on first run
            self.set_baseline(
                test_name=test_name,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                commit_sha=commit_sha,
                notes="Auto-set on first run"
            )
            baseline_score = cvss_score
            relative_score = 0.0  # First run has no improvement/regression
        else:
            baseline_score = baseline_row['baseline_cvss_score']
            # Relative score = baseline - current
            # Positive = improvement (score decreased)
            # Negative = regression (score increased)
            relative_score = baseline_score - cvss_score
        
        # Save test result
        cursor.execute('''
            INSERT INTO test_history 
            (test_name, run_date, commit_sha, cvss_score, cvss_vector, relative_score, 
             test_status, execution_time_seconds, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            test_name,
            datetime.now().isoformat(),
            commit_sha,
            cvss_score,
            cvss_vector,
            relative_score,
            status,
            execution_time_seconds,
            json.dumps(details) if details else None
        ))
        
        self.conn.commit()
        
        # Cleanup: Keep only last 100 runs per test
        cursor.execute('''
            DELETE FROM test_history 
            WHERE test_name = ? 
            AND id NOT IN (
                SELECT id FROM test_history 
                WHERE test_name = ? 
                ORDER BY run_date DESC 
                LIMIT 100
            )
        ''', (test_name, test_name))
        
        self.conn.commit()
        
        return {
            'test_name': test_name,
            'baseline_score': baseline_score,
            'current_score': cvss_score,
            'relative_score': relative_score,
            'status': status,
            'run_date': datetime.now().isoformat()
        }
    
    def get_test_history(self, test_name: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieve recent test run history for a specific test.
        
        Args:
            test_name: Unique identifier for the test
            limit: Maximum number of recent runs to return (default: 10)
        
        Returns:
            List of dictionaries, each containing:
            - run_date, cvss_score, cvss_vector, relative_score, status, details, etc.
            Ordered by run_date DESC (most recent first)
        """
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT 
                id,
                test_name,
                run_date,
                commit_sha,
                cvss_score,
                cvss_vector,
                relative_score,
                test_status,
                execution_time_seconds,
                details
            FROM test_history
            WHERE test_name = ?
            ORDER BY run_date DESC
            LIMIT ?
        ''', (test_name, limit))
        
        rows = cursor.fetchall()
        
        return [
            {
                'id': row['id'],
                'test_name': row['test_name'],
                'run_date': row['run_date'],
                'commit_sha': row['commit_sha'],
                'cvss_score': row['cvss_score'],
                'cvss_vector': row['cvss_vector'],
                'relative_score': row['relative_score'],
                'status': row['test_status'],
                'execution_time_seconds': row['execution_time_seconds'],
                'details': json.loads(row['details']) if row['details'] else None
            }
            for row in rows
        ]
    
    def get_all_current_scores(self) -> List[Dict[str, Any]]:
        """
        Get the most recent test result for all tests with their baselines.
        
        Used by dashboard to display current status of all tests.
        
        Returns:
            List of dictionaries, each containing:
            - test_name
            - baseline_score, baseline_vector, baseline_date
            - current_score, current_vector, current_date
            - relative_score (improvement/regression)
            - status, execution_time, etc.
        """
        cursor = self.conn.cursor()
        
        # Get all baselines
        cursor.execute('SELECT * FROM test_baseline ORDER BY test_name')
        baselines = {row['test_name']: dict(row) for row in cursor.fetchall()}
        
        results = []
        
        for test_name, baseline in baselines.items():
            # Get most recent run for this test
            cursor.execute('''
                SELECT * FROM test_history
                WHERE test_name = ?
                ORDER BY run_date DESC
                LIMIT 1
            ''', (test_name,))
            
            latest_run = cursor.fetchone()
            
            if latest_run:
                results.append({
                    'test_name': test_name,
                    'baseline_score': baseline['baseline_cvss_score'],
                    'baseline_vector': baseline['baseline_vector'],
                    'baseline_date': baseline['baseline_date'],
                    'current_score': latest_run['cvss_score'],
                    'current_vector': latest_run['cvss_vector'],
                    'current_date': latest_run['run_date'],
                    'relative_score': latest_run['relative_score'],
                    'status': latest_run['test_status'],
                    'execution_time_seconds': latest_run['execution_time_seconds'],
                    'details': json.loads(latest_run['details']) if latest_run['details'] else None
                })
            else:
                # Baseline exists but no runs yet (shouldn't happen, but handle gracefully)
                results.append({
                    'test_name': test_name,
                    'baseline_score': baseline['baseline_cvss_score'],
                    'baseline_vector': baseline['baseline_vector'],
                    'baseline_date': baseline['baseline_date'],
                    'current_score': None,
                    'current_vector': None,
                    'current_date': None,
                    'relative_score': 0.0,
                    'status': 'NO_RUNS',
                    'execution_time_seconds': None,
                    'details': None
                })
        
        return results
    
    def get_baseline(self, test_name: str) -> Optional[Dict[str, Any]]:
        """
        Get baseline information for a specific test.
        
        Args:
            test_name: Unique identifier for the test
        
        Returns:
            Dictionary with baseline info, or None if no baseline exists
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM test_baseline WHERE test_name = ?', (test_name,))
        row = cursor.fetchone()
        
        if row:
            return dict(row)
        return None
    
    def close(self):
        """Close database connection."""
        self.conn.close()
    
    def __enter__(self):
        """Context manager support."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager support - ensures connection is closed."""
        self.close()


# Example usage for testing
if __name__ == '__main__':
    # Quick test of database functionality
    with SecurityTestDatabase('test_example.db') as db:
        # Save a test result (auto-sets baseline on first run)
        result = db.save_test_result(
            test_name='test_brute_force_password',
            cvss_score=9.3,
            cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N',
            status='PASS',
            details={
                'dynamic_params': {'AC': 'L', 'VA': 'L'},
                'test_observations': {
                    'attempts_before_lockout': 7,
                    'lockout_duration_seconds': 300
                }
            },
            execution_time_seconds=378.5,
            commit_sha='abc123'
        )
        
        print(f"Baseline: {result['baseline_score']}")
        print(f"Current: {result['current_score']}")
        print(f"Improvement: {result['relative_score']:+.1f}")
        
        # Simulate a second run with improved security
        result2 = db.save_test_result(
            test_name='test_brute_force_password',
            cvss_score=7.5,  # Lower score = better security
            cvss_vector='CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N',
            status='PASS',
            details={'dynamic_params': {'AC': 'H', 'VA': 'L'}},
            execution_time_seconds=390.2,
            commit_sha='def456'
        )
        
        print(f"\nSecond run:")
        print(f"Baseline: {result2['baseline_score']}")
        print(f"Current: {result2['current_score']}")
        print(f"Improvement: {result2['relative_score']:+.1f}")  # Should be +1.8
        
        # Get history
        history = db.get_test_history('test_brute_force_password', limit=5)
        print(f"\nHistory: {len(history)} runs")
        
        # Get all current scores
        all_scores = db.get_all_current_scores()
        print(f"\nAll tests: {len(all_scores)}")
    
    # Cleanup test database
    os.remove('test_example.db')
    print("\n✅ Database module working correctly!")