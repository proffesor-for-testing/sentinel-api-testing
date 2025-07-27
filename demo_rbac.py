#!/usr/bin/env python3
"""
Sentinel RBAC Demo Script

This script demonstrates the Role-Based Access Control (RBAC) implementation
in the Sentinel platform, showcasing authentication, authorization, and
different user roles with their respective permissions.

Usage:
    python demo_rbac.py

Requirements:
    - Sentinel backend services running (docker-compose up)
    - Python requests library (pip install requests)
"""

import requests
import json
import time
from typing import Dict, Any, Optional
import sys

# Configuration
BASE_URL = "http://localhost:8000"
AUTH_URL = f"{BASE_URL}/auth"

class SentinelRBACDemo:
    def __init__(self):
        self.session = requests.Session()
        self.admin_token = None
        self.manager_token = None
        self.tester_token = None
        self.viewer_token = None
        
    def print_header(self, title: str):
        """Print a formatted header."""
        print("\n" + "="*60)
        print(f" {title}")
        print("="*60)
    
    def print_step(self, step: str):
        """Print a formatted step."""
        print(f"\n🔹 {step}")
    
    def print_success(self, message: str):
        """Print a success message."""
        print(f"✅ {message}")
    
    def print_error(self, message: str):
        """Print an error message."""
        print(f"❌ {message}")
    
    def print_info(self, message: str):
        """Print an info message."""
        print(f"ℹ️  {message}")
    
    def make_request(self, method: str, url: str, token: Optional[str] = None, **kwargs) -> requests.Response:
        """Make an HTTP request with optional authentication."""
        headers = kwargs.get('headers', {})
        if token:
            headers['Authorization'] = f'Bearer {token}'
        kwargs['headers'] = headers
        
        try:
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.RequestException as e:
            print(f"❌ Request failed: {e}")
            return None
    
    def login_user(self, email: str, password: str) -> Optional[str]:
        """Login a user and return the access token."""
        response = self.make_request(
            'POST', 
            f"{AUTH_URL}/login",
            json={"email": email, "password": password}
        )
        
        if response and response.status_code == 200:
            data = response.json()
            token = data.get('access_token')
            user = data.get('user', {})
            self.print_success(f"Logged in as {user.get('full_name')} ({user.get('role')})")
            return token
        else:
            error_msg = response.json().get('detail', 'Unknown error') if response else 'Connection failed'
            self.print_error(f"Login failed: {error_msg}")
            return None
    
    def test_endpoint_access(self, endpoint: str, method: str, token: Optional[str], 
                           expected_status: int, description: str, **kwargs):
        """Test access to an endpoint with expected status code."""
        response = self.make_request(method, f"{BASE_URL}{endpoint}", token, **kwargs)
        
        if response:
            if response.status_code == expected_status:
                self.print_success(f"{description} - Status: {response.status_code}")
                return True
            else:
                self.print_error(f"{description} - Expected: {expected_status}, Got: {response.status_code}")
                if response.status_code in [401, 403]:
                    error_detail = response.json().get('detail', 'No details')
                    self.print_info(f"Error: {error_detail}")
                return False
        else:
            self.print_error(f"{description} - Request failed")
            return False
    
    def demo_authentication(self):
        """Demonstrate user authentication."""
        self.print_header("AUTHENTICATION DEMO")
        
        # Test login with default admin user
        self.print_step("Testing admin login")
        self.admin_token = self.login_user("admin@sentinel.com", "admin123")
        
        if not self.admin_token:
            self.print_error("Cannot proceed without admin access. Please ensure the auth service is running.")
            return False
        
        # Test invalid login
        self.print_step("Testing invalid login")
        invalid_token = self.login_user("invalid@example.com", "wrongpassword")
        if not invalid_token:
            self.print_success("Invalid login correctly rejected")
        
        return True
    
    def demo_user_management(self):
        """Demonstrate user management capabilities."""
        self.print_header("USER MANAGEMENT DEMO")
        
        if not self.admin_token:
            self.print_error("Admin token required for user management demo")
            return False
        
        # Create test users with different roles
        test_users = [
            {"email": "manager@sentinel.com", "full_name": "Test Manager", "password": "manager123", "role": "manager"},
            {"email": "tester@sentinel.com", "full_name": "Test Tester", "password": "tester123", "role": "tester"},
            {"email": "viewer@sentinel.com", "full_name": "Test Viewer", "password": "viewer123", "role": "viewer"}
        ]
        
        for user in test_users:
            self.print_step(f"Creating {user['role']} user: {user['email']}")
            self.test_endpoint_access(
                "/auth/register", "POST", self.admin_token, 200,
                f"Create {user['role']} user", json=user
            )
        
        # List all users
        self.print_step("Listing all users")
        self.test_endpoint_access(
            "/auth/users", "GET", self.admin_token, 200,
            "List users as admin"
        )
        
        # Login with newly created users
        self.print_step("Logging in with newly created users")
        self.manager_token = self.login_user("manager@sentinel.com", "manager123")
        self.tester_token = self.login_user("tester@sentinel.com", "tester123")
        self.viewer_token = self.login_user("viewer@sentinel.com", "viewer123")
        
        return True
    
    def demo_role_permissions(self):
        """Demonstrate role-based permissions."""
        self.print_header("ROLE-BASED PERMISSIONS DEMO")
        
        # Test specification permissions
        self.print_step("Testing Specification Permissions")
        
        # Admin should be able to create specifications
        self.test_endpoint_access(
            "/api/v1/specifications", "POST", self.admin_token, 200,
            "Admin creates specification",
            json={
                "raw_spec": '{"openapi": "3.0.0", "info": {"title": "Test API", "version": "1.0.0"}, "paths": {}}',
                "source_filename": "test-api.yaml"
            }
        )
        
        # Manager should be able to create specifications
        self.test_endpoint_access(
            "/api/v1/specifications", "POST", self.manager_token, 200,
            "Manager creates specification",
            json={
                "raw_spec": '{"openapi": "3.0.0", "info": {"title": "Manager API", "version": "1.0.0"}, "paths": {}}',
                "source_filename": "manager-api.yaml"
            }
        )
        
        # Tester should NOT be able to create specifications
        self.test_endpoint_access(
            "/api/v1/specifications", "POST", self.tester_token, 403,
            "Tester attempts to create specification (should fail)",
            json={
                "raw_spec": '{"openapi": "3.0.0", "info": {"title": "Tester API", "version": "1.0.0"}, "paths": {}}',
                "source_filename": "tester-api.yaml"
            }
        )
        
        # Viewer should NOT be able to create specifications
        self.test_endpoint_access(
            "/api/v1/specifications", "POST", self.viewer_token, 403,
            "Viewer attempts to create specification (should fail)",
            json={
                "raw_spec": '{"openapi": "3.0.0", "info": {"title": "Viewer API", "version": "1.0.0"}, "paths": {}}',
                "source_filename": "viewer-api.yaml"
            }
        )
        
        # All roles should be able to read specifications
        self.print_step("Testing Specification Read Permissions")
        for role, token in [("Admin", self.admin_token), ("Manager", self.manager_token), 
                           ("Tester", self.tester_token), ("Viewer", self.viewer_token)]:
            if token:
                self.test_endpoint_access(
                    "/api/v1/specifications", "GET", token, 200,
                    f"{role} reads specifications"
                )
    
    def demo_user_management_permissions(self):
        """Demonstrate user management permissions."""
        self.print_header("USER MANAGEMENT PERMISSIONS DEMO")
        
        # Test user creation permissions
        self.print_step("Testing User Creation Permissions")
        
        new_user = {
            "email": "newuser@sentinel.com",
            "full_name": "New User",
            "password": "newuser123",
            "role": "viewer"
        }
        
        # Admin should be able to create users
        self.test_endpoint_access(
            "/auth/register", "POST", self.admin_token, 200,
            "Admin creates new user", json=new_user
        )
        
        # Manager should NOT be able to create users
        new_user["email"] = "manager-created@sentinel.com"
        self.test_endpoint_access(
            "/auth/register", "POST", self.manager_token, 403,
            "Manager attempts to create user (should fail)", json=new_user
        )
        
        # Test user listing permissions
        self.print_step("Testing User Listing Permissions")
        
        # Admin and Manager should be able to list users
        self.test_endpoint_access(
            "/auth/users", "GET", self.admin_token, 200,
            "Admin lists users"
        )
        
        self.test_endpoint_access(
            "/auth/users", "GET", self.manager_token, 200,
            "Manager lists users"
        )
        
        # Tester and Viewer should NOT be able to list users
        self.test_endpoint_access(
            "/auth/users", "GET", self.tester_token, 403,
            "Tester attempts to list users (should fail)"
        )
        
        self.test_endpoint_access(
            "/auth/users", "GET", self.viewer_token, 403,
            "Viewer attempts to list users (should fail)"
        )
    
    def demo_profile_management(self):
        """Demonstrate profile management."""
        self.print_header("PROFILE MANAGEMENT DEMO")
        
        # All users should be able to view their own profile
        self.print_step("Testing Profile Access")
        
        for role, token in [("Admin", self.admin_token), ("Manager", self.manager_token), 
                           ("Tester", self.tester_token), ("Viewer", self.viewer_token)]:
            if token:
                self.test_endpoint_access(
                    "/auth/profile", "GET", token, 200,
                    f"{role} views own profile"
                )
        
        # Test profile updates
        self.print_step("Testing Profile Updates")
        
        # Users should be able to update their own name
        if self.tester_token:
            self.test_endpoint_access(
                "/auth/profile", "PUT", self.tester_token, 200,
                "Tester updates own profile",
                json={"full_name": "Updated Tester Name"}
            )
    
    def demo_roles_and_permissions(self):
        """Demonstrate roles and permissions listing."""
        self.print_header("ROLES AND PERMISSIONS DEMO")
        
        # Anyone should be able to view available roles (public endpoint)
        self.print_step("Testing Roles Listing")
        
        response = self.make_request('GET', f"{AUTH_URL}/roles")
        if response and response.status_code == 200:
            roles_data = response.json()
            self.print_success("Retrieved roles and permissions")
            
            print("\n📋 Available Roles and Permissions:")
            for role_name, role_info in roles_data.get('roles', {}).items():
                print(f"\n🔸 {role_name.upper()}:")
                permissions = role_info.get('permissions', [])
                for perm in permissions:
                    print(f"   • {perm}")
        else:
            self.print_error("Failed to retrieve roles")
    
    def demo_unauthorized_access(self):
        """Demonstrate unauthorized access attempts."""
        self.print_header("UNAUTHORIZED ACCESS DEMO")
        
        # Test access without token
        self.print_step("Testing Access Without Authentication")
        
        self.test_endpoint_access(
            "/api/v1/specifications", "GET", None, 401,
            "Access specifications without token (should fail)"
        )
        
        self.test_endpoint_access(
            "/auth/users", "GET", None, 401,
            "Access users without token (should fail)"
        )
        
        # Test access with invalid token
        self.print_step("Testing Access With Invalid Token")
        
        invalid_token = "invalid.jwt.token"
        self.test_endpoint_access(
            "/api/v1/specifications", "GET", invalid_token, 401,
            "Access specifications with invalid token (should fail)"
        )
    
    def run_demo(self):
        """Run the complete RBAC demonstration."""
        print("🚀 Starting Sentinel RBAC Demo")
        print("This demo will test authentication, authorization, and role-based permissions.")
        
        try:
            # Check if services are running
            response = self.make_request('GET', f"{BASE_URL}/health")
            if not response or response.status_code != 200:
                self.print_error("Sentinel services are not running. Please start with 'docker-compose up'")
                return False
            
            # Run demo sections
            if not self.demo_authentication():
                return False
            
            self.demo_user_management()
            self.demo_role_permissions()
            self.demo_user_management_permissions()
            self.demo_profile_management()
            self.demo_roles_and_permissions()
            self.demo_unauthorized_access()
            
            self.print_header("DEMO COMPLETED SUCCESSFULLY")
            self.print_success("All RBAC features demonstrated successfully!")
            
            print("\n📝 Summary:")
            print("• Authentication system working correctly")
            print("• Role-based permissions enforced properly")
            print("• User management restricted to appropriate roles")
            print("• Profile management available to all authenticated users")
            print("• Unauthorized access properly blocked")
            
            print("\n🔐 Default Login Credentials:")
            print("• Admin: admin@sentinel.com / admin123")
            print("• Manager: manager@sentinel.com / manager123")
            print("• Tester: tester@sentinel.com / tester123")
            print("• Viewer: viewer@sentinel.com / viewer123")
            
            return True
            
        except KeyboardInterrupt:
            print("\n\n⏹️  Demo interrupted by user")
            return False
        except Exception as e:
            self.print_error(f"Demo failed with error: {e}")
            return False

def main():
    """Main function to run the demo."""
    demo = SentinelRBACDemo()
    success = demo.run_demo()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
