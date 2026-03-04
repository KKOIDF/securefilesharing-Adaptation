import requests
import sys
import json
import io
from datetime import datetime
import time

class SecureShareAPITester:
    def __init__(self, base_url="https://safeexchange.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.user_token = None
        self.admin_token = None
        self.test_user_email = f"testuser_{int(time.time())}@example.com"
        self.test_admin_email = f"testadmin_{int(time.time())}@example.com"
        self.test_password = "TestPass123!"
        self.uploaded_file_id = None
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            status = "✅ PASS"
        else:
            status = "❌ FAIL"
        
        result = f"{status} - {name}"
        if details:
            result += f" | {details}"
        
        print(result)
        self.test_results.append({
            "name": name,
            "success": success,
            "details": details
        })
        return success

    def make_request(self, method, endpoint, data=None, files=None, token=None, expect_status=200):
        """Make HTTP request with error handling"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        if token:
            headers['Authorization'] = f'Bearer {token}'
        
        if files:
            # Remove Content-Type for file uploads
            headers.pop('Content-Type', None)
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers)
            elif method == 'POST':
                if files:
                    response = requests.post(url, files=files, headers=headers)
                else:
                    response = requests.post(url, json=data, headers=headers)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers)
            
            success = response.status_code == expect_status
            
            if success:
                try:
                    return True, response.json()
                except:
                    return True, response.content
            else:
                try:
                    error_detail = response.json().get('detail', f'Status {response.status_code}')
                except:
                    error_detail = f'Status {response.status_code}'
                return False, error_detail
                
        except Exception as e:
            return False, str(e)

    def test_root_endpoint(self):
        """Test root API endpoint"""
        success, response = self.make_request('GET', '')
        if success and 'SecureShare API' in str(response):
            return self.log_test("Root API Endpoint", True, "API is accessible")
        else:
            return self.log_test("Root API Endpoint", False, f"Response: {response}")

    def test_user_registration(self):
        """Test user registration"""
        # Test regular user registration
        user_data = {
            "email": self.test_user_email,
            "password": self.test_password,
            "full_name": "Test User",
            "role": "user"
        }
        
        success, response = self.make_request('POST', 'auth/register', user_data, expect_status=200)
        user_reg_success = self.log_test("User Registration", success, 
                                       f"User: {response}" if success else f"Error: {response}")
        
        # Test admin registration
        admin_data = {
            "email": self.test_admin_email,
            "password": self.test_password,
            "full_name": "Test Admin",
            "role": "admin"
        }
        
        success, response = self.make_request('POST', 'auth/register', admin_data, expect_status=200)
        admin_reg_success = self.log_test("Admin Registration", success,
                                        f"Admin: {response}" if success else f"Error: {response}")
        
        return user_reg_success and admin_reg_success

    def test_user_login_and_otp(self):
        """Test login flow with OTP verification"""
        # Test user login
        login_data = {
            "email": self.test_user_email,
            "password": self.test_password
        }
        
        success, response = self.make_request('POST', 'auth/login', login_data, expect_status=200)
        if not success:
            return self.log_test("User Login", False, f"Login failed: {response}")
        
        user_otp = response.get('otp_for_demo')
        if not user_otp:
            return self.log_test("User Login", False, "No OTP received")
        
        self.log_test("User Login", True, f"OTP received: {user_otp}")
        
        # Test OTP verification
        otp_data = {
            "email": self.test_user_email,
            "otp": user_otp
        }
        
        success, response = self.make_request('POST', 'auth/verify-otp', otp_data, expect_status=200)
        if success and 'access_token' in response:
            self.user_token = response['access_token']
            return self.log_test("User OTP Verification", True, "Token received")
        else:
            return self.log_test("User OTP Verification", False, f"Error: {response}")

    def test_admin_login_and_otp(self):
        """Test admin login flow with OTP verification"""
        # Test admin login
        login_data = {
            "email": self.test_admin_email,
            "password": self.test_password
        }
        
        success, response = self.make_request('POST', 'auth/login', login_data, expect_status=200)
        if not success:
            return self.log_test("Admin Login", False, f"Login failed: {response}")
        
        admin_otp = response.get('otp_for_demo')
        if not admin_otp:
            return self.log_test("Admin Login", False, "No OTP received")
        
        self.log_test("Admin Login", True, f"OTP received: {admin_otp}")
        
        # Test OTP verification
        otp_data = {
            "email": self.test_admin_email,
            "otp": admin_otp
        }
        
        success, response = self.make_request('POST', 'auth/verify-otp', otp_data, expect_status=200)
        if success and 'access_token' in response:
            self.admin_token = response['access_token']
            return self.log_test("Admin OTP Verification", True, "Token received")
        else:
            return self.log_test("Admin OTP Verification", False, f"Error: {response}")

    def test_file_upload(self):
        """Test file upload with encryption"""
        if not self.user_token:
            return self.log_test("File Upload", False, "No user token available")
        
        # Create a test file
        test_content = b"This is a test file for encryption testing. It contains some data to verify integrity."
        test_file = io.BytesIO(test_content)
        
        files = {'file': ('test_document.txt', test_file, 'text/plain')}
        
        success, response = self.make_request('POST', 'files/upload', files=files, 
                                            token=self.user_token, expect_status=200)
        
        if success and 'file_id' in response:
            self.uploaded_file_id = response['file_id']
            return self.log_test("File Upload", True, 
                               f"File ID: {response['file_id']}, Hash: {response.get('hash', 'N/A')}")
        else:
            return self.log_test("File Upload", False, f"Error: {response}")

    def test_file_list(self):
        """Test file listing"""
        if not self.user_token:
            return self.log_test("File List", False, "No user token available")
        
        success, response = self.make_request('GET', 'files/list', token=self.user_token)
        
        if success and 'files' in response:
            file_count = len(response['files'])
            return self.log_test("File List", True, f"Found {file_count} files")
        else:
            return self.log_test("File List", False, f"Error: {response}")

    def test_file_download(self):
        """Test file download and decryption"""
        if not self.user_token or not self.uploaded_file_id:
            return self.log_test("File Download", False, "No token or file ID available")
        
        success, response = self.make_request('GET', f'files/download/{self.uploaded_file_id}', 
                                            token=self.user_token, expect_status=200)
        
        if success:
            # Check if we got file content back
            if isinstance(response, bytes) and len(response) > 0:
                return self.log_test("File Download", True, f"Downloaded {len(response)} bytes")
            else:
                return self.log_test("File Download", False, "No file content received")
        else:
            return self.log_test("File Download", False, f"Error: {response}")

    def test_file_sharing(self):
        """Test file sharing between users"""
        if not self.user_token or not self.uploaded_file_id:
            return self.log_test("File Sharing", False, "No token or file ID available")
        
        share_data = {
            "email": self.test_admin_email
        }
        
        success, response = self.make_request('POST', f'files/share/{self.uploaded_file_id}', 
                                            share_data, token=self.user_token, expect_status=200)
        
        if success:
            return self.log_test("File Sharing", True, f"Shared with {self.test_admin_email}")
        else:
            return self.log_test("File Sharing", False, f"Error: {response}")

    def test_admin_endpoints(self):
        """Test admin-only endpoints"""
        if not self.admin_token:
            return self.log_test("Admin Endpoints", False, "No admin token available")
        
        # Test admin users endpoint
        success, response = self.make_request('GET', 'admin/users', token=self.admin_token)
        users_success = self.log_test("Admin - Users List", success, 
                                    f"Found {len(response.get('users', []))} users" if success else f"Error: {response}")
        
        # Test admin logs endpoint
        success, response = self.make_request('GET', 'admin/logs', token=self.admin_token)
        logs_success = self.log_test("Admin - Activity Logs", success,
                                   f"Found {len(response.get('logs', []))} logs" if success else f"Error: {response}")
        
        # Test admin stats endpoint
        success, response = self.make_request('GET', 'admin/stats', token=self.admin_token)
        stats_success = self.log_test("Admin - Statistics", success,
                                    f"Stats: {response}" if success else f"Error: {response}")
        
        return users_success and logs_success and stats_success

    def test_rbac_enforcement(self):
        """Test Role-Based Access Control"""
        if not self.user_token:
            return self.log_test("RBAC Enforcement", False, "No user token available")
        
        # Test that regular user cannot access admin endpoints
        success, response = self.make_request('GET', 'admin/users', token=self.user_token, expect_status=403)
        rbac_users = self.log_test("RBAC - User blocked from admin/users", success,
                                 "Access correctly denied" if success else f"Unexpected: {response}")
        
        success, response = self.make_request('GET', 'admin/logs', token=self.user_token, expect_status=403)
        rbac_logs = self.log_test("RBAC - User blocked from admin/logs", success,
                                "Access correctly denied" if success else f"Unexpected: {response}")
        
        success, response = self.make_request('GET', 'admin/stats', token=self.user_token, expect_status=403)
        rbac_stats = self.log_test("RBAC - User blocked from admin/stats", success,
                                 "Access correctly denied" if success else f"Unexpected: {response}")
        
        return rbac_users and rbac_logs and rbac_stats

    def test_file_deletion(self):
        """Test file deletion"""
        if not self.user_token or not self.uploaded_file_id:
            return self.log_test("File Deletion", False, "No token or file ID available")
        
        success, response = self.make_request('DELETE', f'files/delete/{self.uploaded_file_id}', 
                                            token=self.user_token, expect_status=200)
        
        if success:
            return self.log_test("File Deletion", True, "File deleted successfully")
        else:
            return self.log_test("File Deletion", False, f"Error: {response}")

    def run_all_tests(self):
        """Run all backend API tests"""
        print("🔍 Starting SecureShare Backend API Tests")
        print("=" * 60)
        
        # Test sequence
        tests = [
            self.test_root_endpoint,
            self.test_user_registration,
            self.test_user_login_and_otp,
            self.test_admin_login_and_otp,
            self.test_file_upload,
            self.test_file_list,
            self.test_file_download,
            self.test_file_sharing,
            self.test_admin_endpoints,
            self.test_rbac_enforcement,
            self.test_file_deletion
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                self.log_test(test.__name__, False, f"Exception: {str(e)}")
        
        print("\n" + "=" * 60)
        print(f"📊 Test Results: {self.tests_passed}/{self.tests_run} passed")
        
        if self.tests_passed < self.tests_run:
            print("\n❌ Failed Tests:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  - {result['name']}: {result['details']}")
        
        return self.tests_passed, self.tests_run, self.test_results

def main():
    tester = SecureShareAPITester()
    passed, total, results = tester.run_all_tests()
    
    # Return appropriate exit code
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())