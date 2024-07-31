from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User, Group
from .models import Organization, Role
from django.core import mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .utils import generate_token

class ManagementViewsTestCase(TestCase):
    
    def setUp(self):
        self.client = Client()
        
        # Create groups
        self.super_admin_group, _ = Group.objects.get_or_create(name="super admin")
        self.admin_group, _ = Group.objects.get_or_create(name="admin")
        self.member_group, _ = Group.objects.get_or_create(name="member")
        self.manager_group, _ = Group.objects.get_or_create(name="manager")
        
        # Create users
        self.super_admin_user = User.objects.create_user(username="superadmin", password="password123")
        self.super_admin_user.groups.add(self.super_admin_group)
        
        self.admin_user = User.objects.create_user(username="adminuser", password="password123")
        self.admin_user.groups.add(self.admin_group)
        
        self.regular_user = User.objects.create_user(username="regularuser", password="password123")
        
        # Create an organization
        self.organization = Organization.objects.create(name="Test Org", description="A test organization.")
        self.admin_user.organization = self.organization
        self.admin_user.save()
        
        # Create a role
        self.role = Role.objects.create(name="Test Role", description="A test role.", organization=self.organization)
    
    def test_signup_view_get(self):
        self.client.login(username="adminuser", password="password123")
        response = self.client.get(reverse("signup"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "signup.html")

    def test_signup_view_post(self):
        self.client.login(username="adminuser", password="password123")
        response = self.client.post(reverse("signup"), {
            "fn": "Test",
            "ln": "User",
            "un": "testuser",
            "email": "testuser@example.com",
            "pw1": "password123",
            "pw2": "password123",
            "organization": self.organization.id,
            "role": "member"
        })
        self.assertEqual(response.status_code, 302)  # Redirects after successful registration
        self.assertTrue(User.objects.filter(username="testuser").exists())
        self.assertEqual(len(mail.outbox), 1)  # Check if an email was sent
    
    def test_login_view(self):
        response = self.client.post(reverse("in"), {
            "un": "superadmin",
            "pw1": "password123"
        })
        self.assertEqual(response.status_code, 302)  # Redirects after successful login
        self.assertEqual(int(self.client.session['_auth_user_id']), self.super_admin_user.pk)

    def test_logout_view(self):
        self.client.login(username="superadmin", password="password123")
        response = self.client.get(reverse("lout"))
        self.assertEqual(response.status_code, 302)  # Redirects after logout
        self.assertNotIn('_auth_user_id', self.client.session)
    
    def test_create_organization(self):
        self.client.login(username="superadmin", password="password123")
        response = self.client.post(reverse("create_org"), {
            "name": "New Org",
            "description": "A new organization."
        })
        self.assertEqual(response.status_code, 302)  # Redirects after creation
        self.assertTrue(Organization.objects.filter(name="New Org").exists())

    def test_update_organization(self):
        self.client.login(username="adminuser", password="password123")
        response = self.client.post(reverse("update_organization", args=[self.organization.id]), {
            "name": "Updated Org",
            "description": "Updated description."
        })
        self.assertEqual(response.status_code, 302)  # Redirects after update
        self.organization.refresh_from_db()
        self.assertEqual(self.organization.name, "Updated Org")
    
    def test_delete_organization(self):
        self.client.login(username="superadmin", password="password123")
        response = self.client.post(reverse("delete_organization", args=[self.organization.id]))
        self.assertEqual(response.status_code, 302)  # Redirects after deletion
        self.assertFalse(Organization.objects.filter(id=self.organization.id).exists())
    
    def test_create_role(self):
        self.client.login(username="adminuser", password="password123")
        response = self.client.post(reverse("create_role", args=[self.organization.id]), {
            "name": "New Role",
            "description": "A new role."
        })
        self.assertEqual(response.status_code, 302)  # Redirects after creation
        self.assertTrue(Role.objects.filter(name="New Role").exists())

    def test_update_role(self):
        self.client.login(username="adminuser", password="password123")
        response = self.client.post(reverse("update_role", args=[self.role.id]), {
            "name": "Updated Role",
            "description": "Updated role description."
        })
        self.assertEqual(response.status_code, 302)  # Redirects after update
        self.role.refresh_from_db()
        self.assertEqual(self.role.name, "Updated Role")
    
    def test_delete_role(self):
        self.client.login(username="adminuser", password="password123")
        response = self.client.post(reverse("delete_role", args=[self.role.id]))
        self.assertEqual(response.status_code, 302)  # Redirects after deletion
        self.assertFalse(Role.objects.filter(id=self.role.id).exists())
    
    def test_user_update(self):
        self.client.login(username="superadmin", password="password123")
        response = self.client.post(reverse("user_update", args=[self.regular_user.id]), {
            "first_name": "Updated",
            "last_name": "User",
            "email": "updateduser@example.com",
            "role": "admin"
        })
        self.assertEqual(response.status_code, 302)  # Redirects after update
        self.regular_user.refresh_from_db()
        self.assertEqual(self.regular_user.first_name, "Updated")
    
    def test_delete_user(self):
        self.client.login(username="superadmin", password="password123")
        response = self.client.post(reverse("user_delete", args=[self.regular_user.id]))
        self.assertEqual(response.status_code, 302)  # Redirects after deletion
        self.assertFalse(User.objects.filter(id=self.regular_user.id).exists())
