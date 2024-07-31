from django.db import models
from django.contrib.auth.models import User

class Organization(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class Role(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

    def __str__(self):
        return self.name

# Add fields to the Default User model
User.add_to_class('organization', models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True))
User.add_to_class('roles', models.ManyToManyField(Role, blank=True))


