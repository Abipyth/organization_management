from django.shortcuts import render,HttpResponse,redirect,get_object_or_404
from .models import *
from django.contrib import messages
from django.contrib.auth.models import User,Group
from django.contrib.auth import login,logout,authenticate
#from django.views.decorators.csrf import csrf_exempt ## if testing api using postman
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.utils.encoding import force_bytes,force_str,DjangoUnicodeDecodeError
from .utils import GenerateToken,generate_token,PasswordResetTokenGenerator
from django.core.mail import EmailMessage
from django.conf import settings
import threading
from django.views.generic import View
from django.contrib.auth.decorators import login_required,user_passes_test
class EmailThread(threading.Thread):
    def __init__(self,email_msg):
        self.email_msg=email_msg
        threading.Thread.__init__(self)
    def run(self):
        return self.email_msg.send()


def signup(request):
    if is_admin(request.user):
        organizations = Organization.objects.filter(id=request.user.organization.id)
    else:
        organizations = Organization.objects.all()
    organizations = Organization.objects.all()
    if request.method=="POST":
        fn=request.POST.get("fn")
        ln=request.POST.get("ln")
        un=request.POST.get("un")
        email=request.POST.get("email")
        pw1=request.POST.get("pw1")
        pw2=request.POST.get("pw2")
        org_id = request.POST.get("organization")
        role=request.POST.get("role")

        # Fetch the organization from the database
        try:
            organization = Organization.objects.get(id=org_id)
        except Organization.DoesNotExist:
            messages.info(request, 'Selected organization does not exist.')
            return redirect('signup')  # Redirect back to signup page

        # Check if the user is an admin and validate organization
        
        if is_admin(request.user) and request.user.organization != organization:
            if request.user.organization != organization:
                messages.info(request, 'You do not have permission to add members to other organizations. You can only add users to your own organization.')
                return redirect('organization_list')  # Redirect to organization list page

        if pw1!=pw2:
            messages.warning(request,"password doesnt match")
            return render(request,"signup.html", {"organizations": organizations})
        try:
            if User.objects.filter(username=un).exists():
                messages.warning(request,"User already exist")  ## info blue color
                return render(request,"signup.html", {"organizations": organizations})
             
        except Exception as e:
            messages.warning(request,f"something went wrong in {str(e)}")

        user=User.objects.create_user(first_name=fn,last_name=ln,username=un, email=email, password=pw1)
        user.is_active=False
        user.save()
        if role=="admin":
            admin_group, created= Group.objects.get_or_create(name="admin")
            user.groups.add(admin_group)

        elif role=="super admin":
            super_admin_group, created= Group.objects.get_or_create(name="super admin")
            user.groups.add(super_admin_group)
        elif role=="member":
            member_group, created= Group.objects.get_or_create(name="member")
            user.groups.add(member_group)
        else:
            manager_group, created= Group.objects.get_or_create(name="manager")
            user.groups.add(manager_group)

        # Assign the user to an organization
        organization = Organization.objects.get(pk=org_id)
        user.organization = organization
        user.save()

        ### Account activation through email link
        current_site=get_current_site(request)
        email_sub="ACTIVATE YOUR ACCOUNT HERE"
        msg=render_to_string("activate_mail.html",{
            "user":user,
            "domain":current_site.domain,
            "uid":urlsafe_base64_encode(force_bytes(user.pk)),
            "token":generate_token.make_token(user)
        })
        email_msg=EmailMessage(email_sub,msg,settings.EMAIL_HOST_USER, [email])
        EmailThread(email_msg).start()
        messages.info(request,"We have sent activation link to your mail, Activate your account by clicking link on your email")
        if user.is_active==True:
            messages.success(request,"User registered successfully")
            return redirect("in")
    return render(request,"signup.html", {"organizations": organizations})

class AccountActivateView(View):
    def get(self,request,uidb64,token):
        try:
            uid=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=uid)
            print(f"Decoded uid: {uid}, User: {user}")
        except Exception as e:
            messages.warning(request, f"something wrong in {str(e)}")

        try:
            if user is not None and generate_token.check_token(user,token):
                user.is_active=True
                user.save()
                messages.success(request,"account activation success. You can login into your account")
                return render (request,"log.html")
            else:
                messages.warning(request,"Activation link is invalid")
                return render (request, "activate_fail.html")
                
        except Exception as e:
            messages.warning(request, f"Activation link is invalid {str(e)}")
            return render (request, "activate_fail.html")


def log(request):
    try:
        if request.method=="POST":
            un=request.POST.get("un")
            pw1=request.POST.get("pw1")
                
            user=authenticate(request,username=un,password=pw1)
            if user is not None:
                login(request,user)
                messages.success(request,"user logged in successfully")
                return redirect('organization_list')
            else:
                messages.info(request,"Invalid credentials")
            
    except Exception as e:
        print("error", str(e))
    return render (request,"log.html")

def lout(request):
    logout(request)
    messages.success(request,f"user logged out successfully")
    return redirect("in")

def is_admin(user):
    return user.groups.filter(name='admin').exists()

def is_superadmin(user):
    return user.groups.filter(name='super admin').exists()

def is_manager(user):
    return user.groups.filter(name='manager').exists()
def is_member(user):
    return user.groups.filter(name='member').exists()
## create organizations
@user_passes_test(lambda u: is_superadmin(u) or is_admin(u))
@login_required
def create_organization(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')

        if is_superadmin(request.user):
            organization = Organization.objects.create(name=name, description=description)
            messages.success(request, 'Organization created successfully.')
        elif is_admin(request.user):
            # Admins can only create their own organization if it's their first organization
            if not request.user.organization:
                organization = Organization.objects.create(name=name, description=description)
                request.user.organization = organization
                request.user.save()
                messages.success(request, 'Organization created successfully.')
            else:
                messages.info(request, 'You already belong to an organization and cannot create another.')

        return redirect('organization_list')

    return render(request, 'create_org.html')
## update organisations
@user_passes_test(lambda u: is_superadmin(u) or is_admin(u))
@login_required
def update_organization(request, org_id):
    organization = get_object_or_404(Organization, id=org_id)

    if is_admin(request.user) and request.user.organization != organization:
        messages.info(request, 'You do not have permission to update this organization.')
        return redirect('organization_list')

    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')

        if request.user:
            organization.name = name
            organization.description = description
            organization.save()
            messages.success(request, 'Organization updated successfully.')
        else:
            messages.info(request, 'You do not have permission to update this organization.')

        return redirect('organization_list')

    context = {'organization': organization}
    return render(request, 'update_org.html', context)
## view organizations
def organization_list(request):
    organizations = Organization.objects.all()
    is_super_admin = request.user.groups.filter(name='super admin').exists()
    is_admin = request.user.groups.filter(name='admin').exists()

    context = {
        'organizations': organizations,
        'is_super_admin': is_super_admin,
        'is_admin': is_admin,
    }
    return render(request, 'org_list.html', context)
## update organizations
@user_passes_test(lambda u: is_superadmin(u) or is_admin(u))
@login_required
def delete_organization(request, org_id):
    organization = get_object_or_404(Organization, id=org_id)

    if is_admin(request.user) and request.user.organization != organization:
        messages.info(request, 'You do not have permission to delete this organization.')
        return redirect('organization_list')

    if request.user:
        organization.delete()
        messages.success(request, 'Organization deleted successfully.')
    else:
        messages.info(request, 'You do not have permission to delete this organization.')

    return redirect('organization_list')

################ROLE################### Create roles in organizations
@user_passes_test(lambda u: is_superadmin(u) or is_admin(u))
@login_required
def create_role(request, org_id):
    organization = get_object_or_404(Organization, id=org_id)

    if is_admin(request.user) and request.user.organization != organization:
        messages.info(request, 'You do not have permission to create a role in this organization.')
        return redirect('organization_list')

    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')

        if request.user:
            Role.objects.create(name=name, description=description, organization=organization)
            messages.success(request, 'Role created successfully.')
        else:
            messages.info(request, 'You do not have permission to create a role.')

        return redirect('role_list', org_id=org_id)

    context = {'organization': organization}
    return render(request, 'create_role.html', context)
##update roles in organizations
@user_passes_test(lambda u: is_superadmin(u) or is_admin(u))
@login_required
def update_role(request, role_id):
    role = get_object_or_404(Role, id=role_id)
    organization = role.organization

    if is_admin(request.user) and request.user.organization != organization:
        messages.info(request, 'You do not have permission to update this role.')
        return redirect('organization_list')

    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')

        if request.user:
            role.name = name
            role.description = description
            role.save()
            messages.success(request, 'Role updated successfully.')
        else:
            messages.info(request, 'You do not have permission to update this role.')

        return redirect('role_list', org_id=organization.id)

    context = {'role': role, 'organization': organization}
    return render(request, 'update_role.html', context)
## delete roles in organizations
@user_passes_test(lambda u: is_superadmin(u) or is_admin(u))
@login_required
def delete_role(request, role_id):
    role = get_object_or_404(Role, id=role_id)
    organization = role.organization
    
    if is_admin(request.user) and request.user.organization != organization:
        messages.info(request, 'You do not have permission to delete this role.')
        return redirect('organization_list')

    if request.user:
        role.delete()
        messages.success(request, 'Role deleted successfully.')
    else:
        messages.info(request, 'You do not have permission to delete this role.')

    return redirect('role_list', org_id=organization.id)
## view roles in organizations
@login_required
def role_list(request, org_id):
    organization = get_object_or_404(Organization, id=org_id)
    roles = Role.objects.filter(organization=organization)
    is_super_admin = request.user.groups.filter(name='super admin').exists()
    is_admin = request.user.groups.filter(name='admin').exists()
    context = {'roles': roles, 
               'organization': organization, 
               'is_super_admin': is_super_admin,
                'is_admin': is_admin,}
    return render(request, 'role_list.html', context)

#########USER REGISTRATION ######## Create users in organizations
@login_required
def user_list(request, org_id):
    organization = get_object_or_404(Organization, id=org_id)
    profile=request.user.profile
    # Loop through users and fetch their corresponding profile
    users = User.objects.filter(organization=organization).prefetch_related('roles')
    is_super_admin = request.user.groups.filter(name='super admin').exists()
    is_admin = request.user.groups.filter(name='admin').exists()

    context = {
        'organization': organization,
        'is_super_admin': is_super_admin,
        'is_admin': is_admin,
        'profile':profile,
        'users':users,
    }
    return render(request, 'users_list.html', context)

## Update users in organizations
@login_required
@user_passes_test(lambda u: is_superadmin(u) or is_admin(u))
def user_update(request, user_id):
    user = get_object_or_404(User, id=user_id)
    organization = user.organization
    profile=request.user.profile
    if is_admin(request.user) and request.user.organization != organization:
        messages.info(request, 'You do not have permission to update this user.')
        return redirect('organization_list')

    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        role = request.POST.get('role')
        bio=request.POST.get('bio')
        avatar=request.FILES.get('avatar')

        if request.user:
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
            user.role = role
            user.profile.bio=bio
            if avatar:
                user.profile.avatar=avatar
            user.save()            
            messages.success(request, 'User updated successfully.')
        else:
            messages.info(request, 'You do not have permission to update this user.')

        return redirect('user_list', org_id=organization.id)

    context = {'user': user, 'organization': organization,'profile': profile}
    return render(request, 'user_update.html', context)

## delete users in organizations
@login_required
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    organization = user.organization

    if is_admin(request.user) and request.user.organization != organization:
        messages.info(request, 'You do not have permission to delete this user.')
        return redirect('user_list', org_id=organization.id)

    if request.user:
        user.delete()
        messages.success(request, 'User deleted successfully.')
    else:
        messages.info(request, 'You do not have permission to delete this user.')

    return redirect('user_list', org_id=organization.id)

#### class based function for #######resetting the password#######
class ReqResetPWView(View):
    def get(self,request):
        return render (request,"reset_pw_page.html")
    
    def post(self,request):
        email=request.POST.get("email")
        user=User.objects.filter(email=email)

        if user.exists():
            current_site=get_current_site(request)
            email_sub="RESET YOUR PASSWORD"
            msg=render_to_string("reset_pw_mail.html",
                                 {
                                     "user":user[0],
                                     "domain":current_site.domain,
                                     "uid":urlsafe_base64_encode(force_bytes(user[0].pk)),  ### hashing in string format in usrlsafebaseencode
                                     "token":PasswordResetTokenGenerator().make_token(user[0])

                                 })
            email_msg=EmailMessage(email_sub,msg, settings.EMAIL_HOST_USER,[email])
            EmailThread(email_msg).start()   #.start() is called on the EmailThread instance, which starts a new thread and executes the run method, sending the email asynchronously.
            messages.info(request,"WE HAVE SENT YOU AN EMAIL FOR RESET THE PASSWORD")
            return render (request,"reset_pw_page.html")
## set new passowrd        
class SetNewPWView(View):
    def get(self,request,uidb64,token):
        context={
            "uidb64":uidb64,
            "token": token

        }
        try:
            u_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=u_id)
            token=token

            if not PasswordResetTokenGenerator.check_token(user,token):
                messages.warning(request,"password reset link is invalid please try again")
                return render (request,"reset_pw_page.html")
            
        except Exception as e:
            print("error in get request", str(e))

        return render (request,"set_new_pw.html",context)
    
    def post (self,request,uidb64,token):
        context={
            "uidb64":uidb64,
            "token": token}
        
        pw=request.POST.get("pass1")
        confirm_pw=request.POST.get("pass2")
        if pw!=confirm_pw:
            messages.warning(request,"password doesnt match enter correct password")
            return render (request,"set_new_pw.html",context)
        try:
            u_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=u_id)
            user.set_password(pw)
            user.save()
            messages.success(request, "password reset success please login with your new password")
            return redirect (log)
        except Exception as e:
            messages.error(request,"something went wrong & error in saving the new password",str(e))
            print("last error in saving the new password", str(e))
            return render (request,"set_new_pw.html",context)
        return render (request,"set_new_pw.html",context)
    
### profile view
@login_required
def profile(request):
    profile = request.user.profile  # Assuming the Profile is created using a signal
    user = request.user
    context = {
        'profile': profile,
        'user': user
    }
    return render(request, 'user_profile.html', context)