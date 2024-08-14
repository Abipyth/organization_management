from management import views
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
admin.site.site_header="MANAGEMENT ADMIN"
admin.site.site_header="ADMIN"
urlpatterns = [
    path("admin/", admin.site.urls),
    path("", views.organization_list, name='org_list'),
    path("signup",views.signup,name="signup"),
    path("activate/<uidb64>/<token>",views.AccountActivateView.as_view(), name="activate"),
    path("in",views.log,name="in"),
     path('create/', views.create_organization, name='create_org'),
     path('organizations/', views.organization_list, name='organization_list'),
    path('update/<int:org_id>/', views.update_organization, name='update_organization'),
    path('delete/<int:org_id>/', views.delete_organization, name='delete_organization'),
    path("lout",views.lout,name="lout"),

    path('organizations/<int:org_id>/roles/', views.role_list, name='role_list'),
    path('organizations/<int:org_id>/users/', views.user_list, name='user_list'),

    path('organizations/<int:org_id>/roles/create/', views.create_role, name='create_role'),
    path('roles/update/<int:role_id>/', views.update_role, name='update_role'),

    path('users/update/<int:user_id>/', views.user_update, name='user_update'),
    path('roles/delete/<int:role_id>/', views.delete_role, name='delete_role'),
    path('users/delete/<int:user_id>/', views.delete_user, name='user_delete'),
        ### password reset
    path("req_reset_pw", views.ReqResetPWView.as_view(), name="req_reset_pw"),
    path("set_new_pw/<uidb64>/<token>",views.SetNewPWView.as_view(), name="set_new_pw" ),
]+ static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
