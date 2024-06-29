from django.urls import path,include
from .import views
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.urls import re_path

schema_view = get_schema_view(
   openapi.Info(
      title="Snippets API",
      default_version='v1',
      description="Test description",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns=[
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('user/register/', views.User_Registration.as_view(), name='user-registration'),
    path('user/update-or-add-email/', views.UpdateOrAddEmail.as_view(), name='update-or-add-email'),
    path('user/verify-email/', views.VerifyEmail.as_view(), name='verify-email'),
    path('user/login/', views.Login.as_view(), name='login'),
    path('user/logout/', views.UserLogout.as_view(), name='logout'),
    path('user/forgot-password/', views.ForgotPassword.as_view(), name='forgot-password'),
    path('user/set-new-password/', views.SetNewPassword.as_view(), name='set-new-password'),
    
    path('contact/add_number/',views.AddNumberInContactList.as_view()),
    path('contact/repost_spam/',views.MarkNumberSpam.as_view()),
    path('contact/search_by_name/',views.SearchDetailByName.as_view()),
    path('contact/search_by_number/',views.SearchDetailByNumber.as_view()),
    path('contact/contact_list/',views.ContactList.as_view()),
   
]
