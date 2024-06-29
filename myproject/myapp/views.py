from django.shortcuts import render,redirect
import requests
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializer import *
from .models import *
from django.contrib.auth.hashers import make_password, check_password
import re
from django.contrib.auth import login, logout
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAuthenticatedOrReadOnly, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import random
from django.conf import settings
from django.core.mail import send_mail
from datetime import timedelta
from .pagination import CustomPageNumberPagination
from datetime import timezone



def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp_email(email, otp):
    subject = 'OTP for user Registration '
    message = f'your otp for Registration is :  {otp}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)




def get_token_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }



class User_Registration(APIView):
    @swagger_auto_schema(
        operation_description="This if for User Registration",
        operation_summary="User can Register using this api with email field is optional",
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number':openapi.Schema(type=openapi.TYPE_STRING),
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
                'email': openapi.Schema(type=openapi.TYPE_STRING),
            },
            requried=['phone_number', 'password', 'name']
        ),
    )
    def post(self, request):
        try:
            data = request.data
            try:
                email = data.get('email')
                password = data.get('password')
                name = data.get('name')
                phone_number=data.get('phone_number')


                def password_validate(password):
                    if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(){}[\]:;,<>\'\"~])[A-Za-z\d!@#$%^&*(){}[\]:;,<>\'\"~]{8,16}$', password):
                        raise ValueError(
                            "Password must be 8 to 16 characters long with one uppercase, one lowercase, a number, and a special character.")
                
                phone_number_regex = r'^\+?[1-9]\d{1,14}$'
                if not phone_number or not re.match(phone_number_regex, phone_number):
                    return Response({'message': 'Please enter a valid phone number.'}, status=status.HTTP_400_BAD_REQUEST)

                
                if not password:
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Password is required."}, status=status.HTTP_400_BAD_REQUEST)

                try:
                    password_validate(password)
                except Exception as e:
                    return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


                user_password = make_password(password)
                existing_user = UserRegistration.objects.filter(phone_number=phone_number).first()
                if existing_user:
                    
                    return Response({"Response": "User already Present", "status": status.HTTP_208_ALREADY_REPORTED}, status.HTTP_208_ALREADY_REPORTED)
                else:
                    try:
                        if email:
                            otp = generate_otp()
                            send_otp_email(email, otp)
                            user = UserRegistration.objects.create(email=email, password=user_password,name=name,phone_number=phone_number)
                            user.is_registered = True
                            user.save()
                            return Response({'message': 'user registered successfully please verify the otp send on mail'}, status=status.HTTP_201_CREATED)
                        else:
                            user = UserRegistration.objects.create(password=user_password,name=name,phone_number=phone_number)
                            user.is_registered = True
                            user.save()
                            return Response({'message': 'user registered successfully'}, status=status.HTTP_201_CREATED)
                    except Exception as e:
                        return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': f'could not register user try again{str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

            except Exception as e:
                print(e)
                return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': 'could not register user try again'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(str(e))
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': 'could not register user try again'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdateOrAddEmail(APIView):
    @swagger_auto_schema(
        operation_description='Update or Add Email',
        operation_summary='Add or update your email and verify it using OTP',
        tags=['User Profile'],

        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'registered_phone_number': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['email', 'phone_number']
        ),
    )
    def post(self, request):
        try:
            data = request.data
            email = data.get('email')
            phone_number = data.get('registered_phone_number')

            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not email or not re.match(email_regex, email):
                return Response({'message': 'Please enter a valid email address.'}, status=status.HTTP_400_BAD_REQUEST)

            user = UserRegistration.objects.get(phone_number=phone_number)

            if user.email:
                otp = generate_otp()
                send_otp_email(email, otp)
                user.otp = otp
                user.otp_created_at = timezone.now()
                user.save()
                return Response({'message': 'OTP sent successfully for email update.'}, status=status.HTTP_200_OK)
            
            else:
                otp = generate_otp()
                send_otp_email(email, otp)
                user.email = email
                user.otp = otp
                user.otp_created_at = timezone.now()
                user.is_verified = False  
                user.save()
                return Response({'message': 'Email added successfully. Verify using OTP.'}, status=status.HTTP_200_OK)

        except UserRegistration.DoesNotExist:
            return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)




class VerifyEmail(APIView):
    @swagger_auto_schema(
        operation_description='Verify you email',
        operation_summary='user has to verify his/her email using the otp sended within 3 minutes',
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'otp': openapi.Schema(type=openapi.TYPE_NUMBER)
            },
        ),
    )
    def post(self, request):
        data = request.data
        email = data.get('email')
        otp = data.get('otp')
        
        try:
            user = UserRegistration.objects.get(email=email)
            time_difference = timezone.now()-user.otp_created_at
            print(type(otp),type(user.otp))

            if time_difference <= timedelta(minutes=3):
                if int(otp) == user.otp:
                    user.is_valid = True
                    user.is_verified = True
                    user.save()
                    return Response({'status': status.HTTP_200_OK, 'message': "User Verified Successfully"}, status=status.HTTP_200_OK)
                return Response({'status': status.HTTP_400_BAD_REQUEST, "message": "Invalid OTP"}, status.HTTP_400_BAD_REQUEST)
            else:
                otp = generate_otp()
                send_otp_email(email, otp)
                user.otp = otp
                user.otp_created_at = timezone.now()
                user.save()
                return Response({'status': status.HTTP_400_BAD_REQUEST, "message": "time out for  OTP \n new opt sended \n try again using new otp"}, status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(e)
            return Response({'status': status.HTTP_404_NOT_FOUND, "message": "User not found"}, status.HTTP_404_NOT_FOUND)


class Login(APIView):
    @swagger_auto_schema(
        operation_description="login here",
        operation_summary='login to you account',
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['phone_number', 'password'],
            properties={
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
    )
    def post(self, request):
        try:
            data = request.data

            phone_number = data.get('phone_number')
            password = data.get('password')

            phone_number_regex = r'^\+?[1-9]\d{1,14}$'
            if not phone_number or not re.match(phone_number_regex, phone_number):
                return Response({'message': 'Please enter a valid phone number.'}, status=status.HTTP_400_BAD_REQUEST)

            if not password:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Password is required."}, status=status.HTTP_400_BAD_REQUEST)

            user = UserRegistration.objects.get(
                phone_number=phone_number, is_registered=True)

            try:
                if check_password(password, user.password):
                    try:
                        login(request, user)
                        token = get_token_for_user(user)
                        # serializer=UserRegistrationsSerializer(user)
                        user.is_verified=True
                        user.save()
                        return Response({"status": status.HTTP_200_OK, 'message': 'Login successfully', 'token': token, "Your user id": user.id}, status=status.HTTP_200_OK)
                    except Exception as e:
                        return Response({"messsage": f"user not found{str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': "invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                print(e)
                return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': 'user not found', 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLogout(APIView):
    def get(self, request):
        logout(request)
        return Response({"status": status.HTTP_200_OK, 'message': 'logout successfully done'}, status.HTTP_200_OK)


class ForgotPassword(APIView):
    @swagger_auto_schema(
        operation_description="Forgot Password",
        operation_summary="Reset Your password using new otp",
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['phone_number'],
            properties={
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING)
            },
        ),
    )
    def post(self, request):
        try:
            data = request.data
            phone_number = data.get('phone_number')
            phone_number_regex = r'^\+?[1-9]\d{1,14}$'

            if not phone_number or not re.match(phone_number_regex, phone_number):
                return Response({'message': 'Please enter a valid phone number.'}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                user = UserRegistration.objects.get(phone_number=phone_number)
                
                if user.email:
                    otp = generate_otp()
                    send_otp_email(user.email, otp)
                    user.otp = otp
                    user.otp_created_at = timezone.now()
                    user.save()
                    return Response({'message': 'Please Check you Email , OTP sent successfully for password reset.'}, status=status.HTTP_200_OK)
                
                else:
                    return Response({'message': 'No email associated with this phone number. Please add a email first'}, status=status.HTTP_404_NOT_FOUND)
                
            except UserRegistration.DoesNotExist:
                return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except UserRegistration.DoesNotExist:
            return Response({'message': 'User not found.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class SetNewPassword(APIView):
    @swagger_auto_schema(
        operation_description='Set New Password',
        operation_summary='Please Enter you new password',
        tags=['OAuth'],

        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
                'email':openapi.Schema(type=openapi.TYPE_STRING),
                'otp': openapi.Schema(type=openapi.TYPE_NUMBER),
                'new_password': openapi.Schema(type=openapi.TYPE_STRING),
                'confirm_password': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
    )
    def post(self, request):
        try:
            data = request.data
            data['email'] = email
            email = data.get('email')
            phone_number=data.get('phone_number')
            otp = data.get('otp')
            password = data.get('new_password')
            cpassword = data.get('confirm_password')

            if not password:
                return Response({"message": "Please enter a new password"}, status=status.HTTP_400_BAD_REQUEST)
            if password != cpassword:
                return Response({"message": "New password and Confirm password must be the same."}, status=status.HTTP_400_BAD_REQUEST)

            password_regex = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$'
            if not re.match(password_regex, password):
                return Response({"message": "Invalid password format"}, status=status.HTTP_403_FORBIDDEN)

            try:
                user = UserRegistration.objects.get(phone_number=phone_number , email=email)
                
                time_difference = timezone.now()-user.otp_created_at
                if time_difference <= timedelta(minutes=3):
                    if otp == user.otp:
                        user.set_password(password)
                        user.save()
                        return Response({'status': status.HTTP_200_OK, 'message': "Password Changed Successfully"}, status=status.HTTP_200_OK)
                    return Response({'status': status.HTTP_400_BAD_REQUEST, "message": "Invalid OTP"}, status.HTTP_400_BAD_REQUEST)
                else:
                    otp = generate_otp()
                    send_otp_email(email, otp)
                    user.otp = otp
                    user.otp_created_at = timezone.now()
                    user.save()
                    return Response({'status': status.HTTP_400_BAD_REQUEST, "message": "time out for  OTP \n new opt sended \n try again using new otp"}, status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'status': status.HTTP_404_NOT_FOUND, "message": "User not found"}, status.HTTP_404_NOT_FOUND)
        except:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, "message": "User not found"}, status.HTTP_500_INTERNAL_SERVER_ERROR)



class AddNumberInContactList(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Add Number in your contact list",
        operation_summary="Add Number in your contact list",
        tags=['Contact'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING), 
            },
            required=['name', 'phone_number']
        ),
        responses={
            status.HTTP_201_CREATED: "Number added successfully",
            status.HTTP_400_BAD_REQUEST: "Invalid data provided",
            status.HTTP_401_UNAUTHORIZED: "Unauthorized access",
            status.HTTP_500_INTERNAL_SERVER_ERROR: "Internal Server Error",
        }
    )
    def post(self, request):
        try:
            serializer = ContactSerializer(data=request.data, context={'request': request})  
            if serializer.is_valid():
                serializer.save(owner=request.user)
                return Response({'message': 'Number added successfully'}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'message': 'Internal Server Error', 'error': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
            
            
class MarkNumberSpam(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Mark Number as spam",
        operation_summary="Mark Number as spam",
        tags=['Spam'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['phone_number']
        ),
        responses={
            status.HTTP_200_OK: "Number marked as spam successfully",
            status.HTTP_400_BAD_REQUEST: "Invalid data provided",
            status.HTTP_401_UNAUTHORIZED: "Unauthorized access",
            status.HTTP_500_INTERNAL_SERVER_ERROR: "Internal Server Error",
        }
    )
    def post(self, request):
        try:
            serializer = SpamReportSerializer(data=request.data,context={'request': request})
            if serializer.is_valid():
                serializer.save(reporter=request.user)
                return Response({'message': 'Number marked as spam successfully'}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'message': 'Internal Server Error', 'error': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class SearchDetailByName(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Search details by name",
        operation_summary="Search details by name",
        tags=['Search'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['name']
        ),
        responses={
            status.HTTP_200_OK: "Details found successfully",
            status.HTTP_400_BAD_REQUEST: "Invalid data provided",
            status.HTTP_401_UNAUTHORIZED: "Unauthorized access",
            status.HTTP_404_NOT_FOUND: "Details not found",
            status.HTTP_500_INTERNAL_SERVER_ERROR: "Internal Server Error",
        }
    )
    def post(self, request):
        try:
            name = request.data.get('name')
            user = request.user

            contact_details = Contact.objects.filter(owner=user, name__icontains=name).first()

            if contact_details:
                serializer = ContactSerializer(contact_details)
                contact_data = serializer.data
                
                associated_email = UserRegistration.objects.filter(phone_number=contact_details.phone_number).values('email').first()
                if associated_email:
                    contact_data['email'] = associated_email.get('email', None)
                
                spam_likelihood = SpamReport.objects.filter(reporter=user, phone_number=contact_details.phone_number).count()
                contact_data['spam_likelihood'] = spam_likelihood
                
                return Response(contact_data, status=status.HTTP_200_OK)
            else:
                other_details = UserRegistration.objects.filter(name__icontains=name).values('name', 'phone_number').first()

                if other_details:
                    spam_likelihood = SpamReport.objects.filter(phone_number=other_details['phone_number']).count()
                    return Response({
                        'name': other_details['name'],
                        'phone_number': other_details['phone_number'],
                        'spam_likelihood': spam_likelihood
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({'message': 'Details not found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'message': 'Internal Server Error', 'error': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SearchDetailByNumber(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Search details by phone number",
        operation_summary="Search details by phone number",
        tags=['Search'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['phone_number']
        ),
        responses={
            status.HTTP_200_OK: "Details found successfully",
            status.HTTP_400_BAD_REQUEST: "Invalid data provided",
            status.HTTP_401_UNAUTHORIZED: "Unauthorized access",
            status.HTTP_404_NOT_FOUND: "Details not found",
            status.HTTP_500_INTERNAL_SERVER_ERROR: "Internal Server Error",
        }
    )
    def post(self, request):
        try:
            phone_number = request.data.get('phone_number')
            user = request.user

            contact_details = Contact.objects.filter(owner=user, phone_number=phone_number).first()

            if contact_details:
                serializer = ContactSerializer(contact_details)
                contact_data = serializer.data
                
                associated_email = UserRegistration.objects.filter(phone_number=phone_number).values('email').first()
                if associated_email:
                    contact_data['email'] = associated_email.get('email', None)
                
                spam_likelihood = SpamReport.objects.filter(reporter=user, phone_number=phone_number).count()
                contact_data['spam_likelihood'] = spam_likelihood
                
                return Response(contact_data, status=status.HTTP_200_OK)
            else:
                other_details = UserRegistration.objects.filter(phone_number=phone_number).values('name', 'phone_number').first()
                spam_likelihood = SpamReport.objects.filter(reporter=user, phone_number=phone_number).count()
                if other_details:
                    return Response({
                        'message': 'Contact not found in your list',
                        'name': other_details['name'],
                        'phone_number': other_details['phone_number'],
                        'spam_likelehood':spam_likelihood
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({'message': 'Details not found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'message': 'Internal Server Error', 'error': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class ContactList(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve all contacts in the owner's contact list",
        operation_summary="Retrieve all contacts",
        tags=['ContactList'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        responses={
            status.HTTP_200_OK: "Contacts retrieved successfully",
            status.HTTP_401_UNAUTHORIZED: "Unauthorized access",
            status.HTTP_500_INTERNAL_SERVER_ERROR: "Internal Server Error",
        }
    )
    def get(self, request):
        try:
            user = request.user
            contacts = Contact.objects.filter(owner=user)
            serializer = ContactSerializer(contacts, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'message': 'Internal Server Error', 'error': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
