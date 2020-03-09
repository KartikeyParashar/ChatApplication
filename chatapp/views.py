import os
import jwt
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.http import JsonResponse
from django.shortcuts import render
from django.template.loader import render_to_string
from django_short_url.views import ShortURL
from django_short_url.views import get_surl
from dotenv import load_dotenv
from rest_framework import status
from rest_framework.views import APIView

from .forms import RegistrationForm, LoginForm, ForgotPasswordForm, ResetForm
from .rediss import Redis

load_dotenv()

redis = Redis()
# obj.c


class RegistrationView(APIView):

    def get(self, request, *args, **kwargs):
        form = RegistrationForm()
        return render(request, 'register.html', {'form': form})

    def post(self, request, *args, **kwargs):
        import pdb
        pdb.set_trace()
        response = {
                        "success": False,
                        "message": "Something Went Wrong!",
                        "data": []
                   }

        username = request.data['username']
        email = request.data['email']
        password = request.data['password']

        user = User.objects.create_user(username=username, password=password, email=email)
        user.set_password(password)

        # user.is_active = False
        # user.save()

        token = jwt.encode({'id': user.id}, 'secret', algorithm='HS256').decode('utf-8')

        surl = get_surl(token)

        surl = surl.split("/")

        message = render_to_string('activation.html', {'user': user,
                                                        'domain': get_current_site(request).domain,
                                                        'token': surl[2]
                                                       })
        subject = f'Activation Link from {get_current_site(request).domain}'
        # os.getenv("EMAIL"))

        send_mail(subject, message, os.getenv("EMAIL"), ['parasharkartikey@gmail.com'], fail_silently=False)

        response["message"] = "Successfully Registered"
        response["success"] = True

        return JsonResponse(data=response, status=status.HTTP_201_CREATED)


def activate(request, token):

    # import pdb
    # pdb.set_trace()

    response = {"success": 'Success', "message": "Your account is activated", "data": []}
    token1 = ShortURL.objects.get(surl=token)
    token = token1.lurl
    payload = jwt.decode(token, 'secret', algorithm='HS256')
    id = payload['id']
    user = User.objects.get(pk=id)

    if user:
        user.is_active = True
        user.save()
        response = {"success": 'Success', "message": "Your account is activated Successfully!"}
        return JsonResponse(data=response, status=status.HTTP_201_CREATED)
    else:
        return JsonResponse(data=response, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):

    # import pdb
    # pdb.set_trace()

    def get(self, request, *args, **kwargs):
        form = LoginForm()
        return render(request, 'signup.html', {'form': form})

    def post(self, request):
        response = {
            "success": False,
            "message": 'Unable to Login',
            "data": []
        }

        username = request.data.get('username')
        # password = request.data.get('password')

        user = User.objects.get(username=username)
        print(user)
        if user is not None:
            token = jwt.encode({'id': user.id}, 'secret', algorithm='HS256').decode('utf-8')
            response = {
                "success": 'Success',
                "message": 'Successfully Login',
                "data": [token]
            }

            redis.set(user.id, token)
            return JsonResponse(data=response, status=status.HTTP_200_OK)
        else:
            return JsonResponse(data=response, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):

    # import pdb
    # pdb.set_trace()

    def post(self, request):
        token = request.META['HTTP_TOKEN']
        payload = jwt.decode(token, 'secret', algorithm='HS256')
        user_id = payload.get('id')
        redis.delete(user_id)

        response = {
                      "success": 'Success',
                      "message": "User Logged Out",
                      "data": []
                   }

        return JsonResponse(data=response, status=status.HTTP_200_OK)


class ForgotPassword(APIView):
    # import pdb
    # pdb.set_trace()

    def get(self, request, *args, **kwargs):
        form = ForgotPasswordForm()
        return render(request, 'reset.html', {'form': form})

    def post(self, request):
        # form = ForgotPasswordForm(data=request.data)

        response = {
                      "success": False,
                      "message": "User not Found",
                      "data": []
                   }

        email = request.data['email']
        user = User.objects.create_user(email=email)

        token = jwt.encode({'id': user.id}, 'secret', algorithm='HS256').decode('utf-8')
        surl = get_surl(token)
        surl = surl.split('/')

        message = render_to_string('forgot.html', {
            'user': user,
            'domain': get_current_site(request).domain,
            'token': surl[2]
        })
        subject = f'Reset Password Link from {get_current_site(request).domain}'
        send_mail(subject, message, os.getenv("EMAIL"), ['parasharkartikey@gmail.com'], fail_silently=False)

        response["message"] = "Successfully Registered"
        response["success"] = True

        return JsonResponse(data=response, status=status.HTTP_200_OK)


class ResetPassword(APIView):

    # import pdb
    # pdb.set_trace()

    def get(self, request, *args, **kwargs):
        form = ResetForm()
        return render(request, 'reset.html', {'form': form})

    def post(self, request):
        response = {
            "success": False,
            "message": "User not Found",
            "data": []
        }
        password = request.data['password']

        token1 = ShortURL.objects.get(surl=token)
        token = token1.lurl

        payload = jwt.decode(token, 'secret', algorithms='HS256')
        user_id = payload.get('id')

        new_password = User.objects.create_user(password=password)
        new_password.set_password(new_password)
        new_password.save()

        response = {
            "success": True,
            "message": "User password is reset Successfully",
            "data": []
        }
        return JsonResponse(data=response, status=status.HTTP_200_OK)


# def reset_password(request, token):
#
#     # import pdb
#     # pdb.set_trace()
#
#     response = {
#         "success": False,
#         "message": "User not Found",
#         "data": []
#     }
#     password = request.data['password']
#
#     token1 = ShortURL.objects.get(surl=token)
#     token = token1.lurl
#     payload = jwt.decode(token, 'secret', algorithm='HS256')
#     id = payload['id']
#     user = User.objects.get(pk=id)
#
#     new_password = User.objects.create_user(password=password)
#     new_password.set_password(new_password)
#     new_password.save()
#
#     response = {
#         "success": True,
#         "message": "User password is reset Successfully",
#         "data": []
#     }
#     return JsonResponse(data=response, status=status.HTTP_200_OK)