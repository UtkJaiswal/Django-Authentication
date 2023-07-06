from django.shortcuts import render,redirect
from django.contrib.auth import authenticate,login,logout
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
# Create your views here.
# username - Aman
# password - Aman*123
# def index(request):
#     print("user-",request.user.is_anonymous)
    
#     if request.user.is_anonymous:
#         return JsonResponse({'success': 'You are an eligible user'}, status=200)

    
#     return JsonResponse({'error': 'Chala ja yaha se chor kahi ka'}, status=401)


# @csrf_exempt
# def loginUser(request):
#     if request.method == "POST":
#         username = request.POST.get("username")
#         password = request.POST.get("password")
#         # print(username,password)
#         user = authenticate(username=username, password=password)

#         if user is not None:
#             login(request, user)

#             refresh = RefreshToken.for_user(user)
#             access_token = str(refresh.access_token)
            
#             response_data = {
#                 'username': username,
#                 'access_token': access_token
#             }
#             response = JsonResponse(response_data, status=200)
#             response["auth_token"] = "123"
#             return response
#         else:
#             return JsonResponse({'error': 'Invalid username or password'}, status=401)

#     return JsonResponse({}, status=405)  # Method not allowed
@csrf_exempt
def loginUser(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return JsonResponse({'message': 'Login successful'}, status=200)
        else:
            return JsonResponse({'message': 'Invalid credentials'}, status=401)

    return JsonResponse({'message': 'Method not allowed'}, status=405)

def index(request):
    if request.user.is_authenticated:
        return JsonResponse({'message': 'Success'}, status=200)
    else:
        return JsonResponse({'message': 'Not a valid user'}, status=401)



def logoutUser(request):
    if not request.user.is_authenticated:
        return JsonResponse({'message': 'You are already logged out'}, status=200)

    logout(request)
    return JsonResponse({'message': 'Successfully logged out'}, status=200)


@csrf_exempt
def signup_api(request):
    try:
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')

            if User.objects.filter(username=username).exists():
                return JsonResponse({'message': 'Username already exists'}, status=400)
            
            user = User.objects.create_user(username=username, password=password)
            return JsonResponse({'message': 'Signup successful'}, status=201)

        return JsonResponse({'message': 'Method not allowed'}, status=405)
    
    except Exception as e:
        return JsonResponse({'message': 'An error occurred', 'error': str(e)}, status=500)

