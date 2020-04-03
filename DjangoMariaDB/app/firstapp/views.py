# Create your views here.
#IMPORT models
from .models import Movie,ApiUsers

#IMPORT LIBRARIRES/FUNCTIONS
#from django.shortcuts import render , HttpResponse
from django.http import JsonResponse
import json
from firstapp.customClasses import *
#IMPORT DJANGO PASSWORD HASH GENERATOR AND COMPARE
from django.contrib.auth.hashers import make_password, check_password

#check_password(noHashPassword,HashedPassword) this funcion validate if the password match to the hash

def users(request):
 if request.method =='GET':
    response_data = {}
    response_data["api_users"] = {}
    cont = 0
    for i in ApiUsers.objects.all():
        response_data["api_users"][cont] = {}
        response_data["api_users"][cont]['user'] = i.user
        response_data["api_users"][cont]['password'] = i.password
        response_data["api_users"][cont]['api_key'] = i.api_key
        cont = cont + 1

    response_data['result'] = 'success'
    return JsonResponse(response_data, status = 200)
 else:
    response_data['result'] = 'error'
    respnse_data['message'] = 'Invalid Request'
    return JsonResponse(response_data, status = 403)

def movies(request):
 if request.method =='GET':
    response_data = {}
    response_data["movie"] = {}
    cont = 0
    for i in Movie.objects.all():
        response_data["movie"][cont] = {}
        response_data["movie"][cont]['id'] = i.movieid
        response_data["movie"][cont]['title'] = i.movietitle
        response_data["movie"][cont]['releaseDate'] = i.releasedate
        response_data["movie"][cont]['imageUrl'] = i.imageurl
        response_data["movie"][cont]['description'] = i.description
        cont = cont + 1

    response_data['result'] = 'success'
    return JsonResponse(response_data, status = 200)
 else:
    response_data['result'] = 'error'
    respnse_data['message'] = 'Invalid Request'
    return JsonResponse(response_data, status = 403)

def login(request):

    #VALIDATE METHOD
    if request.method == 'POST':

        #DECLARE RESPONSE
        response_data = {}
        functionCheck = checkJson()
        create_ApiKey = ApiKey()
        check_Json = functionCheck.isJson(request.body)


        #CHECK JSON STRUCTURE
        if check_Json == True:
            json_data = json.loads(request.body)
            check_Error = False
            message_Error = ""

            #Checa si los parametros enviados son correctos
            if 'user' not in json_data:
                check_Error = True
                message_Error = "User is required"
            elif 'password' not in json_data:
                check_Error = True
                message_Error = "Password is required"
            if check_Error == True:
                response_data['result'] = 'error'
                response_data['message'] = message_Error
                return JsonResponse(response_data, status=401)
            else:
                #Con un try se valida si el usario es correcto de lo contrario sale el mensaje de error
                try:
                    usr = json_data.get("user")
                    usr = ApiUsers.objects.get(user=usr)
                except ApiUsers.DoesNotExist:
                    response_data['result'] = 'error'
                    response_data['message'] = 'User Doesn´t Exist or the Password is Incorrect'
                    return JsonResponse(response_data, status=401)

                #Se obtiene el usuario junto el hash para poder validar
                usr = json_data.get("user")
                pswd = json_data.get("password")
                user_in_turn = ApiUsers.objects.get(user=usr)
                codify_password = user_in_turn.password

                #Funcion que recibe el hash y la contraseña escrita y las compara
                function_checkPassword = check_password(pswd, codify_password)

                #Si es correcto entra si no te sale el mensaje de error
                if function_checkPassword == True:
                    #Se valida si tiene api_key si la tiene la cre si no solo muestra el resultado correcto
                    if user_in_turn.api_key == None:
                        create_key = create_ApiKey.generate_key_complex()
                        user_in_turn.api_key = create_key
                        user_in_turn.save()
                        response_data['result'] = 'Succes'
                        response_data['message'] = 'Valild Credentials'
                        response_data['userApiKey'] = user_in_turn.api_key
                        return JsonResponse(response_data, status=200)
                    else:
                        response_data['result'] = 'Succes'
                        response_data['message'] = 'Valild Credentials'
                        response_data['userApiKey'] = user_in_turn.api_key
                        return JsonResponse(response_data, status=200)
                else:
                    response_data['result'] = 'error'
                    response_data['message'] = 'User Doesn´t Exist or the Password is Incorrect'
                    return JsonResponse(response_data, status=401)


        else:
            response_data['result'] = 'error'
            response_data['message'] = 'Invalid Json'
            return JsonResponse(response_data, status=400)


    else:
        response_data = {}
        response_data['result'] = 'error'
        response_data['message'] = 'Invalid Request'
        return JsonResponse(responseData, status=400)

def makepassword(request,password):
    hashPassword = make_password(password)
    response_data = {}
    response_data['password'] = hashPassword
    return JsonResponse(response_data, status=200)



def movieApi_key(request):

        #VALIDATE METHOD
        if request.method == 'POST':


            #DECLARE RESPONSE
            response_data = {}
            functionCheck = checkJson()
            check_Json = functionCheck.isJson(request.body)
            fucnction_Api_Key = ApiKey()



            #CHECK JSON STRUCTURE
            if check_Json == True:
                json_data = json.loads(request.body)
                check_Error = False
                message_Error = ""

                apikey = request.headers["user-api-key"]



                if apikey == None:
                    response_data = {}
                    response_data['result'] = 'error'
                    response_data['message'] = 'user-api-key is required'
                    return response_data
                else:
                    #Checa si los parametros enviados son correctos
                    if 'user' not in json_data:
                        check_Error = True
                        message_Error = "User is required"
                    elif 'password' not in json_data:
                        check_Error = True
                        message_Error = "Password is required"
                    if check_Error == True:
                        response_data['result'] = 'error'
                        response_data['message'] = message_Error
                        return JsonResponse(response_data, status=401)
                    else:
                        #Con un try se valida si el usario es correcto de lo contrario sale el mensaje de error
                        try:
                            usr = json_data.get("user")
                            usr = ApiUsers.objects.get(user=usr)
                        except ApiUsers.DoesNotExist:
                            response_data['result'] = 'error'
                            response_data['message'] = 'User Doesn´t Exist or the Password is Incorrect'
                            return JsonResponse(response_data, status=401)

                        #Se obtiene el usuario junto el hash para poder validar
                        usr = json_data.get("user")
                        pswd = json_data.get("password")
                        user_in_turn = ApiUsers.objects.get(user=usr)
                        codify_password = user_in_turn.password


                        #Funcion que recibe el hash y la contraseña escrita y las compara
                        function_checkPassword = check_password(pswd, codify_password)

                        #Si es correcto entra si no te sale el mensaje de error
                        if function_checkPassword == True:
                            user_apikey = request.headers["user-api-key"]
                            current_apikey = user_in_turn.api_key
                            if current_apikey == user_apikey:
                                response_data = {}
                                response_data["movie"] = {}
                                cont = 0
                                for i in Movie.objects.all():
                                    response_data["movie"][cont] = {}
                                    response_data["movie"][cont]['id'] = i.movieid
                                    response_data["movie"][cont]['title'] = i.movietitle
                                    response_data["movie"][cont]['releaseDate'] = i.releasedate
                                    response_data["movie"][cont]['imageUrl'] = i.imageurl
                                    response_data["movie"][cont]['description'] = i.description
                                    cont = cont + 1

                                response_data['result'] = 'success'
                                return JsonResponse(response_data, status = 200)
                            else:
                                response_data['result'] = 'error'
                                response_data['message'] = current_apikey
                                return JsonResponse(response_data, status=401)


                        else:
                            response_data['result'] = 'error'
                            response_data['message'] = 'User Doesn´t Exist or the Password is Incorrect'
                            return JsonResponse(response_data, status=401)


        else:
            response_data = {}
            response_data['result'] = 'error'
            response_data['message'] = 'Invalid Request'
            return JsonResponse(responseData, status=400)
