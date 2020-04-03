from django.urls import path

from . import views

urlpatterns = [
    path('client/login',views.login,name='login'),
    path('generate_password/<str:password>',views.makepassword,name='makepassword'),
    path('users',views.users,name='users'),
    path('client/movie',views.movieApi_key,name='movieApi_key'),
    path('movies',views.movies,name='movies')
]
