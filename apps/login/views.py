from django.shortcuts import render, redirect
from models import LogIn, NewUser
from django.contrib import messages


def index(request):
    if 'username' in request.session:  # TODO this needs to redirect to the logged IN page if user in session
        return redirect('/login/logged_in')  # TODO make this route to the other app
    return render(request, 'login/index.html')


def register(request):  # TODO loop dictionary and save in session and messages
    request.session['login'] = 'reg'
    if request.method == 'POST':
        new_user = NewUser()
        new_user.set_values(request.POST)
        new_user.new_user()
        if new_user.message_dict['truth']:
            new_user.add_user()
            if new_user.add_dict['truth']:
                for key, val in new_user.user_dict.items():
                    request.session[key] = val
            else:  # Loop over add_dict to messages to display registration errors
                for key, val in new_user.add_dict.items():
                    messages.error(request, val)
        else:  # Loop message_dict to messages to display registration errors
            for key, val in new_user.message_dict.items():
                messages.warning(request, val)
    return redirect('/login')  # TODO make this route go to the other app


def user_login(request):
    request.session['login'] = 'log'
    if request.method == 'POST':
        login_user = LogIn(request.POST['username'], request.POST['password'])
        login_user.login()
        if login_user.user_dict['truth']:
            for key, val in login_user.user_dict.items():
                request.session[key] = val
            return redirect('/login/edit/{}'.format(request.session['username']))
        elif login_user.alert_message['truth']:
            messages.error(request, login_user.alert_message['alert'])
    return redirect('/login')  # TODO make this route go to the other app


def is_logged_in(request):
    if 'username' in request.session:
        return redirect('/login/edit/{}'.format(request.session['username']))
    else:
        redirect('/login')


def user_logout(request):
    request.session.flush()  # Removing user from session causes complete logout
    return redirect('/login')  # on logout redirect to login


def edit(request, username):
    if 'username' in request.session:
        if request.session['username'] == username:
            print(username)
            return render(request, 'login/edit.html')
        else:
            request.session.flush()
            messages.warning(request, "Do not change user ID or USERNAME in url bar! You have been logged out")
            return redirect('/login')
    else:
        request.session.flush()
        request.session['login'] = 'reg'
        messages.warning(request, "You must be logged in to be on that page!")
        return redirect('/login')


#  ***** SLUG FIELD *****


# try:
#     Users.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], username=request.POST['username'], email=request.POST['email'], password=request.POST['password'])
# except IntegrityError:
#     messages.warning(request, "User name already in use! Please select a new one")
#     return redirect('/login')
# d ={
#     'first_name': request.POST['first_name'],
#     'last_name': request.POST['last_name'],
#     'username': request.POST['username'],
#     'email': request.POST['email'],
#     'password': request.POST['password'],
#     'password_confirm': request.POST['password_confirm'],
#     'dob_date': request.POST['dob_date'],
# }
# new_user.new_user()
# new_user.add_user()
# print(new_user.user_dict)
# new_user.set_values(request.POST)

# print (new_user.)

# reverse('admin:app_list', kwargs={'app_label': 'auth'}) must declare kwargs to pass dictionary

# if Users.objects.filter(username='dan').exists():
#     password_hash = Users.objects.filter(username='dan').values('password')
#     password_hash = password_hash[0]['password']
#     validated = bcrypt.hashpw(str('123qweASD'), str(password_hash))
#     if validated == str(password_hash):
#         print 'valid'
# print(the_hash == bcrypt.hashpw('secret', the_hash))
# print(the_hash)
# print(salt)
# print(the_hash.find(salt))
