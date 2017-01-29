from django.shortcuts import render, redirect
from models import LogIn, NewUser, AddQuotes, UserQuote, LikeUnlike, OwnedQuotes
from django.contrib import messages

#           **********************
#           ***** INDEX PAGE *****
#           **********************


def index(request):
    if 'username' in request.session:
        return redirect('/dashboard/{}'.format(request.session['username']))
    return render(request, 'login/index.html')


#           *********************
#           ***** DASHBOARD *****
#           *********************


def dashboard(request, username):
    if 'username' in request.session:
        if username == request.session['username']:
            user_quotes = UserQuote(request.session['user_id'])
            user_quotes.pull_quote()
            context = {
                'user_quotes': user_quotes.quotes,
                'other_quotes': user_quotes.others
            }
            return render(request, 'login/dashboard.html', context)  # DASHBOARD
        else:
            return redirect('/')
    else:
        request.session.flush()
        request.session['login'] = 'reg'
        messages.warning(request, "You must be logged in to be on that page!")
        return redirect('/')  # LOGIN PAGE

# =============== LOGIN HANDLERS ===================


#           *********************
#           ***** REGISTER  *****  TODO DO NOT CHANGE THIS FULLY TESTED
#           *********************

def register(request):
    if request.method == 'POST':
        request.session['login'] = 'reg'
        new_user = NewUser()
        new_user.set_values(request.POST)
        new_user.new_user()
        if new_user.message_dict['truth']:
            new_user.add_user()
            if new_user.add_dict['truth']:
                for key, val in new_user.user_dict.items():
                    request.session[key] = val  # put user information in session
                if 'user_id' in request.session:
                    return redirect('/dashboard/{}'.format(request.session['username']))
            else:  # Loop over add_dict to messages to display registration errors
                for key, val in new_user.message_dict.items():
                    messages.error(request, val)
        else:  # Loop message_dict to messages to display registration errors
            for key, val in new_user.message_dict.items():
                messages.warning(request, val)
    return redirect('/')


#           ***** LOGIN *****   TODO DO NOT CHANGE THIS FULLY TESTED


def user_login(request):
    request.session['login'] = 'log'
    if request.method == 'POST':
        login_user = LogIn(request.POST['username'], request.POST['password'])
        login_user.login()
        if login_user.user_dict['truth']:
            for key, val in login_user.user_dict.items():
                request.session[key] = val
            if 'user_id' in request.session:
                return redirect('/dashboard/{}'.format(request.session['username']))
            else:
                return redirect('/')  # TODO make this route go to the other app
        elif login_user.alert_message['truth']:
            messages.error(request, login_user.alert_message['alert'])
            return redirect('/')
    else:
        return redirect('/')  # TODO make this route go to the other app


#           ***** LOGOUT *****  TODO DO NOT CHANGE THIS FULLY TESTED


def user_logout(request):
    request.session.flush()  # Removing user from session causes complete logout
    return redirect('/login')  # on logout redirect to login


# ===========================================
#           ***** QUOTE HANDLERS *****

#           **************************
#           ***** FAV QUOTE PAGE *****
#           **************************


def user_quotes(request, owner_id):  # FULLY TESTED
    if 'user_id' in request.session:
        user_quote = OwnedQuotes(owner_id)
        user_quote.get_quote()
        if user_quote.truth:
            context = {
                "user": user_quote.owner,
                "quotes": user_quote.quotes,
                "times": user_quote.times
            }
            return render(request, 'login/favorite_quote.html', context=context)
        else:
            return redirect('/')
    return redirect('/')


#           **************************
#           ***** MAKE NEW QUOTE *****
#           **************************


def add_quote(request):
    if request.method == 'POST':
        new_quote = AddQuotes()
        new_quote.get_data(request.POST)
        new_quote.quote_validate()
        if new_quote.valid:
            new_quote.add_quote(request.session['user_id'])
        else:
            for key, val in new_quote.message_dict.items():
                messages.error(request, val)
    return redirect('/')


#           ******************************
#           ***** ADD FROM FAVORITE *****
#           ******************************


def favorite_quote(request, quote_id):    # TODO NO LOGIC YET
    if request.method == 'POST':
        if request.POST['like'] == quote_id:
            LikeUnlike().passed_data(quote_id, request.session['user_id'])
    return redirect('/dashboard/{}'.format(request.session['username']))


#           ********************************
#           ***** REMOVE FROM FAVORITE *****
#           ********************************


def remove_favorite(request, quote_id):   # TODO NO LOGIC YET
    if 'user_id' in request.session:
        if request.method == 'POST':
            pass
            new_unlike = LikeUnlike()
            new_unlike.unlike(quote_id, request.session['user_id'])

        return redirect('/dashboard/{}'.format(request.session['username']))
    return redirect('/')


#  ***** SLUG FIELD *****

# return redirect('/login/edit/{}/'.format(request.POST['unlike']))
# try:
#     Users.objects.create(first_name=request.POST['first_name'],
# last_name=request.POST['last_name'], username=request.POST['username'],
#  email=request.POST['email'], password=request.POST['password'])
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
