from __future__ import unicode_literals
from django.core.exceptions import ObjectDoesNotExist
from django.db import models, IntegrityError
import re
import bcrypt
salt = bcrypt.gensalt()


# Regex section
EMAIL_REGEX = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
PASSWORD_REGEX = re.compile(r'((?=.+\d)(?=.+[a-z])(?=.+[A-Z]).{8,})', re.MULTILINE)
name_regex = re.compile(r'[a-zA-Z]+', re.MULTILINE)


class Users(models.Model):
    """This makes the table for registration
    NOTE: Username and Email are unique and you can not have more then 1
    of the name. In the NewUser class .lower() is called to normalize all
    user names and emails to ensure case sensitivity is ignored
    """
    first_name = models.CharField(max_length=75, blank=True, null=True)
    last_name = models.CharField(max_length=75, blank=True, null=True)
    username = models.CharField(max_length=75, blank=True, null=True, unique=True)
    email = models.CharField(max_length=255, blank=True, null=True, unique=True)
    dob_date = models.DateTimeField(auto_now_add=False, blank=True, null=True)
    description = models.TextField(max_length=1000, blank=True, null=True)
    user_level = models.IntegerField(blank=True, null=True)
    password = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True, null=True)

# ***** START of fully tested user validation AND Logic ****


class NewUser(object):
    """How to use this class.
    1. assign NewUser() to a variable EXAMPLE: new_user = NewUser()
    2. pass request.POST to .set_values() EXAMPLE: new_user.set_values(request.POST)
    3. call new_user() function. EXAMPLE: new_user.new_user()
    4. Use a conditional to check if message_dict value 'truth' is true or false
        EXAMPLE: if new_user.message_dict['truth']: This is a truthy expression and handles validation
    5. In the if conditional call new_user.add_user() EXAMPLE: new_user.add_user() This adds to database
        The reason for this in a conditional is to lower the expected rate of the except statment being run
        The chances of it being hit are so low i was unable to get get it to hit even with 50 tries
    6. In the else conditional assign place the dictionary message_dict into messages.warning(request, dict value
    7. Using a for key, val in new_user.message_dict place all values greater then '' (a blank string) in messages
    NOTE: In the building of a dictionary to be passed case sensitivity is ignored by .lowering
    """
    def __init__(self):
        self.fn, self.ln, self.un, self.em, self.pw, self.cpw, self.dob = '', '', '', '', '', '', ''

        self.message_dict = {
            'truth': True,
            'name': '',
            'user': '',
            'email': '',
            'password': '',
            'dob': '',
            'add_fail': ''
        }

        self.user_dict = {
            'first_name': '',
            'last_name': '',
            'username': '',
            'email': '',
            'password': '',
            'dob_date': ''
        }

        self.add_dict = {
            'truth': False,
            'alert': ''
        }

    def set_values(self, args):
        """This takes in request.POST and places the values by key into
            class variables for later use
            EXAMPLE: new_user = NewUser()  new_user.set_values(request.POST)
            *****ENSURE DICTIONARY KEYS MATCH THE BELOW!*****"""
        self.fn = args['first_name'].lower()
        self.ln = args['last_name'].lower()
        self.un = args['username'].lower()
        self.em = args['email'].lower()
        self.pw = args['password']
        self.cpw = args['password_confirm']
        self.dob = args['dob_date']
        return self

    def new_user(self):  # FULLY TESTED All logic in negative tense
        """When called checks all passed values from set_value()
            This will set the values of """
        if len(self.fn) < 3 or not name_regex.match(self.fn):  # Simple test if name above 2 and
            # print('*****FIRST NAME len under 3 and regex FAIL*****')  # TODO
            self.message_dict['truth'] = False
            self.message_dict['name'] = 'Name must be 2 or more letters and letters only'
        if len(self.ln) < 3 or not name_regex.match(self.ln):
            # print('*****LAST NAME len under 3 and regex FAIL*****')  # TODO
            self.message_dict['truth'] = False
            self.message_dict['name'] = 'Name must be 2 or more letters and letters only'
        if Users.objects.filter(username=self.un).exists():  # works!
            # print('*****USERNAME in database FAIL*****')  # TODO
            self.message_dict['truth'] = False
            self.message_dict['user'] = 'User name is already used please select a new one'
        if self.un == '':  # works!
            # print('*****USERNAME in database FAIL*****')  # TODO
            self.message_dict['truth'] = False
            self.message_dict['user'] = 'Username can not be blank'
        if Users.objects.filter(email=self.em).exists():  # works!
            # print('*****EMAIL in database FAIL*****')
            self.message_dict['truth'] = False
            self.message_dict['email'] = 'Email already used please select a new one'
        elif not re.match(EMAIL_REGEX, self.em):
            # print('*****EMAIL regex FAIL*****')  # Test complete
            self.message_dict['truth'] = False
            self.message_dict['email'] = 'Please enter a valid email'
        if self.pw != self.cpw:
            # print('*****PASSWORDS done not match FAIL*****')  # TODO
            self.message_dict['truth'] = False
            self.message_dict['password'] = 'Passwords do not match'
        elif self.pw < 8:
            # print('*****PASSWORD to short FAIL*****')  # TODO
            self.message_dict['truth'] = False
            self.message_dict['password'] = 'Your password must be 8 characters or longer'
        elif not re.match(PASSWORD_REGEX, self.pw):
            # print('*****PASSWORDS regex FAIL*****')  # TODO
            self.message_dict['truth'] = False
            self.message_dict['password'] = 'Password must have 1 Number 1 Capital, 1 lowercase letter'
        if self.dob > '':  # Test PASSED
            # print('*****DOB greater then blank PASS*****')  # TODO
            if int(self.dob[0:4]) > 2004:
                # print('*****DOB before 2004 FAIL*****')  # TODO
                self.message_dict['truth'] = False
                self.message_dict['dob'] = 'You must have been born before 2004 to register'
        elif self.dob == '':
            self.message_dict['truth'] = False
            self.message_dict['dob'] = 'You must have been born before 2004 to register'
        if self.message_dict['truth']:
            # print('*****ALL PASS Making user_dict NOW*****')  # TODO
            x = self.pw
            self.user_dict = {
                'first_name': self.fn.title(),
                'last_name': self.ln.title(),
                'username': self.un,
                'email': self.em,
                'password': bcrypt.hashpw(str(x), salt),
                'dob_date': self.dob,
                'user_level': 9 if not Users.objects.filter(user_level=9).exists() else 1,  # test PASSED
            }
        return self

    def add_user(self):  # Fully tested
        """While this can be called at any time it will fail nicely while some what intensively
            It should be called ONLY after an if statement check on message_dict['truth'] to avoid
            having to handle an error. This will return failure messages or positive messages
             *** The messages are store in add_dict with values ['alert] and ['truth'] respectively ***"""
        # print('*****IN ADD USER*****')  # TODO REMOVE FOR FINAL
        if self.message_dict['truth']:
            # print('*****FIRST IF self.message_dict.truth PASS *****')  # TODO REMOVE FOR FINAL
            try:
                x = self.user_dict
                Users.objects.create(first_name=x['first_name'], last_name=x['last_name'],
                                     username=x['username'], email=x['email'],
                                     dob_date=x['dob_date'], user_level=x['user_level'],
                                     password=x['password'])
                self.add_dict['truth'] = True
                self.add_dict['alert'] = 'Registration Complete!'
                # print('*****TRY get_or_create(x_dict) PASS*****')  # TODO REMOVE FOR FINAL
            except IntegrityError:
                # print('*****EXCEPT IntegrityError can not register FAIL*****')  # TODO REMOVE FOR FINAL
                self.add_dict['truth'] = False
                self.add_dict['alert'] = 'Registration Failed Please try again'
        else:
            # print('*****INSANITY ERROR IF THIS ERROR IS HERE LOGICAL FLAWS IN ABOVE CODE*****')  # TODO REMOVE FOR FINAL
            self.add_dict['truth'] = False
            self.add_dict['alert'] = "You are exiting the normal realm of possibilities. Lets just start over!"
        return self


# ***** END OF NewUser() CLASS *****
# ***** START OF IsAdmin() CLASS *****


class IsAdmin(object):  # Fully tested
    """Class handles finding admin level. It is implemented by doing the fallowing
       1. set a new instance of the class passing in username as a parameter.
       EXAMPLE: is_admin = IsAdmin('username')
       2. call the method find_admin_level taking in no parameters
       EXAMPLE: is_admin.find_admin_level
       3. now is_admin.admin will have a True or False value depending on if admin
       EXAMPLE: is_admin.admin ==> True, or False depending on admin_level
       4. or you can find the number value of user level
       EXAMPLE: is_admin.level ==> returns the user_level from DB
       NOTE: This class can be expanded to handle more admin level types since it is
       started at the highest level of exclusivity first
        """

    def __init__(self, username):
        self.username = username
        self.level = 0
        self.admin = False

    def find_admin_level(self):
        if len(self.username) > 0:
            if Users.objects.filter(username=self.username).values('user_level').exists():
                self.level = Users.objects.filter(username=self.username).values('user_level')
                self.level = self.level[0]['user_level']
                if self.level > 8:
                    self.admin = True


# ***** END OF IsAdmin CLASS *****
# ***** START OF LogIn CLASS *****


class LogIn(object):
    def __init__(self, username, password):
        # TODO pick if dict or var is better to handle info passing
        self.username = username
        self.password = password
        self.validated = False

        self.user_dict = {
            'truth': False,
            'first_name': '',
            'last_name': '',
            'username': '',
            'email': '',
            'dob_date': ''
        }

        self.alert_message = {
            'truth': False,
            'alert': ''
        }

    def login(self):
        print ('***** START LOGIN *****')  # TODO
        if Users.objects.filter(username=self.username).exists():
            if Users.objects.filter(username=self.username).values('password').exists():
                password_hash = Users.objects.filter(username=self.username).values('password')
                password_hash = password_hash[0]['password']
                validated = bcrypt.hashpw(str(self.password), str(password_hash))
                if validated == str(password_hash):
                    self.validated = True
                    user_obj = Users.objects.filter(username=self.username)
                    self.user_dict = {
                        'truth': True,
                        'first_name': user_obj[0].first_name,
                        'last_name': user_obj[0].last_name,
                        'username': user_obj[0].username,
                        'email': user_obj[0].email,
                        'dob_date': str(user_obj[0].dob_date)[0:10]
                    }
        elif Users.objects.filter(email=self.username).exists():
            if Users.objects.filter(email=self.username).values('password').exists():
                password_hash = Users.objects.filter(email=self.username).values('password')
                password_hash = password_hash[0]['password']
                validated = bcrypt.hashpw(str(self.password), str(password_hash))
                if validated == str(password_hash):
                    self.validated = True
        else:
            self.alert_message['truth'] = True
            self.alert_message['alert'] = "User name or Email did not match password"


# ***** End of fully tested user validation ****

# +++++ TESTING CODE +++++


# +++++ END TESTING CODE +++++

# ***** EXPERIMENTAL FUNCTIONAL CODE NOT FULLY TESTED *****


class EditUser(object):  # TODO class not fully tested only each piece on it's own
    """In class instance creation you MUST pass in the user name of the user you
        This information should be taken from the session['user_id'] to ensure higher
        security of adjusting of user information and admin level control"""
    def __init__(self, username):
        self.username = username
        self.add_dict = {
            'truth': False,
            'alert': ''
        }

    def add_dec(self, dec):
        """Function allowing the creation of user description based on initial assignment values
            This ensures the user only has control of there user"""
        if dec < 1:  # TODO
            self.add_dict['truth'] = False
            self.add_dict['alert'] = "You have to actually type something if you want us to save it!"
        if Users.objects.filter(username=self.username).exists():  # works!
            self.add_dict['truth'] = True
            self.add_dict['alert'] = 'You have added a description of yourself! Thanks!'
        else:
            self.add_dict['truth'] = False
            self.add_dict['alert'] = 'Something went wrong on our end. Please try again'
        return self

# ***** END EXPERIMENTAL FUNCTIONAL CODE NOT FULLY TESTED *****

# ***** UNTESTED CODE BELOW USE WITH CAUTION *****


class GET(models.Manager):

    @staticmethod
    def ui(user_id):
        return Users.objects.filter(id=user_id)


class Set(models.Manager):

    @staticmethod
    def new_user(fn, ln, un, email, dob, des, pw):
        """This makes a new user"""
        hash_pw = bcrypt.hashpw(pw, bcrypt.gensalt(14))
        Users.objects.create(first_name=fn, last_name=ln, username=un, email=email, dob_date=dob, description=des,
                             password=hash_pw)

    @staticmethod
    def update(where, user, new_val):
        """The where is the column name to be updated
            The user is the user name to update
            The new_val is the value to be passed in"""
        user_instances = Users.objects.filter(username=user)
        if where == 'first_name':
            user_instances.update(first_name=new_val)  # Updates first name
        if where == 'last_name':
            user_instances.update(last_name=new_val)
        if where == 'username':
            user_instances.update(username=new_val)
        if where == 'email':
            user_instances.update(email=new_val)
        if where == 'description':
            user_instances.update(description=new_val)
        if where == 'password':
            hash_pw = bcrypt.hashpw(new_val, salt)
            user_instances.update(password=hash_pw)


# ***** REFACTOR AND REMOVE THE CODE BELOW *****


class Registration(models.Model):  # TODO

    @staticmethod
    def register(fn, ln, un, email, dob, des, pw):
        hash_pw = bcrypt.hashpw(pw, bcrypt.gensalt(14))
        Users.objects.create(first_name=fn, last_name=ln, username=un, email=email, dob_date=dob, description=des, password=hash_pw)

    @staticmethod
    def add_user(first_name, last_name, username, email, dob_date):
        return_dictionary = {
            'truth': False,
            'alert': ''
        }
        """This will check if a user is valid and return an error message if user is in the DB already"""
        #  TODO set user_level by default. first user max all others low
        try:
            Users.objects.get(user_level=9)
            try:
                Users.objects.create(first_name, last_name, username, email, dob_date)
                return Users.objects.filter(username=username)
            except IntegrityError:
                return False
        except ObjectDoesNotExist:
            try:
                Users.objects.create(first_name, last_name, username, email, dob_date, user_level=9)
                return Users.objects.filter(username=username)
            except IntegrityError:
                return False

    @staticmethod
    def name_validate(name):
        """This function validates a name with a simple regex for letter only and length greater then 2"""
        if len(name) > 2 and name_regex.match(name):
            return True
        return False


# ***** REFACTOR AND REMOVE THE CODE ABOVE *****


# ***** SLUG FIELD *****

# NAME_REGEX     = re.compile(r'^[a-zA-Z -\']{3,}$')  # Other Regex to test
# PASSWORD_REGEX = re.compile(r'^([A-Z])+([a-z])+([0-9])+$')
# Create your models here.
# , fn, ln, un, em, pw, cpw, dob
# @staticmethod
# def login_validate(username, password):
#     print('***** models.py login_validate start *****')  # TOD
#     try:
#         print('***** login_validate TRY is run *****')  # TODO
#         password_hash = Users.objects.get(username=username)
#         password_hash = password_hash.password
#     except ObjectDoesNotExist:
#         print('***** login_validate EXCEPT is run *****')
#         to_return = {
#             'truth': False,
#             'alert': "User name and password are incorrect"
#         }
#         return to_return
#         # checked_password = check_password(password, password_hash)  #TODO use hashed password
#         # print(checked_password)
#         # if checked_password:
#     if password == password_hash:
#         user_object = Users.objects.get(username=username)
#         user_dictionary = {
#             'truth': True,
#             'alert': "Login Complete!",
#             'first_name': user_object.first_name,
#             'last_name': user_object.last_name,
#             'username': user_object.username,
#             'email': user_object.email,
#             'user_id': user_object.id
#         }
#         return user_dictionary
#     else:
#         return False

