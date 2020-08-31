from flask_wtf import FlaskForm
from wtforms_components import DateField, DateRange
from wtforms import StringField, BooleanField, PasswordField, SubmitField
from wtforms.validators import InputRequired, DataRequired, EqualTo, Length, Email, ValidationError
from dtapp.DBconnect import engine, create_engine, text
from dtapp import logging
import pandas as pd
import logging




''' Validation Functions:'''
# Unique email validator, Unique password validator, and  Unique username validator (enduser)
def uniquedata(form, field):
    with engine.connect() as conn:
        val = ''
        usrdatnm = str(field.label.text)
        if (usrdatnm == 'Username'):
            val = 'username'
        elif(usrdatnm == 'Email'):
            val = 'email'
        sql_query="SELECT " + val + " FROM dev.usrcreds ORDER BY user_id;"  
        usrdatadf = pd.read_sql(sql_query,conn)
        usrdata = usrdatadf.to_dict('list')[val]
        if field.data in usrdata:
            logging.error("Email/Username " + str(field.data) + " already exists in database.")
            raise ValidationError("Error. Username/email "+ str(field.data) +" already exists in database.")
    
# Unique dashboard information validation function
def uniquedashb(form, field):
    with engine.connect() as conn:
        sql_query="SELECT title FROM dev.dashboardinfo ORDER BY dashboardid;"  
        dashbdf = pd.read_sql(sql_query,conn)
        dashbdata = dashbdf.to_dict('list')["title"]
        if field.data in dashbdata:
            logging.error("Dashboard Title " + str(field.data) + " already exists in database.")
            raise ValidationError("Error. Dashboard Title " + str(field.data) + " already exists.")
    

# Checks if enduser email is in database and is enabled.
def enduservalid(form,field):
    with engine.connect() as conn:
        endusr = str(field.data) # end user email address/username entered
        sql_query="SELECT username, email FROM dev.usrcreds WHERE usertype='enduser' AND enabled=true ORDER BY user_id;"  
        usrdatdf = pd.read_sql(sql_query,conn)
        usrmail = usrdatdf.to_dict('list')["email"]
        usrnm = usrdatdf.to_dict('list')["username"]
        if not(endusr in usrmail) and not(endusr in usrnm):
            logging.error(str("Enduser " + str(field.data) + " doesn't exist in database."))
            raise ValidationError(str("Error. Enduser " + endusr + " does not exist in DB."))



'''Flask WTF-Forms Classes:'''
# Login form class.
class LoginForm(FlaskForm):
    try:
        # Setting username requirements for registration form
        username = StringField('Username', validators = [InputRequired(), Length(min = 3, max = 30)])
        email = StringField('Email', validators = [InputRequired(), Email(), Length(min = 3, max = 100)])
        password = PasswordField('Password', validators = [InputRequired(), Length(min = 3, max = 30)])
        submit = SubmitField('Login')
    except Exception as e:
        logging.error(str("Error: " + str(e)))

# Registration form class.
class RegForm(FlaskForm):
    try:
        # Setting username requirements for registration form
        username = StringField('Username', validators = [InputRequired(), Length(min = 3, max = 30),uniquedata])
        email = StringField('Email', validators = [InputRequired(), Email(),Length(min = 3, max = 100),uniquedata])
        password = PasswordField('Password', validators = [InputRequired(), Length(min = 3, max = 30)])
        pw_confirm = PasswordField('Re-type your password', validators = [InputRequired(), EqualTo('password', message = "Incorrect password")])
        submit = SubmitField('Sign up')
    except Exception as e:
        logging.error(str("Error: " + str(e)))

# Dashboard information form class.
class DashbinfoForm(FlaskForm):
    # Setting username requirements for registration form
    try:
        dbtitle = StringField('Title', validators = [InputRequired(), uniquedashb, Length(min = 3, max = 200)])
        dbcatg = StringField('Category', validators = [InputRequired(), Length(min = 3, max = 200)])
        ddate = DateField('Publication Date', validators = [InputRequired(), DateRange(format = '%m/%d/%Y')])
        author = StringField('Author(s)', validators = [InputRequired(), Length(min = 3, max = 50)])
        enduser = StringField('Enduser (Username/Email)', validators = [InputRequired() ,enduservalid, Length(min = 3, max = 100)]) # later add dropdown for endusers. # add more email addresses to notify
        externurl = BooleanField('External Url?')
        submit = SubmitField('Request your Dashboard Page')
    # add description variable for dashbinfo later
    except Exception as e:
        logging.error(str("Error: " + str(e)))

# Please note the following:
# The adminstrator enabling form is written in pure html because it was more convenient for the circumstances of this form.
# Please attempt to use CRSF security with the Administration form.
# May write admin form class with Flask-WTF if you know how to do so
# Requirements: multiple check boxes in admin form, also form fields dynamically change.
# WT forms not suited for mutliple check boxes or dynamically changing fields.



    







