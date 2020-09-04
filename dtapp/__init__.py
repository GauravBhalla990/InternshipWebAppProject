from flask import Flask
import json
import logging
import datetime as dt
from dtapp.helpers import MyRotatingFileHandler
import urllib.parse
import os


# Flag variable to change app to use HTTP or HTTPs requests.
# Set to False is HTTP requests (no SSL)
is_https_req = True

# Initializing the Flask App.
app = Flask(__name__)

# Creating logs directory if doesn't already exist
if not os.path.exists(os.path.dirname(__file__) + "/logs"):
    os.makedirs(os.path.dirname(__file__) + "/logs")
output_file = os.path.dirname(__file__)+"/logs/dtappinfo.log"

# Configuring logger to output logs in .json format and rotate to .zip every 12 hours
logging.basicConfig(format= '{"levelname":"%(levelname)s","lineno":"%(lineno)s", "funcname":"%(funcName)s" ,"filename": "%(filename)s",  "message": "%(message)s","timestamp":"%(asctime)s"}',
level = logging.DEBUG,handlers = [MyRotatingFileHandler(filename = output_file, when = "h", interval = 12)]) # change when and interval parameters for development if necessary


#Loading information from config/config.json file.
# Setting port number and version for MVP Dashboard app
with open('dtapp/config/config.json') as f:
    data = json.load(f)
    portnum = data["server_url"]["portnum"] 
    dbappversion = data["appinfo"]["version"] #getting version of the dashboard app
    app.config['SECRET_KEY'] = data["appinfo"]["Secret_key"]  # App Secret Key can also be os.urandom(24) after importing os
    aboutpublishdt = data["appinfo"]["AboutUsDate"]

    # Microsoft OAuth credentials (get when registering OAuth application on service's portal)
    ms_client_id = data["Azure_AD_API"]["MS_Client_ID"]
    ms_client_secret = data["Azure_AD_API"]["MS_Client_Secret"]
    ms_tenant_id = data["Azure_AD_API"]["MS_Tenant_ID"]
    ms_authorization_base_url = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize" %(ms_tenant_id)
    ms_token_url = "https://login.microsoftonline.com/%s/oauth2/v2.0/token" %(ms_tenant_id)
    ms_scope = data["Azure_AD_API"]["MS_Scope"]
    ms_redirect_uri = data["Azure_AD_API"]["MS_Redirect_URI"] #Change redirect uri in config file when deploying to Virtual Private Server.
    mslogoutrd = urllib.parse.quote_plus(data["Azure_AD_API"]["MS_Logout_RD"]) # encoding url to valid ASCII for sending over the internet
    ms_logout_url = "https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=%s" %(mslogoutrd)
    
    # ArcGIS API credentials
    # PowerBI API credentials
    #..
    #..


#Importing flask routes file
from dtapp import routes
