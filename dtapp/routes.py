from flask import render_template, session, redirect, abort, url_for, request, flash# , jsonify, request, make_response
from requests_oauthlib import OAuth2Session
from dtapp import logging, app, dbappversion, aboutpublishdt, is_https_req, ms_client_id, ms_client_secret, ms_tenant_id, ms_authorization_base_url, ms_token_url, ms_scope, ms_redirect_uri, ms_logout_url
from dtapp.DBconnect import  read_allusers, register_user, read_dashbs, login_time, mod_enable, read_unableusers, insertdashbinfo, read_userdashbs,read_devdashbs, insert_auditlog
from dtapp.forms import RegForm, LoginForm, DashbinfoForm
import logging
import json
import jwt
import os
import datetime as dt


''' Custom Functions and Error Handling:'''
# If username and usertype not in session, directing to Forbidden page.
def nohardcoderoute():
    if (not ('username' in session and 'usertype' in session)):
        logging.warning("User attempting to access restricted page without logging in.")
        abort(403)
    return None


# Must be used with nohardcoderoute()
# Restricting access to some web pages for dev users only.
# If enduser tries to access web page in dev or admin route, 403 error. 
def endusronly():
    if('usertype' in session):
        if (session['usertype'] != 'enduser'):
            logging.critical(session['username'] + " (" + session['usertype'] + ") "+ "attempting to access restricted page.")
            logging.info("Redirecting user to Abort 403 Error page.")
            abort(403)
    return None


# Must be used with nohardcoderoute()
# Restricting access to some web pages for dev users only.
# If enduser tries to access web page in dev or admin route, 403 error. 
def devsonly():
    if('usertype' in session):
        if (session['usertype'] != 'devuser' and session['usertype'] != 'admin' ):
            logging.critical(session['username'] + " (" + session['usertype'] + ") "+ "attempting to access restricted page.")
            logging.info("Redirecting user to Abort 403 Error page.")
            abort(403)
    return None

# Must be used with nohardcoderoute() and devsonly(). The admin must be a dev user.
# Restricting access to some web pages to the admin only. 
# If enduser tries to access web page in dev or admin route, 403 error. 
def adminonly():
    if('usertype' in session):
        if (session['usertype'] != 'admin'):
            logging.critical(session['username'] + " (" + session['usertype'] + ") "+ "attempting to access restricted page.")
            logging.info("Redirecting user to Abort 403 Error page.")
            abort(403)
    return None



# Returns email of user or returns None if user DNE.
def getusrmail(userinfo):
    # Reading current users from DB.
    usr_dict = read_allusers().to_dict('list')
    # If username/email given, is not in DB, then return None.
    if not (userinfo in usr_dict['username'] or userinfo in usr_dict['email']):
        logging.warning("No username/email "  + userinfo + " exists.")
        return None
    # If in the usernames, return the email.
    elif (userinfo in usr_dict['username']):
        email_indx = usr_dict['username'].index(userinfo)
        return usr_dict['email'][email_indx]
    # Otherwise, just return the given input (email)
    return userinfo

# Gets the user type of an existing user or returns None if user DNE.
def getusrtype(usrmail):
    # Reading current users from DB.
    usrdct = read_allusers().to_dict('list')
    # If user email is not in DB, returning None.
    if not(usrmail in usrdct['email']):
        logging.warning("No email "+ usrmail + " exists.")
        return None
    # If user is in DB, returning his/her usertype.
    email_indx = usrdct['email'].index(usrmail)
    return usrdct['usertype'][email_indx]

#Error handling for page not found
@app.errorhandler(404)
def page_not_found(error):
    logging.error("404 Error: Page not found")
    return render_template("all/pagenotfound.html",title = "Page Not Found"), 404 

# Also 403 errors for users who attempt to view
# dashboards that they are not assigned
@app.errorhandler(403)
def Forbidden(error):
    logging.error("403 Error: Attempt to access forbidden page")
    return render_template("all/Forbidden.html",title = "Forbidden"), 403



'''Routes:'''
# Route to index page
@app.route('/')
def index():
    # If the username and the usertype are both in session.
    if ('username' in session and 'usertype' in session): 
        # For the admin user.
        if(session['usertype'] == 'admin'):
            logging.info("Redirecting to admin home page.")
            return redirect(url_for('adminhome'))
        # For the devOps users or data scientists.
        elif(session['usertype'] == 'devuser'):
            logging.info("Redirecting to devuser home page.")
            return redirect(url_for('devhome'))
        # For the endusers-stakeholders.
        elif(session['usertype'] == 'enduser'):
            logging.info("Redirecting to enduser home page.")
            return redirect(url_for('home'))
    # Otherwise, Redirecting to login page
    logging.info("Redirecting to login page.")
    return redirect(url_for('login'))

# Login page for end users.
@app.route('/login', methods = ['GET','POST'])
def login():
    # Initializing login form.
    form = LoginForm()
    # If the client browser makes a POST request,
    if request.method == 'POST':
        # Temporarily storing username and password data.
        usrnm = form.username.data
        passwd = form.password.data
        usrthere = False
        usrs = read_allusers().to_dict('list')
        idnum = 0
        # Checking if user is in DB and getting user info if he/she is in DB.
        if (usrnm in usrs['username']):
            usrthere = True
            idnum = usrs['username'].index(usrnm)
        elif (usrnm in usrs['email']):
            usrthere = True
            idnum = usrs['email'].index(usrnm)

        # Going to enduser routes (only). devusers cannot logging in through this normal logging in page.
        if (usrthere and usrs['usertype'][idnum] == "enduser" 
        and usrs["enabled"][idnum] == True and usrs['password'][idnum] == passwd):
            logging.info("Enduser " + usrnm + " logged in. Redirecting to enduser route network.")
            login_time(getusrmail(usrs['username'][idnum])) #updating login time
            flash(f'You have logged in as {usrnm} (enduser)','primary')
            session['username'] = usrnm
            session['usertype'] = 'enduser'
            return redirect(url_for('index'))
        # If the user not enabled by Admin.
        elif (usrthere and usrs["enabled"][idnum] == False):
            logging.info("Unable user trying to logging in.")
            flash(f'You cannot login until the administrator enables your account','warning')
        # If the user typed the wrong password for his account.
        elif (usrthere and not(usrs['password'][idnum] == passwd )):
            logging.info("Incorrect password")
            flash(f'Incorrect password for {usrnm}', 'warning')
        # If the user does not exist in the Data Base.
        elif (not(usrthere)):
            logging.info('Incorrect username/email: ' + usrnm + ' and password: ' + passwd)
            flash(f'Incorrect username/email. There is no account associated with {usrnm}', 'danger')
        # Otherwise.
        else:
            flash(f'Something went wrong. Please try again or contact the admin.','primary')

    # Rendering login template.
    logging.info("Loading login form on login page.")
    return render_template("all/login.html", title = 'Login', form = form) 




# End User Homepage
@app.route("/home")
def home():
    nohardcoderoute()
    endusronly()
    logging.info("Session username is" + "::::" +  session['username'])
    dashbinfo = read_userdashbs(getusrmail(session['username'])).to_dict('records')
    logging.info("Loading home page template.")
    # Returning the enduser/home template.
    return render_template('enduser/home.html', dashboards=dashbinfo,
    version = dbappversion, Aboutpbdate = aboutpublishdt)



# Registration Information page for enduser
@app.route("/registration", methods = ['GET', 'POST'])
def registration():
    # Initializing registration form.
    form = RegForm()
    # If client browser makes a POST request.
    if request.method == "POST":
        # If form is validated.
        if form.validate_on_submit():
            # Registering stakeholder/enduser in the DB.
            register_user(str(form.username.data), str(form.email.data), str(form.password.data))
            logging.info(str("Account created for" + str(form.username.data) + ". Redirecting to login page."))
            flash(f'Account requested for {form.username.data}. You may login after your account request has been approved.', 
            'success') # using success bootstrap class
            # Redirecting to login.
            return redirect(url_for("login"))
        else:
            logging.warning("Email/username entered already exists in DB, or did not type password correctly the second time.")
            flash(f'Incorrect re-typed password or username/email entered already exists. Please try again.', 
            'danger')
    # Rendering Registration template.
    logging.info("Creating Registration form on registration template for enduser.")
    return render_template('enduser/registration.html',version = dbappversion, title = 'Register', form = form)

    


# Admin Home
@app.route("/admin_home")
def adminhome():
    nohardcoderoute()
    devsonly()
    adminonly()
    # Rendering administrator home page template.
    logging.info("Loading admin home page template.")
    return render_template("admin/home.html", title = "Adminstration", version = dbappversion)
    

# Admin route
@app.route("/enableusers",methods = ['GET', 'POST'])
def enableusr():
    nohardcoderoute() 
    devsonly()
    adminonly()
    # Reading all disabled stakhodler users
    unableusers = read_unableusers().to_dict('list')['username']
    # When client browser makes a post request.
    # If submitting and there is more than one unable user.
    # Then enabling all disabled users selected to be enabled.
    if request.method == "POST" and (len(unableusers) > 0):
        users_en = request.form.getlist("usersenabled")
        logging.info("Admin has enabled " + ' '.join([str(user) for user in users_en])) 
        for user in users_en:
            mod_enable(getusrmail(user))
        flash(str("Users " + ' '.join([str(user) for user in users_en]) + " were succesfully enabled and can now login" ), 'success')
        logging.info("Redirecting to admin home page")
        return redirect(url_for('adminhome'))
    logging.info("Loading Enable Users form template.")
    # Render enable users template.
    return render_template("admin/enableusers.html", userinfo = unableusers, title ="Admin: Enable Users" , version = dbappversion)


# Dev user routes.
# Dev Login
# only internal members can access this page
@app.route("/internal")
def internal():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    # Starting OAuth2.0 session with Azure AD REST API.
    OAuth_ses = OAuth2Session(ms_client_id, 
    scope = ms_scope,
    redirect_uri = ms_redirect_uri)
   
    # Acquiring Full Authoriziation URL and State for CRSF.
    authorization_url, state = OAuth_ses.authorization_url(ms_authorization_base_url) # Returning full auth_url and state


    # Creating keys folder if it does not already exist
    if not os.path.exists(os.path.dirname(__file__) + "/keys"):
        os.makedirs(os.path.dirname(__file__) + "/keys")

    # Storing the authorization request.
    with open("dtapp/keys/request_auth_url.json","w") as f:
        json.dump(authorization_url, f)

    # Storing the authorization response.
    with open("dtapp/keys/response_auth_url.json","w") as f:
        authresp = {'authorization_url': authorization_url ,'state':state}
        json.dump(authresp, f)

    # Storing the state in the Flask session.
    session["ms_oauth_state"] = state
    logging.info("Redirecting to authorization_url: " + authorization_url)
    logging.info("State: " + state)
    
    # Redirecting to the full authorization url.
    return redirect(authorization_url)



# Step 2: User authorization, this happens on the provider.
# Change route name to '/mscallback' when requesting from ArcGis and PowerBI APIs later to avoid confusion
# Ensure to change redirect_uri/callback url in azure portal
@app.route("/callback", methods=["GET"])
def callback():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    # Logging information about the request URL sent to the Azure AD REST API.
    # The request.url is slightly different for HTTP and HTTPs requests.
    defaulturi=request.url
    logging.info(" default_uri ::: " + defaulturi)
    redirect_uri1=request.base_url
    my_uri=url_for('callback', _scheme='https', _external=True)
    logging.info(" https_uri ::: " + my_uri)
    logging.info(" redirect_uri ::: " + redirect_uri1)
    logging.info(" callback redirect ::: " + ms_redirect_uri)
    newuri = request.url.replace('http://', 'https://', 1)  #(for https)
    logging.info("New HTTPS URI ::: " + newuri)

    authuri = newuri if is_https_req else request.url
    
    # Creating OAuth session for acquiring token.
    OAuth_ses2 = OAuth2Session(ms_client_id, state=session['ms_oauth_state'],
    scope = ms_scope,
    redirect_uri = ms_redirect_uri)
    token = OAuth_ses2.fetch_token(ms_token_url, client_secret=ms_client_secret,
                               authorization_response = authuri, verify = is_https_req) #set verify = true when get ssl for webserver
    
    # Storing the access token from the full token.
    mytoken = token['access_token']
 
    # Works but not when verify = True which
    # is used to verify that the token was signed by the sender and not altered in any way.
    header = jwt.get_unverified_header(mytoken)
    claims = jwt.decode(mytoken, verify = False) 
    # Attempt to decrypt header and secret too.
  

      
    # Logging common claims for Devusers from Azure AD and user from another directory. 
    logging.info('Header = \n{}\n\n'.format(header))
    logging.info('Claims = \n{}\n\n'.format(claims))
    logging.info('name = {}'.format(claims['name']))
    logging.info('given_name = {}'.format(claims['given_name']))
    logging.info('family_name = {}'.format(claims['family_name']))
    logging.info('ipaddr = {}'.format(claims['ipaddr']))
    logging.info('unique_name = {}'.format(claims['unique_name']))
    logging.info('iss = {}'.format(claims['iss']))


    # Is user from developers Azure AD or from another directory?
    idpval = True if ("idp" in claims) else False

    # Inserting audit information into the database or updating logging in time if user already there.
    if (idpval):
        logging.info(claims['name'] + " is external guest user.")
        logging.info('idp = {}'.format(claims['idp']))
        email_addr = claims['email']
        logging.info('email = {}'.format(email_addr))
        insert_auditlog(claims['name'], claims['email'], claims['given_name'],claims['family_name'], claims['ipaddr'], claims['unique_name'], claims['idp'])
    else:
        logging.info(claims['name'] + " is internal user.")
        email_addr = claims['upn']
        logging.info('email = {}'.format(email_addr))
        insert_auditlog(claims['name'], claims['upn'], claims['given_name'],claims['family_name'], claims['ipaddr'], claims['unique_name']) 

    # Connecting user acct from Azure AD or Another User directory to their account
    # in the web app.    
    session['username'] = getusrmail(email_addr) # return value is None if user not in DB.
    session['usertype'] = getusrtype(email_addr) # return value is None if user not in DB.
    
    # If user is not in the DB, then registering new dev user.
    if (session['username'] == None and session['usertype'] == None):
        session['username'] = email_addr # Please note that username can denote the username or email
        register_user(claims['name'], email_addr, None, 'devuser', True)
        session['usertype'] = 'devuser'
    
    # Creating user response folder if it does not already exist
    if not os.path.exists(os.path.dirname(__file__) + "/keys/" + claims['given_name']):
        os.makedirs(os.path.dirname(__file__) + "/keys/" + claims['given_name'])

    # Writing keys/req_callback.json
    with open("dtapp/keys/request_callback.json", 'w') as f:
        logging.info("Writing authorization response to keys/auth_resp.json")
        json.dump(authuri,f)

    # Writing encrypted (JWT) token in keys/token.json
    with open("dtapp/keys/"+claims['given_name']+"/resp_token_callback.json", 'w') as f:
        logging.info("Writing token to keys/token.json")
        json.dump(token, f)
    
    # Writing payload of decrypted (JWT) token to keys/claim_resp.json
    with open("dtapp/keys/"+claims['given_name']+"/resp_claim.json", 'w') as f:
        logging.info("Writing payload of decrypted token to keys/claim_resp.json")
        json.dump(claims,f) 
      
    

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    session['ms_oauth_token'] = token
    logging.info("Redirecting to devlogin page.")
    return redirect(url_for('devlogin'))

   

#def refresh_token
#...
#...

# After verifiying devuser is logged in with Microsoft Authorization page, taking to web app login
@app.route("/devlogin", methods = ['GET','POST'])
def devlogin():
    nohardcoderoute()
    devsonly()
    # Updating user logging in time, and then redirecting to user homepage.
    logging.info("Recording logging-in time of user.")
    login_time(getusrmail(session['username']))
    if (session['usertype'] == "admin"):
         flash(f'You have logged in as {session["username"]} (admin)','primary')
    elif (session['usertype'] == 'devuser'):
         flash(f'You have logged in as {session["username"]} (devuser)','primary')
    
    # Redirecting to index.
    logging.info("Redirecting to Index.")
    return(redirect(url_for('index')))



# Profile supposed to get user information from Outlook API, 
# So can use mail with Flask web app.
def profile():
    """Fetching a protected resource using an OAuth 2 token."""
    return

# Dev Home route.
@app.route("/dev_home")
def devhome():
    nohardcoderoute()
    devsonly()
    # Temporary:  while not receiving user information from the Microsoft Auth. Server to start Flask session.
    logging.info("Session username is" + ":::" +  session['username'])
    if (session['username'] == 'guest'):
        dashbinfo = read_dashbs().to_dict('records')
    else:
        dashbinfo = read_devdashbs(getusrmail(session['username'])).to_dict('records')
    logging.info("Loading devuser's homepage.")
    return render_template("devuser/home.html", title = "DevOPs", version = dbappversion, dashboards = dashbinfo, Aboutpbdate = aboutpublishdt)
    
# insert dashboard page for dev user
@app.route("/insertdashb",methods = ['GET', 'POST'])
def devuser():
    nohardcoderoute()
    devsonly()
    form = DashbinfoForm()
    logging.info("Going to dev user dashboard information form.")
    if request.method == "POST":
        if form.validate_on_submit():
            logging.info("Account created.")
            insertdashbinfo(form.dbtitle.data, form.dbcatg.data, form.ddate.data, form.author.data, form.externurl.data, getusrmail(session['username']), getusrmail(form.enduser.data)) #and email
            flash(f'Dashboard page requested for {form.dbtitle.data}.', 
            'success') # using success bootstrap class
            return redirect(url_for("devhome"))
        else:
            #logging.warning("Email/username entered already exists in DB, or did not type password correctly the second time.")
            flash(f'Dashboard {form.dbtitle.data} may already exist or you may have entered some information incorrectly. Please try again.', 
            'danger')
            #logging.info("Creating Registration form. Calling registration route.")
    logging.info("Rendering insertdashb template web page.")
    return render_template('devuser/insertdashb.html',version = dbappversion, title = 'Add your Dashboard', form = form)


@app.route('/dev_logout')
def devlogout():
    #nohardcoderoute()
    return render_template('devuser/devlogout.html', title = "Logout")

#Log out page for all users
@app.route('/logout')
def logout():
    # Logging out based on the usertype.
    # Enduser.
    if (session['usertype'] == 'enduser'):
        logging.info("Enduser "+ session['username'] +  " logging out.")
    # Devuser.
    elif (session['usertype'] == 'devuser'):
        logging.info("Devuser "+ session['username'] +  " logging out.")
        return redirect(ms_logout_url)
    # Adminstrator.
    elif (session['usertype'] == 'admin'):
        logging.info("Adminstrator "+ session['username'] +  " logging out.")
        return redirect(ms_logout_url)
    # Remove the username from the session if it's there
    logging.info("Popping session username.")
    session.pop('username',None) # delete curr username in session and replace w/ None
    session.pop('usertype',None) # delete curr usertype in session and replace w/ None
    # Redirecting to index page.
    logging.info("Redirecting to index page.")
    return redirect(url_for('index'))


# Dashboard Apps and AboutUs App Routes:
# About US is for all user types.
@app.route("/AboutUs")
def AboutUs():
    nohardcoderoute()
    logging.info("User going to About Us. Ensure that techblogpost app is already running on port 5002 (for testing only).")
    return render_template("all/about.html", title = "AboutUs", version = dbappversion)


# Example Dashboard Routes for Endusers
# Possible PHI Data Dashboards (Not Applicable for prototype):
# Preterm Dashboard Page
@app.route("/PreTerm")
def PreTerm():
    nohardcoderoute()
    logging.info("Loading PreTerm dashboard.")
    return render_template('all/Pre_term.html', title = 'Pre_term1 Dashboard',version = dbappversion)


# Asthma Dashboard Page
@app.route("/Asthma")
def Asthma():
    nohardcoderoute()
    logging.info("Loading Asthma dashboard.")
    return render_template('all/Asthma.html', title = 'Asthma1 Dashboard',version = dbappversion)


# NON-PHI Data Dashboards (For Project Prototype):
# Testing Dashboards exported to HTML
# Bokeh (HTML) VI Dashboard
@app.route("/BokehVIdashboard")
def bokehdashboard():
    #nohardcoderoute()
    logging.info("Loading BokehVIdashboard")
    return render_template('all/bokehDashboard.html', version = dbappversion)

# Plotly HTML VI Dashboard
@app.route("/plotlyHtmldashboard")
def plotlyhtmldb():
    nohardcoderoute()
    logging.info("Loading plotlyHtmldashboard")
    return render_template('all/plotlyHTMLdashboard.html', version = dbappversion)


# VI Geomap of Dallas Cities with Bokeh
@app.route("/geomapbokeh")
def geomap():
    nohardcoderoute()
    logging.info("Loading Bokeh geomap example 1.")
    return render_template("all/geomapex.html")

# VI Geomap of Dallas Cities with Plotly
@app.route("/geomapplotly")
def geomap2():
    nohardcoderoute()
    logging.info("Loading Bokeh geomap example 2.")
    return render_template("all/geomapex2.html")

# Other dashboards
# Arcgis example geomap.
@app.route('/arcgis_example')
def arcgis():
    nohardcoderoute()
    logging.info("Loading Arcgis example.")
    return render_template('all/arcgis_ex.html', title = "Arcgis Map", version = dbappversion)
# PowerBI example dashboard.
@app.route('/powerbi_example')
def powerbi():
    nohardcoderoute()
    logging.info("Loading PowerBI example.")
    return render_template('all/powerbi_ex.html', title = "PowerBI Report", version = dbappversion)

# Rshiny example dashboard.
@app.route('/shiny_example')
def shiny():
    nohardcoderoute()
    logging.info("Loading Rshiny example.")
    return render_template('all/rshiny_ex.html', title = "Rshiny App", version = dbappversion)


