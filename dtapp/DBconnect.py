import datetime as dt
import pandas as pd
from sqlalchemy import create_engine, text
import json
import logging
from dtapp import logging


try:
    # Getting config information for connecting to Database (DB).
    logging.info("Getting information form config file for starting DB connection.")
    with open('dtapp/config/config.json') as f:
        data = json.load(f)
        host = data["dbconfiginfo"]["host"] # Originally, was '10.117.112.75'
        dbname = data["dbconfiginfo"]["dbname"] 
        schema = data["dbconfiginfo"]["schema"]
        username = data["dbconfiginfo"]["username"]
        password = data["dbconfiginfo"]["password"]
        port = data["dbconfiginfo"]["port"]

    #Connecting to the PostgreSQL DB
    def connection_pgsql(schema,username,password,port,host,db):
        '''Creates a connection to pgsql and returns the connection object along with the schema read from db_config.'''
        schema = schema
        engine = create_engine('postgresql://{}:{}@{}:{}/{}'.format(username, password,host,port,dbname))
        logging.info("Successful postgreSQL DB connection.")
        return engine,schema

    # Creating SQLAlchemy engine and schema objects
    engine,schema= connection_pgsql(schema,username,password,port,host,dbname) #engine, schema are global vars

     
    # Function to update user's last login date/time into postgreSQL database
    def login_time(email):
        with engine.connect() as conn: # automatically does conn.begin() and conn.commit()
            logging.info("Updating logging-in time")
            time_now = str(dt.datetime.now().strftime("%B %d, %Y %H:%M:%S.%f"))
            conn.execute("UPDATE dev.usrcreds SET last_login = %s WHERE email = %s ;", 
            (time_now,email))
        
    
    # Modding enabled value for admin use only.
    def mod_enable(email):
        with engine.connect() as conn: # automatically does conn.begin() and conn.commit()
            logging.info("Modding enabled value of username for testing purposes only.")
            enabled = "True"
            conn.execute("UPDATE dev.usrcreds SET enabled = %s WHERE username = %s ;", 
            (enabled,email))
    
    # Registering users with Enabled set as False until Vency updates to true
    def register_user(user_name, email, pword, user_type = "enduser", enabled = "False"):
        with engine.connect() as conn:
            logging.info("Registering the user")
            # Getting Current date and time in str format
            time_now = str(dt.datetime.now().strftime("%B %d, %Y %H:%M:%S.%f"))
            last_log = None # Changes to NULL in the DB
            # Getting the idnum for the new user
            sql_query="SELECT user_id FROM dev.usrcreds;"
            df_users = pd.read_sql(sql_query,conn)
            if(len(df_users["user_id"]) > 0):
                idnum = max([user for user in df_users["user_id"]]) + 1
            else:
                idnum = 0
            # Inserting user information into table
            conn.execute("INSERT INTO dev.usrcreds VALUES (%s, %s, %s, %s, %s, %s, %s, %s);",
            (str(idnum), str(user_name), pword, email,time_now, last_log, enabled, user_type))
    
  
    # Insert entry to dashboard information table. note must be enduser email.
    def insertdashbinfo(dbtitle, dbcatg, ddate, author, extern, email, enduser = "all"):
        with engine.connect() as conn:
            logging.info("Modding some values of dashbtable for testing purposes only.")
            sql_query_two="SELECT dashboardid FROM dev.dashboardinfo;" #"SELECT table_schema, table_name FROM information_schema.tables WHERE (table_schema = 'public') ORDER BY table_schema, table_name;" 
            df_dashb=pd.read_sql(sql_query_two, conn)
            link = str('/' + dbtitle)
            if(len(df_dashb["dashboardid"]) > 0):
                idnum = max([user for user in df_dashb["dashboardid"]]) + 1
            else:
                idnum = 0
            conn.execute("INSERT INTO dev.dashboardinfo VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);",
            (str(idnum), dbtitle, ddate, link, author, enduser, extern, dbcatg, email))

    #Inserting into the audit logs table.
    def insert_auditlog(usrnm, email, given_name, family_name, ipaddr, uniquename, idp = False): 
        with engine.connect() as conn:
            sql_query = "SELECT username FROM dev.audit_log;"
            usrs = pd.read_sql(sql_query, conn)
            usrs = [usr for usr in usrs['username']] # won't work if left as df must conver to list object in python.
            time_now = str(dt.datetime.now().strftime("%B %d, %Y %H:%M:%S.%f"))
            # If user doesn't exist yet, inserting all information from the claims response.
            # For PCCI data scientists,
            if idp == False:
                conn.execute("INSERT INTO dev.audit_log VALUES (%s, %s, %s, %s, %s, %s, %s, %s);",
                (usrnm, email, given_name, None, family_name, ipaddr, uniquename, time_now))
            # For guest users (from other directories),
            else:
                conn.execute("INSERT INTO dev.audit_log VALUES (%s, %s, %s, %s, %s, %s, %s, %s);",
                (usrnm, email, given_name, idp, family_name, ipaddr, uniquename, time_now))
                     
    # Function used for debugging when making the flaskapp work with the DB.
    def mod_info(usrtyp, idn):
        with engine.connect() as conn:
            #logging.info("Modding value of.")
            #conn.execute("UPDATE dev.usrcreds SET usertype = %s WHERE user_id = %s ;", (usrtyp,idn))
            #conn.execute("DELETE FROM dev.dashboardinfo WHERE dashboardid = %s ;", (idn))
            #conn.execute("UPDATE dev.dashboardinfo SET enduser = %s WHERE dashboardid = %s ;", ("stakeholder@example.com", idn))
            #conn.execute("DELETE FROM dev.audit_log WHERE username = %s ;",(usrnm))
            return None # comment when you are using for debugging.
        return None
 
    # Reading all users in the dev.usrcred table
    def read_allusers():
        with engine.connect() as conn:
            logging.info("Reading from Creds table")
            sql_query="SELECT user_id, username, password, email, created_on, last_login, enabled, usertype FROM dev.usrcreds ORDER BY user_id;"  #WHERE enabled=false
            all_users = pd.read_sql(sql_query,conn)
            return all_users

    # Reading all users form the dev.usrcreds table which are not enabled by the adminstrator yet.
    def read_unableusers():
        with engine.connect() as conn:
            logging.info("Getting users that have not been enabled")
            sql_query2="SELECT username, email FROM dev.usrcreds WHERE enabled=false ORDER BY user_id;"  #
            unable_users = pd.read_sql(sql_query2,conn)
            return unable_users
        
    # Reading all dashboard information from the devs.dashbinfo table 
    def read_dashbs():
        with engine.connect() as conn:
            logging.info("Reading from dashbinfo table.")
            sql_query3= "SELECT dashboardid, title, ddate, routes, author, enduser, externalurl, catg, email FROM dev.dashboardinfo ORDER BY dashboardid;"
            all_dashbs=pd.read_sql(sql_query3,conn)
            return all_dashbs
    
        
    # Specialized Read function for displaying enduser dashboards on homepage
    def read_userdashbs(email):
        with engine.connect() as conn:
            logging.info("Reading from dashbinfo table for specific user.")
            sql_query3= "SELECT dashboardid, title, ddate, routes, author, enduser, externalurl, catg FROM dev.dashboardinfo WHERE enduser='"+email+"' OR catg='Other' ORDER BY dashboardid;"
            dashbs=pd.read_sql(sql_query3,conn)
            dashbs["dashboardid"] = [num for num in range(len(dashbs["dashboardid"]))]
            return dashbs

    # Reading only dashboards that devusers have authored.s
    def read_devdashbs(email):
        with engine.connect() as conn:
            logging.info("Reading from dashbinfo table for specific dev user.")
            # Note the WHERE clause is slightly different here.
            sql_query3= "SELECT dashboardid, title, ddate, routes, author, enduser, externalurl, catg FROM dev.dashboardinfo WHERE email='"+email+"' OR catg='Other' ORDER BY dashboardid;"
            dashbs=pd.read_sql(sql_query3,conn)
            dashbs["dashboardid"] = [num for num in range(len(dashbs["dashboardid"]))]
            return dashbs

    # Reading all audit logs from dev.audit_log table.
    def read_auditlogs():
        with engine.connect() as conn:
            logging.info("Reading audit logs from dev audit logs table.")
            sql_query = "SELECT username, email, given_name, idp, family_name, ipaddr, unique_name, login_on FROM dev.audit_log;"
            auditlogs = pd.read_sql(sql_query,conn)
            return auditlogs


 

# Catching errors and logging to the dtappinfo.log.
except Exception as e:
    logging.error(str(e))



