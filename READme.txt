Web App Notation:
*****************

DB- stands for Database
dashb- stands for dashboard
admin- adminstrator of DashboardTechApp
devuser- data scientist/developer user
enduser- stakeholders;clients


MVP WebApp Tree Structure of Files:
***********************************

C:.
│   app.py
│   READme.txt
│
├───Dashboards_ex
│       bokehdashb.py
│       geomapex2_bokeh.py
│       geomapex_bokeh.py
│       plotlydashb.py
│
├───flaskapp
│   │   DBconnect.py
│   │   forms.py
│   │   routes.py
│   │   __init__.py
│   │
│   ├───config
│   │       config.json
│   │
│   ├───data_files
│   ├───geodata
│   ├───logs
│   │       auth_resp.json
│   │       bokehdashb.json
│   │       DTAppInfo.json
│   │       MSdata_keys.json
│   │       MSdata_openid.json
│   │       plotlydashb.json
│   │       token.json
│   │
│   ├───static
│   │   │   styling.css
│   │   │
│   │   ├───bootstrap-4.5.0-dist
│   │   │   ├───css
│   │   │   └───js
│   │   └───PCCI_logo
│   └───templates
└───READthese
        DBlogininfo.txt
        requirements.txt