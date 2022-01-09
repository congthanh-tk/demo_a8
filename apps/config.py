# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
from decouple import config


class Config(object):

    basedir = os.path.abspath(os.path.dirname(__file__))


    # This will create a file in <app> FOLDER
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + \
        os.path.join(basedir, 'db.sqlite3')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Set up the App SECRET_KEY
    SECRET_KEY = config('SECRET_KEY', default='10dI3mAnToanUDWeb')
    
    # Black list
    blacklists = ["/bin/sh",
                  "/bin/rbash",
                  "/bin/zsh",
                  "/bin/bash",
                  "/bin/csh",
                  "/bin/ksh",
                  "dir",
                  "cd",
                  "chdir",
                  "md",
                  "mkdir",
                  "copy",
                  "move",
                  "ren",
                  "del",
                  "exit",
                  "echo",
                  "type",
                  "fc",
                  "cls",
                  "help",
                  "date",
                  "time",
                  "driverquery",
                  "hostname",
                  "RHOST",
                  "rport",
                  "systeminfo",
                  "ver",
                  "gpresult",
                  "gpupdate",
                  "ipconfig",
                  "ping",
                  "tracert",
                  "nslookup",
                  "route",
                  "arp",
                  "netsh",
                  "getmac",
                  "telnet",
                  "nc",
                  "tftp",
                  "cls",
                  "cmd",
                  "color",
                  "promp",
                  "title",
                  "help",
                  "shutdown",
                  "taskkill",
                  "tasklist",
                  "schtasks",
                  "openfiles",
                  "xcopy",
                  "replace",
                  "print",
                  "move",
                  "process",
                  "run",
                  "system",
                  "powershell"]


class ProductionConfig(Config):
    DEBUG = False

    # Security
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 3600

    # PostgreSQL database
    SQLALCHEMY_DATABASE_URI = '{}://{}:{}@{}:{}/{}'.format(
        config('DB_ENGINE', default='postgresql'),
        config('DB_USERNAME', default='appseed'),
        config('DB_PASS', default='pass'),
        config('DB_HOST', default='localhost'),
        config('DB_PORT', default=5432),
        config('DB_NAME', default='appseed-flask')
    )


class DebugConfig(Config):
    DEBUG = True


# Load all possible configurations
config_dict = {
    'Production': ProductionConfig,
    'Debug': DebugConfig
}
