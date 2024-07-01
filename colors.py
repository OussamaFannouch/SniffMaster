#!/usr/bin/env python3
# - Simple Terminal Colorizing -
# U+0A75
def bold(text):
    return bcolors.BOLD + text + bcolors.ENDC

def underline(text):
    return bcolors.UNDERLINE + text + bcolors.ENDC

def blue(text):
    return bcolors.CBLUE + text + bcolors.ENDC
    
def green(text):
    return bcolors.OKGREEN + text + bcolors.ENDC

def red(text):
    return bcolors.CRED + text + bcolors.ENDC

def red_light(text):
    return bcolors.CRED2 + text + bcolors.ENDC

def yellow(text):
    return bcolors.CYELLOW + text + bcolors.ENDC

def beige(text):
    return bcolors.CBEIGE + text + bcolors.ENDC

def green_light(text):
    return bcolors.CGREEN + text + bcolors.ENDC

def violet(text):
    return bcolors.CVIOLET + text + bcolors.ENDC

class bcolors:
    # example = bcolors.OKGREEN + "I am green" + bcolors.ENDC + " and I am not"
    CRED    = '\33[31m'
    CGREEN  = '\33[32m'
    CYELLOW = '\33[33m'
    CBLUE   = '\33[34m'
    CVIOLET = '\33[35m'
    CBEIGE  = '\33[36m'
    CGREY    = '\33[90m'
    CRED2    = '\33[91m'
    CGREEN2  = '\33[92m'
    CYELLOW2 = '\33[93m'
    CBLUE2   = '\33[94m'
    CVIOLET2 = '\33[95m'
    CBEIGE2  = '\33[96m'
    CWHITE2  = '\33[97m'
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
