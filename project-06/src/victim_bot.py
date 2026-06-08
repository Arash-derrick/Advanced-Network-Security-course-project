import os
import time
import random
import dns .resolver

def pick_secret ()->str :

    forced =os .getenv ("SECRET","").strip ()
    if forced :
        return forced

    raw =os .getenv ("CANDIDATES","").strip ()
    if raw :
        candidates =[x .strip ()for x in raw .split (",")if x .strip ()]
    else :
        candidates =[
        "charlie-payroll.internal",
        "charlie-vpn.internal",
        "charlie-hr.internal",
        ]

    return random .choice (candidates )

SECRET =pick_secret ()
DEBUG =os .getenv ("DEBUG","0").strip ()in {"1","true","TRUE","yes","YES"}

print ("[*] Victim Bot Online.")
if DEBUG :
    print (f"[*] (debug) chosen secret: {SECRET}")

res =dns .resolver .Resolver (configure =False )
res .nameservers =["10.0.0.53"]
res .timeout =2.0
res .lifetime =2.0

while True :
    try :
        res .resolve (SECRET ,"A")
        if DEBUG :
            print (f"[BOT] visited {SECRET}")
    except Exception as e :
        if DEBUG :
            print (f"[BOT] error: {e}")

    time .sleep (10 )
