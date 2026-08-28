from urllib import request as urlreq
from flask import request

def open_remote():
    loc = request.args.get("loc")
    urlreq.urlopen(loc)
