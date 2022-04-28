import random
import string
import threading
import time
from datetime import datetime, timedelta
import traceback
import sys
import re

# WSGI-Related
import requests
import werkzeug.exceptions
import werkzeug.datastructures
from flask import Flask, request, render_template, redirect, jsonify, session, abort, Response
from flask_sqlalchemy import SQLAlchemy

# Security Thingys
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from html import escape
from flask_cors import CORS


def xss_detect(markup):
    if escape(markup) == markup:  # No <script> tags
        return False
    return True


class _RatelimitError(werkzeug.exceptions.HTTPException):
    code = 429
    name = "Too many requests"
    description = "The limit of connections per user was exceeded. Ratelimits end after one Minute"


def get_id(maxlen=6):
    return ''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=maxlen))


app = Flask(__name__)
app.config["SECRET_KEY"] = "rgnvr9e8htf98rehgv98rehgv9e"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
CORS(app)
app.blacklist = []

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["60 per minute"],
)


@app.errorhandler(werkzeug.exceptions.HTTPException)
def internal(error):
    print(error)
    err = Error(
        name=error.name,
        details=f"{error.code} {error.description}",
        id=get_id(),
        website_uri_name=Website.query.filter_by(website_uri=request.path
                                                 .replace("/errors/", "")
                                                 .replace("/log/", "")
                                                 .replace("/status/", "")
                                                 ).first().name if hasattr(
            Website.query.filter_by(website_uri=request.path
                                    .replace("/errors/", "")
                                    .replace("/log/", "")
                                    .replace("/status/", "")
                                    ).first(), "name") else request.path
    )
    db.session.add(err)
    db.session.commit()

    if isinstance(error, werkzeug.exceptions.HTTPException):
        return render_template("genericHttpFail.html", error=error.code, http=error), error.code
    etype, value, tb = sys.exc_info()
    print(traceback.print_exception(etype, value, tb))
    return render_template("genericOtherFail.html", error=300, http=error,
                           error_formatted=traceback.print_exception(etype, value, tb)), 300


@app.errorhandler(429)
def ratelimit_handler(e):
    markup = render_template("genericHttpFail.html", error=429, http=_RatelimitError)
    headers = werkzeug.datastructures.Headers()
    headers.add("Retry-After", 60)
    headers.add("Allow", "GET")
    res = Response(markup, status=429, headers=headers, mimetype="text/html", content_type="text/html")
    return res


db = SQLAlchemy(app)
running = True


@app.before_request
def block_method():
    if request.user_agent == "":
        app.blacklist.append(request.environ.get('REMOTE_ADDR'))
    else:
        if request.environ.get('REMOTE_ADDR') in app.blacklist:
            app.blacklist.pop(app.blacklist.index(request.environ.get('REMOTE_ADDR')))
    print(request.user_agent)
    ip = request.environ.get('REMOTE_ADDR')
    if ip in app.blacklist:
        abort(403)


def remove_emojis(data):
    emoj = re.compile("["
                      u"\U0001F600-\U0001F64F"  # emoticons
                      u"\U0001F300-\U0001F5FF"  # symbols & pictographs
                      u"\U0001F680-\U0001F6FF"  # transport & map symbols
                      u"\U0001F1E0-\U0001F1FF"  # flags (iOS)
                      u"\U00002500-\U00002BEF"  # chinese char
                      u"\U00002702-\U000027B0"
                      u"\U00002702-\U000027B0"
                      u"\U000024C2-\U0001F251"
                      u"\U0001f926-\U0001f937"
                      u"\U00010000-\U0010ffff"
                      u"\u2640-\u2642"
                      u"\u2600-\u2B55"
                      u"\u200d"
                      u"\u23cf"
                      u"\u23e9"
                      u"\u231a"
                      u"\ufe0f"  # dingbats
                      u"\u3030"
                      "]+", re.UNICODE)
    text = re.sub(emoj, '', data)
    return ''.join([i if ord(i) < 128 else ' ' for i in text])


def handle_catch(caller, on_exception):
    try:
        return caller()
    except:
        return on_exception


def backgroundchecks():
    while running:
        pages = Website.query.all()
        for page in pages:
            print(f"Checking {page.name}")
            try:
                print(page.active)
                if page.active == 1:
                    req = requests.get(page.website_uri, headers=page.headers)
                    incident = WebsiteResponse(id=get_id(20), name=page.name, response_text=req.text,
                                               response_text_query=page.response_text_query,
                                               status_code=req.status_code,
                                               website_uri=page.website_uri,
                                               last_response_successful=req.status_code < 400,
                                               response_time_elapsed=req.elapsed.total_seconds() * 1000)
                    db.session.add(incident)
                    db.session.commit()
                    print(f"{page.name} passed the Uptime Check!")
                else:
                    continue
            except Exception as error:
                err = Error(
                    name=str(type(error)),
                    details=f"{str(error)}",
                    id=get_id(),
                    website_uri_name=page.name
                )
                db.session.add(err)
                db.session.commit()
                print(f"{page.name} failed the Uptime Check!")
        time.sleep(60)


loop = threading.Thread(target=backgroundchecks)


class Website(db.Model):
    id = db.Column(db.String(100), primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    response_text_query = db.Column(db.String(99999999), nullable=True)
    website_uri = db.Column(db.String(128), nullable=False)
    active = db.Column(db.Integer, default=1)
    headers = db.Column(db.JSON)


class Error(db.Model):
    id = db.Column(db.String(100), primary_key=True)
    name = db.Column(db.String(40))
    details = db.Column(db.String(130))
    website_uri_name = db.Column(db.String(64))
    date = db.Column(db.DateTime, default=datetime.utcnow)


class WebsiteResponse(db.Model):
    id = db.Column(db.String(100), primary_key=True)
    page_id = db.Column(db.String(100))
    name = db.Column(db.String(64), nullable=False)
    response_text = db.Column(db.String(99999999), nullable=False)
    response_text_query = db.Column(db.String(99999999), nullable=True)
    status_code = db.Column(db.Integer, nullable=True, default=200)
    date = db.Column(db.DateTime, default=datetime.now)
    website_uri = db.Column(db.String(128), nullable=False)
    last_response_successful = db.Column(db.Integer, default=1)
    response_time_elapsed = db.Column(db.Integer, default=1)


@app.route("/")
@app.route("/status")
@limiter.limit("30 per minute",
               error_message=lambda: render_template("genericHttpFail.html", error=420, http=_RatelimitError))
def index():
    pages = Website.query.all()
    outages = []
    search_fails = []
    for page in pages:
        resps = WebsiteResponse.query.filter_by(name=page.name).all()
        i = WebsiteResponse.query.filter_by(name=page.name, last_response_successful=0).first()
        j = WebsiteResponse.query.filter_by(name=page.name, last_response_successful=1).first()

        if i in resps and resps.index(i) == 0:
            outages.append(i)
        if j and page.response_text_query not in j.response_text:
            search_fails.append((page, j))

    return render_template("index.html", pages=pages, outages=outages, search_fails=search_fails)


@app.route("/activate/<id>", methods=["POST"])
@limiter.limit("60 per minute",
               error_message=lambda: render_template("genericHttpFail.html", error=420, http=_RatelimitError))
def activate(id):
    website = Website.query.filter_by(id=id).first()
    website.active = 1
    db.session.commit()
    website = Website.query.filter_by(id=id).first()
    print(website.active)
    return jsonify({
        "website": website.name
    })


@app.route("/supersecretsettings")
@limiter.limit("30 per minute",
               error_message=lambda: render_template("genericHttpFail.html", error=420, http=_RatelimitError))
def settings():
    return render_template("settings.html")


@app.route("/supersecretsettings", methods=["POST"])
def settings_post():
    session["rmbIsSidebar"] = bool(request.form.get("contextIsNav", 1))

    return redirect("/")


@app.route("/deactivate/<id>", methods=["POST"])
@limiter.limit("60 per minute",
               error_message=lambda: render_template("genericHttpFail.html", error=420, http=_RatelimitError))
def deactivate(id):
    website = Website.query.filter_by(id=id).first()
    website.active = 0
    db.session.commit()
    return jsonify({
        "website": website.name
    })


@app.route("/delete/<id>")
@limiter.limit("30 per minute")
def delete_prompt(id):
    page = Website.query.filter_by(id=id).first()
    return render_template("confirm-delete.html", page=page)


@app.route("/delete/<id>/f")
def delete(id):
    page = Website.query.filter_by(id=id).first()
    print(page.name)
    WebsiteResponse.query.filter_by(name=page.name).delete()
    Website.query.filter_by(id=id).delete()
    db.session.commit()
    return redirect("/")


@app.route("/new")
@limiter.limit("3/minute")
def new():
    return render_template("new.html")


@app.route("/new", methods=["POST"])
def new_m_post():
    try:
        up = requests.get(request.form["website_uri"])
    except:
        abort(302, description=f"The Website URI {request.form['website_uri']} was not found")
    if "use-custom-headers" in request.form and str(request.form["use-custom-headers"]) == "on":
        print("yeet")
        headers = {
            "accept": request.form.get("content-type"),
            "Accept-Charset": request.form.get("accept-charset"),
        }
    else:
        print("yeet 2")
        headers = {}
    exists = Website.query.filter_by(name=request.form["name"]).first()
    if exists:
        abort(409, description=f'{request.form["name"]} already exists')
    if xss_detect(request.form["name"]) or xss_detect(request.form["website_uri"]):
        abort(403, description="The Monitor was not created due to attempted (and prevented) XSS")
    nw = Website(id=get_id(), name=request.form["name"], response_text_query=request.form.get("query_text", ""),
                 website_uri=request.form["website_uri"], active=1,
                 headers=headers)

    db.session.add(nw)
    db.session.commit()
    return redirect("/")


@app.route("/i/<id>")
@limiter.limit("30 per minute")
def incident_by_id(id):
    incident = WebsiteResponse.query.filter_by(id=id).first()
    if not incident:
        return render_template("empty-log.html")
    return render_template("incident.html", incident=incident, is_running_now=bool(incident.last_response_successful))

@app.route("/status/<website>")
@limiter.limit("30 per minute")
def render_website_status(website):
    page = Website.query.filter_by(name=website).first()
    if not page:
        abort(404)
    try:
        req = requests.get(page.website_uri, headers=page.headers)
        incident = WebsiteResponse(id=get_id(20), name=page.name, response_text=req.text,
                                   response_text_query=page.response_text_query, status_code=req.status_code,
                                   website_uri=page.website_uri, last_response_successful=req.status_code < 400,
                                   response_time_elapsed=req.elapsed.total_seconds() * 1000)

        db.session.add(incident)
        db.session.commit()
        uptime = (str(WebsiteResponse.query.filter_by(name=page.name, last_response_successful=1).count()),
                  str(WebsiteResponse.query.filter_by(name=page.name, last_response_successful=0).count()))
        latest_incident_date = WebsiteResponse.query.filter_by(name=page.name, last_response_successful=1).first()
        up_since = datetime.now() - latest_incident_date.date if hasattr(latest_incident_date,
                                                                         "date") else datetime.utcnow()
        return render_template("status.html", page=page, response=incident, request=req, round=round, uptime=uptime,
                               latest=latest_incident_date, up_since=up_since, re=re, escape=escape,
                               remove_emojis=remove_emojis, handle_catch=handle_catch,len=len)

    except Exception as error:
        err = Error(
            name=str(type(error)),
            details=f"{str(error)}",
            id=get_id(),
            website_uri_name=website
        )
        db.session.add(err)
        db.session.commit()
        return redirect(f"/errors/{website}")


@app.route("/log")
@limiter.limit("30 per minute")
def incident_log():
    pages = WebsiteResponse.query.order_by(WebsiteResponse.date.desc()).all()

    if not pages:
        return render_template("error404.html", error=404)
    return render_template("a_log.html", incidents=pages, round=round)


@app.route("/log/<website>")
@limiter.limit("30 per minute")
def incident_log_by_website(website):
    pages = WebsiteResponse.query.filter_by(name=website).order_by(WebsiteResponse.date.desc()).all()
    page = Website.query.filter_by(name=website).first()

    if not pages:
        return render_template("empty-log.html", page=page)
    return render_template("log.html", incidents=pages, round=round, page=page)


@app.route("/errors/<website>")
@limiter.limit("30 per minute")
def error_log_by_website(website):
    errors = Error.query.filter_by(website_uri_name=website).all()

    return render_template("errorlog.html", errors=errors, page=Website.query.filter_by(name=website).first())


@app.route("/errors")
@limiter.limit("30 per minute")
def error_log():
    errors = Error.query.order_by(Error.date.desc()).all()

    return render_template("a_errorlog.html", errors=errors)


@app.route("/log/<website>/latest")
@limiter.limit("30 per minute")
def get_latest_incident_by_website(website):
    latest = WebsiteResponse.query.filter_by(name=website).order_by(WebsiteResponse.date.desc()).first()
    return redirect(f"/i/{latest.id}")


@app.route("/log/<website>/first")
@limiter.limit("30 per minute")
def get_first_incident_by_website(website):
    first = WebsiteResponse.query.filter_by(name=website).order_by(WebsiteResponse.date.desc()).all()[-1]
    return redirect(f"/i/{first.id}")


if __name__ == "__main__":
    loop.start()
    app.run("0.0.0.0", 80)
    running = False
