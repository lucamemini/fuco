import json

from flask import Flask, render_template, request, make_response
from flask_restful import reqparse, abort, Api, Resource
import os
from subprocess import Popen
from urllib.parse import quote
from uuid import uuid1

import json
import pprint
import time
import jinja2

from cortex4py.api import Api
from cortex4py.query import *

template_folder='web/templates/'


import fucoconfig as cfg 
api = Api(cfg.cortex["host"], cfg.cortex["apikey"])

app = app = Flask(__name__,
            static_url_path='',
            static_folder='web/static',
            template_folder=template_folder)

@app.template_filter('fang')
def fang():
    """Custom filter"""
    return input.upper()


def get_analyzer_by_type(t):
    analyzers = api.analyzers.get_by_type(t)
    return analyzers

def run_analisys(analizer,datatype,data):
   # Run an analyzer against a domain
   job = api.analyzers.run_by_name(analizer, {
       'data': data,
       'dataType': datatype,
       'pap': 1,
       'tlp': 1
   }, force=1)
   print('Task {} Question {} ({}) jobId {} Status {}'.format(analizer, data, datatype, job.id, job.status))
#   print("JOB ANALISYS:")
#   print(json.dumps(job.json(), indent=2))
   return job.json()

@app.route('/')
def home():
    result = get_analyzer_by_type("domain")
    return render_template('index.html', data=result)
#    return app.send_static_file('index.html')


@app.route('/getAnalyzer', methods=['GET'])
def getAnalyzer():
   t = str(request.args.get('type')) 
   result = get_analyzer_by_type(t)
   return render_template('analyzer.html', data=result)

@app.route('/getAnalisys', methods=['GET'])
def getAnalisys():
   JobId = str(request.args.get('JobId')) 

   i = 5
   while i < 15:
     time.sleep(i)
     report = api.jobs.get_report(JobId)
     if report.status == "Success":
       break
     if report.status == "Failure":
       break
     i += 1

   if os.path.exists(template_folder+report.analyzerName+".long.html"):
     print("Using report template: "+template_folder+report.analyzerName+".long.html")
     env = jinja2.Environment()
     env.filters["fang"] = fang
####### Solo per debug
#     print(json.dumps(report.json(), indent=2))
#     return render_template(report.analyzerName+".long.html", artifact=report)
#######################################
     try:
         return render_template(report.analyzerName+".long.html", artifact=report)
     except Exception as err:
#         print(f"Unexpected {err=}, {type(err)=}")
         print("Unexpected error: "+str(err))
         return "<pre>Template error: <code>"+json.dumps(report.json(), indent=2)+"</code></pre>"
   else:
     print("Report template: "+template_folder+report.analyzerName+".long.html not found")
     return "<pre>Template not found: <code>"+json.dumps(report.json(), indent=2)+"</code></pre>"

@app.route('/getShort', methods=['GET'])
def getShort():
   JobId = str(request.args.get('JobId')) 

   i = 1
   while i < 10:
     report = api.jobs.get_report(JobId)
     if report.status == "Success":
       break
     if report.status == "Failure":
       break
     i += 1
     time.sleep(i)

   try:
     taxonomies = report.report['summary']['taxonomies'][0]
     level = taxonomies.get("level")
     if level == "info": 
         taxonomies['css'] = "bg-info";
     elif level == "safe": 
         taxonomies['css'] = "bg-success";
     elif level == "suspicious": 
         taxonomies['css'] = "bg-warning";
     elif level == "malicious": 
         taxonomies['css'] = "bg-danger";
     else:
         taxonomies['css'] = "bg-secondary";
   except:
     taxonomies = dict() 
     taxonomies['css'] = "bg-secondary"
     taxonomies['namespace'] = report.analyzerName
     taxonomies['predicate'] = "Summary"
     taxonomies['value'] = "NoData"

   if os.path.exists(template_folder+report.analyzerName+".short.html"):
     template = report.analyzerName+".short.html"
     print("Using custom short template: "+template)
     try:
         return render_template(template, t=taxonomies)
     except:
         return taxonomies
   elif os.path.exists(template_folder+"generic.short.html"):
     template = "generic.short.html"
     print("Using generic short template: "+template)
     try:
         return render_template(template, t=taxonomies)
     except:
         return taxonomies
   else:
     print("Report short template not found")
     return taxonomies

@app.route('/analysis', methods=['POST'])
def analysis():
    data = request.form.get('tosearch')
    if not bool(data):
      return make_response("551",500)
    datatype = request.form.get('DataType')
    if not bool(datatype):
      return make_response("552",500)
    #for key in request.form.get('analyzer'):
    #print(request.form.getlist('analyzer')) # https://stackoverflow.com/questions/31859903/get-the-value-of-a-checkbox-in-flask
    analyzer_list = request.form.getlist('analyzer');
    if not bool(analyzer_list):
      return make_response("553",500)
    print(request.form)
    result = dict()
    result['analysis'] = list()
    result['fuco'] = dict()
    result['fuco']['question'] = data
    result['fuco']['datatype'] = datatype
    for k in analyzer_list:
#      result.append(run_analisys(k,datatype,data))
      result['analysis'].append(run_analisys(k,datatype,data))

    try:
      return render_template('report.html', data=result)
    except:
       return result


@app.errorhandler(404)
def not_found(error):
    return make_response("404", 404)


if __name__ == '__main__':
    app.run(debug = False)
