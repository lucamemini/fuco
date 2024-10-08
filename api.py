import json

from flask import Flask, render_template, request, make_response
from flask_restful import reqparse, abort, Api, Resource
import os
from subprocess import Popen
from urllib.parse import quote
from uuid import uuid1

import json
from pprint import pprint
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

# TLP / PAP
# WHITE: 0
# GREEN: 1
# AMBER: 2
# RED: 3
def run_analisys(analizer,datatype,data):
   # Run an analyzer against a domain
   job = api.analyzers.run_by_name(analizer, {
       'data': data,
       'dataType': datatype,
       'pap': 2,
       'tlp': 2
   }, force=1)
   print('Task {} Question {} ({}) jobId {} Status {}'.format(analizer, data, datatype, job.id, job.status))
#   print("JOB ANALISYS:")
#   print(json.dumps(job.json(), indent=2))
   return job.json()

@app.route('/')
#def home():
#    result = get_analyzer_by_type("domain")
#    return render_template('index.html', data=result)
##    return app.send_static_file('index.html')
def home():
    q_param = request.args.get('q')
    type_param = request.args.get('t')
    if q_param and type_param:
        # Eseguire le operazioni desiderate con i parametri q e type
        return render_template('index.html', q=q_param, t=type_param)
    else:
        result = get_analyzer_by_type("domain")
        return render_template('index.html', t=result)

@app.route('/getAnalyzer', methods=['GET'])
def getAnalyzer():
   t = str(request.args.get('type')) 
   result = get_analyzer_by_type(t)
   return render_template('analyzer.html', data=result)

@app.route('/lastAnalisys', methods=['GET'])
def lastAnalisis():
   query = And(Eq('status', 'Success'))
   jobs = api.jobs.find_all(query, range='0-150', sort='-createdAt')
   organized_data = {}

   for item in jobs:
       data_value = item.data
       if data_value not in organized_data:
          organized_data[data_value] = []
       organized_data[data_value].append(item)

#   for data_value, items in organized_data.items():
#         pprint(data_value)
#         for job in items:
#             pprint(job)

#        print(f"Dati per '{data_value}':")
#        for job in items:
#            report = api.jobs.get_report(job.id).report
#            print('   Result {}'.format(json.dumps(report.get('summary', {}))))
   
   return render_template('lastAnalisys.html', data=organized_data)

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

   t = list()

   try:
    t = report.report['summary']['taxonomies']
   except:
    taxonomies = dict()
    taxonomies['level'] = "undef"
    taxonomies['namespace'] = report.analyzerName
    taxonomies['predicate'] = "Summary"
    taxonomies['value'] = "NoData"
    t.append(taxonomies)

   if os.path.exists(template_folder+report.analyzerName+".short.html"):
     template = report.analyzerName+".short.html"
     print("Using custom short template: "+template)
     try:
         return render_template(template, taxonomies=t)
     except Exception as err:
         print("Unexpected error: "+str(err))
         return t
   elif os.path.exists(template_folder+"generic.short.html"):
     template = "generic.short.html"
     print("Using generic short template: "+template)
     try:
         return render_template(template, taxonomies=t)
     except Exception as err:
         print("Unexpected error: "+str(err)) 
         return t
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
