import json

from flask import Flask, render_template, request, make_response
from flask_restful import reqparse, abort, Api, Resource

import pprint
import time

from cortex4py.api import Api
from cortex4py.query import *

from flask_apscheduler import APScheduler
import json, threading, time

import fucoconfig as cfg
api = Api(cfg.cortex["host"], cfg.cortex["apikey"])

## thx to  Clivant a.k.a Chai Heng
## https://www.techcoil.com/blog/how-to-use-threading-condition-to-wait-for-several-flask-apscheduler-one-off-jobs-to-complete-execution-in-your-python-3-application/
class JobsSynchronizer:

    def __init__(self, num_tasks_to_complete):
        self.condition = threading.Condition()
        self.current_completed = 0
        self.status_list = []
        self.num_tasks_to_complete = num_tasks_to_complete

    def notify_task_completion(self, status_to_report=None):
        with (self.condition):
            self.current_completed = self.current_completed + 1
            if status_to_report is not None:
                self.status_list.append(status_to_report)
            # Notify waiting thread
            if self.current_completed == self.num_tasks_to_complete:
                self.condition.notify()

    def wait_for_tasks_to_be_completed(self):
        with(self.condition):
            self.condition.wait()

    def get_status_list(self):
        return self.status_list


def get_analyzer_by_type(t):
    analyzers = api.analyzers.get_by_type(t)
    return analyzers

app = app = Flask(__name__,
            static_url_path='',
            static_folder='web/static',
            template_folder='web/templates')
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()


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

@app.route('/analysis', methods=['POST'])
def create_analysis():
    data = request.form.get('tosearch')
    datatype = request.form.get('DataType')
    #for key in request.form.get('analyzer'):
    #print(request.form.getlist('analyzer')) # https://stackoverflow.com/questions/31859903/get-the-value-of-a-checkbox-in-flask
    analyzer_list = request.form.getlist('analyzer');
    print(request.form)

    job_synchronizer = JobsSynchronizer(len(analyzer_list))
    i=1
    for k in analyzer_list:
    #  print(k)
    #  print(datatype)
    #  print(data)
    #  result = run_analisys(k,datatype,data)
      app.apscheduler.add_job(func=run_analisys, trigger='date', args=[job_synchronizer, i, k, datatype, data], id='j' + str(i))
      i=i+1
    return request.form

#def scheduled_task(job_synchronizer, task_id):
#    for i in range(10):
#        time.sleep(1)
#        print('Task {} running iteration {}'.format(task_id, i))
#    job_synchronizer.notify_task_completion('Task {} completed execution'.format(task_id))

def run_analisys(job_synchronizer, task_id, analizer, datatype, data):
   # Run an analyzer against a domain
   CortexJob = api.analyzers.run_by_name(analizer, {
       'data': data,
       'dataType': datatype,
       'tlp': 1,
       'pap': 1
   }, force=1)
   print(json.dumps(CortexJob.json(), indent=2))

   t = 1
   while t < 10:
     time.sleep(t)
     report = api.jobs.get_report(CortexJob.id)
     print('Task {} Time {} jobId {} Status {}'.format(task_id, t, CortexJob.id, report.status))
     if report.status == "Success":
       break
     if report.status == "Failure":
       break
     t += 1
   print(report.report)
   job_synchronizer.notify_task_completion(report)
#   return report.report

@app.errorhandler(404)
def not_found(error):
    return make_response("404", 404)


if __name__ == '__main__':
    app.run(debug = False)
    
