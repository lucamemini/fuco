import json
import pprint
import time

from cortex4py.api import Api
from cortex4py.query import *

import fucoconfig as cfg
api = Api(cfg.cortex["host"], cfg.cortex["apikey"])

# Get enabled analyzers
#analyzers = api.analyzers.find_all({}, range='all')

# Display enabled analyzers' names
#for analyzer in analyzers:
#  print('Analyzer {} is enabled'.format(analyzer.name))

## Run an analyzer against a domain
#job1 = api.analyzers.run_by_name('', {
#    'data': 'google.com',
#    'dataType': 'domain',
#    'tlp': 1,
#    'message': 'custom message sent to analyzer',
#    'parameters': {
#        'key1': 'value1',
#        'key2': True,
#        'key3': 10
#    }
#}, force=1)
#print(json.dumps(job1.json(), indent=2))

# Run an analyzer against a domain
job2 = api.analyzers.run_by_name('DNSSinkhole_1_0', {
    'data': 'cuore.org',
    'dataType': 'domain',
    'tlp': 1
}, force=1)
print(json.dumps(job2.json(), indent=2))

id = job2.id

i = 1
while i < 6:
  time.sleep(i)
  report = api.jobs.get_report(id)
  print(report.status)
  if report.status == "Success":
    break
  if report.status == "Failed":
    break
  i += 1

print("============")
print(report.report)
print("============")


#print('Job summary is {}'.format(json.dumps(report.get('summary', {}))))
#print('Job full is {}'.format(json.dumps(report.get('full', {}))))
#print('Job {} has generated the following artifacts:'.format(id))
#artifacts = api.jobs.get_artifacts(id)
#for a in artifacts:
#   print('- [{}]: {}'.format(a.dataType, a.data))

