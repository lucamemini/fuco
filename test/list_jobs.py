import json
import pprint
import time

from cortex4py.api import Api
from cortex4py.query import *

import fucoconfig as cfg
api = Api(cfg.cortex["host"], cfg.cortex["apikey"])

# Fetch the last 10 successful jobs that have been executed against domain names
#query = And(Eq('status', 'Success'), Eq('dataType', 'domain'))
query = And(Eq('status', 'Success'))
jobs = api.jobs.find_all(query, range='0-150', sort='-createdAt')

# Display summaries of the jobs above
#for job in jobs:
#  report = api.jobs.get_report(job.id).report
#  print("Artifact: "+job.data)
#  print('   Job summary for {} is {}'.format(job.analyzerName,json.dumps(report.get('summary', {}))))

##  print('Job {} has generated the following artifacts:'.format(job.id))
##  artifacts = api.jobs.get_artifacts(job.id)
##  for a in artifacts:
##    print('- [{}]: {}'.format(a.dataType, a.data))


# Dizionario per organizzare i dati per chiave "data"
organized_data = {}

# Organizza i dati per chiave "data"
for item in jobs:
    data_value = item.data
    if data_value not in organized_data:
        organized_data[data_value] = []
    organized_data[data_value].append(item)

# Stampa i dati organizzati
for data_value, items in organized_data.items():
    print(f"Dati per '{data_value}':")
    for job in items:
        report = api.jobs.get_report(job.id).report
        print('  Report {} Result {}'.format(job.analyzerName, json.dumps(report.get('summary', {}))))
        #print(item)
