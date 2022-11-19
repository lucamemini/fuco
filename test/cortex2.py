import json

from cortex4py.api import Api
from cortex4py.query import *

import fucoconfig as cfg
api = Api(cfg.cortex["host"], cfg.cortex["apikey"])

id = "MY7ggIQBC9TJKwsv3GsV"
#id = "bI4AgIQBC9TJKwsvlmds"

report = api.jobs.get_report(id).report
print('Job summary is {}'.format(json.dumps(report.get('summary', {}))))
print('Job full is {}'.format(json.dumps(report.get('full', {}))))
print('Job {} has generated the following artifacts:'.format(id))
artifacts = api.jobs.get_artifacts(id)
for a in artifacts:
   print('- [{}]: {}'.format(a.dataType, a.data))

print("============")

# Fetch the last 10 successful jobs that have been executed against domain names
#query = And(Eq('status', 'Success'), Eq('dataType', 'domain'))
#jobs = api.jobs.find_all(query, range='0-10', sort='-createdAt')

# Display summaries of the jobs above
#for job in jobs:
#  report = api.jobs.get_report(job.id).report
#  print('Job summary is {}'.format(json.dumps(report.get('summary', {}))))

#  print('Job {} has generated the following artifacts:'.format(job.id))
#  artifacts = api.jobs.get_artifacts(job.id)
#  for a in artifacts:
#    print('- [{}]: {}'.format(a.dataType, a.data))

