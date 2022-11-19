import json
import pprint
import time

from cortex4py.api import Api
from cortex4py.query import *

import fucoconfig as cfg
api = Api(cfg.cortex["host"], cfg.cortex["apikey"])

# Get enabled analyzers
#analyzers = api.analyzers.find_all({}, range='all')
analyzers = api.analyzers.get_by_type('domain')

# Display enabled analyzers' names
for analyzer in analyzers:
  print('Analyzer {} is enabled'.format(analyzer.name))
  print(analyzer)
