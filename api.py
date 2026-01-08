import json

from flask import Flask, render_template, request, make_response, jsonify
from flask_restful import reqparse, abort, Api, Resource
import os
from subprocess import Popen
from urllib.parse import quote
from uuid import uuid1

import json
from pprint import pprint
import time
import jinja2

import re
import ipaddress

from cortex4py.api import Api
from cortex4py.query import *

template_folder='web/templates/'

import fucoconfig as cfg 
api = Api(cfg.cortex["host"], cfg.cortex["apikey"])

app = Flask(__name__,
            static_url_path='',
            static_folder='web/static',
            template_folder=template_folder)
 
@app.template_filter('fang')
def fang(s):
    """Custom filter: upper-case a string"""
    try:
        return s.upper()
    except Exception:
        return s

@app.template_filter('urlencode')
def urlencode_filter(s):
    return quote(str(s))


def get_analyzer_by_type(t):
    analyzers = api.analyzers.get_by_type(t)
    return analyzers

def get_recent_searches():
    query = And(Eq('status', 'Success'))
    jobs = api.jobs.find_all(query, range='0-50', sort='-createdAt')
    recent = {}
    for job in jobs:
        dt = job.dataType
        if dt not in recent:
            recent[dt] = {}
        data = job.data
        if data not in recent[dt]:
            if len(recent[dt]) < 10:
                recent[dt][data] = []
        if data in recent[dt]:
            recent[dt][data].append(job.id)
    return recent

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
        recent = get_recent_searches()
        return render_template('index.html', t=result, recent=recent)

############### API REQUEST

## Api SHORT

@app.route('/api/short', methods=['POST'])
def api_short():
    try:
        request_data = request.get_json()
        if not request_data:
            return jsonify({"error": "Nessun dato JSON fornito"}), 400

        raw_data = request_data.get('Data')
        if not raw_data:
            return jsonify({"error": "Parametro 'Data' mancante"}), 400

        datatype = request_data.get('DataType')
        analyzer_list = request_data.get('analyzer_list')
        if not analyzer_list or not isinstance(analyzer_list, list):
            return jsonify({"error": "Parametro 'analyzer_list' mancante o non valido"}), 400

        # Lista finale di input validi (IP o altro)
        input_items = []

        # Solo se DataType non è specificato: deduzione automatica
        if not datatype:
            ipv4_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
            domain_regex = r'^(?!\-)([A-Za-z0-9\-]{1,63}(?<!\-)\.)+[A-Za-z]{2,6}$'
            url_regex = r'^https?:\/\/[^\s\/$.?#].[^\s]*$'
            sha256_regex = r'^[A-Fa-f0-9]{64}$'
            md5_regex = r'^[a-fA-F0-9]{32}$'
            email_regex = r'^[^@]+@[^@]+\.[^@]+$'

            # Caso: IP multipli separati da virgola
            if ',' in raw_data:
                ip_candidates = [ip.strip() for ip in raw_data.split(',')]
                for ip in ip_candidates:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if not ip_obj.is_private:
                            input_items.append((ip, "ip"))
                    except ValueError:
                        continue
            elif re.match(ipv4_regex, raw_data):
                ip_obj = ipaddress.ip_address(raw_data)
                if not ip_obj.is_private:
                    input_items.append((raw_data, "ip"))
#                else:
#                    return jsonify({"error": "IP privato non accettato"}), 400

            elif re.match(domain_regex, raw_data):
                input_items.append((raw_data, "domain"))
            elif re.match(url_regex, raw_data):
                input_items.append((raw_data, "url"))
            elif re.match(sha256_regex, raw_data):
                input_items.append((raw_data, "sha256"))
            elif re.match(md5_regex, raw_data):
                input_items.append((raw_data, "md5"))
            elif re.match(email_regex, raw_data):
                input_items.append((raw_data, "email"))
            else:
                return jsonify({"error": "Impossibile determinare automaticamente il tipo di dato"}), 400

        else:
            # Usa DataType esplicitamente specificato
            if datatype.lower() == "ip" and ',' in raw_data:
                ip_candidates = [ip.strip() for ip in raw_data.split(',')]
                for ip in ip_candidates:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if not ip_obj.is_private:
                            input_items.append((ip, "ip"))
                    except ValueError:
                        continue
                if not input_items:
                    return jsonify({"error": "Nessun IP pubblico valido trovato"}), 400
            else:
                input_items.append((raw_data, datatype.lower()))

        # Esecuzione dell’analisi per ogni elemento valido e ogni analyzer
        job_results = []
        for data, dtype in input_items:
            for analyzer in analyzer_list:
                job_result = run_analisys(analyzer, dtype, data)
                job_results.append((data, analyzer, job_result))

        # Monitoraggio dei job fino a completamento
        final_results = []
        for data, analyzer, job in job_results:
            job_id = job['id']

            # Polling dello stato del job
            i = 5
            while i < 15:
                time.sleep(i)
                report = api.jobs.get_report(job_id)
                if report.status in ("Success", "Failure"):
                    break
                i += 1

            result_entry = {
                "input": data,
                "analyzer": analyzer,
                "status": report.status,
            }

            if report.status == "Success":
                try:
                    result_entry["taxonomies"] = report.report['summary']['taxonomies']
                except:
                    result_entry["taxonomies"] = [{
                        "level": "undef",
                        "namespace": report.analyzerName,
                        "predicate": "Summary",
                        "value": "NoData"
                    }]
            else:
                result_entry["taxonomies"] = [{
                    "level": "undef",
                    "namespace": report.analyzerName,
                    "predicate": "Summary",
                    "value": "Error"
                }]

            final_results.append(result_entry)

        return jsonify(final_results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


## end API SHORT

@app.route('/api/analysis', methods=['POST'])
def api_analysis():
    try:
        # Parsing del JSON dalla richiesta
        request_data = request.get_json()
        
        # Verifica dei parametri richiesti
        if not request_data:
            return jsonify({"error": "Nessun dato JSON fornito"}), 400
            
        data = request_data.get('Data')
        if not data:
            return jsonify({"error": "Parametro 'Data' mancante"}), 400
            
        datatype = request_data.get('DataType')
        if not datatype:
           # Determinazione automatica del tipo di dato
           ipv4_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
           domain_regex = r'^(?!\-)([A-Za-z0-9\-]{1,63}(?<!\-)\.)+[A-Za-z]{2,6}$'
           url_regex = r'^https?:\/\/[^\s\/$.?#].[^\s]*$'
           sha256_regex = r'^[A-Fa-f0-9]{64}$'
           md5_regex = r'^[a-fA-F0-9]{32}$'
           email_regex = r'^[^@]+@[^@]+\.[^@]+$'

           if re.match(ipv4_regex, data):
              datatype = "ip"
           elif re.match(domain_regex, data):
              datatype = "domain"
           elif re.match(url_regex, data):
              datatype = "url"
           elif re.match(sha256_regex, data):
              datatype = "sha256"
           elif re.match(md5_regex, data):
              datatype = "md5"
           elif re.match(email_regex, data):
              datatype = "email"
        else:
           return jsonify({"error": "Impossibile determinare automaticamente il tipo di dato"}), 400
            
        analyzer_list = request_data.get('analyzer_list')
        if not analyzer_list or not isinstance(analyzer_list, list):
            return jsonify({"error": "Parametro 'analyzer_list' mancante o non valido"}), 400
        
        # Esecuzione dell'analisi per ogni analyzer
        job_results = []
        for analyzer in analyzer_list:
            job_result = run_analisys(analyzer, datatype, data)
            job_results.append(job_result)
        
        # Monitoraggio dei job fino a completamento
        final_results = []
        for job in job_results:
            job_id = job['id']
            
            # Polling dello stato del job
            i = 5
            while i < 15:
                time.sleep(i)
                report = api.jobs.get_report(job_id)
                if report.status == "Success" or report.status == "Failure":
                    break
                i += 1
            
            # Aggiungi il risultato completo
            if report.status == "Success":
                final_results.append(report.json())
            else:
                final_results.append({"id": job_id, "status": report.status, "error": "Analisi non completata"})
        
        # Prepara la risposta JSON
        response = {
            "question": data,
            "datatype": datatype,
            "results": final_results
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/getAnalyzer', methods=['GET'])
def get_analyzers():
    try:
        # Usa il metodo get_by_type per ottenere gli analyzer per vari tipi comuni
        # poiché sappiamo che questo funziona nel codice esistente
        analyzer_types = ["domain", "ip", "url", "file", "hash", "mail", "mail_subject", "other"]
        
        all_analyzers = []
        all_data_types = set()
        
        # Raccoglie gli analyzer per ciascun tipo
        for analyzer_type in analyzer_types:
            type_analyzers = api.analyzers.get_by_type(analyzer_type)
            if type_analyzers:
                for analyzer in type_analyzers:
                    # Verifica se l'analyzer è già stato aggiunto (evita duplicati)
                    if not any(a.get('name') == analyzer.name for a in all_analyzers):
                        analyzer_data = {
                            "id": analyzer.id if hasattr(analyzer, 'id') else "N/A",
                            "name": analyzer.name if hasattr(analyzer, 'name') else "N/A",
                            "version": analyzer.version if hasattr(analyzer, 'version') else "N/A",
                            "description": analyzer.description if hasattr(analyzer, 'description') else "N/A",
                            "dataTypeList": analyzer.dataTypeList if hasattr(analyzer, 'dataTypeList') else [],
                            "type": analyzer_type
                        }
                        
                        all_analyzers.append(analyzer_data)
                        
                        # Aggiungi i data type supportati
                        if hasattr(analyzer, 'dataTypeList'):
                            for data_type in analyzer.dataTypeList:
                                all_data_types.add(data_type)
        
        # Alternativa: se vuoi comunque provare a usare find_all con un oggetto query
        # basato sull'esempio nel tuo codice originale
        try:
            query = Any()  # Questo dovrebbe creare una query che corrisponde a tutto
            more_analyzers = api.analyzers.find_all(query, range='all')
            
            # Processa questi analyzer se la chiamata ha avuto successo
            for analyzer in more_analyzers:
                if not any(a.get('name') == analyzer.name for a in all_analyzers):
                    analyzer_data = {
                        "id": analyzer.id if hasattr(analyzer, 'id') else "N/A",
                        "name": analyzer.name if hasattr(analyzer, 'name') else "N/A",
                        "version": analyzer.version if hasattr(analyzer, 'version') else "N/A",
                        "description": analyzer.description if hasattr(analyzer, 'description') else "N/A",
                        "dataTypeList": analyzer.dataTypeList if hasattr(analyzer, 'dataTypeList') else [],
                        "type": analyzer.type if hasattr(analyzer, 'type') else "unknown"
                    }
                    
                    all_analyzers.append(analyzer_data)
                    
                    if hasattr(analyzer, 'dataTypeList'):
                        for data_type in analyzer.dataTypeList:
                            all_data_types.add(data_type)
        except Exception as find_all_error:
            # Se fallisce, ignora silenziosamente e continua con i risultati di get_by_type
            pass
        
        response = {
            "analyzers": all_analyzers,
            "supportedDataTypes": list(all_data_types)
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

### END API


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

       # Get taxonomies like in getShort
       report = api.jobs.get_report(item.id)
       t = []
       try:
           t = report.report['summary']['taxonomies']
       except:
           taxonomies = {}
           taxonomies['level'] = "undef"
           taxonomies['namespace'] = report.analyzerName
           taxonomies['predicate'] = "Summary"
           taxonomies['value'] = "NoData"
           t.append(taxonomies)
       organized_data[data_value].append(t)

   return organized_data

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
