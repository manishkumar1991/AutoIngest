import random
from flask import Flask, render_template, request
import json
import csv
import requests
import time
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError
import os



app = Flask(__name__)

# List of dropdown options
dropdown_options = [
    "ADAssessmentRecommendation", "ADSecurityAssessmentRecommendation", "Anomalies", "ASimAuditEventLogs",
    "ASimAuthenticationEventLogs", "ASimDhcpEventLogs", "ASimDnsActivityLogs", "ASimDnsAuditLogs", 
    "ASimFileEventLogs", "ASimNetworkSessionLogs", "ASimProcessEventLogs", "ASimRegistryEventLogs", 
    "ASimUserManagementActivityLogs", "ASimWebSessionLogs", "AWSCloudTrail", "AWSCloudWatch", 
    "AWSGuardDuty", "AWSVPCFlow", "AzureAssessmentRecommendation", "CommonSecurityLog", 
    "DeviceTvmSecureConfigurationAssessmentKB", "DeviceTvmSoftwareVulnerabilitiesKB", 
    "ExchangeAssessmentRecommendation", "ExchangeOnlineAssessmentRecommendation", "GCPAuditLogs", 
    "GoogleCloudSCC", "SCCMAssessmentRecommendation", "SCOMAssessmentRecommendation", 
    "SecurityEvent", "SfBAssessmentRecommendation", "SfBOnlineAssessmentRecommendation", 
    "SharePointOnlineAssessmentRecommendation", "SPAssessmentRecommendation", "SQLAssessmentRecommendation", 
    "StorageInsightsAccountPropertiesDaily", "StorageInsightsDailyMetrics", 
    "StorageInsightsHourlyMetrics", "StorageInsightsMonthlyMetrics", "StorageInsightsWeeklyMetrics", 
    "Syslog", "UCClient", "UCClientReadinessStatus", "UCClientUpdateStatus", "UCDeviceAlert", 
    "UCDOAggregatedStatus", "UCDOStatus", "UCServiceUpdateStatus", "UCUpdateAlert", 
    "WindowsClientAssessmentRecommendation", "WindowsEvent", "WindowsServerAssessmentRecommendation","Custom Table"
]

reserved_columns = ["_ResourceId", "id", "_SubscriptionId", "TenantId", "Type", "UniqueId", "Title","_ItemId","verbose_b","verbose","MG","_ResourceId_s"]

tenant_id = "17cea101-dd9b-43d0-9d67-f028b6efc55f"  # Tenant ID the data collection endpoint resides in
app_id = "1e1b4f6a-2c84-4e0e-8488-412e21868b62"  # Application ID created and granted permissions
app_secret = "RfX8Q~wicwQVYUFplpXsbwbSfo7ciyvKx3_cEa1O"  # Secret created for the application

workspace_id = "c64eb659-e5d8-4727-a9cd-ea4a085138e6"
workspaceName = "personal-workspace"
resourceGroupName = "test_infrastructure"
subscriptionId = "f70efef4-6505-4727-acd8-9d0b3bc0b80e"
dataCollectionEndpointname = "ingestsamplelogs"
endpoint_uri = "https://ingestsamplelogs-6xlj.eastus-1.ingest.monitor.azure.com" # logs ingestion endpoint of the DCR
dcr_directory=[]



def get_schema_for_builtin(query_table):
    # Obtain the access token
    credential = DefaultAzureCredential()
    token = credential.get_token('https://api.loganalytics.io/.default').token
    # Set the API endpoint
    url = f'https://api.loganalytics.io/v1/workspaces/c64eb659-e5d8-4727-a9cd-ea4a085138e6/query'
    # Create the payload
    payload = json.dumps({
        'query': query_table+'|getschema'
    })
    # Set the headers
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    # Make the request
    query_response = requests.post(url, headers=headers, data=payload)
    schema=[]
    for each in json.loads(query_response.text).get('tables')[0].get('rows'):
        if each[0] in reserved_columns:
            continue
        elif each[3] == "bool":
            schema.append({        
            'name': each[0],
            'type': "boolean",
            })
        else:
            schema.append({        
            'name': each[0],
            'type': each[3],
            })
    return schema

def convert_data_csv_to_json(csv_file):
    data = []
    with open(csv_file, 'r',encoding='utf-8-sig') as file:
        reader = csv.DictReader(file)
        for row in reader:
            table_name=row['Type']
            data.append(row)
        for item in data:
            for key in list(item.keys()):
                # If the key matches 'TimeGenerated [UTC]', rename it
                if key.endswith('[UTC]'):
                    substring = key.split(" [")[0] 
                    item[substring] = item.pop(key)                               
    return data , table_name

def create_dcr(schema,table,table_type,prnumber):
    #suffic_num = str(random.randint(100,999))
    dcrname=table+"_DCR"+str(prnumber)
    request_object={ 
            "location": "eastus", 			
            "properties": {
                "streamDeclarations": {
                    "Custom-dcringest"+str(prnumber): {
                        "columns": json.loads(schema)
                    }
                },				
			"dataCollectionEndpointId": f"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Insights/dataCollectionEndpoints/{dataCollectionEndpointname}",			
              "dataSources": {}, 
              "destinations": { 
                "logAnalytics": [ 
                  { 
                    "workspaceResourceId": f"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}",
                    "workspaceId": workspace_id,
                    "name": "DataCollectionEvent"+str(prnumber)
                  } 
                ] 
              }, 
              "dataFlows": [ 
                    {
                        "streams": [
                            "Custom-dcringest"+str(prnumber)
                        ],
                        "destinations": [
                            "DataCollectionEvent"+str(prnumber)
                        ],
                        "transformKql": "source",
                        "outputStream": f"{table_type}-{table}"
                    } 
                        ] 
                }
        }
    method="PUT"
    url=f"https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Insights/dataCollectionRules/{dcrname}?api-version=2022-06-01"
    return request_object , url , method ,"Custom-dcringest"+str(prnumber)

def gettoken():
    body = {
    'client_id': app_id,
    'resource': "https://management.azure.com/",
    'client_secret': app_secret,
    'grant_type': 'client_credentials'
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    uri = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
    response = requests.post(uri, data=body, headers=headers)
    bearer_token = response.json().get('access_token')
    return bearer_token

def hit_api(url,request,method):
    access_token = gettoken()
    headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
    }
    try:
        if method == "GET":
            response = requests.request(method, url, headers=headers)
        else:
            response = requests.request(method, url, headers=headers, json=request)
    except Exception as e:
        print(f"Upload failed: {e}")       
    return response

def senddtosentinel(immutable_id,data_result,stream_name,flag_status):
    if flag_status == 0:
        print("DCR is not created for the table. Please create DCR first")
        return
    print("Waiting for data to be sent to sentinel (This will take atleast 20 seconds)")
    time.sleep(10)
    credential = DefaultAzureCredential()
    client = LogsIngestionClient(endpoint=endpoint_uri, credential=credential, logging_enable=True)
    try:
        client.upload(rule_id=immutable_id, stream_name=stream_name, logs=data_result)
    except HttpResponseError as e:
        print(f"Upload failed: {e}")



def start_ingest_call(filepath,table_name):
    prnumber = random.randint(100,999)
    flag=0    
    data_result,tablename = convert_data_csv_to_json(filepath)
    if table_name == "na" and tablename in dropdown_options: # case where table name is not provided in that scenario table name will be fetched from type column of csv file
        table_name = tablename           
    schema = get_schema_for_builtin(table_name)
    request_body, url_to_call , method_to_use ,stream_name = create_dcr(json.dumps(schema, indent=4),table_name,"Microsoft",prnumber)
    response_body=hit_api(url_to_call,request_body,method_to_use)
    print(f"Response of DCR creation: {response_body.text}")
    dcr_directory.append({
    'DCRname':table_name+'_DCR'+str(prnumber),
    'imutableid':json.loads(response_body.text).get('properties').get('immutableId'),
    'stream_name':stream_name
    })
    for dcr in dcr_directory:
        if table_name in dcr['DCRname'] and str(prnumber) in dcr['DCRname'] :
            immutable_id = dcr['imutableid']
            stream_name = dcr['stream_name']
            flag=1
            break
    print(dcr_directory)    
    print(f"Ingestion started for {table_name}")       
    senddtosentinel(immutable_id,data_result,stream_name,flag)  



# Route to display the form (Home page)
@app.route('/')
def form():
    return render_template('form.html', options=dropdown_options)

# Route to handle form submission
@app.route('/submit', methods=['POST'])
def submit():
    if request.method == 'POST':
        form_data = {
            'tenant_id': request.form['tenant_id'],
            'app_id': request.form['app_id'],
            'app_secret': '******',  # Masking the App Secret
            'workspace_id': request.form['workspace_id'],
            'workspace_name': request.form['workspace_name'],
            'resource_group_name': request.form['resource_group_name'],
            'endpoint_name': request.form['endpoint_name'],
            'endpoint_uri': request.form['endpoint_uri'],
            'details': request.form['details'], #sample data
            'option': request.form['option'] #table name
        }
        table_name = form_data.get('option')
        sample_data = form_data.get('details')
        print(f"Table Name: {table_name}")
        with open('tempfile.csv', 'w') as file:
            file.write(sample_data)
        start_ingest_call('tempfile.csv',table_name)          
        #Pass the collected data to the results page
        return render_template('results.html', data=form_data)

# Route to display the Simulate page

@app.route('/submit_simulate', methods=['POST'])
def submit_simulate():
    if request.method == 'POST':
        form_data = {
            'tenant_id': request.form['tenant_id'],
            'app_id': request.form['app_id'],
            'app_secret': '******',  # Masking the App Secret
            'workspace_id': request.form['workspace_id'],
            'workspace_name': request.form['workspace_name'],
            'resource_group_name': request.form['resource_group_name'],
            'endpoint_name': request.form['endpoint_name'],
            'endpoint_uri': request.form['endpoint_uri'],
            'attack_type': request.form['attack_type'] #attack_type data
        }
        if form_data.get('attack_type') == "Brute force":
            directory = r"C:\Auto-ingest\sampledata\bruteforce"
            for name in os.listdir(directory):
                print(f"Reading file: {os.path.join(directory, name)}")
                start_ingest_call(os.path.join(directory, name),"na")
        return render_template('results1.html', data=form_data)

@app.route('/simulate')
def form1():
    return render_template('simulate.html', options=dropdown_options)


# Route to display the Help page
@app.route('/help')
def help_page():
    return render_template('help.html')

# Run the Flask app
if __name__ == '__main__':   
    app.run(debug=True)
