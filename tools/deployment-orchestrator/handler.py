import urllib3
from boto3 import session, client
import json
import os

GOOD_COLOR = '#489DE5'
BAD_COLOR = '#B7081B'
MEH_COLOR = '#828581'

def respond(title, subtitle, description, description_name, body, body_name, body2, body2_name, details):
    message = {}
    message['blocks'] = []
    subtitle = "*{}*".format(subtitle) if subtitle else ''
    message['blocks'].append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "{}\n{}".format(title, subtitle)
                    }
                })
    message['blocks'].append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*{}:*\n{}".format(description_name, description)
                    }
                })
    message['blocks'].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*{}:*\n{}".format(body_name, body)
                }
            })
    if body2 and body2_name:
        message['blocks'].append({
            
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*{}:*\n{}".format(body2_name, body2)
                    }
                
            })
    message['blocks'].append( {
                "type": "divider"
            }) 
    message['blocks'].append( {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": details
                    }
                ]
            })

    http = urllib3.PoolManager()
    message['channel'] = os.environ['slackChannel'],
    print("message:")
    print(message)
    url = os.environ['webhookUrl']
    headers = {"content-type": "application/json" }
    response = http.request('POST', url, body=json.dumps(message), headers=headers)
    print("response:")
    print(response.status)
    print(response.data)

def cw_alarm(event):
    if event["detail"]["state"]["value"] == "ALARM":
        title = "⚠️ CloudWatch Alarm triggered."
    elif event["detail"]["state"]["value"] == "OK":
        title = "✅ CloudWatch Alarm recovered."
    else:
        title = "CloudWatch Alarm transition."
        
    context = event["resources"].pop()
    subtitle = event["detail"]["alarmName"]
    respond(title, subtitle, event["detail"]["configuration"]["description"], 'Description', event["detail"]["state"]["reason"], 'Body', False, False, context)

def ecs_service(event):
    state_message_map = {
        # "SERVICE_STEADY_STATE" : "web-app service is steady.", meh
        "SERVICE_TASK_START_IMPAIRED" : "web-app ECS service is having trouble starting tasks.",
        "ECS_OPERATION_THROTTLED" : "web-app ECS cluster operations are being throttled.",
        "SERVICE_TASK_CONFIGURATION_FAILURE" : "web-app task config failure.",
    }
    if event['detail']['eventName'] not in state_message_map.keys():
        print("state message not in map.")
        return
       
    respond("☢️ ECS Cluster State Change.", "", event['detail']['eventName'], 'State', state_message_map[event['detail']['eventName']], 'Description', False, False, event["detail"]['clusterArn'])
    
    

def ecs_task(event):
    message = False # use this to track if we actually wanna send a message

    # if event['detail']['lastStatus'] == 'DEPROVISIONING' and event['detail']['desiredStatus'] == 'STOPPED':
    #     message = 'Stopping a task/container.'
    #     reason = event['detail']['stoppedReason']
    #     title = "ECS Task State Change."

    # if event['detail']['lastStatus'] == 'STOPPED' and event['detail']['desiredStatus'] == 'STOPPED':
    #     message = 'Task/container has been killed.'
    #     reason = event['detail']['stoppedReason']
    #     title = "ECS Task State Change."

    if event['detail']['lastStatus'] == 'PENDING' and event['detail']['desiredStatus'] == 'RUNNING':
        message = 'Creating a new container/task.'
        reason = ''
        title = "👶 ECS Task State Change."

    # if event['detail']['lastStatus'] == 'RUNNING' and event['detail']['desiredStatus'] == 'RUNNING':
    #     message = 'New container/task is up.'
    #     reason = ''
    #     title = "😎 ECS Task State Change."

    if not message:
        print("we don't care about this detail")
        return

    body2 = "*Most recent task state:* {}\nDesired task state: {}".format(event['detail']['lastStatus'],event['detail']['desiredStatus'])
    respond(title, False, message, 'Message', reason, 'Reason', body2, 'Details', event["detail"]['clusterArn'])

def invoke(event, context):
    if "detail-type" not in event:
        raise ValueError("ERROR: Event object is not a valid CloudWatch event")
    detail = event["detail"]
    print(json.dumps(event))
    if event["detail-type"] == "CloudWatch Alarm State Change":
        cw_alarm(event)
        
    if event["detail-type"] == "ECS Task State Change":
        ecs_task(event)
    if event["detail-type"] == "ECS Service Action":
        ecs_service(event)