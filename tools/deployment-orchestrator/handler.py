import urllib3
from boto3 import session, client
import json
import os

GOOD_COLOR = '#489DE5'
BAD_COLOR = '#B7081B'
# WARN_COLOR = ''
MEH_COLOR = '#828581'

def respond(message):
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
        title = "CloudWatch Alarm triggered."
        name = "⛈ *{}*".format(event["detail"]["alarmName"])
    elif event["detail"]["state"]["value"] == "OK":
        title = "CloudWatch Alarm recovered."
        name = "🔅 *{}*".format(event["detail"]["alarmName"])
    else:
        title = "CloudWatch Alarm transition."
        name = "☔️ *{}*".format(event["detail"]["alarmName"])
    payload = {
        "blocks": [
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": name
                    },
                    {
                        "type": "mrkdwn",
                        "text": title
                    }
                ]
            },  
                {
                    "type": "divider"
                },
                {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": event["detail"]["state"]["reason"]
                }
            ]
        }
            ]
        }
    respond(payload)

def ecs_service(event):
    state_message_map = {
        "SERVICE_STEADY_STATE" : "web-app service is steady.",
        "SERVICE_TASK_START_IMPAIRED" : "web-app service start is impaired.",
        "ECS_OPERATION_THROTTLED" : "web-app operations are being throttled.",
        "SERVICE_TASK_CONFIGURATION_FAILURE" : "web-app task config failure.",
    }
    if event['detail']['eventName'] not in state_message_map.keys():
        print("state message not in map.")
        return

    payload =  {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "ECS State Change"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Message*"
                    },
                    {
                        "type": "mrkdwn",
                        "text": state_message_map[event['detail']['eventName']]
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Log level*"
                    },
                    {
                        "type": "mrkdwn",
                        "text": event["detail"]["eventType"]
                    }
                ]
            },
            {
                "type": "divider"
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": event['detail']['clusterArn']
                    }
                ]
            }
        ]
    }
       
    respond(payload)
    

def ecs_task(event):
    message = False # use this to track if we actually wanna send a message

    if event['detail']['lastStatus'] == 'DEPROVISIONING' and event['detail']['desiredStatus'] == 'STOPPED':
        message = 'We\'re going down, babeyy. Killing a task/container.'
        reason = event['detail']['stoppedReason']

    if event['detail']['lastStatus'] == 'STOPPED' and event['detail']['desiredStatus'] == 'STOPPED':
        message = 'Task/container is dead. We\'re out of business.'
        reason = event['detail']['stoppedReason']

    if event['detail']['lastStatus'] == 'PENDING' and event['detail']['desiredStatus'] == 'RUNNING':
        message = 'Creating a new container/task. We\'re almost back in business.'
        reason = ''

    if event['detail']['lastStatus'] == 'RUNNING' and event['detail']['desiredStatus'] == 'RUNNING':
        message = 'New container/task is up. We\'re back, babeyy.'
        reason = ''

    if not message:
        print("we don't care about this detail")
        return

    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*ECS Task State Change*"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Reason*\n{}".format(reason)
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Message*\n{}".format(message)
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "*Most recent task state:* {}".format(event['detail']['lastStatus'])
                    }
                ]
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "*Desired task state:* {}".format(event['detail']['desiredStatus'])
                    }
                ]
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                "text": "*Cluster:* {}".format(event['detail']['clusterArn'])
            }
        ]
            }
        ]
    }

    respond(payload)

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