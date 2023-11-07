import hmac

import hashlib

import json

import os

import boto3


sm_client = boto3.client('secretsmanager')

sqs_client = boto3.client('sqs')

QUEUE_URL = os.environ['QUEUE_URL']


def get_github_secret():
    secret_arn = os.environ['SECRET_ARN']
    return json.loads(sm_client.get_secret_value(SecretId=secret_arn)['SecretString'])['SECRET']


def verify_hmac(secret, body, signature):
    hmac_gen = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()

    expected_signature = f'sha256={hmac_gen}'

    return hmac.compare_digest(expected_signature, signature)


def handler(event, context):
    github_secret = get_github_secret()

    github_signature = event['headers'].get('x-hub-signature-256')

    if not github_signature:
        print('Missing signature, skipping.')
        return {
            'statusCode': 401,
            'body': json.dumps(
                'Unauthorized - Missing GitHub Signature'
            )
        }

    payload_body = event['body']

    payload_body_json = json.loads(event['body'])

    github_event = event['headers'].get('x-github-event', '')

    if github_event != 'delete' or payload_body_json.get('ref_type') != 'branch':
        print('Not delete or not branch, skipping.')
        return {
            'statusCode': 202,
            'body': json.dumps(f'Ignored {github_event} event')
        }
    
    signature_valid = verify_hmac(github_secret, payload_body, github_signature)

    if not signature_valid:
        print('Invalid signature, skipping')
        return {
            'statusCode': 403,
            'body': json.dumps('Unauthorized - Invalid signature')
        }

    message = {
        'event': 'BRANCH_DELETED',
        'branch': payload_body_json.get('ref')
    }

    print('Sending message', message)

    sqs_response = sqs_client.send_message(
        QueueUrl=QUEUE_URL,
        MessageBody=json.dumps(message)
    )
    
    print('Sending message', sqs_response)

    return {
        'statusCode': 200,
        'body': json.dumps('Delete event processed successfully')
    }
