import boto3
import logging
import os
import json

logger = logging.getLogger()
logger.setLevel(logging.INFO)
# Setup clients
secret_manager_client = boto3.client('secretsmanager')
iam_client = boto3.client('iam')
sns_client = boto3.client('sns')
user_name = "DevMauricio"

def lambda_handler(event, context):
    """Secrets Manager Rotation Template

    This is a template for creating an AWS Secrets Manager rotation lambda

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the event parameters do not contain the expected keys

    """
    logger.info("Event data: {}".format(json.dumps(event)))
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Make sure the version is staged correctly
    metadata = secret_manager_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    if step == "createSecret":
        create_secret(secret_manager_client, arn, token)

    elif step == "setSecret":
        set_secret(secret_manager_client, arn, token)

    elif step == "testSecret":
        test_secret(secret_manager_client, arn, token)

    elif step == "finishSecret":
        finish_secret(secret_manager_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")

def create_secret(secret_manager_client, arn, token):
    """Create the secret

    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.

    Args:
        secret_manager_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

    """
    # Make sure the current secret exists
    secret_manager_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        secret_manager_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except secret_manager_client.exceptions.ResourceNotFoundException:
        iam_access_keys = iam_client.list_access_keys(UserName=user_name)
        metadata_iam = iam_access_keys["AccessKeyMetadata"]
        if not metadata_iam:
            msg = "%s does not have Access Keys and Secret Access keys created"
            logger.error(msg % user_name)
            raise ValueError(msg % user_name)
        if len(metadata_iam) != 2:
            msg = "%s does not have two Access Keys and Secret Access keys created"
            logger.error(msg % user_name)
            raise ValueError(msg % user_name)  
        print(metadata_iam)

        for item in metadata_iam:
            if item["Status"] == "Inactive":
                iam_client.delete_access_key(UserName=user_name,AccessKeyId=item["AccessKeyId"])

        create_access_key = iam_client.create_access_key(UserName=user_name)
        credentials = {
            'AccessKeyId': create_access_key['AccessKey']['AccessKeyId'],
            'SecretAccessKey': create_access_key['AccessKey']['SecretAccessKey']
        }
        secret_string = json.dumps(credentials)
        
        iam_access_keys = iam_client.list_access_keys(UserName=user_name)
        metadata_iam = iam_access_keys["AccessKeyMetadata"]
        
        if metadata_iam[0]["CreateDate"] > metadata_iam[1]["CreateDate"]:
            iam_client.update_access_key(UserName=user_name, AccessKeyId=metadata_iam[1]["AccessKeyId"], Status='Inactive')
            msg_sns = {
                "OldAccessKeyId": metadata_iam[1]["AccessKeyId"],
                "NewAccessKeyId": metadata_iam[0]["AccessKeyId"],
                "secret_name": arn
            }
            sns_client.publish(TopicArn='arn:aws:sns:us-east-1:809489680864:workshop-ssm',Message=json.dumps(msg_sns))
        else:
            iam_client.update_access_key(UserName=user_name, AccessKeyId=metadata_iam[0]["AccessKeyId"], Status='Inactive')
            msg_sns = {
                "OldAccessKeyId": metadata_iam[0]["AccessKeyId"],
                "NewAccessKeyId": metadata_iam[1]["AccessKeyId"],
                "secret_name": arn
            }
            sns_client.publish(TopicArn='arn:aws:sns:us-east-1:809489680864:workshop-ssm',Message=json.dumps(msg_sns))

        # Put the secret
        secret_manager_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=secret_string, VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))


def set_secret(secret_manager_client, arn, token):
    """Set the secret

    This method should set the AWSPENDING secret in the service that the secret belongs to. For example, if the secret is a database
    credential, this method should take the value of the AWSPENDING secret and set the user's password to this value in the database.

    Args:
        secret_manager_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    # This is where the secret should be set in the service

    logger.info("This step is optional for this case")

def test_secret(secret_manager_client, arn, token):
    """Test the secret

    This method should validate that the AWSPENDING secret works in the service that the secret belongs to. For example, if the secret
    is a database credential, this method should validate that the user can login with the password in AWSPENDING and that the user has
    all of the expected permissions against the database.

    If the test fails, this function should raise an exception. (Any exception.)
    If no exception is raised, the test is considered to have passed. (The return value is ignored.)

    Args:
        secret_manager_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    # This is where the secret should be tested against the service
    logger.info("This step is optional for this case")

def finish_secret(secret_manager_client, arn, token):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.

    Args:
        secret_manager_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist

    """
    # First describe the secret to get the current version
    metadata = secret_manager_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    secret_manager_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))