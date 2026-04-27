-- Phantom user IAM access key creation — privilege escalation pivot.
--
-- An attacker who can call iam:CreateAccessKey on a BedrockAPIKey-* phantom
-- user inherits the user's bedrock:*, iam:ListRoles, kms:DescribeKey,
-- ec2:Describe* permissions and gains persistent AKIA credentials that
-- survive Bedrock key revocation.
--
-- Replace <YOUR_EVENT_DATA_STORE_ID>.

SELECT
    eventTime,
    awsRegion,
    userIdentity.arn          AS actor_arn,
    userIdentity.type         AS actor_type,
    userIdentity.sessionContext.sessionIssuer.userName AS actor_role,
    sourceIPAddress,
    userAgent,
    requestParameters.userName AS phantom_user,
    responseElements.accessKey.accessKeyId AS new_access_key_id,
    responseElements.accessKey.status      AS new_key_status
FROM <YOUR_EVENT_DATA_STORE_ID>
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName   = 'CreateAccessKey'
  AND requestParameters.userName LIKE 'BedrockAPIKey-%'
  AND eventTime  >= timestamp_sub(NOW(), INTERVAL '90' DAY)
ORDER BY eventTime DESC;
