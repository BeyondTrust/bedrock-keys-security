-- Phantom user IAM access key creation (privilege escalation pivot).
--
-- An attacker who can call iam:CreateAccessKey on a BedrockAPIKey-* phantom
-- user inherits the user's bedrock:*, iam:ListRoles, kms:DescribeKey,
-- ec2:Describe* permissions and gains persistent AKIA credentials that
-- survive Bedrock key revocation.
--
-- CloudTrail Lake stores requestParameters and responseElements as
-- map<varchar,varchar> (not structs, not JSON strings). Top-level keys are
-- accessed with element_at(map, 'key'). Values that are themselves nested
-- objects are stored as JSON-stringified strings, so deep paths like
-- responseElements.accessKey.accessKeyId require JSON_EXTRACT_SCALAR over
-- the inner string.
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
    element_at(requestParameters, 'userName')                                  AS phantom_user,
    JSON_EXTRACT_SCALAR(element_at(responseElements, 'accessKey'), '$.accessKeyId') AS new_access_key_id,
    JSON_EXTRACT_SCALAR(element_at(responseElements, 'accessKey'), '$.status')      AS new_key_status
FROM <YOUR_EVENT_DATA_STORE_ID>
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName   = 'CreateAccessKey'
  AND element_at(requestParameters, 'userName') LIKE 'BedrockAPIKey-%'
  AND eventTime  >= current_timestamp - INTERVAL '90' DAY
ORDER BY eventTime DESC;
