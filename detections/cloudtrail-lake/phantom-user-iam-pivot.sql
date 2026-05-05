-- Phantom user IAM access key creation (privilege escalation pivot).
--
-- CloudTrail Lake stores requestParameters / responseElements as
-- map<varchar,varchar>. Top-level keys: element_at(map, 'key'). Nested
-- values are JSON-stringified, so deep paths need JSON_EXTRACT_SCALAR.
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
