-- LLMjacking invocation spike from a Bedrock bearer principal.
--
-- Detects any phantom user (BedrockAPIKey-*) or service-specific credential
-- principal that issues more than 100 Bedrock InvokeModel-family calls in any
-- 5-minute window. Tune the threshold to your baseline.
--
-- Run against a CloudTrail Lake event data store. Replace <YOUR_EVENT_DATA_STORE_ID>.
--
-- Reference: https://github.com/BeyondTrust/bedrock-keys-security

SELECT
    userIdentity.userName        AS principal,
    bin(eventTime, 5m)           AS window_start,
    awsRegion                    AS region,
    COUNT(*)                     AS invocations,
    APPROX_COUNT_DISTINCT(sourceIPAddress) AS distinct_source_ips,
    ARRAY_AGG(DISTINCT eventName) AS event_names
FROM <YOUR_EVENT_DATA_STORE_ID>
WHERE eventSource    = 'bedrock.amazonaws.com'
  AND eventName     IN ('InvokeModel', 'InvokeModelWithResponseStream',
                        'Converse', 'ConverseStream', 'CallWithBearerToken')
  AND eventTime     >= timestamp_sub(NOW(), INTERVAL '24' HOUR)
  AND userIdentity.userName LIKE 'BedrockAPIKey-%'
GROUP BY userIdentity.userName, bin(eventTime, 5m), awsRegion
HAVING COUNT(*) > 100
ORDER BY invocations DESC
LIMIT 50;
