-- LLMjacking invocation spike from a Bedrock bearer principal.
--
-- Detects any Bedrock bearer principal (long-term phantom user OR
-- short-term STS-derived bearer token) that issues more than 100 Bedrock
-- InvokeModel-family calls in any 5-minute window. Tune the threshold to
-- your baseline.
--
-- Anchored on additionalEventData.callWithBearerToken (the universal
-- signal for any Bedrock API key request) and grouped by
-- userIdentity.principalId — not userName — so short-term keys are
-- visible. Short-term keys do not use BedrockAPIKey-* usernames; their
-- userName is the assumed-role / session name.
--
-- Run against a CloudTrail Lake event data store. Replace <YOUR_EVENT_DATA_STORE_ID>.
--
-- Reference: https://github.com/BeyondTrust/bedrock-keys-security

SELECT
    userIdentity.principalId     AS principal,
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
  AND additionalEventData.callWithBearerToken = true
GROUP BY userIdentity.principalId, bin(eventTime, 5m), awsRegion
HAVING COUNT(*) > 100
ORDER BY invocations DESC
LIMIT 50;
