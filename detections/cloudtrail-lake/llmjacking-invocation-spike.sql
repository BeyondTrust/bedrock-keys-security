-- LLMjacking invocation spike from a Bedrock bearer principal.
--
-- Detects any Bedrock bearer principal (long-term phantom user OR
-- short-term STS-derived bearer token) that issues more than 100 Bedrock
-- InvokeModel-family calls in any 5-minute window. Tune the threshold to
-- your baseline.
--
-- Anchored on additionalEventData.callWithBearerToken (the universal
-- signal for any Bedrock API key request) and grouped by
-- userIdentity.principalId (not userName), so short-term keys are
-- visible. Short-term keys do not use BedrockAPIKey-* usernames; their
-- userName is the assumed-role / session name.
--
-- CloudTrail Lake stores additionalEventData as map<varchar,varchar>
-- (not a struct), so the bearer-token field is read with element_at and
-- compared as a string ("true"). Time bucketing uses to_unixtime /
-- from_unixtime arithmetic because the Trino-based CloudTrail Lake
-- dialect does not support a `bin(eventTime, 5m)` literal.
--
-- Run against a CloudTrail Lake event data store. Replace <YOUR_EVENT_DATA_STORE_ID>.
--
-- Reference: https://github.com/BeyondTrust/bedrock-keys-security

SELECT
    userIdentity.principalId                                                  AS principal,
    from_unixtime(floor(to_unixtime(eventTime) / 300) * 300)                  AS window_start,
    awsRegion                                                                 AS region,
    COUNT(*)                                                                  AS invocations,
    APPROX_DISTINCT(sourceIPAddress)                                          AS distinct_source_ips,
    ARRAY_AGG(DISTINCT eventName)                                             AS event_names
FROM <YOUR_EVENT_DATA_STORE_ID>
WHERE eventSource = 'bedrock.amazonaws.com'
  AND eventName  IN ('InvokeModel', 'InvokeModelWithResponseStream',
                     'Converse', 'ConverseStream', 'CallWithBearerToken')
  AND eventTime >= current_timestamp - INTERVAL '24' HOUR
  AND element_at(additionalEventData, 'callWithBearerToken') = 'true'
GROUP BY userIdentity.principalId,
         from_unixtime(floor(to_unixtime(eventTime) / 300) * 300),
         awsRegion
HAVING COUNT(*) > 100
ORDER BY invocations DESC
LIMIT 50;
