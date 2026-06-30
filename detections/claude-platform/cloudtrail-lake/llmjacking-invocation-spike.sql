-- LLMjacking invocation spike from a Claude Platform API key principal.
--
-- Detects any Claude Platform API key principal (long-term AeaApiKey-*
-- phantom user OR short-term STS-derived API key) that issues
-- more than 100 API-key-authenticated data-plane calls (CreateInference,
-- CreateBatch, CreateFile, etc.) in any 5-minute window. Tune the
-- threshold to your baseline.
--
-- Anchored on requestParameters.callWithBearerToken (the universal
-- signal for any Claude Platform API key request) and grouped by
-- userIdentity.principalId (not userName), so short-term keys are
-- visible. Short-term keys do not use AeaApiKey-* usernames; their
-- userName is the assumed-role / session name.
--
-- CloudTrail Lake stores requestParameters as map<varchar,varchar>
-- (not a struct), so the API key-token field is read with element_at
-- and compared as a string ("true"). Time bucketing uses to_unixtime /
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
    element_at(requestParameters, 'bearerTokenType')                          AS key_type,
    COUNT(*)                                                                  AS invocations,
    APPROX_DISTINCT(sourceIPAddress)                                          AS distinct_source_ips,
    ARRAY_AGG(DISTINCT eventName)                                             AS event_names
FROM <YOUR_EVENT_DATA_STORE_ID>
WHERE eventSource = 'aws-external-anthropic.amazonaws.com'
  AND eventTime  >= current_timestamp - INTERVAL '24' HOUR
  AND element_at(requestParameters, 'callWithBearerToken') = 'true'
GROUP BY userIdentity.principalId,
         from_unixtime(floor(to_unixtime(eventTime) / 300) * 300),
         awsRegion,
         element_at(requestParameters, 'bearerTokenType')
HAVING COUNT(*) > 100
ORDER BY invocations DESC
LIMIT 50;
