-- Bearer token used in 2+ regions within 1 hour (LLMjacking fan-out).
--
-- Anchored on additionalEventData.callWithBearerToken (the universal
-- signal for any Bedrock API key request), so this query catches both
-- long-term keys (phantom users) and short-term keys (STS-derived
-- bearer tokens). Aggregating by principalId (not userName) is what
-- makes short-term keys visible: their userName is the assumed role
-- or session name, not BedrockAPIKey-*.
--
-- Run against your CloudTrail Athena table. Replace <CLOUDTRAIL_DB>.<CLOUDTRAIL_TABLE>.
-- Adjust the time partition predicates to your partitioning scheme.

WITH bedrock_calls AS (
    SELECT
        useridentity.principalid  AS principal,
        awsregion                 AS region,
        eventtime                 AS event_time
    FROM <CLOUDTRAIL_DB>.<CLOUDTRAIL_TABLE>
    WHERE eventsource = 'bedrock.amazonaws.com'
      AND eventname  IN ('InvokeModel','InvokeModelWithResponseStream',
                         'Converse','ConverseStream','CallWithBearerToken')
      AND json_extract_scalar(additionaleventdata, '$.callWithBearerToken') = 'true'
      AND eventtime >= date_format(current_timestamp - INTERVAL '24' HOUR,
                                    '%Y-%m-%dT%H:%i:%sZ')
)
SELECT
    principal,
    date_trunc('hour', from_iso8601_timestamp(event_time)) AS hour_bucket,
    cardinality(array_agg(DISTINCT region))                AS distinct_regions,
    array_agg(DISTINCT region)                             AS regions,
    count(*)                                               AS calls
FROM bedrock_calls
GROUP BY principal, date_trunc('hour', from_iso8601_timestamp(event_time))
HAVING cardinality(array_agg(DISTINCT region)) >= 2
ORDER BY distinct_regions DESC, calls DESC;
