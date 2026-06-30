-- Claude Platform API key used in 2+ regions within 1 hour (LLMjacking).
--
-- Anchored on requestParameters.callWithBearerToken (the universal
-- signal for any Claude Platform API key request), so this query
-- catches both long-term keys (AeaApiKey-* phantom users) and
-- short-term keys (STS-derived API keys). Aggregating by
-- principalId (not userName) is what makes short-term keys visible:
-- their userName is the assumed role or session name, not AeaApiKey-*.
--
-- Scoped to eventcategory = 'Data': on Claude Platform inference is logged as
-- data events while workspace / vault operations are management events, so this
-- excludes default-logged ListWorkspaces / GetWorkspace calls that would
-- otherwise inflate the cross-region count with benign multi-region admin.
-- (eventcategory is a column in the CloudTrail-generated Athena table; if your
-- table predates it, add it to the table definition or drop this predicate.)
--
-- Run against your CloudTrail Athena table. Replace <CLOUDTRAIL_DB>.<CLOUDTRAIL_TABLE>.
-- Adjust the time partition predicates to your partitioning scheme.

WITH claude_platform_calls AS (
    SELECT
        useridentity.principalid  AS principal,
        awsregion                 AS region,
        eventtime                 AS event_time
    FROM <CLOUDTRAIL_DB>.<CLOUDTRAIL_TABLE>
    WHERE eventsource = 'aws-external-anthropic.amazonaws.com'
      AND eventcategory = 'Data'
      AND json_extract_scalar(requestparameters, '$.callWithBearerToken') = 'true'
      AND eventtime >= date_format(current_timestamp - INTERVAL '24' HOUR,
                                    '%Y-%m-%dT%H:%i:%sZ')
)
SELECT
    principal,
    date_trunc('hour', from_iso8601_timestamp(event_time)) AS hour_bucket,
    cardinality(array_agg(DISTINCT region))                AS distinct_regions,
    array_agg(DISTINCT region)                             AS regions,
    count(*)                                               AS calls
FROM claude_platform_calls
GROUP BY principal, date_trunc('hour', from_iso8601_timestamp(event_time))
HAVING cardinality(array_agg(DISTINCT region)) >= 2
ORDER BY distinct_regions DESC, calls DESC;
