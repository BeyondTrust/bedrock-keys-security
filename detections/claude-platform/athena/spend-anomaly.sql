-- Top Claude Platform API-key-authenticated principals over the last 7 days
-- (CreateInference / CreateBatch / CreateFile / etc.).
--
-- Surface-level spend / capacity anomaly query. AeaApiKey-* phantom
-- users (or STS-derived sessions) that suddenly climb the leaderboard
-- are LLMjacking candidates.
--
-- Aggregated by userIdentity.principalId, not userName: a short-term key's
-- userName is its assumed-role / session name (or empty), so grouping by
-- principalId is what keeps STS-derived keys visible on the leaderboard.
--
-- Replace <CLOUDTRAIL_DB>.<CLOUDTRAIL_TABLE>.

SELECT
    useridentity.principalid     AS principal,
    json_extract_scalar(requestparameters,
                        '$.bearerTokenType')           AS key_type,
    count(*)                     AS invocations,
    cardinality(array_agg(DISTINCT awsregion))         AS regions,
    cardinality(array_agg(DISTINCT sourceipaddress))   AS source_ips,
    min(eventtime)               AS first_seen,
    max(eventtime)               AS last_seen
FROM <CLOUDTRAIL_DB>.<CLOUDTRAIL_TABLE>
WHERE eventsource = 'aws-external-anthropic.amazonaws.com'
  AND json_extract_scalar(requestparameters, '$.callWithBearerToken') = 'true'
  AND eventtime >= date_format(current_timestamp - INTERVAL '7' DAY,
                                '%Y-%m-%dT%H:%i:%sZ')
GROUP BY useridentity.principalid,
         json_extract_scalar(requestparameters, '$.bearerTokenType')
ORDER BY invocations DESC
LIMIT 50;
