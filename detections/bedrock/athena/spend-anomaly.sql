-- Top Bedrock InvokeModel principals over the last 7 days.
--
-- Surface-level spend / capacity anomaly query. Phantom users that suddenly
-- climb the leaderboard are LLMjacking candidates.
--
-- Replace <CLOUDTRAIL_DB>.<CLOUDTRAIL_TABLE>.

SELECT
    useridentity.username        AS principal,
    count(*)                     AS invocations,
    cardinality(array_agg(DISTINCT awsregion))         AS regions,
    cardinality(array_agg(DISTINCT sourceipaddress))   AS source_ips,
    min(eventtime)               AS first_seen,
    max(eventtime)               AS last_seen
FROM <CLOUDTRAIL_DB>.<CLOUDTRAIL_TABLE>
WHERE eventsource = 'bedrock.amazonaws.com'
  AND eventname  IN ('InvokeModel','InvokeModelWithResponseStream',
                     'Converse','ConverseStream','CallWithBearerToken')
  AND eventtime >= date_format(current_timestamp - INTERVAL '7' DAY,
                                '%Y-%m-%dT%H:%i:%sZ')
GROUP BY useridentity.username
ORDER BY invocations DESC
LIMIT 50;
