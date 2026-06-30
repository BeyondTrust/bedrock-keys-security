-- Claude Platform on AWS API key-token usage broken down by API key type.
--
-- Maps long-term (AEAA) vs short-term (aws-external-anthropic-api-key-)
-- API key use per principal over the last 7 days. Flags LLMjacking on the
-- static-credential path, and automated workloads still on a long-term API
-- key that should have migrated to short-term.
--
-- Aggregated by userIdentity.principalId, not userName: a short-term key's
-- userName is its assumed-role / session name, so principalId is what keeps
-- STS-derived keys attributable per type.
--
-- Replace <CLOUDTRAIL_DB>.<CLOUDTRAIL_TABLE>.

SELECT
    useridentity.principalid                           AS principal,
    json_extract_scalar(requestparameters,
                        '$.bearerTokenType')           AS key_type,
    count(*)                                           AS invocations,
    cardinality(array_agg(DISTINCT awsregion))         AS regions,
    cardinality(array_agg(DISTINCT sourceipaddress))   AS source_ips,
    min(eventtime)                                     AS first_seen,
    max(eventtime)                                     AS last_seen
FROM <CLOUDTRAIL_DB>.<CLOUDTRAIL_TABLE>
WHERE eventsource = 'aws-external-anthropic.amazonaws.com'
  AND json_extract_scalar(requestparameters,
                          '$.callWithBearerToken') = 'true'
  AND eventtime >= date_format(current_timestamp - INTERVAL '7' DAY,
                                '%Y-%m-%dT%H:%i:%sZ')
GROUP BY useridentity.principalid,
         json_extract_scalar(requestparameters, '$.bearerTokenType')
ORDER BY invocations DESC
LIMIT 100;
