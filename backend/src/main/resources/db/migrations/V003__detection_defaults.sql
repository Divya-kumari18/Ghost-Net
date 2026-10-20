UPDATE ids_rules SET threshold_count=1 WHERE threshold_count IS NULL;
UPDATE ids_rules SET window_seconds=60 WHERE window_seconds IS NULL;
UPDATE ids_rules SET distinct_ports=false WHERE distinct_ports IS NULL;
UPDATE security_events SET analyzed=false WHERE analyzed IS NULL;
-- Upgrade only the unchanged legacy seed, preserving operator-authored rules.
UPDATE ids_rules SET rule_name='Repeated RDP Connections',
    rule_content='Ten RDP SYN connections in sixty seconds; a connection-rate heuristic',
    threshold_count=10, window_seconds=60, payload_pattern=NULL
WHERE rule_name='RDP Brute Force Pattern'
  AND rule_content='Detect repeated RDP attempts to TCP/3389'
  AND NOT EXISTS(SELECT 1 FROM ids_rules WHERE rule_name='Repeated RDP Connections');
