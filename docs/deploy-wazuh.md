# Deploying to Wazuh

Tested with wazuh-manager 4.14.7. The rules use the built-in JSON decoder, so no custom decoder is
needed. Rule IDs 100700 to 100799 are reserved by this pack; change them if they collide with your
local rules.

## 1. Rules on the manager

```bash
cp detections/wazuh/llm_rules.xml /var/ossec/etc/rules/llm_rules.xml
chown wazuh:wazuh /var/ossec/etc/rules/llm_rules.xml
systemctl restart wazuh-manager
```

With [wazuh-docker](https://github.com/wazuh/wazuh-docker) (single-node):

```bash
docker cp detections/wazuh/llm_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/llm_rules.xml
docker restart single-node-wazuh.manager-1
```

## 2. Ship the log from the agent

On the host where the LLM application runs, add the block from
`detections/wazuh/ossec-localfile.conf` to the agent's `ossec.conf` (adjust the path) and restart
the agent. Or use centralized configuration (`agent.conf`) for a group of agents.

## 3. Check

```bash
/var/ossec/bin/wazuh-logtest
```

Paste a line from `datasets/sample.jsonl`; for example the completion containing `pixel.png` should
match rule 100742 (LLMD-005). The whole dataset can be replayed with the client used by the tests:

```bash
docker cp tests/wazuh_logtest_client.py <manager>:/tmp/
docker cp datasets/sample.jsonl <manager>:/tmp/
docker exec <manager> /var/ossec/framework/python/bin/python3 /tmp/wazuh_logtest_client.py /tmp/sample.jsonl
```

## Implementation notes

- **Level 0 does not feed correlation.** Frequency and `if_matched_*` rules only counted events
  whose rule had a level above 0 in our tests, so the base tool-call rule is level 2 (still below the
  default `log_alert_level` of 3, so it produces no alert).
- **One alert per event.** Wazuh reports the deepest matching rule only. Where one event satisfies
  several LLMD rules, a child rule carries all their groups (`llmd_004,llmd_006,llmd_007` on 100732).
  Filter dashboards on `rule.groups: llmd_*`, not on rule IDs.
- **Frequency counts final rules only.** A `frequency` rule with `if_matched_sid` counts only events
  whose final rule is that sid; events that went on to a more specific child are not counted, and
  `if_matched_group` did not change that in our tests. Keep counted base rules free of children
  where you can.
- **No nested correlation.** A rule with `if_matched_group` under another correlation rule was
  never evaluated, while the same rule under a plain parent worked.
- **Change detection works.** `frequency="2"` with `same_field` + `different_field` reliably
  detects a changed MCP tool description (LLMD-014), within the rule's timeframe.
- **Regex quirks.** Patterns are PCRE2 without UTF mode. Non-ASCII characters are written as UTF-8
  byte sequences (Unicode tag characters are `\xF3\xA0[\x80\x81][\x80-\xBF]`), and character
  classes containing quotes did not match under 4.14, so they are avoided.
