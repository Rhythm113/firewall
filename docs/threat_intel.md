# Threat Intelligence Feeds

## Overview

The threat intelligence system fetches IP blocklists from public
feeds and imports them into the database reputation system.

Source: soc-server/threat_intel.c

## Architecture

A background thread (intel_aggregator_thread) performs periodic
feed fetches and provides a manual trigger mechanism.

```
init_threat_intel() -> creates thread
  thread:
    curl_global_init()
    run_all_fetches()  [immediate first fetch]
    loop:
      pthread_cond_timedwait(6 hours)
      OR signal from trigger_feed_fetch()
      run_all_fetches()
    curl_global_cleanup()
```

## Configuration

- Default fetch interval: 6 hours (pthread_cond_timedwait)
- Can be triggered manually via trigger_feed_fetch()
- Manual trigger available via REST API:
  POST /api/v2/threat-intel/fetch

## Feed Sources

### 1. Feodo Tracker (abuse.ch)

- URL: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
- Type: Known botnet C2 servers
- External reputation score: 15 (low)
- Attack types: "botnet_c2"
- Import count: all valid IPs in feed
- Parser: Skips lines starting with #

### 2. Binary Defense

- URL: https://www.binarydefense.com/banlist.txt
- Type: Known malicious IPs
- External reputation score: 20
- Attack types: "malicious_ip"
- Import count: all valid IPs in feed

### 3. CI Army

- URL: http://cinsscore.com/list/ci-badguys.txt
- Type: Known scanners and malicious hosts
- External reputation score: 25
- Attack types: "scanner"
- Note: Uses HTTP (not HTTPS)

## Processing Flow

Each feed is fetched via libcurl (download_url helper):

1. curl_easy_init() with URL
2. 15-second timeout
3. Follow redirects (CURLOPT_FOLLOWLOCATION)
4. Custom User-Agent: "Nullsploit-SOC/2.0"
5. Response stored in dynamically-growing buffer

After download, each feed has a dedicated parser:

1. Split response by \r\n
2. Skip comment lines (starting with #)
3. Extract IP address using sscanf("%63s")
4. Validate minimum length (> 6 chars)
5. Call db_save_threat_intel() to store the indicator
6. Call db_update_ip_reputation() to set external score

## Tuning

Reputation scores for external feeds:
| Feed | Score | Rationale |
|------|-------|-----------|
| Feodo | 15 | Botnet C2s are highly malicious |
| BinaryDefense | 20 | General malicious hosts |
| CI Army | 25 | Scanners (less severe) |

Lower score = more suspicious. Score 15 will combine with local
score via LEAST() to produce the effective score.

## Integration

- REST trigger: POST /api/v2/threat-intel/fetch in DashboardController
  proxies to soc_receiver on port 8445
- Data stored in: threat_intel table (raw indicators) and
  ip_reputation table (external_score)
- Frontend: Shows external reputation IPs in a paginated table
  with a "Fetch From Sources Live" button
