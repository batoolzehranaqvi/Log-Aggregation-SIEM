# Kibana Security Dashboard & SIEM Detection Rules Configuration Guide

This technical guide outlines the implementation of a real-time Security Operations Center (SOC) dashboard and automated threat detection engine within Kibana. Designed to consume structured log telemetry from the containerized Filebeat and Logstash pipeline, this setup translates raw log events into actionable security intelligence and real-time incident alerts.

---

## 1. Index Pattern & Data View Setup

Before constructing visualizations or detection rules, Kibana must map the structured fields produced by the Logstash Grok and GeoIP filters.

### 1.1 Creating the Data View
1. Navigate to **Stack Management** > **Data Views** (formerly Index Patterns) in Kibana.
2. Click **Create data view**.
3. Set the **Name** and **Index pattern** to `security-logs-*`.
4. Set the **Time field** to `@timestamp`.
5. Save the Data View.

### 1.2 Elastic Common Schema (ECS) Field Inventory
The dashboard relies on standardized ECS field names generated during the Logstash enrichment phase:

| Field Name | Data Type | Description |
| :--- | :--- | :--- |
| `@timestamp` | Date | Event occurrence timestamp |
| `log.type` | Keyword | Source log classification (`auth` or `nginx_access`) |
| `source.ip` | IP Address | Originating IP address of the client or attacker |
| `user.name` | Keyword | Targeted user account in SSH login attempts |
| `event.outcome` | Keyword | Authentication result (`success` or `failure`) |
| `http.request.method` | Keyword | HTTP verb (`GET`, `POST`, etc.) |
| `url.path` | Keyword | Requested web URI path |
| `http.response.status_code` | Integer | HTTP response status (`200`, `401`, `403`, etc.) |
| `user_agent.name` | Keyword | Client browser or scanner identification string |
| `geoip.location` | Geo-point | Latitude and longitude mapped from `source.ip` |

---

## 2. Interactive SOC Visualization Widgets

Constructing a multi-widget dashboard provides immediate visibility into host authentication trends, web application threat patterns, and geographic attack distributions.

### Widget 1: Real-Time Geographic Attack Map
* **Visualization Type**: Maps (Elastic Maps) or Coordinate Map.
* **Objective**: Plot the origin of incoming external requests and SSH authentication failures geographically.
* **Configuration**:
  * **Layer Type**: Documents or Aggregations (Geohash Grid).
  * **Geospatial Field**: `geoip.location`.
  * **Tooltip Metrics**: Count of events, distinct count of `source.ip`.
  * **KQL Filter**: `not source.ip: (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)` (Excludes internal RFC 1918 traffic).

### Widget 2: SSH Authentication Status Breakdown
* **Visualization Type**: Donut Chart / Pie Chart.
* **Objective**: Display the proportion of successful logins versus failed authentication attempts.
* **Configuration**:
  * **Bucket Aggregation**: Terms aggregation on `event.outcome`.
  * **Metric**: Count of records.
  * **Color Schema**: Green for `success`, Solid Red for `failure`.
  * **KQL Filter**: `log.type: "auth"`.

### Widget 3: SSH Brute-Force Velocity Metric & Line Chart
* **Visualization Type**: Combined Metric & TSVB (Time Series Visual Builder) Line Chart.
* **Objective**: Track the frequency of failed login attempts over time to detect burst attacks.
* **Configuration**:
  * **Y-Axis Metric**: Count of events.
  * **X-Axis Bucket**: Date Histogram interval (e.g., `1 minute` or `5 minutes`).
  * **Split Series**: Terms aggregation on `source.ip` (Top 5 IPs).
  * **KQL Filter**: `log.type: "auth" and event.outcome: "failure"`.

### Widget 4: Web Application Vulnerability Scanning Heatmap
* **Visualization Type**: Vertical Bar Chart / Data Table.
* **Objective**: Identify top targeted web URIs, suspicious scanners, and unauthorized resource access attempts.
* **Configuration**:
  * **X-Axis Bucket**: Terms aggregation on `url.path` (Size: 10).
  * **Sub-Bucket**: Split Bar by `http.response.status_code`.
  * **Metrics**: Count of HTTP requests.
  * **KQL Filter**: `log.type: "nginx_access" and http.response.status_code: (401 or 403 or 404 or 500)`.

### Widget 5: Live Security Audit Log Stream Table
* **Visualization Type**: Data Table / Discover Save View.
* **Objective**: Provide SOC analysts with a live inspection feed of high-risk security events.
* **Configuration**:
  * **Columns**: `@timestamp`, `log.type`, `source.ip`, `user.name`, `url.path`, `http.response.status_code`, `event.outcome`.
  * **Sorting**: `@timestamp` Descending.
  * **KQL Filter**: `event.outcome: "failure" or http.response.status_code >= 400 or url.path: (*.env* or *.git* or *select*)`.

---

## 3. Real-Time SIEM Threat Detection Rules

Kibana Alerting & Rule Management automatically evaluates incoming Elasticsearch indices against predefined threshold conditions.

### Rule 1: SSH Password Brute-Force Attack Detection
* **Rule Type**: Threshold / Inventory Rule.
* **Evaluation Frequency**: Check every `1 minute` over a lookback window of `2 minutes`.
* **KQL Query**: `log.type: "auth" AND event.outcome: "failure"`
* **Group By**: `source.ip`
* **Threshold Condition**: IS ABOVE `5` occurrences.
* **Severity Level**: High.
* **Description**: Flags any single IP address attempting more than 5 failed SSH logins within 2 minutes, signaling automated dictionary or brute-force attacks.

### Rule 2: Web Reconnaissance & Vulnerability Scanning Detection
* **Rule Type**: Threshold Rule.
* **Evaluation Frequency**: Check every `1 minute` over a lookback window of `3 minutes`.
* **KQL Query**: `log.type: "nginx_access" AND (url.path: (*.env* OR *.git* OR *cgi-bin* OR *select*) OR user_agent.name: (*Scanner* OR *AuditTool*))`
* **Group By**: `source.ip`
* **Threshold Condition**: IS ABOVE `3` occurrences.
* **Severity Level**: High.
* **Description**: Detects clients attempting path traversal, sensitive configuration extraction (`.env`, `.git/config`), or running automated web assessment scanners.

### Rule 3: Unauthorized Administrative Account Escalation
* **Rule Type**: Custom Query Rule.
* **Evaluation Frequency**: Real-time / Every `1 minute`.
* **KQL Query**: `log.type: "auth" AND event.outcome: "success" AND user.name: ("root" OR "admin") AND NOT source.ip: (10.0.0.0/8 OR 192.168.1.0/24)`
* **Threshold Condition**: IS ABOVE `0` occurrences (Triggers on single match).
* **Severity Level**: Critical.
* **Description**: Triggers an immediate critical alert if a successful administrative session (`root` or `admin`) originates from an external or unapproved IP address.

---

## 4. Automated Incident Alerting & Webhook Integrations

When a SIEM rule triggers, Kibana dispatches automated alert payloads to external incident management platforms (such as Slack, PagerDuty, or custom Webhook endpoints).

### 4.1 Slack Webhook Integration Payload
Configure the Kibana Action connector to transmit formatted alert cards to a designated Slack security channel:

```json
{
  "text": "🚨 *SIEM SECURITY ALERT TRIGGERED* 🚨\n*Rule Name:* {{context.rule.name}}\n*Severity:* {{context.rule.severity}}\n*Target IP:* `{{context.group}}` \n*Triggered Events:* {{context.date}}\n*Details:* Identified {{context.results.total}} suspicious security events meeting detection criteria.\n*Action Required:* Verify IP reputation and isolate target host if necessary."
}
```

### 4.2 Automated IP Blacklisting Workflow (SOAR Integration)
To move from passive alerting to active remediation, the webhook payload can target a local SOAR (Security Orchestration, Automation, and Response) listener or Python script that dynamically updates host firewall rules (such as `iptables` or AWS Security Groups):

```bash
# Example automated firewall remediation rule triggered by alert payload
sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP
```

This completes the end-to-end telemetry loop: raw log generation ➔ shipping via Filebeat ➔ enrichment via Logstash ➔ indexing in Elasticsearch ➔ visualization and rule detection in Kibana ➔ automated firewall enforcement.
