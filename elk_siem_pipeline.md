# Real-Time SIEM & Log Aggregation Pipeline Guide

This guide provides the complete architectural workflow, configuration files, and setup instructions for building a real-time log ingestion and security observability pipeline using **Filebeat**, **Logstash**, **Elasticsearch**, and **Kibana**.

## 1. System Architecture & Components

- **Filebeat**: Acts as a lightweight log harvester on edge nodes, tailing application logs and sending them to Logstash via port 5044 [103, 202].
- **Logstash**: Acts as the central ETL engine [185, 202]. It receives log batches, parses unstructured strings into structured JSON using Grok filters [188, 208], enriches client IP addresses with GeoIP metadata [80, 208], and routes output documents to Elasticsearch [46, 205].
- **Elasticsearch**: A distributed search engine that indexes log documents for fast time-series searching and correlation [49, 202].
- **Kibana**: Provides real-time dashboarding, visualizations, and search interfaces [87, 202].

---

## 2. Environment Setup

To deploy the stack using container orchestration, prepare three configuration files in your project directory:

### A. Docker Compose Specification (`docker-compose.yml`)

Set up services for `elasticsearch` (port 9200), `logstash` (ports 5044, 9600), `kibana` (port 5601), and `filebeat` [203]:

```yaml
version: '3.8'

services:
  elasticsearch:
    image: elasticsearch:7.17.9
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"

  logstash:
    image: logstash:7.17.9
    container_name: logstash
    volumes:
      - ./logstash-security.conf:/usr/share/logstash/pipeline/logstash.conf:ro
    ports:
      - "5044:5044"

  kibana:
    image: kibana:7.17.9
    container_name: kibana
    ports:
      - "5601:5601"

  filebeat:
    image: filebeat:7.17.9
    container_name: filebeat
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
```

---

### B. Filebeat Configuration (`filebeat.yml`)

Configure Filebeat inputs to harvest logs and forward them to Logstash [190, 206]:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/syslog
      - /var/log/nginx/*.log

output.logstash:
  hosts: ["logstash:5044"]
```

---

### C. Logstash Grok Pipeline Configuration (`logstash-security.conf`)

Configure Logstash to parse incoming Beats streams, apply Grok filters, enrich GeoIP metadata, and output to Elasticsearch [46, 205, 208]:

```grok
input {
  beats {
    port => 5044
  }
}

filter {
  if [log][file][path] =~ "syslog" {
    grok {
      match => { "message" => "%{SYSLOGBASE} %{GREEDYDATA:message_body}" }
    }
  }

  if [clientip] {
    geoip {
      source => "clientip"
      target => "geoip"
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "security-logs-%{+YYYY.MM.dd}"
  }
}
```

---

## 3. Verification & Operational Steps

1. Start all containers in detached mode (`docker-compose up -d`) [218].
2. Verify Logstash receives data on port 5044 [205] and Elasticsearch responds on port 9200 [41, 42].
3. Open Kibana at port 5601 [44, 207], create an Index Pattern for `security-logs-*` [47, 207], and build real-time dashboards to analyze security telemetry [95, 210].
