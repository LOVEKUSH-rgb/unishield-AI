# UniShield Service Level Objectives (SLOs)

## Overview
This document defines the operational Service Level Objectives (SLOs) derived from the Prometheus monitoring stack for UniShield.

## 1. API Availability SLO
- **Objective**: 99.9%
- **Calculation**: 
  - Successful `up{job="unishield-api"}` scrapes / Total Scrapes over a 30-day window.
- **Limitation**: Depends entirely on Prometheus scrape reliability.

## 2. Pipeline Success Rate
- **Objective**: 99.9%
- **Calculation**: 
  - `100 - (unishield:ingestion_drop_rate / unishield:ingestion_events_per_second * 100)`
- **Description**: Evaluates the percentage of incoming events (via Zeek/PCAP) successfully parsed and committed to Flow creation.

## 3. Database Operation Success Rate
- **Objective**: 99.99%
- **Calculation**: 
  - `100 - (unishield:database_error_rate / rate(unishield_database_operations_total))`
- **Description**: Measures the reliability of saving Alerts and Incidents.

> [!WARNING]
> Do not conflate Platform SLOs with Security KPIs. A 100% Pipeline Success Rate means the software did not crash or drop events, it does not mean 100% of cyber threats were detected.
