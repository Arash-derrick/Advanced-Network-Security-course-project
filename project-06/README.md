# Challange: Oracles Pulse (DNS Cache Timing Side-Channel)

## Overview
This project explores a **DNS cache timing side-channel attack**. In this scenario, a resolver caches DNS answers, and an internal bot keeps a specific "hot" domain in the cache. The goal is to act as an observer/attacker and identify which domain from a list of candidates is being kept "hot" by analyzing the response times of the DNS resolver.

## Challenge Goal
The objective of this challenge is to:
- Understand how DNS caching behavior can act as a **Timing Oracle**.
- Develop a script (`solve.py`) to measure DNS resolution times with high precision.
- Implement a strategy to identify the cached domain while avoiding "cache-warming" (where the attacker's own probes accidentally cache the domains).
- Successfully extract the hidden domain to retrieve the flag.

## Repository Structure
```text
project-06/
├── README.md
├── src/
└── scripts/
    └── solve.py
```
## Project Workflow
   1. Environment Setup: The infrastructure is containerized. Start it using:
```text
      docker compose up --build
```
   
   2. Analysis: The script victim_bot.py (internal) ensures one domain from suspicious_domains.txt is always in the resolver’s cache.
   3. Probing Strategy:
	   - Send DNS queries for each candidate domain.
	   - Measure the Round Trip Time (RTT) for each query.
   	- Differentiate between a Cache Hit (very fast response) and a Cache Miss (slower response requiring recursive resolution).
   4. Execution: Run the solution script to identify the target domain:
```text
        python3 scripts/solve.py
```
## Key Security Concept: Timing Side-Channel
The core principle of this project is the Information Leakage through timing:
   - Cache Hit: If a domain is already in the cache (warm), the resolver responds almost instantly.
   - Cache Miss: If it’s not cached (cold), the resolver must query upstream servers, causing a measurable delay.

By statistically analyzing these delays, we can infer sensitive information about the internal network’s state or the “victim’s” activity.

## Deliverable
- A functional solve.py script.
- The identified “hot” domain and the resulting flag.