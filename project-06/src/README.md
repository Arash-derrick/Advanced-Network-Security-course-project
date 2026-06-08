# Ex2: Oracles Pulse (DNS timing side channel)

Goal
- A resolver caches DNS answers.
- A bot keeps one internal domain hot in cache.

Run
```bash
sudo docker compose up --build
```

Student task
- Use `suspicious_domains.txt` as candidates.
- Write `solve.py` to identify the hot domain.

Notes
- Measure each candidate multiple times, but watch out for your own measurements warming the cache.
- It is often better to do one warm-up query and then a single measurement per candidate.
