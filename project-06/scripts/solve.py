import time
import dns.resolver

RESOLVER_IP = "127.0.0.1"
RESOLVER_PORT = 5053
CAND_FILE = "suspicious_domains.txt"

def make_resolver():
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [RESOLVER_IP]
    r.port = RESOLVER_PORT
    r.timeout = 2.0
    r.lifetime = 2.0
    return r

def timed_query(res, name: str) -> float:
    t0 = time.perf_counter()
    try:
        res.resolve(name, "A")
    except Exception:
        pass
    return time.perf_counter() - t0

def main():
    with open(CAND_FILE, "r", encoding="utf-8") as f:
        candidates = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]

    res = make_resolver()

    timed_query(res, "warmup.example.com")

    results = []
    for d in candidates:
        dt = timed_query(res, d) 
        results.append((dt, d))

    results.sort()
    hot_time, hot_domain = results[0]

    print("== Timings (fastest first) ==")
    for dt, d in results:
        print(f"{dt*1000:8.2f} ms  {d}")

    print("\n== HOT DOMAIN ==")
    print(hot_domain)

if __name__ == "__main__":
    main()
