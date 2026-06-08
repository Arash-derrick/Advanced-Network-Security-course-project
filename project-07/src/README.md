# Ex4: DoH Whispers (size fingerprinting)

Goal
- The capture is encrypted-like traffic, but the response sizes leak which domain was queried.
- Your job is to map each query to a domain using only packet sizes.

Student task
- Use `doh_whispers_capture.pcap`.
- Use `domains.txt` as the candidate set.
- Write a short script (or do it in Wireshark) to map each transaction to the correct domain.

Hint
- Focus on server to client packets.
