# Challenge: 0-RTT Replay

## Overview
This project analyzes a **0-RTT replay vulnerability** in a ticket-based fast reconnect protocol.  
The service accepts early data and performs a **non-idempotent action** without replay protection. As a result, the same early data block can be replayed with the same ticket, causing the sensitive action to execute multiple times and making it possible to retrieve the flag.

## Challenge Goal
The goal of this challenge is to:
- analyze the replay weakness in the protocol,
- reproduce the vulnerable behavior in the lab environment,
- exploit the 0-RTT replay flaw against the live service,
- and obtain the flag.

## Service Information
- **Target:** `x.y.z.w:2135`
- **Source file:** `src/server_source/server.py`

## Vulnerability Summary
The challenge is based on the following properties:
- **ticket-based fast reconnect**
- **acceptance of early data**
- **non-idempotent server action**
- **missing replay protection**
- **replay of the same early block using the same ticket**

This combination allows a classic **0-RTT replay attack**.

## Repository Structure
```text
project-04/
├── README.md
├── src/
│   └── server_source/
│       └── server.py
└── scripts/
└── solve.py
```
## Expected Workflow
	1- Connect to the service at x.y.z.w:2135.
	2- Obtain or reuse a valid ticket for fast reconnect.
	3- Send early data to the server.
	4- Replay the same early-data block using the same ticket.
	5- Trigger the non-idempotent action multiple times.
	6- Increase the balance and retrieve the flag.
	7- Write the exact flag value to flag.txt on a single line.

## Deliverable
The final output must be the exact flag value saved in:

```text
flag.txt
```
## Notes
This challenge is intended for educational and research purposes in a controlled environment.
