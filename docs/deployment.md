# Deployment notes

## Rate limiting at the edge
KrakenWAF rate limits by the observed client IP. When deployed directly on the TCP edge this is the socket peer address and requires no header trust chain.

## Behind a load balancer / reverse proxy
If KrakenWAF is deployed behind a trusted proxy, configure:

- `--trusted-proxy-cidrs 10.0.0.0/8,192.168.0.0/16`
- `--real-ip-header x-forwarded-for`

Only requests whose TCP peer IP belongs to a configured trusted CIDR will be allowed to override the effective client IP from the configured header. This avoids trusting spoofed client-supplied forwarding headers on untrusted links.


## Request inspection scope

DFA, regex, vectorscan, and libinjection inspection run against a synthesized full-request payload made from the HTTP method, URI, flattened headers, and body bytes. Streaming body inspection also evaluates a rolling full-request window so POST and REST payload detections are not limited to query-string inspection alone.
