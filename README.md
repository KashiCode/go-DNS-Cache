![image](https://github.com/user-attachments/assets/e34e161a-bb61-4695-b7ce-d91699d766a5)

![image](https://github.com/user-attachments/assets/06e66e74-798a-45b0-8192-e455a9fb7fa7)

| Query            | UDP command                                                                       | TCP command ( `+tcp`)                               |
| --------------------- | --------------------------------------------------------------------------------- | ----------------------------------------------------- |
| **IPv4 lookup**       | `dig @127.0.0.1 -p 8053 example.com A`                                            | `dig @127.0.0.1 -p 8053 example.com A +tcp`           |
| **IPv6 lookup**       | `dig @127.0.0.1 -p 8053 example.com AAAA`                                         | `dig @127.0.0.1 -p 8053 example.com AAAA +tcp`        |
| **CNAME**   | `dig @127.0.0.1 -p 8053 www.macports.org`                                         | `dig @127.0.0.1 -p 8053 www.macports.org +tcp`        |
| **NXDOMAIN**     | `dig @127.0.0.1 -p 8053 no-such-host-1234.com A`                                  | `dig @127.0.0.1 -p 8053 no-such-host-1234.com A +tcp` |
| **Root NS list**      | `dig @127.0.0.1 -p 8053 . NS`                                                     | `dig @127.0.0.1 -p 8053 . NS +tcp`                    |
| **TXT record**        | `dig @127.0.0.1 -p 8053 _dmarc.google.com TXT`                                    | `dig @127.0.0.1 -p 8053 _dmarc.google.com TXT +tcp`   |
| **Concurrency deduplication**  | `for i in {1..8}; do dig @127.0.0.1 -p 8053 wikipedia.org A & done; wait` | `+tcp` added                           |

| Feature | Explaination |
|------|----------------------|
| **Port Listener** | Listens to UDP **and** TCP requests on `0.0.0.0:8053`. |
| **Recursive resolution** | Recursive algorithm that starts at the root → follows NS delegation → stops when an answer RR-set is found or 15 hops are exceeded. |
| **TTL Caching** | In-memory cache map keyed by `<domain>:<type>` with per-entry TTL eviction.|
| **De-duplication** | `Deduper` collapses any concurrent identical lookups.|
| **Header patching** | Before DNS response to a Query the TX-ID bytes are copied, RD bit is copied, the RA is set, and the AA is cleared. |
| **CNAME Followup** | if the RR set of the response contains CNAME a recursive lookup finds the target name and updates ANCOUNT. |
| **Logging** | Logs for all queries and for the response latency – `ANS` (recursive walk with no record), `CACHE` (query stored in cache already), `CNAME` (alias), or `FAIL`(error) |

