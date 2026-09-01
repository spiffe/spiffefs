# SPIFFE FS

[![Apache 2.0 License](https://img.shields.io/github/license/spiffe/spiffefs)](https://opensource.org/licenses/Apache-2.0)
[![Development Phase](https://github.com/spiffe/spiffe/blob/main/.img/maturity/dev.svg)](https://github.com/spiffe/spiffe/blob/main/MATURITY.md#development)

A filesystem to deliver using the spiffe filesystem delivery spec

## Warning

This code is very early in development and is very experimental. Please do not use it in production yet. Please do consider testing it out, provide feedback,
and maybe provide fixes.


## Usage

```
spiffefs [-mode=broker|delegated] [-broker-address <addr>] [-umount] <mountpoint>
```

## Modes

`spiffefs` gets workloads' credentials from one of two upstream APIs, selected
with `-mode`.

### `-mode=broker` (default)

The [SPIFFE Broker API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Broker_API.md).
`spiffefs` connects to a SPIRE Agent's broker endpoint (or anything else serving
that API, such as `spire-ha-agent`), names each reading process with a
`WorkloadPIDReference`, and the agent attests that reference with its own
workload attestor stack. Trust bundles — the workload's own trust domain and
everything its registration entry federates with — arrive inline on the same
stream, so what a workload is told to trust follows from its own entry rather
than from anything `spiffefs` holds.

| | Flag | Environment | Default |
| --- | --- | --- | --- |
| Broker endpoint | `-broker-address` | `SPIFFE_BROKER_ADDRESS` | `unix:///var/run/spire/agent/sockets/main/broker/broker.sock` |
| Workload API socket | — | `SPIFFE_ENDPOINT_SOCKET` | `unix:///var/run/spire/agent/sockets/main/public/api.sock` |

Both accept `unix://` and `tcp://`. A bare path is read as `unix://`.

Requirements:

- `spiffefs` needs **its own registration entry**. The broker endpoint is mTLS,
  and the client certificate is an X509-SVID `spiffefs` fetches for itself from
  the Workload API socket above.
- That SPIFFE ID must be listed in the agent's broker allowlist, permitted to
  use `type.googleapis.com/spiffe.broker.WorkloadPIDReference`:

  ```hcl
  agent {
      ...
      experimental {
          broker {
              socket_path = "/run/spire/agent/sockets/main/broker/broker.sock"
              brokers = [
                  {
                      id = "spiffe://example.org/spiffefs"
                      allowed_reference_types = [
                          { type_url = "type.googleapis.com/spiffe.broker.WorkloadPIDReference" },
                      ]
                  },
              ]
          }
      }
  }
  ```

  PID references are node-local, so `allow_over_tcp` is left off: reach the
  endpoint over a unix socket.
- The endpoint's server certificate is verified against the trust bundle, but
  its SPIFFE ID is not pinned — the agent presents its own SVID, whose ID is not
  predictable from configuration.

### `-mode=delegated` (deprecated)

SPIRE's Delegated Identity API over the agent's private admin socket. This was
the original behavior and is kept for existing deployments; **it will be
removed**. `SPIFFE_ENDPOINT_SOCKET` overrides the admin socket path, which
defaults to `/var/run/spire/agent/sockets/main/private/admin.sock`.

It needs `spiffefs`'s SPIFFE ID in the agent's `authorized_delegates`, and
because trust bundles arrive on one process-wide stream rather than per
workload, a workload is served the intersection of what its entry entitles it to
and what that stream has delivered.
