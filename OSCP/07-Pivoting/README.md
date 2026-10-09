# 7. Pivoting

[Main guide](../README.md) · [Tunnel commands](../Reference/Pivoting.md)

Technique companion: [Pivoting and lateral movement](Techniques/Cross-Platform/08-Pivoting-and-Lateral-Movement.md). Worked example: [Pirate](../../Writeups/HTB-Machines/Pirate-Writeup.md).

1. List interfaces, routes, local listeners, and discovered internal names on the foothold.
2. Record which internal destination the foothold can reach and whether the destination is in the exercise scope.
3. Choose a local forward for one service, SOCKS for compatible TCP tools, or a routed tunnel for broader access.
4. Start the tunnel and confirm one known service before expanding enumeration.
5. Add the internal host to the target tracker; repeat service enumeration using the working route.

| Method | Practical checks |
| --- | --- |
| SSH local forwarding | Listener address/port is local to the machine running SSH; the destination is reached from the SSH server |
| SSH dynamic / Chisel SOCKS | Proxy configuration points to the actual local SOCKS listener; the client supports the proxy |
| Ligolo | Correct agent session, interface, route, and target subnet; avoid conflicting local/VPN routes |
| Callback forwarding | The internal target can reach the callback address; forward the listener separately if needed |

For ordinary SOCKS/proxychains scans, use TCP connect mode, disable host discovery and local name resolution when appropriate, and start with a narrow port list. Raw SYN packets and UDP do not follow a normal TCP SOCKS proxy.

Record both ends of each tunnel, process/session names, routes added, and cleanup commands. Tunnel failure, destination filtering, and application authentication failure need different fixes.
