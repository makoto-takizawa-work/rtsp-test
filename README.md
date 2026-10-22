# RTSP Test Client

An interactive RTSP diagnostic client written in Python. It is intended for testing RTSP control requests and checking the reception of RTP/RTCP packets.

## Features

- Supports RTSP `OPTIONS`, `DESCRIBE`, `SETUP`, `PLAY`, and `TEARDOWN` requests
- Identifies video and audio tracks from SDP
- Supports Digest Authentication (MD5 / MD5-sess / SHA-256 / SHA-256-sess, including `qop=auth`)
- Supports the following transport modes:
  - TCP interleaved
  - UDP unicast
  - UDP multicast
- Monitors RTP/RTCP packet reception

> This tool is intended for diagnostics. It does not decode or play video or audio.

## Requirements

- Python 3.9 or later is recommended
- Network connectivity to the RTSP server
- For multicast testing, multicast traffic must be permitted by routers, switches, and the operating system along the network path

## Running the Client

Run the following command in the directory containing `rtsp_test.py`:

```bash
python3 rtsp_test.py
```

If prompted, enter the RTSP URL and authentication credentials as instructed on the screen. For example:

```text
rtsp://192.0.2.10:554/stream1
```

The IP address above is for illustrative purposes only. Replace it with the URL of your actual RTSP server.

## Commands

The following interactive commands are available after starting the client:

| Command | Description |
|---|---|
| `options` | Sends `OPTIONS` and checks supported methods and other information |
| `describe` | Sends `DESCRIBE` and retrieves the SDP |
| `setup video tcp` | Sets up the video track using TCP interleaved |
| `setup audio tcp` | Sets up the audio track using TCP interleaved |
| `setup video udp` | Sets up the video track using UDP unicast |
| `setup audio udp` | Sets up the audio track using UDP unicast |
| `setup video multicast` | Sets up the video track using multicast |
| `setup audio multicast` | Sets up the audio track using multicast |
| `play` | Sends `PLAY` to start streaming |
| `receive [seconds]` | Checks RTP/RTCP reception for the specified number of seconds |
| `status` | Displays the connection and session status |
| `teardown` | Sends `TEARDOWN` |
| `quit` | Exits the client |

### Example Session

```text
options
describe
setup video udp
play
receive 10
status
teardown
quit
```

To test audio, use `setup audio ...`. The RTSP server must support the selected track and transport mode.

## Transport Modes

### TCP Interleaved

RTP/RTCP packets are carried over the RTSP TCP connection. This allows you to test streaming separately from UDP port availability and multicast routing.

### UDP Unicast

The client reserves UDP ports for RTP/RTCP and advertises them in the `client_port` parameter of the `SETUP` request's `Transport` header. If a firewall or NAT is present, make sure the incoming UDP packets can reach the client.

### UDP Multicast

The client joins the multicast group using the destination address and port specified in the server's `SETUP` response. Make sure multicast traffic is permitted on the network and that IGMP and switch configurations are correct where required.

When receiving multiple multicast groups on the same UDP port, settings such as `SO_REUSEADDR` and `SO_REUSEPORT` may be relevant on macOS and other operating systems. Packet delivery when sharing a port depends on the operating system and socket configuration. Verify which socket actually receives the packets.

## RTCP and Timeouts

RTP carries media data, while RTCP carries control information such as transmission and reception quality statistics. If no RTCP packets arrive, a call to `recvfrom()` on the RTCP socket may time out. However, this does not necessarily mean that RTP reception or the RTSP session itself has timed out.

The `Session: ...;timeout=10` header parameter generally indicates the RTSP session timeout. Whether the server disconnects a session when RTCP is absent, or requires RTSP requests to keep the session alive, depends on the server implementation and applicable specifications.

To investigate the cause of a disconnection, compare the following:

1. Record the `Session` and `Transport` headers in the `SETUP` response.
2. Capture RTSP, RTP, and RTCP traffic simultaneously using Wireshark or a similar tool.
3. Compare tests performed under the same conditions, with and without RTCP traffic.
4. Check the server logs for timeout events and transport-resource cleanup.

This client may not implement RTCP Receiver Report transmission. If your test requires RTCP transmission, verify whether that functionality is implemented in the script.

## Troubleshooting

### `Address already in use`

- Check whether another process is using the port.
- Verify the RTP and RTCP port numbers.
- For multicast testing that requires sharing a port, configure `SO_REUSEADDR` and, if necessary, `SO_REUSEPORT` before calling `bind()`.
- After changing socket reuse settings, test whether packets from multiple groups are received as expected.

### RTP Packets Are Not Received

- Check whether the target track is present in the SDP returned by `DESCRIBE`.
- Verify the `Transport` header, destination address, and port in the `SETUP` response.
- Confirm that `PLAY` succeeds.
- For UDP unicast, check the client ports and firewall settings.
- For multicast, check the group address, network interface, routing, and IGMP/switch configuration.
- Use a packet capture to verify that RTP packets reach the expected network interface.

### Only RTCP Times Out

The server may not be transmitting RTCP, the RTCP port may be incorrect, or the configuration may not use RTCP. Evaluate RTP packet counts and received bytes separately from RTCP reception status.

## Limitations

- This client does not decode or play video or audio.
- SDP and `Transport` header parsing are limited to the features implemented in the script.
- Features such as `rtcp-mux` (multiplexing RTP and RTCP on the same port) are not supported unless explicitly implemented.
- Check the implementation before using it with RTSPS (RTSP over TLS), server-specific authentication methods, or complex redirection scenarios.
- Use this tool only with servers and test environments you are authorized to access.

## Disclaimer

You are free to use, copy, modify, and redistribute this code for any purpose. This code is provided **"AS IS"**, without warranties or guarantees of any kind, whether express or implied. The author accepts no responsibility or liability whatsoever for any damages, losses, claims, or other consequences arising from the use of, or inability to use, this code. You use this code entirely at your own risk.
