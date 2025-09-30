#!/usr/bin/env python3
"""
FlareProx - Simple URL Redirection via Cloudflare Workers
Redirect all traffic through Cloudflare Workers for any provided URL
"""

import argparse
import asyncio
import getpass
import json
import os
import random
import secrets
import requests
import string
import socket
import struct
import time
import contextlib
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from websockets.exceptions import ConnectionClosed
from websockets.legacy.client import WebSocketClientProtocol, connect as ws_connect
import ipaddress


# Global DNS resolution cache: hostname -> (ip, timestamp)
_dns_cache: Dict[str, Tuple[str, float]] = {}
_DNS_CACHE_TTL = 300  # 5 minutes


class FlareProxError(Exception):
    """Custom exception for FlareProx-specific errors."""
    pass


class WorkerFallbackRequired(Exception):
    """Raised when the worker requests a relay fallback."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class TunnelSetupError(Exception):
    """Raised when an upstream tunnel cannot be established."""
    pass


def resolve_hostname_to_ipv4(hostname: str, timeout: float = 5.0, use_cache: bool = True) -> Optional[str]:
    """
    Resolve a hostname to its IPv4 address using Cloudflare DNS-over-HTTPS.
    Forces IPv4-only resolution and caches results.
    
    Args:
        hostname: The hostname to resolve
        timeout: Request timeout in seconds
        use_cache: Whether to use cached results
        
    Returns:
        IPv4 address as string, or None if resolution fails
    """
    # Check cache first
    if use_cache:
        cached = _dns_cache.get(hostname)
        if cached:
            ip, timestamp = cached
            if time.time() - timestamp < _DNS_CACHE_TTL:
                return ip
    
    # Resolve via Cloudflare DoH
    try:
        doh_url = f"https://cloudflare-dns.com/dns-query?name={hostname}&type=A"
        headers = {"Accept": "application/dns-json"}
        
        response = requests.get(doh_url, headers=headers, timeout=timeout)
        response.raise_for_status()
        
        data = response.json()
        
        # Check for successful DNS response
        if data.get("Status") == 0 and data.get("Answer"):
            # Find first IPv4 address in answers
            for answer in data["Answer"]:
                ip = answer.get("data", "")
                # Validate IPv4 format
                if ip and _is_valid_ipv4(ip):
                    # Cache the result
                    if use_cache:
                        _dns_cache[hostname] = (ip, time.time())
                    return ip
        
        return None
        
    except Exception:
        # On error, return None (caller will handle)
        return None


def _is_valid_ipv4(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False


def check_if_cloudflare_ip(target: str, use_doh: bool = True, doh_timeout: float = 5.0) -> Tuple[bool, str]:
    """
    Check if an IP address or hostname resolves to Cloudflare IP ranges.
    
    Args:
        target: IP address or hostname
        use_doh: Whether to use DNS-over-HTTPS for resolution (default: True)
        doh_timeout: Timeout for DoH requests in seconds (default: 5.0)
        
    Returns:
        Tuple of (is_cloudflare_ip, resolved_ip)
    """
    # Try to parse as IP first
    try:
        ip_obj = ipaddress.ip_address(target)
        is_cf = _is_cloudflare_ip_address(ip_obj)
        return (is_cf, target)
    except ValueError:
        pass
    
    # Not an IP, treat as hostname - resolve it
    if use_doh:
        resolved_ip = resolve_hostname_to_ipv4(target, timeout=doh_timeout)
        if resolved_ip:
            try:
                ip_obj = ipaddress.ip_address(resolved_ip)
                is_cf = _is_cloudflare_ip_address(ip_obj)
                return (is_cf, resolved_ip)
            except ValueError:
                return (False, resolved_ip)
        else:
            # Resolution failed
            return (False, target)
    else:
        # Fall back to standard DNS resolution
        try:
            resolved_ip = socket.gethostbyname(target)
            ip_obj = ipaddress.ip_address(resolved_ip)
            is_cf = _is_cloudflare_ip_address(ip_obj)
            return (is_cf, resolved_ip)
        except (socket.gaierror, socket.herror, ValueError):
            return (False, target)


def _is_cloudflare_ip_address(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Check if an IP address object is in Cloudflare ranges."""
    # Cloudflare IPv4 CIDR ranges
    cf_ipv4 = (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    )

    # Cloudflare IPv6 CIDR ranges
    cf_ipv6 = (
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    )
    
    if isinstance(ip, ipaddress.IPv4Address):
        # Use cached networks for performance
        if not hasattr(_is_cloudflare_ip_address, '_cf_ipv4_networks'):
            _is_cloudflare_ip_address._cf_ipv4_networks = [
                ipaddress.ip_network(cidr) for cidr in cf_ipv4
            ]
        return any(ip in network for network in _is_cloudflare_ip_address._cf_ipv4_networks)
    else:
        # IPv6
        if not hasattr(_is_cloudflare_ip_address, '_cf_ipv6_networks'):
            _is_cloudflare_ip_address._cf_ipv6_networks = [
                ipaddress.ip_network(cidr) for cidr in cf_ipv6
            ]
        return any(ip in network for network in _is_cloudflare_ip_address._cf_ipv6_networks)


class CloudflareManager:
    """Manages Cloudflare Worker deployments for FlareProx."""

    def __init__(
        self,
        api_token: str,
        account_id: str,
        zone_id: Optional[str] = None,
        worker_settings: Optional[Dict] = None
    ):
        self.api_token = api_token
        self.account_id = account_id
        self.zone_id = zone_id
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        self._account_subdomain = None
        self.worker_settings = worker_settings or {}

    @property
    def worker_subdomain(self) -> str:
        """Get the worker subdomain for workers.dev URLs."""
        if self._account_subdomain:
            return self._account_subdomain

        # Try to get configured subdomain
        url = f"{self.base_url}/accounts/{self.account_id}/workers/subdomain"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                subdomain = data.get("result", {}).get("subdomain")
                if subdomain:
                    self._account_subdomain = subdomain
                    return subdomain
        except requests.RequestException:
            pass

        # Fallback: use account ID as subdomain
        self._account_subdomain = self.account_id.lower()
        return self._account_subdomain

    def _generate_worker_name(self) -> str:
        """Generate a unique worker name."""
        timestamp = str(int(time.time()))
        random_suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
        return f"flareprox-{timestamp}-{random_suffix}"

    def _get_worker_script(self) -> str:
        """Return the Cloudflare Worker script.
        Modes:
          - http (default): original HTTP proxy from upstream flareprox-main
          - socks: minimal SOCKS-over-WebSocket bridge compatible with our client
        """
        mode = (self.worker_settings.get("mode") or "http").lower()

        if mode == "http":
            # Module-style version of the original upstream HTTP proxy
            return """
export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const targetUrl = getTargetUrl(url, request.headers);
      if (!targetUrl) {
        return createErrorResponse('No target URL specified', {
          usage: {
            query_param: '?url=https://example.com',
            header: 'X-Target-URL: https://example.com',
            path: '/https://example.com'
          }
        }, 400);
      }

      let targetURL;
      try { targetURL = new URL(targetUrl); }
      catch (e) { return createErrorResponse('Invalid target URL', { provided: targetUrl }, 400); }

      const targetParams = new URLSearchParams();
      for (const [key, value] of url.searchParams) {
        if (!['url', '_cb', '_t'].includes(key)) {
          targetParams.append(key, value);
        }
      }
      if (targetParams.toString()) {
        targetURL.search = targetParams.toString();
      }

      const proxyRequest = createProxyRequest(request, targetURL);
      const response = await fetch(proxyRequest);
      return createProxyResponse(response, request.method);
    } catch (error) {
      return createErrorResponse('Proxy request failed', { message: error.message, timestamp: new Date().toISOString() }, 500);
    }
  }
}

function getTargetUrl(url, headers) {
  let targetUrl = url.searchParams.get('url');
  if (!targetUrl) targetUrl = headers.get('X-Target-URL');
  if (!targetUrl && url.pathname !== '/') {
    const pathUrl = url.pathname.slice(1);
    if (pathUrl.startsWith('http')) targetUrl = pathUrl;
  }
  return targetUrl;
}

function createProxyRequest(request, targetURL) {
  const proxyHeaders = new Headers();
  const allowedHeaders = ['accept','accept-language','accept-encoding','authorization','cache-control','content-type','origin','referer','user-agent'];
  for (const [key, value] of request.headers) {
    if (allowedHeaders.includes(key.toLowerCase())) proxyHeaders.set(key, value);
  }
  proxyHeaders.set('Host', targetURL.hostname);
  const custom = request.headers.get('X-My-X-Forwarded-For');
  proxyHeaders.set('X-Forwarded-For', custom || generateRandomIP());
  return new Request(targetURL.toString(), { method: request.method, headers: proxyHeaders, body: ['GET','HEAD'].includes(request.method) ? null : request.body });
}

function createProxyResponse(response, requestMethod) {
  const responseHeaders = new Headers();
  for (const [key, value] of response.headers) {
    if (!['content-encoding','content-length','transfer-encoding'].includes(key.toLowerCase())) {
      responseHeaders.set(key, value);
    }
  }
  responseHeaders.set('Access-Control-Allow-Origin', '*');
  responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD');
  responseHeaders.set('Access-Control-Allow-Headers', '*');
  if (requestMethod === 'OPTIONS') return new Response(null, { status: 204, headers: responseHeaders });
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders });
}

function createErrorResponse(error, details, status) {
  return new Response(JSON.stringify({ error, ...details }), { status, headers: { 'Content-Type': 'application/json' } });
}

function generateRandomIP() {
  return [1,2,3,4].map(() => Math.floor(Math.random()*255)+1).join('.');
}
"""

        # SOCKS-over-WebSocket minimal bridge (keeps 'ready' control for client compatibility)
        auth_token = json.dumps(self.worker_settings.get("auth_token", ""))
        socks_password = json.dumps(self.worker_settings.get("socks_password", ""))
        return ("""
import { connect } from 'cloudflare:sockets';

const AUTH_TOKEN = AUTH_TOKEN_PLACEHOLDER;
const SOCKS_PASSWORD = SOCKS_PASSWORD_PLACEHOLDER;
const textEncoder = new TextEncoder();

export default {
  async fetch(request) {
    if (AUTH_TOKEN && request.headers.get('Authorization') !== AUTH_TOKEN) {
      return new Response('Unauthorized', { status: 401 });
    }
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected Upgrade: websocket', { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();
    server.binaryType = 'arraybuffer';

    server.addEventListener('message', async ({ data }) => {
      try {
        if (typeof data !== 'string') { server.close(1003, 'Invalid request'); return; }
        const payload = JSON.parse(data);
        const hostname = payload.hostname;
        const port = Number(payload.port);
        const password = payload.password ?? payload.psw ?? '';
        if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) { server.close(1008, 'Invalid target'); return; }
        if (SOCKS_PASSWORD && password !== SOCKS_PASSWORD) { server.close(1008, 'Invalid credentials'); return; }

        let socket;
        try { socket = connect({ hostname, port }); }
        catch (e) { server.close(1011, 'Upstream connect failed'); return; }

        // Minimal control for client handshake
        try { server.send(JSON.stringify({ type: 'ready' })); } catch (_) {}

        const inbound = new ReadableStream({
          start(controller) {
            server.addEventListener('message', event => {
              const p = event.data;
              if (typeof p === 'string') controller.enqueue(textEncoder.encode(p));
              else if (p instanceof ArrayBuffer) controller.enqueue(new Uint8Array(p));
            });
            server.addEventListener('error', ev => controller.error(ev));
            server.addEventListener('close', () => controller.close());
          },
          cancel() { try { socket && socket.close && socket.close(); } catch (_) {} }
        });

        inbound.pipeTo(socket.writable).catch(() => server.close(1011, 'Client error'));
        socket.readable.pipeTo(new WritableStream({
          write(chunk) { server.send(chunk instanceof ArrayBuffer ? chunk : new Uint8Array(chunk)); },
          close() { server.close(); },
          abort() { server.close(1011, 'Upstream aborted'); }
        })).catch(() => server.close(1011, 'Upstream error'));
      } catch (e) { server.close(1003, 'Invalid request'); }
    }, { once: true });

    return new Response(null, { status: 101, webSocket: client });
  }
}
"""
        ).replace("AUTH_TOKEN_PLACEHOLDER", auth_token).replace("SOCKS_PASSWORD_PLACEHOLDER", socks_password)

    def create_deployment(self, name: Optional[str] = None) -> Dict:
        """Deploy a new Cloudflare Worker."""
        if not name:
            name = self._generate_worker_name()

        script_content = self._get_worker_script()
        url = f"{self.base_url}/accounts/{self.account_id}/workers/scripts/{name}"

        compatibility_flags = self.worker_settings.get("compatibility_flags", ["nodejs_compat"])
        if isinstance(compatibility_flags, str):
            compatibility_flags = [compatibility_flags]
        elif not isinstance(compatibility_flags, list):
            compatibility_flags = ["nodejs_compat"]

        metadata = {
            "main_module": "worker.js",
            "compatibility_date": self.worker_settings.get("compatibility_date", "2023-09-04"),
            "compatibility_flags": compatibility_flags
        }

        files = {
            'metadata': (None, json.dumps(metadata), 'application/json'),
            'worker.js': ('worker.js', script_content, 'application/javascript+module')
        }

        headers = {"Authorization": f"Bearer {self.api_token}"}

        try:
            response = requests.put(url, headers=headers, files=files, timeout=60)
            response.raise_for_status()
        except requests.HTTPError as e:
            detail = ""
            if e.response is not None:
                try:
                    payload = e.response.json()
                    errors = payload.get("errors") if isinstance(payload, dict) else None
                    if errors:
                        detail = json.dumps(errors)
                    elif payload:
                        detail = json.dumps(payload)
                except (ValueError, AttributeError):
                    detail = e.response.text
            message = detail or str(e)
            raise FlareProxError(f"Failed to create worker: {message}")
        except requests.RequestException as e:
            raise FlareProxError(f"Failed to create worker: {e}")

        worker_data = response.json()

        # Enable subdomain
        subdomain_url = f"{self.base_url}/accounts/{self.account_id}/workers/scripts/{name}/subdomain"
        try:
            requests.post(subdomain_url, headers=self.headers, json={"enabled": True}, timeout=30)
        except requests.RequestException:
            pass  # Subdomain enabling is not critical

        worker_url = f"https://{name}.{self.worker_subdomain}.workers.dev"

        return {
            "name": name,
            "url": worker_url,
            "created_at": time.strftime('%Y-%m-%d %H:%M:%S'),
            "id": worker_data.get("result", {}).get("id", name),
            "auth_token": self.worker_settings.get("auth_token", ""),
            "socks_password": self.worker_settings.get("socks_password", "")
        }

    def list_deployments(self) -> List[Dict]:
        """List all FlareProx deployments."""
        url = f"{self.base_url}/accounts/{self.account_id}/workers/scripts"

        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            raise FlareProxError(f"Failed to list workers: {e}")

        data = response.json()
        workers = []

        for script in data.get("result", []):
            name = script.get("id", "")
            if name.startswith("flareprox-"):
                workers.append({
                    "name": name,
                    "url": f"https://{name}.{self.worker_subdomain}.workers.dev",
                    "created_at": script.get("created_on", "unknown")
                })

        return workers

    def test_deployment(self, deployment_url: str, target_url: str, method: str = "GET") -> Dict:
        """Test a deployment endpoint."""
        test_url = f"{deployment_url}?url={target_url}"

        try:
            response = requests.request(method, test_url, timeout=30)
            return {
                "success": True,
                "status_code": response.status_code,
                "response_length": len(response.content),
                "headers": dict(response.headers)
            }
        except requests.RequestException as e:
            return {
                "success": False,
                "error": str(e)
            }

    def cleanup_all(self) -> None:
        """Delete all FlareProx workers."""
        workers = self.list_deployments()

        for worker in workers:
            url = f"{self.base_url}/accounts/{self.account_id}/workers/scripts/{worker['name']}"
            try:
                response = requests.delete(url, headers=self.headers, timeout=30)
                if response.status_code in [200, 404]:
                    print(f"Deleted worker: {worker['name']}")
                else:
                    print(f"Could not delete worker: {worker['name']}")
            except requests.RequestException:
                print(f"Error deleting worker: {worker['name']}")


class LocalSocksServer:
    def __init__(self, endpoint: Dict, worker_defaults: Dict, client_defaults: Dict, bind_host: str):
        self.endpoint = dict(endpoint)
        self.bind_host = bind_host
        self.auth_token = self.endpoint.get("auth_token") or worker_defaults.get("auth_token", "")
        self.socks_password = self.endpoint.get("socks_password") or worker_defaults.get("socks_password", "")
        self.websocket_url = self._build_websocket_url(self.endpoint.get("url", ""))
        self.name = self.endpoint.get("name", "unknown")
        self._server: Optional[asyncio.AbstractServer] = None
        self.port: Optional[int] = None
        self.cf_override_ip = (client_defaults.get("cf_override_ip") or "").strip()
        self.cf_hostnames = [h.lower() for h in client_defaults.get("cf_hostnames", []) if isinstance(h, str)]
        relay_defaults = client_defaults.get("relay") if isinstance(client_defaults.get("relay"), dict) else {}
        self.relay_config = dict(relay_defaults)
        self.relay_url = (self.relay_config.get("url") or "").strip()
        self.relay_auth_token = (self.relay_config.get("auth_token") or "").strip()
        relay_password = (self.relay_config.get("socks_password") or "").strip()
        self.relay_password = relay_password or self.socks_password
        self.relay_enabled = bool(self.relay_config.get("enabled")) and bool(self.relay_url)
        self.handshake_timeout = float(self.relay_config.get("handshake_timeout", client_defaults.get("handshake_timeout", 5.0)))
        # Increase default buffer to 256KB to capture full TLS handshakes
        replay_limit = self.relay_config.get("retry_buffer_bytes", 262144)
        try:
            replay_limit = int(replay_limit)
        except (TypeError, ValueError):
            replay_limit = 262144
        self.replay_buffer_bytes = max(0, replay_limit)
        # DoH settings
        self.use_doh = bool(client_defaults.get("use_doh", True))
        self.doh_timeout = float(client_defaults.get("doh_timeout", 5.0))

    class _HandshakeState:
        def __init__(self, limit: int) -> None:
            self.limit = max(0, int(limit))
            self._segments: List[bytes] = []
            self._captured = 0
            self._replay_consumed = False
            self.confirmed = False

        def record(self, chunk: bytes) -> None:
            if self.confirmed or self._replay_consumed or self.limit == 0 or not chunk:
                return
            available = self.limit - self._captured
            if available <= 0:
                return
            piece = bytes(chunk[:available])
            if piece:
                self._segments.append(piece)
                self._captured += len(piece)

        def mark_established(self) -> None:
            if not self.confirmed:
                self.confirmed = True
                self._segments.clear()

        @property
        def has_replay(self) -> bool:
            return not self.confirmed and not self._replay_consumed and bool(self._segments)

        def consume(self) -> List[bytes]:
            if not self.has_replay:
                return []
            self._replay_consumed = True
            segments = list(self._segments)
            self._segments.clear()
            return segments

    @staticmethod
    def _parse_control_frame(message: str) -> Optional[Dict]:
        if not message or len(message) > 65536:
            return None
        try:
            data = json.loads(message)
        except (TypeError, ValueError):
            return None

        if isinstance(data, dict) and isinstance(data.get("type"), str):
            return data
        return None

    @staticmethod
    def _build_websocket_url(url: str) -> str:
        parsed = urlparse(url)
        scheme = 'wss' if parsed.scheme == 'https' else 'ws'
        path = parsed.path or ''
        if parsed.query:
            path = f"{path}?{parsed.query}"
        if not parsed.netloc:
            return url
        return f"{scheme}://{parsed.netloc}{path}"

    async def start(self, port_hint: Optional[int] = None) -> None:
        if not self.websocket_url:
            raise FlareProxError(f"Endpoint {self.name} does not have a valid URL.")

        listen_port = port_hint if port_hint not in (None, 0) else 0

        try:
            self._server = await asyncio.start_server(self._handle_client, self.bind_host, listen_port)
        except OSError:
            if listen_port != 0:
                self._server = await asyncio.start_server(self._handle_client, self.bind_host, 0)
            else:
                raise

        sock = self._server.sockets[0].getsockname()
        self.port = sock[1]

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        websocket: Optional[WebSocketClientProtocol] = None
        peer = writer.get_extra_info('peername', 'unknown')

        try:
            result = await self._negotiate(reader, writer)
            if not result:
                return

            hostname, port, request_data = result
            
            # Check if target matches manual CF hostname list for override
            connect_hostname = hostname
            if self.cf_override_ip and self._matches_cf_host(hostname.lower()):
                connect_hostname = self.cf_override_ip

            try:
                websocket, upstream_source = await self._connect_upstream(
                    connect_hostname, hostname, port
                )
            except TunnelSetupError:
                await self._send_failure(writer)
                return

            await self._send_success(writer, request_data)

            websocket = await self._bridge_streams(
                reader,
                writer,
                websocket,
                upstream_source,
                hostname,
                port
            )

        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                if websocket is not None:
                    await websocket.close()
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _negotiate(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[Tuple[str, int, bytes]]:
        try:
            header = await reader.readexactly(2)
        except asyncio.IncompleteReadError:
            return None

        version, method_count = header
        if version != 5:
            return None

        try:
            await reader.readexactly(method_count)
        except asyncio.IncompleteReadError:
            return None

        writer.write(b"\x05\x00")
        await writer.drain()

        try:
            request = await reader.readexactly(4)
        except asyncio.IncompleteReadError:
            return None

        version, command, _, address_type = request
        if version != 5 or command != 1:
            await self._send_failure(writer, 0x07)
            return None

        # Build the full request data to echo back in success response
        request_data = bytearray(request)

        try:
            if address_type == 1:
                raw_address = await reader.readexactly(4)
                hostname = socket.inet_ntoa(raw_address)
                request_data.extend(raw_address)
            elif address_type == 3:
                length = await reader.readexactly(1)
                raw_address = await reader.readexactly(length[0])
                hostname = raw_address.decode("utf-8")
                request_data.extend(length)
                request_data.extend(raw_address)
            elif address_type == 4:
                raw_address = await reader.readexactly(16)
                hostname = socket.inet_ntop(socket.AF_INET6, raw_address)
                request_data.extend(raw_address)
            else:
                await self._send_failure(writer, 0x08)
                return None

            raw_port = await reader.readexactly(2)
            port = struct.unpack(">H", raw_port)[0]
            request_data.extend(raw_port)
        except asyncio.IncompleteReadError:
            return None

        if port <= 0 or port > 65535:
            await self._send_failure(writer, 0x09)
            return None

        return hostname, port, bytes(request_data)

    async def _bridge_streams(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        websocket: WebSocketClientProtocol,
        upstream_source: str,
        original_hostname: str,
        port: int
    ) -> Optional[WebSocketClientProtocol]:
        active_ws = websocket
        active_source = upstream_source
        handshake_state = self._HandshakeState(self.replay_buffer_bytes)
        fallback_used = active_source != "worker"

        client_task = asyncio.create_task(reader.read(65536), name=f"client-{original_hostname}")
        upstream_task = asyncio.create_task(active_ws.recv(), name=f"upstream-{original_hostname}")

        async def switch_to_relay(reason: str) -> None:
            nonlocal active_ws, active_source, fallback_used, client_task, upstream_task

            if fallback_used:
                raise TunnelSetupError(reason)
            if not self.relay_enabled:
                raise TunnelSetupError(reason)

            # Get any buffered data (might be empty if worker closed before client sent anything)
            replay_segments = handshake_state.consume()

            old_client_task = client_task
            old_upstream_task = upstream_task

            if old_client_task and not old_client_task.done():
                old_client_task.cancel()
                with contextlib.suppress(Exception):
                    await old_client_task

            if old_upstream_task and not old_upstream_task.done():
                old_upstream_task.cancel()
                with contextlib.suppress(Exception):
                    await old_upstream_task

            with contextlib.suppress(Exception):
                await active_ws.close()

            active_ws = await self._connect_relay(original_hostname, port)
            
            # Replay any buffered data (if any)
            if replay_segments:
                for segment in replay_segments:
                    if segment:
                        await active_ws.send(segment)
                print(f"{self.name}: retry via relay ({reason}) for {original_hostname}:{port} with {sum(len(s) for s in replay_segments)} bytes buffered")
            else:
                print(f"{self.name}: retry via relay ({reason}) for {original_hostname}:{port} - fresh connection, no buffered data")

            active_source = "relay"
            fallback_used = True
            client_task = asyncio.create_task(reader.read(65536), name=f"client-{original_hostname}")
            upstream_task = asyncio.create_task(active_ws.recv(), name=f"upstream-{original_hostname}")

        try:
            while True:
                done, _ = await asyncio.wait(
                    [client_task, upstream_task],
                    return_when=asyncio.FIRST_COMPLETED
                )

                client_done = client_task in done
                upstream_done = upstream_task in done

                # Always handle upstream-side events first. This ensures that
                # early worker closes trigger relay failover even when the
                # client hasn't sent data yet (browser behavior).
                if upstream_done:
                    try:
                        message = upstream_task.result()
                    except (ConnectionClosed, OSError, asyncio.IncompleteReadError, Exception) as exc:
                        # Catch-all: any connection failure before handshake = retry via relay
                        if (
                            active_source == "worker"
                            and not handshake_state.confirmed
                            and self.relay_enabled
                        ):
                            # If the client already had data ready in this iteration,
                            # capture it into the handshake buffer so it can be replayed
                            # after switching to the relay.
                            if client_done:
                                try:
                                    if client_task.exception() is None:
                                        _buf = client_task.result()
                                        if _buf:
                                            handshake_state.record(_buf)
                                except Exception:
                                    pass
                            try:
                                reason = f"worker connection lost: {type(exc).__name__}"
                                await switch_to_relay(reason)
                                continue
                            except TunnelSetupError as fallback_exc:
                                raise fallback_exc from exc
                        if handshake_state.confirmed:
                            break
                        raise TunnelSetupError(f"Upstream connection failed: {exc}") from exc

                    # Normal upstream message path
                    if isinstance(message, str):
                        payload = None
                        if not handshake_state.confirmed:
                            control = self._parse_control_frame(message)
                            if control:
                                ctrl_type = control.get("type")
                                reason = control.get("message") or control.get("code") or "Upstream reported error"
                                if ctrl_type == "error":
                                    if active_source == "worker" and not fallback_used:
                                        try:
                                            await switch_to_relay(reason)
                                            continue
                                        except TunnelSetupError as fallback_exc:
                                            raise fallback_exc
                                    raise TunnelSetupError(reason)
                                if ctrl_type == "ready":
                                    upstream_task = asyncio.create_task(active_ws.recv(), name=f"upstream-{original_hostname}")
                                    # Continue to also process client-side readiness in the same iteration
                                    # (do not 'continue' here).
                                else:
                                    # Ignore unknown control frames before handshake completion
                                    upstream_task = asyncio.create_task(active_ws.recv(), name=f"upstream-{original_hostname}")
                                # Fall through to client processing if any
                                
                        else:
                            payload = message.encode("utf-8")
                    else:
                        payload = message

                    if payload:
                        handshake_state.mark_established()
                        try:
                            writer.write(payload)
                            await writer.drain()
                        except Exception as exc:
                            raise TunnelSetupError("Failed to forward upstream data to client") from exc
                    # Re-arm upstream task if we didn't switch to relay
                    if active_ws is not None:
                        upstream_task = asyncio.create_task(active_ws.recv(), name=f"upstream-{original_hostname}")

                if client_done:
                    # Check for task exception
                    if client_task.exception() is not None and not isinstance(client_task.exception(), (asyncio.CancelledError,)):
                        exc = client_task.exception()
                        raise TunnelSetupError(f"Client read error: {exc}") from exc
                    data = client_task.result()
                    if not data:
                        break
                    handshake_state.record(data)
                    try:
                        await active_ws.send(data)
                    except (ConnectionClosed, OSError, Exception) as exc:
                        # Catch-all: any send failure before handshake = retry via relay
                        if (
                            active_source == "worker"
                            and not handshake_state.confirmed
                            and self.relay_enabled
                        ):
                            try:
                                reason = f"worker send failed: {type(exc).__name__}"
                                await switch_to_relay(reason)
                                continue
                            except TunnelSetupError as fallback_exc:
                                raise fallback_exc from exc
                        if handshake_state.confirmed:
                            break
                        raise TunnelSetupError(f"Failed to send to upstream: {exc}") from exc
                    client_task = asyncio.create_task(reader.read(65536), name=f"client-{original_hostname}")
        finally:
            # Properly clean up tasks to avoid "exception never retrieved" warnings
            for task in (client_task, upstream_task):
                if not task.done():
                    task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                except Exception:
                    # Suppress exceptions from canceled tasks
                    pass

        return active_ws

    async def _send_failure(self, writer: asyncio.StreamWriter, code: int = 0x01) -> None:
        writer.write(b"\x05" + bytes([code]) + b"\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
        await writer.drain()

    async def _send_success(self, writer: asyncio.StreamWriter, request_data: bytes) -> None:
        # Send a minimal RFC 1928-compliant success reply.
        # For CONNECT, BND.ADDR/BND.PORT are the server-bound address; it's
        # acceptable to return IPv4 0.0.0.0:0, which is widely used and
        # compatible with Firefox/Chrome/curl.
        writer.write(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
        await writer.drain()

    async def _connect_upstream(
        self, 
        connect_hostname: str, 
        original_hostname: str, 
        port: int
    ) -> Tuple[WebSocketClientProtocol, str]:
        # Pre-detect Cloudflare destinations and configured CF hostnames.
        # If detected, prefer immediate relay to avoid CF->CF worker egress failures.
        try:
            # Match configured hostname patterns first
            if self._matches_cf_host(original_hostname.lower()):
                if self.relay_enabled:
                    print(f"{self.name}: pre-fallback to relay for {original_hostname}:{port} (hostname matches cf_hostnames)")
                    websocket = await self._connect_relay(original_hostname, port)
                    return websocket, "relay"
            # Resolve with DoH (if enabled) and check CF ranges without blocking the loop
            is_cf, resolved_ip = await asyncio.to_thread(
                check_if_cloudflare_ip,
                original_hostname,
                self.use_doh,
                self.doh_timeout,
            )
            if is_cf and self.relay_enabled:
                print(f"{self.name}: pre-fallback to relay for {original_hostname}:{port} (Target served by Cloudflare IP range)")
                websocket = await self._connect_relay(original_hostname, port)
                return websocket, "relay"
        except Exception:
            # Ignore detection errors and continue with normal flow
            pass

        # Try worker first (default path)
        try:
            websocket = await self._connect_worker(connect_hostname, port)
            return websocket, "worker"
        except WorkerFallbackRequired as exc:
            # Worker explicitly requested relay (e.g., CF IP detected)
            if not self.relay_enabled:
                raise TunnelSetupError(exc.reason)
            print(f"{self.name}: fallback to relay for {original_hostname}:{port} ({exc.reason})")
            websocket = await self._connect_relay(original_hostname, port)
            return websocket, "relay"

    async def _connect_worker(self, hostname: str, port: int) -> WebSocketClientProtocol:
        extra_headers = {}
        if self.auth_token:
            extra_headers["Authorization"] = self.auth_token

        try:
            websocket = await ws_connect(self.websocket_url, extra_headers=extra_headers, max_size=None)
        except Exception as exc:
            raise TunnelSetupError(f"Failed to open worker tunnel: {exc}") from exc

        try:
            await websocket.send(json.dumps({
                "hostname": hostname,
                "port": port,
                "password": self.socks_password
            }))
        except Exception as exc:
            with contextlib.suppress(Exception):
                await websocket.close()
            raise TunnelSetupError("Failed to transmit worker handshake") from exc

        control = await self._await_control_message(websocket)
        if control.get("type") == "ready":
            return websocket

        message = control.get("message") or control.get("code") or "Worker rejected connection"
        with contextlib.suppress(Exception):
            await websocket.close()

        if control.get("code") == "cloudflare-blocked":
            raise WorkerFallbackRequired(message)

        raise TunnelSetupError(message)

    async def _connect_relay(self, hostname: str, port: int) -> WebSocketClientProtocol:
        if not self.relay_enabled or not self.relay_url:
            raise TunnelSetupError("Relay not configured")

        extra_headers = {}
        if self.relay_auth_token:
            extra_headers["Authorization"] = self.relay_auth_token

        try:
            websocket = await ws_connect(self.relay_url, extra_headers=extra_headers, max_size=None)
        except Exception as exc:
            raise TunnelSetupError(f"Failed to open relay tunnel: {exc}") from exc

        try:
            await websocket.send(json.dumps({
                "hostname": hostname,
                "port": port,
                "password": self.relay_password
            }))
        except Exception as exc:
            with contextlib.suppress(Exception):
                await websocket.close()
            raise TunnelSetupError("Failed to transmit relay handshake") from exc

        control = await self._await_control_message(websocket)
        if control.get("type") == "ready":
            return websocket

        message = control.get("message") or control.get("code") or "Relay rejected connection"
        with contextlib.suppress(Exception):
            await websocket.close()
        raise TunnelSetupError(message)

    async def _await_control_message(self, websocket: WebSocketClientProtocol) -> Dict:
        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=self.handshake_timeout)
        except asyncio.TimeoutError as exc:
            raise TunnelSetupError("Timed out waiting for upstream acknowledgement") from exc
        except Exception as exc:
            raise TunnelSetupError("Upstream channel closed during handshake") from exc

        if isinstance(raw, (bytes, bytearray, memoryview)):
            raise TunnelSetupError("Unexpected binary response from upstream")

        try:
            data = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise TunnelSetupError("Invalid control response from upstream") from exc

        if not isinstance(data, dict):
            raise TunnelSetupError("Malformed control response from upstream")

        return data

    def _matches_cf_host(self, hostname: str) -> bool:
        """Check if hostname matches configured Cloudflare hostname patterns."""
        if not self.cf_hostnames:
            return False

        for entry in self.cf_hostnames:
            if hostname == entry:
                return True
            if entry.startswith("*.") and hostname.endswith(entry[1:]):
                return True
        return False


class SocksServerGroup:
    def __init__(self, servers: List[LocalSocksServer]):
        self.servers = servers

    def summary(self) -> List[Tuple[str, str, int]]:
        report = []
        for server in self.servers:
            if server.port is not None:
                report.append((server.name, server.bind_host, server.port))
        return report

    async def close(self) -> None:
        await asyncio.gather(*(server.close() for server in self.servers), return_exceptions=True)


class FlareProx:
    """Main FlareProx manager class."""

    def __init__(self, config_file: Optional[str] = None):
        self._config_path = None
        self._config_dirty = False
        self.config = self._load_config(config_file)
        self.worker_settings = self._prepare_worker_settings(self.config.get("worker", {}))
        self.client_settings = self._prepare_client_settings(self.config.get("client", {}))
        self.config["worker"] = self.worker_settings
        self.config["client"] = self.client_settings
        self.cloudflare = self._setup_cloudflare()
        self.endpoints_file = "flareprox_endpoints.json"
        self._ensure_config_file_exists()

        if self._config_dirty:
            self._persist_config()

    def _load_config(self, config_file: Optional[str] = None) -> Dict:
        """Load configuration from file."""
        config = {"cloudflare": {}, "worker": {}, "client": {}}

        # Try specified config file
        if config_file and os.path.exists(config_file):
            self._config_path = config_file
            config = self._load_config_file(config_file, config)

        # Try default config files
        default_configs = [
            "flareprox.json",
            "cloudproxy.json",  # Legacy support
            os.path.expanduser("~/.flareprox.json")
        ]

        for default_config in default_configs:
            if os.path.exists(default_config):
                if not self._config_path:
                    self._config_path = default_config
                config = self._load_config_file(default_config, config)
                break

        if not self._config_path:
            self._config_path = config_file or "flareprox.json"

        return config

    def _load_config_file(self, config_path: str, config: Dict) -> Dict:
        """Load configuration from a JSON file."""
        try:
            with open(config_path, 'r') as f:
                file_config = json.load(f)

            if "cloudflare" in file_config:
                config["cloudflare"].update(file_config["cloudflare"])

            if "worker" in file_config and isinstance(file_config["worker"], dict):
                config["worker"].update(file_config["worker"])

            if "client" in file_config and isinstance(file_config["client"], dict):
                config["client"].update(file_config["client"])
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load config file {config_path}: {e}")

        return config

    def _setup_cloudflare(self) -> Optional[CloudflareManager]:
        """Setup Cloudflare manager if credentials are available."""
        cf_config = self.config.get("cloudflare", {})
        api_token = cf_config.get("api_token")
        account_id = cf_config.get("account_id")

        if api_token and account_id:
            return CloudflareManager(
                api_token=api_token,
                account_id=account_id,
                zone_id=cf_config.get("zone_id"),
                worker_settings=self.worker_settings
            )
        return None

    def _ensure_config_file_exists(self) -> None:
        """Create a default config file if none exists."""
        config_files = ["flareprox.json", os.path.expanduser("~/.flareprox.json")]

        # Check if any config file exists
        config_exists = any(os.path.exists(f) for f in config_files)

        if not config_exists:
            # Don't create a default config automatically
            # Let the user run 'python3 flareprox.py config' to set up
            pass

    def _persist_config(self) -> None:
        if not self._config_path:
            return

        try:
            with open(self._config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not update config file {self._config_path}: {e}")
        finally:
            self._config_dirty = False

    def _generate_secret(self, size: int = 24) -> str:
        return secrets.token_urlsafe(size)

    def _prepare_worker_settings(self, worker_config: Dict) -> Dict:
        settings = dict(worker_config or {})
        updated = False

        if "mode" not in settings:
            settings["mode"] = "http"  # default behavior matches original project
            updated = True

        if not settings.get("socks_password"):
            settings["socks_password"] = self._generate_secret()
            print("Generated worker SOCKS password for this session. Update your config to persist it.")
            updated = True

        if "auth_token" not in settings:
            settings["auth_token"] = ""
            updated = True

        if not settings.get("compatibility_date"):
            settings["compatibility_date"] = "2023-09-04"
            updated = True

        flags = settings.get("compatibility_flags")
        if not isinstance(flags, list) or not flags:
            settings["compatibility_flags"] = ["nodejs_compat"]
            updated = True

        if updated:
            self._config_dirty = True

        return settings

    def _prepare_client_settings(self, client_config: Dict) -> Dict:
        settings = dict(client_config or {})
        updated = False

        if "bind_host" not in settings:
            settings["bind_host"] = "127.0.0.1"
            updated = True

        if "base_port" not in settings:
            settings["base_port"] = 1080
            updated = True

        if "profiles" not in settings:
            settings["profiles"] = []  # reserved for future multi-client support
            updated = True

        if "auto_random_ports" not in settings:
            settings["auto_random_ports"] = True
            updated = True

        if "cf_override_ip" not in settings:
            settings["cf_override_ip"] = ""
            updated = True

        if "cf_hostnames" not in settings:
            settings["cf_hostnames"] = []
            updated = True

        if "handshake_timeout" not in settings:
            settings["handshake_timeout"] = 5.0
            updated = True

        if "use_doh" not in settings:
            settings["use_doh"] = True  # Enable DoH by default
            updated = True

        if "doh_timeout" not in settings:
            settings["doh_timeout"] = 5.0
            updated = True

        relay_cfg = settings.get("relay")
        if not isinstance(relay_cfg, dict):
            settings["relay"] = {
                "enabled": False,
                "url": "",
                "auth_token": "",
                "socks_password": ""
            }
            updated = True
        else:
            defaults = {
                "enabled": False,
                "url": "",
                "auth_token": "",
                "socks_password": ""
            }
            for key, value in defaults.items():
                if key not in relay_cfg:
                    relay_cfg[key] = value
                    updated = True

        if updated:
            self._config_dirty = True

        return settings

    @property
    def is_configured(self) -> bool:
        """Check if FlareProx is properly configured."""
        return self.cloudflare is not None

    def _save_endpoints(self, endpoints: List[Dict]) -> None:
        """Save endpoints to local file."""
        try:
            with open(self.endpoints_file, 'w') as f:
                json.dump(endpoints, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save endpoints: {e}")

    def _load_endpoints(self) -> List[Dict]:
        """Load endpoints from local file."""
        if os.path.exists(self.endpoints_file):
            try:
                with open(self.endpoints_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return []

    def _merge_and_save_endpoints(self, new_entries: List[Dict]) -> None:
        if not new_entries:
            return

        existing = {entry.get("name"): entry for entry in self._load_endpoints() if entry.get("name")}

        for entry in new_entries:
            name = entry.get("name")
            if not name:
                continue
            if name in existing:
                existing[name].update(entry)
            else:
                existing[name] = entry

        self._save_endpoints(list(existing.values()))

    def _prepare_endpoint_for_client(self, endpoint: Dict) -> Dict:
        prepared = dict(endpoint)
        prepared.setdefault("auth_token", self.worker_settings.get("auth_token", ""))
        prepared.setdefault("socks_password", self.worker_settings.get("socks_password", ""))
        return prepared

    def _select_endpoints_for_client(self, limit: Optional[int] = None) -> List[Dict]:
        endpoints = self._load_endpoints()
        if limit and limit > 0:
            endpoints = endpoints[:limit]
        return [self._prepare_endpoint_for_client(endpoint) for endpoint in endpoints]

    def run_socks_servers(
        self,
        endpoints: List[Dict],
        bind_host: Optional[str] = None,
        base_port: Optional[int] = None,
        auto_random: Optional[bool] = None
    ) -> None:
        if not endpoints:
            print("No endpoints available to start SOCKS servers.")
            return

        host = bind_host or self.client_settings.get("bind_host")
        random_ports = self.client_settings.get("auto_random_ports", True) if auto_random is None else auto_random
        start_port = base_port if base_port is not None else self.client_settings.get("base_port")

        prepared = [self._prepare_endpoint_for_client(endpoint) for endpoint in endpoints]

        try:
            asyncio.run(self._run_socks_servers(prepared, host, start_port, random_ports))
        except KeyboardInterrupt:
            print("\nStopped local SOCKS proxies.")

    async def _run_socks_servers(
        self,
        endpoints: List[Dict],
        bind_host: str,
        base_port: Optional[int],
        auto_random: bool
    ) -> None:
        servers: List[LocalSocksServer] = []
        group: Optional[SocksServerGroup] = None
        try:
            for index, endpoint in enumerate(endpoints):
                port_hint: Optional[int]
                if auto_random:
                    port_hint = None
                else:
                    start = base_port if base_port is not None else 0
                    port_hint = start + index

                server = LocalSocksServer(endpoint, self.worker_settings, self.client_settings, bind_host)
                await server.start(port_hint)
                servers.append(server)

            group = SocksServerGroup(servers)
            self._print_socks_summary(group)

            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                pass
        finally:
            if group:
                await group.close()
            elif servers:
                await SocksServerGroup(servers).close()

    def _print_socks_summary(self, group: SocksServerGroup) -> None:
        print("\nLocal SOCKS proxies:")
        for name, host, port in group.summary():
            print(f"  {name}: socks5://{host}:{port}")
        print("Press Ctrl+C to stop.\n")

    def sync_endpoints(self) -> List[Dict]:
        """Sync local endpoints with remote deployments."""
        if not self.cloudflare:
            return []

        try:
            remote_endpoints = self.cloudflare.list_deployments()
            local_map = {endpoint.get("name"): endpoint for endpoint in self._load_endpoints() if endpoint.get("name")}

            merged = []
            for endpoint in remote_endpoints:
                name = endpoint.get("name")
                if name and name in local_map:
                    extra = local_map[name]
                    combined = {**extra, **endpoint}
                    merged.append(combined)
                else:
                    merged.append(endpoint)

            self._save_endpoints(merged)
            return merged
        except FlareProxError as e:
            print(f"Warning: Could not sync endpoints: {e}")
            return self._load_endpoints()

    def create_proxies(self, count: int = 1) -> Dict:
        """Create proxy endpoints."""
        if not self.cloudflare:
            raise FlareProxError("FlareProx not configured")

        print(f"\nCreating {count} FlareProx endpoint{'s' if count != 1 else ''}...")

        results = {"created": [], "failed": 0}

        for i in range(count):
            try:
                endpoint = self.cloudflare.create_deployment()
                results["created"].append(endpoint)
                print(f"  [{i+1}/{count}] {endpoint['name']} -> {endpoint['url']}")
            except FlareProxError as e:
                print(f"  Failed to create endpoint {i+1}: {e}")
                results["failed"] += 1

        # Update local cache
        self._merge_and_save_endpoints(results["created"])
        self.sync_endpoints()

        total_created = len(results["created"])
        print(f"\nCreated: {total_created}, Failed: {results['failed']}")

        return results

    def list_proxies(self) -> List[Dict]:
        """List all proxy endpoints."""
        endpoints = self.sync_endpoints()

        if not endpoints:
            print("No FlareProx endpoints found")
            print("Create some with: python3 flareprox.py create")
            return []

        print(f"\nFlareProx Endpoints ({len(endpoints)} total):")
        print("-" * 80)
        print(f"{'Name':<35} {'URL':<40} {'Status':<8}")
        print("-" * 80)

        for endpoint in endpoints:
            name = endpoint.get("name", "unknown")
            url = endpoint.get("url", "unknown")
            print(f"{name:<35} {url:<40} {'Active':<8}")

        return endpoints


    def test_proxies(self, target_url: str = "https://ifconfig.me/ip", method: str = "GET") -> Dict:
        """Test proxy endpoints and show IP addresses."""
        endpoints = self._load_endpoints()

        if not endpoints:
            print("No proxy endpoints available. Create some first.")
            return {"success": False, "error": "No endpoints available"}

        results = {}
        successful = 0
        unique_ips = set()

        print(f"Testing {len(endpoints)} FlareProx endpoint(s) with {target_url}")

        for endpoint in endpoints:
            name = endpoint.get("name", "unknown")
            print(f"\nTesting endpoint: {name}")

            # Try multiple attempts with different delay
            max_retries = 2
            success = False
            result = None

            for attempt in range(max_retries):
                try:
                    # Add small delay between retries
                    if attempt > 0:
                        time.sleep(1)
                        print(f"   Retry {attempt}...")

                    test_url = f"{endpoint['url']}?url={target_url}"
                    response = requests.request(method, test_url, timeout=30)

                    result = {
                        "success": response.status_code == 200,
                        "status_code": response.status_code,
                        "response_length": len(response.content),
                        "headers": dict(response.headers)
                    }

                    if response.status_code == 200:
                        success = True
                        print(f"Request successful! Status: {result['status_code']}")

                        # Try to extract and show IP address from response
                        try:
                            response_text = response.text.strip()
                            if target_url in ["https://ifconfig.me/ip", "https://httpbin.org/ip"]:
                                if target_url == "https://httpbin.org/ip":
                                    # httpbin returns JSON
                                    data = response.json()
                                    if 'origin' in data:
                                        ip_address = data['origin']
                                        print(f"   Origin IP: {ip_address}")
                                        unique_ips.add(ip_address)
                                else:
                                    # ifconfig.me returns plain text IP
                                    if response_text and len(response_text) < 100:
                                        print(f"   Origin IP: {response_text}")
                                        unique_ips.add(response_text)
                                    else:
                                        print(f"   Response: {response_text[:100]}...")
                            else:
                                print(f"   Response Length: {result['response_length']} bytes")
                        except Exception as e:
                            print(f"   Response Length: {result['response_length']} bytes")

                        successful += 1
                        break  # Success, no need to retry

                    elif response.status_code == 503:
                        print(f"   Server unavailable (503) - target service may be overloaded")
                        if attempt < max_retries - 1:
                            continue  # Retry
                    else:
                        print(f"Request failed! Status: {response.status_code}")
                        break  # Don't retry for other status codes

                except requests.RequestException as e:
                    if attempt < max_retries - 1:
                        print(f"   Connection error, retrying...")
                        continue
                    else:
                        print(f"Request failed: {e}")
                        result = {"success": False, "error": str(e)}
                        break
                except Exception as e:
                    print(f"Test failed: {e}")
                    result = {"success": False, "error": str(e)}
                    break

            results[name] = result if result else {"success": False, "error": "Unknown error"}

        print(f"\nTest Results:")
        print(f"   Working endpoints: {successful}/{len(endpoints)}")
        if successful < len(endpoints):
            failed_count = len(endpoints) - successful
            print(f"   Failed endpoints: {failed_count} (may be due to target service issues)")
        if unique_ips:
            print(f"   Unique IP addresses: {len(unique_ips)}")
            for ip in sorted(unique_ips):
                print(f"      - {ip}")

        return results

    def cleanup_all(self) -> None:
        """Delete all proxy endpoints."""
        if not self.cloudflare:
            raise FlareProxError("FlareProx not configured")

        print(f"\nCleaning up FlareProx endpoints...")

        try:
            self.cloudflare.cleanup_all()
        except FlareProxError as e:
            print(f"Failed to cleanup: {e}")

        # Clear local cache
        if os.path.exists(self.endpoints_file):
            try:
                os.remove(self.endpoints_file)
            except OSError:
                pass


def setup_interactive_config() -> bool:
    """Interactive setup for Cloudflare credentials."""
    print("Getting Cloudflare Credentials:")
    print("1. Sign up at https://cloudflare.com")
    print("2. Go to https://dash.cloudflare.com/profile/api-tokens")
    print("3. Click Create Token and use the 'Edit Cloudflare Workers' template")
    print("4. Set the 'account resources' and 'zone resources' to all. Click 'Continue to Summary'")
    print("5. Click 'Create Token' and copy the token and your Account ID from the dashboard")
    print()

    # Get API token
    api_token = getpass.getpass("Enter your Cloudflare API token: ").strip()
    if not api_token:
        print("API token is required")
        return False

    # Get account ID
    account_id = input("Enter your Cloudflare Account ID: ").strip()
    if not account_id:
        print("Account ID is required")
        return False

    # Create config
    config = {
        "cloudflare": {
            "api_token": api_token,
            "account_id": account_id
        }
    }

    # Save config file (overwrite if exists)
    config_path = "flareprox.json"
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"\nConfiguration saved to {config_path}")
        print("FlareProx is now configured and ready to use!")
        return True
    except IOError as e:
        print(f"Error saving configuration: {e}")
        return False


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(description="FlareProx - Simple URL Redirection via Cloudflare Workers")

    parser.add_argument("command", nargs='?',
                       choices=["create", "list", "test", "cleanup", "help", "config", "socks"],
                       help="Command to execute")

    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("--count", type=int, help="Number of proxies to create or use")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--bind", help="Bind address for local SOCKS proxies")
    parser.add_argument("--start-port", type=int, help="Starting port for local SOCKS proxies")

    return parser


def show_help_message() -> None:
    """Display the main help message."""
    print("FlareProx - Simple URL Redirection via Cloudflare Workers")
    print("\nUsage: python3 flareprox.py <command> [options]")
    print("\nCommands:")
    print("  config    Show configuration help and setup")
    print("  create    Create new proxy endpoints")
    print("  list      List all proxy endpoints")
    print("  test      Test proxy endpoints and show IP addresses")
    print("  socks     Start local SOCKS proxy server(s)")
    print("  cleanup   Delete all proxy endpoints")
    print("  help      Show detailed help")
    print("\nExamples:")
    print("  python3 flareprox.py config")
    print("  python3 flareprox.py create --count 2")
    print("  python3 flareprox.py test")
    print("  python3 flareprox.py test --url https://httpbin.org/ip")
    print("  python3 flareprox.py socks --bind 127.0.0.1")


def show_config_help() -> None:
    """Display configuration help and interactive setup."""
    print("FlareProx Configuration")
    print("=" * 40)

    # Check if already configured with valid credentials
    config_files = ["flareprox.json", os.path.expanduser("~/.flareprox.json")]
    valid_config_found = False
    existing_config_files = []

    for config_file in config_files:
        if os.path.exists(config_file):
            existing_config_files.append(config_file)
            try:
                with open(config_file, 'r') as f:
                    config_data = json.load(f)
                    cf_config = config_data.get("cloudflare", {})
                    api_token = cf_config.get("api_token", "").strip()
                    account_id = cf_config.get("account_id", "").strip()

                    # Check if we have actual credentials (not empty or placeholder)
                    if (api_token and account_id and
                        api_token not in ["", "your_cloudflare_api_token_here"] and
                        account_id not in ["", "your_cloudflare_account_id_here"] and
                        len(api_token) > 10 and len(account_id) > 10):
                        valid_config_found = True
                        break
            except (json.JSONDecodeError, IOError):
                continue

    if valid_config_found:
        print(f"\nFlareProx is already configured with valid credentials.")
        print("Configuration files found:")
        for config_file in existing_config_files:
            print(f"  - {config_file}")
        print()

        choice = input("Do you want to reconfigure? (y/n): ").lower().strip()
        if choice != 'y':
            return

    elif existing_config_files:
        print(f"\nConfiguration files exist but appear to contain placeholder values:")
        for config_file in existing_config_files:
            print(f"  - {config_file}")
        print()

    print("Setting up FlareProx configuration...")
    print()

    if setup_interactive_config():
        print("\nYou can now use FlareProx:")
        print("  python3 flareprox.py create --count 2")
        print("  python3 flareprox.py test")
    else:
        print("\nConfiguration failed. Please try again.")


def show_detailed_help() -> None:
    """Display detailed help information."""
    print("FlareProx - Detailed Help")
    print("=" * 30)
    print("\nFlareProx provides simple URL redirection through Cloudflare Workers.")
    print("All traffic sent to your FlareProx endpoints will be redirected to")
    print("the target URL you specify, supporting all HTTP methods.")
    print("\nFeatures:")
    print("- Support for all HTTP methods (GET, POST, PUT, DELETE, etc.)")
    print("- Automatic CORS headers")
    print("- IP masking through Cloudflare's global network")
    print("- Simple URL-based redirection")
    print("- Free tier: 100,000 requests/day")


def main():
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()

    # Show help if no command provided
    if not args.command:
        show_help_message()
        return

    if args.command == "config":
        show_config_help()
        return

    if args.command == "help":
        show_detailed_help()
        return

    # Initialize FlareProx
    try:
        flareprox = FlareProx(config_file=args.config)
    except Exception as e:
        print(f"Configuration error: {e}")
        return

    if not flareprox.is_configured:
        print("FlareProx not configured. Use 'python3 flareprox.py config' for setup.")
        return

    try:
        if args.command == "create":
            count = args.count if args.count and args.count > 0 else 1
            results = flareprox.create_proxies(count)

            if args.bind:
                created_endpoints = results.get("created", [])
                if created_endpoints:
                    auto_random = flareprox.client_settings.get("auto_random_ports", True)
                    if args.start_port is not None:
                        auto_random = False
                    flareprox.run_socks_servers(
                        created_endpoints,
                        bind_host=args.bind,
                        base_port=args.start_port,
                        auto_random=auto_random
                    )

        elif args.command == "list":
            flareprox.list_proxies()

        elif args.command == "test":
            if args.url:
                flareprox.test_proxies(args.url, args.method)
            else:
                flareprox.test_proxies()

        elif args.command == "socks":
            limit = args.count if args.count and args.count > 0 else None
            endpoints = flareprox._select_endpoints_for_client(limit)

            if not endpoints:
                print("No proxy endpoints available. Create some first.")
                return

            auto_random = flareprox.client_settings.get("auto_random_ports", True)
            if args.start_port is not None:
                auto_random = False

            flareprox.run_socks_servers(
                endpoints,
                bind_host=args.bind,
                base_port=args.start_port,
                auto_random=auto_random
            )

        elif args.command == "cleanup":
            confirm = input("Delete ALL FlareProx endpoints? (y/N): ")
            if confirm.lower() == 'y':
                flareprox.cleanup_all()
            else:
                print("Cleanup cancelled.")

    except FlareProxError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
