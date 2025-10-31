#!/usr/bin/env python3
"""
xcash_node_probe.py

Probe an xcash node's ZMQ and HTTP RPC endpoints to help diagnose connectivity
or protocol mismatches.

Usage:
    python3 scripts/xcash_node_probe.py seed3.xcash.tech

    # Self-test mode (uses default host if not provided)
    python3 scripts/xcash_node_probe.py --self-test

Optional flags:
    --zmq-port 18282            ZMQ RPC port (default: 18282)
    --http-port 18281           HTTP JSON-RPC port (default: 18281)
    --timeout 15                Timeout in seconds for each request
    --get-blocks-fast           Send get_blocks_fast instead of get_hashes_fast over ZMQ
    --self-test                 Run a quick probe against the provided (or default) host
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from typing import Any, Dict, List

try:
    import zmq  # type: ignore
except ImportError:  # pragma: no cover - handled at runtime
    zmq = None  # type: ignore

try:
    import requests  # type: ignore
except ImportError:
    requests = None  # type: ignore


def probe_dns(host: str) -> Dict[str, Any]:
    """Resolve host to all available addresses."""
    result: Dict[str, Any] = {"host": host, "status": "ok", "addresses": [], "error": None}
    try:
        addresses: List[str] = []
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            addr = info[4][0]
            if addr not in addresses:
                addresses.append(addr)
        result["addresses"] = addresses
    except socket.gaierror as exc:
        result["status"] = "error"
        result["error"] = f"DNS lookup failed: {exc}"
    return result


def probe_zmq(host: str, port: int, timeout: float, method: str = "get_hashes_fast") -> Dict[str, Any]:
    """Send a JSON-RPC request over ZMQ RPC."""
    result: Dict[str, Any] = {
        "url": f"tcp://{host}:{port}",
        "status": "ok",
        "elapsed": None,
        "response": None,
        "error": None,
    }

    if zmq is None:
        result["status"] = "skipped"
        result["error"] = "pyzmq is not installed"
        return result

    method = method or "get_hashes_fast"

    if method == "get_hashes_fast":
        params: Dict[str, Any] = {
            "known_hashes": [GENESIS_HASH],
            "start_height": 0,
        }
    elif method == "get_blocks_fast":
        params = {
            "block_ids": [],
            "start_height": 1,
            "prune": True,
            "no_miner_tx": False
        }
    else:
        result["status"] = "error"
        result["error"] = f"Unsupported method: {method}"
        return result

    request_body = {
        "jsonrpc": "2.0",
        "id": "probe",
        "method": method,
        "params": params,
    }

    ctx = zmq.Context.instance()
    sock = ctx.socket(zmq.REQ)
    sock.linger = 0
    sock.rcvtimeo = int(timeout * 1000)
    sock.sndtimeo = int(timeout * 1000)

    try:
        sock.connect(result["url"])
        start = time.perf_counter()
        sock.send_string(json.dumps(request_body))
        reply = sock.recv_string()
        result["elapsed"] = round(time.perf_counter() - start, 3)
        result["response"] = reply
    except zmq.ZMQError as exc:  # pragma: no cover - runtime behaviour
        result["status"] = "error"
        result["error"] = f"ZMQError: {exc}"
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = f"Unexpected error: {exc}"
    finally:
        sock.close(0)

    return result


def sent_zmq_request(url: str, method: str, params: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {}

    request_body = {
        "jsonrpc": "2.0",
        "id": "0",
        "method": method,
        "params": params,
    }


    ctx = zmq.Context.instance()
    sock = ctx.socket(zmq.REQ)
    sock.linger = 0
    sock.rcvtimeo = int(timeout * 1000)
    sock.sndtimeo = int(timeout * 1000)

    try:
        sock.connect(url)
        start = time.perf_counter()
        sock.send_string(json.dumps(request_body))
        reply = sock.recv_string()
        result["elapsed"] = round(time.perf_counter() - start, 3)
        result["response"] = reply
    except zmq.ZMQError as exc:  # pragma: no cover - runtime behaviour
        result["status"] = "error"
        result["error"] = f"ZMQError: {exc}"
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = f"Unexpected error: {exc}"
    finally:
        sock.close(0)

    return result



def probe_http(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Send a get_info request via classic JSON-RPC over HTTP."""
    result: Dict[str, Any] = {
        "url": f"http://{host}:{port}/json_rpc",
        "status": "ok",
        "elapsed": None,
        "response": None,
        "error": None,
    }

    if requests is None:
        result["status"] = "skipped"
        result["error"] = "requests is not installed"
        return result

    payload = {
        "jsonrpc": "2.0",
        "id": "probe",
        "method": "get_info",
        "params": {},
    }

    try:
        start = time.perf_counter()
        response = requests.post(result["url"], json=payload, timeout=timeout)
        result["elapsed"] = round(time.perf_counter() - start, 3)
        result["response"] = {
            "status_code": response.status_code,
            "body": response.text[:3000],  # prevent huge output
        }
    except requests.RequestException as exc:  # type: ignore[union-attr]
        result["status"] = "error"
        result["error"] = f"RequestException: {exc}"
    return result


DEFAULT_TEST_HOST = "seed3.xcash.tech"
GENESIS_HASH = "557393c3e80695e94603e92b4dbf7a2b974c16cf12d1b470d2882916cbfee468"


def run_all_probes(
    host: str,
    zmq_port: int,
    http_port: int,
    timeout: float,
    zmq_method: str = "get_hashes_fast",
) -> Dict[str, Any]:
    """Run all available probes and return their raw results."""
    return {
        "dns": probe_dns(host),
        "zmq": probe_zmq(host, zmq_port, timeout, zmq_method),
        "http": probe_http(host, http_port, timeout),
    }


def get_blocks_fast(
    url: str,
    start_height: int = 1,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    block_ids: List[str] = [],

    params = {
        "block_ids": [],
        "start_height": start_height,
        "prune": False,
    }

    return sent_zmq_request(url, "get_blocks_fast", params, timeout)


def get_hashes_fast(
    url: str,
    hashes: List[str] = [GENESIS_HASH],
    start_height: int = 0,
    timeout: float = 5.0,
) -> Dict[str, Any]:

    params: Dict[str, Any] = {
        "known_hashes": hashes,
        "start_height": start_height,
    }

    return sent_zmq_request(url, "get_hashes_fast", params, timeout)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe xcash node RPC endpoints")
    parser.add_argument(
        "host",
        nargs="?",
        help="Hostname or IP of the node to test (optional when --self-test is used)",
    )
    parser.add_argument("--zmq-port", type=int, default=18282, help="ZMQ RPC port (default: 18282)")
    parser.add_argument("--http-port", type=int, default=18281, help="HTTP JSON-RPC port (default: 18281)")
    parser.add_argument("--timeout", type=float, default=45.0, help="Timeout for each request (seconds)")
    args = parser.parse_args(argv)

    host = args.host

    url = f"tcp://{host}:{args.zmq_port}"


    # result = get_hashes_fast(url)
    # response = json.loads(result['response'])
    # print(json.dumps(response, indent=2))


    # result = get_hashes_fast(url, start_height=99)
    # response = json.loads(result['response'])
    # print(json.dumps(response, indent=2))



    result = get_blocks_fast(url, 74000, args.timeout)
    response = json.loads(result['response'])
    with open("get_blocks_fast_74000.json", "w") as f:
        json.dump(response, f, indent=2)

    # Print the block count from the response
    if 'result' in response and 'blocks' in response['result']:
        block_count = len(response['result']['blocks'])
        print(f"Block count: {block_count}")
    else:
        print("No blocks found in response")
    # print(json.dumps(response, indent=2))
    return 0



if __name__ == "__main__":  # pragma: no cover - script entrypoint
    sys.exit(main())
