#!/usr/bin/env python3
"""Anthropic's Messages API behind an OpenAI-compatible address, for review.py.

    ANTHROPIC_API_KEY=... python3 -I harness/anthropic_proxy.py PORT USAGE.ndjson

tangent's `openai` backend speaks chat completions, and Anthropic's own
OpenAI-compatible endpoint refuses adaptive thinking, which the reviewer runs
with. This takes tangent's request at http://127.0.0.1:PORT/v1, sends it to
/v1/messages (the request's `thinking` and `output_config` as they are, the
conversation cached), and gives the reply back as a chat completion.

A reply's thinking blocks must go back unchanged with its tool calls, and a
chat completion has no place for them, so each reply's blocks are kept here
under its tool calls' ids (or its text) and put back when the conversation
returns. One line a request goes to USAGE.ndjson: the model, the usage as
Anthropic counts it, the stop reason. Standard library only; the key is read
from the environment and never written."""
import hashlib
import http.server
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

KEY = os.environ.get("ANTHROPIC_API_KEY") or sys.exit("ANTHROPIC_API_KEY is not set")
PORT, USAGE = int(sys.argv[1]), sys.argv[2]
kept, lock = {}, threading.Lock()  # a reply's blocks, by what the conversation brings back


def text_of(content):
    if isinstance(content, str):
        return content
    return "".join(p.get("text", "") for p in content or [] if isinstance(p, dict))


def handle(m):
    return hashlib.sha256(text_of(m.get("content")).encode()).hexdigest()


def to_messages(body):
    system, out = [], []

    def add(role, blocks):
        if out and out[-1]["role"] == role:
            out[-1]["content"].extend(blocks)
        else:
            out.append({"role": role, "content": blocks})

    for m in body["messages"]:
        role = m["role"]
        if role == "system":
            system.append(text_of(m.get("content")))
        elif role == "user":
            add("user", [{"type": "text", "text": text_of(m.get("content"))}])
        elif role == "tool":
            add("user", [{"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": text_of(m.get("content"))}])
        elif role == "assistant":
            calls = m.get("tool_calls") or []
            with lock:
                blocks = kept.get(calls[0]["id"] if calls else handle(m))
            if blocks is None:
                blocks = [{"type": "text", "text": t}] if (t := text_of(m.get("content"))) else []
                blocks += [{"type": "tool_use", "id": c["id"], "name": c["function"]["name"],
                            "input": json.loads(c["function"]["arguments"] or "{}")} for c in calls]
            add("assistant", list(blocks))
    req = {"model": body["model"], "max_tokens": body.get("max_tokens") or 8000, "messages": out,
           "cache_control": {"type": "ephemeral"}}
    if system:
        req["system"] = "\n\n".join(system)
    if body.get("tools"):
        req["tools"] = [{"name": t["function"]["name"], "description": t["function"].get("description", ""),
                         "input_schema": t["function"].get("parameters") or {"type": "object"}} for t in body["tools"]]
    for k in ("thinking", "output_config"):
        if body.get(k) is not None:
            req[k] = body[k]
    return req


def ask(req):
    data = json.dumps(req).encode()
    for attempt in range(6):
        r = urllib.request.Request("https://api.anthropic.com/v1/messages", data=data, method="POST", headers={
            "content-type": "application/json", "x-api-key": KEY, "anthropic-version": "2023-06-01"})
        try:
            with urllib.request.urlopen(r, timeout=110) as resp:
                return 200, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            text = e.read().decode(errors="replace")
            if e.code in (429, 500, 502, 503, 529) and attempt < 5:
                time.sleep(min(float(e.headers.get("retry-after") or 2 ** attempt), 30))
                continue
            return e.code, text
        except OSError as e:
            if attempt < 5:
                time.sleep(2 ** attempt)
                continue
            return 502, str(e)


class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        status, reply = ask(to_messages(body))
        if status != 200:
            out = json.dumps({"error": {"message": reply[:2000], "type": "upstream", "code": status}}).encode()
        else:
            blocks = reply.get("content") or []
            text = "".join(b["text"] for b in blocks if b["type"] == "text")
            calls = [{"id": b["id"], "type": "function",
                      "function": {"name": b["name"], "arguments": json.dumps(b["input"])}} for b in blocks if b["type"] == "tool_use"]
            message = {"role": "assistant", "content": text or None}
            if calls:
                message["tool_calls"] = calls
            with lock:
                kept[calls[0]["id"] if calls else handle(message)] = blocks
            u = reply.get("usage") or {}
            with lock, open(USAGE, "a") as f:
                f.write(json.dumps({"model": reply.get("model"), "stop": reply.get("stop_reason"), "usage": u}) + "\n")
            read, wrote = u.get("cache_read_input_tokens") or 0, u.get("cache_creation_input_tokens") or 0
            prompt = (u.get("input_tokens") or 0) + read + wrote
            stop = {"tool_use": "tool_calls", "max_tokens": "length", "refusal": "content_filter"}.get(reply.get("stop_reason"), "stop")
            out = json.dumps({"id": reply.get("id"), "object": "chat.completion", "created": int(time.time()),
                              "model": reply.get("model"),
                              "choices": [{"index": 0, "finish_reason": stop, "message": message}],
                              "usage": {"prompt_tokens": prompt, "completion_tokens": u.get("output_tokens") or 0,
                                        "total_tokens": prompt + (u.get("output_tokens") or 0),
                                        "prompt_tokens_details": {"cached_tokens": read}}}).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
