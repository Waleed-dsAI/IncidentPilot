"""Minimal MCP JSON-RPC stdio transport: initialize, tools/list and tools/call.
No external SDK; intentionally limited to local subprocess, one JSON object per line.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

PROTOCOL = '2024-11-05'

class MCPError(Exception):
    pass

class LocalMCPClient:
    def __init__(self, email_case_id=None):
        self.email_case_id = email_case_id
        self.proc = None
        self.seq = 0

    async def __aenter__(self):
        env = dict(os.environ)
        if self.email_case_id is not None:
            env['MCP_EMAIL_CASE_ID']=str(self.email_case_id)
        root = str(Path(__file__).resolve().parent.parent)
        env['PYTHONPATH'] = os.pathsep.join(filter(None, [root, env.get('PYTHONPATH', '')]))
        self.proc = await asyncio.create_subprocess_exec(sys.executable, '-m', 'incidentpilot.mcp_server',
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, env=env)
        await self.request('initialize', {'protocolVersion': PROTOCOL, 'capabilities': {},
                            'clientInfo': {'name': 'IncidentPilot', 'version': '0.3'}})
        await self.notify('notifications/initialized', {})
        return self

    async def __aexit__(self, *_):
        if self.proc:
            if self.proc.stdin:
                self.proc.stdin.close()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()

    async def _send(self, payload):
        self.proc.stdin.write((json.dumps(payload) + '\n').encode())
        await self.proc.stdin.drain()

    async def notify(self, method, params):
        await self._send({'jsonrpc': '2.0', 'method': method, 'params': params})

    async def request(self, method, params=None):
        self.seq += 1
        req_id = self.seq
        await self._send({'jsonrpc': '2.0', 'id': req_id, 'method': method, 'params': params or {}})
        while True:
            try:
                raw = await asyncio.wait_for(self.proc.stdout.readline(), timeout=20)
            except asyncio.TimeoutError as exc:
                raise MCPError('MCP server response timeout') from exc
            if not raw:
                raise MCPError('MCP server disconnected')
            try:
                reply = json.loads(raw)
            except ValueError as exc:
                raise MCPError('Malformed MCP response') from exc
            if reply.get('id') != req_id:
                continue
            if 'error' in reply:
                raise MCPError(str(reply['error'].get('message', 'MCP tool error')))
            return reply.get('result', {})

    async def list_tools(self):
        return (await self.request('tools/list')).get('tools', [])

    async def call_tool(self, name, args):
        result = await self.request('tools/call', {'name': name, 'arguments': args})
        if result.get('isError'):
            raise MCPError('Tool failed: ' + str(result.get('content', []))[:350])
        texts = [p['text'] for p in result.get('content', []) if p.get('type') == 'text']
        if not texts:
            raise MCPError('Empty MCP tool response')
        try:
            return json.loads(texts[0])
        except ValueError:
            return {'text': texts[0]}
