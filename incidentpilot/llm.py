"""Groq OpenAI-compatible chat-completions adapter, testable without network."""
import json
import os
import httpx

class LLMUnavailable(RuntimeError):
    pass

class GroqLLM:
    def __init__(self, key=None, model=None, transport=None):
        self.key=key if key is not None else os.getenv('GROQ_API_KEY','')
        self.model=model or os.getenv('GROQ_MODEL','llama-3.3-70b-versatile')
        self.transport=transport

    async def complete(self,messages,tools=None):
        if not self.key:
            raise LLMUnavailable('GROQ_API_KEY is not configured; AI investigation not executed')
        payload={'model':self.model,'messages':messages,'temperature':0,'max_tokens':1200}
        if tools:
            payload['tools']=[{'type':'function','function':{'name':t['name'],'description':t['description'],
                                'parameters':t['inputSchema']}} for t in tools]
            payload['tool_choice']='auto'
        try:
            async with httpx.AsyncClient(timeout=35,transport=self.transport) as client:
                res=await client.post('https://api.groq.com/openai/v1/chat/completions',
                       headers={'Authorization':'Bearer '+self.key},json=payload)
            res.raise_for_status()
            return res.json()['choices'][0]['message']
        except (httpx.HTTPError,KeyError,IndexError,ValueError) as exc:
            raise LLMUnavailable('LLM provider call failed: '+type(exc).__name__) from exc

def parse_json(raw):
    text=raw or ''
    text=text.strip()
    if text.startswith('```'):
        text=text.split('\n',1)[-1].rsplit('```',1)[0].strip()
    try:
        data=json.loads(text)
    except ValueError as exc:
        raise LLMUnavailable('LLM did not return valid JSON') from exc
    if not isinstance(data,dict):
        raise LLMUnavailable('LLM response must be an object')
    return data
