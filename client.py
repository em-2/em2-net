#!/usr/bin/env python3.6
import asyncio
import base64
import os
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
import click
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from em2.comms import encoding
from em2.comms.http.push import CT_HEADER
from em2.core import Verbs
from em2.core.components import hash_id, Components
from em2.utils import now_unix_secs, to_unix_ms

BASE_URL = os.getenv('CLIENT_BASE_URL', 'http://localhost:9001/')
CONN = aiohttp.TCPConnector(verify_ssl=False)
LOCAL_DOMAIN = 'em2.node8000.com'


class Caller:
    def __init__(self):
        self.command_lookup = {}
        self.session = None
        self.kwargs = None
        self.loop = asyncio.get_event_loop()

    def add_func(self, func):
        self.command_lookup[func.__name__] = func

    async def acall(self, func_name):
        async with aiohttp.ClientSession(connector=CONN) as session:
            self.session = session
            await self.command_lookup[func_name](self)

    def __call__(self, func_name, **kwargs):
        self.kwargs = kwargs
        self.loop.run_until_complete(self.acall(func_name))

    async def request(self, method, uri, *args, **kwargs):
        url = BASE_URL + uri
        print(f'{method}: {url}')
        func = {
            'get': self.session.get,
            'post': self.session.post,
        }[method.lower()]
        async with func(url, *args, **kwargs) as r:
            print(f'status: {r.status}')
            print('headers:')
            for k, v in r.headers.items():
                print(f'  {k:15}: {v}')
            ct = r.headers.get('Content-Type')
            if 'text/' in ct:
                content = await r.text()
                print(f'response: {content}')
            elif 'application/msgpack' in ct:
                content = await r.read()
                content = encoding.decode(content)
                print(f'response: {content}')
            else:
                content = await r.read()
                print(f'raw response: {content}')
        return content

    @property
    def name(self):
        return self._func.__name__

    async def get(self, uri, *args, **kwargs):
        return await self.request('get', uri, *args, **kwargs)

    async def post(self, uri, *args, **kwargs):
        return await self.request('post', uri, *args, **kwargs)


caller = Caller()


def command(func):
    caller.add_func(func)
    return func


@command
async def index(s):
    await s.get('')


@command
async def auth(s):
    timestamp = now_unix_secs()
    msg = '{}:{}'.format(LOCAL_DOMAIN, timestamp)
    h = SHA256.new(msg.encode())
    private_domain_key = Path('private8000.pem').read_text()
    key = RSA.importKey(private_domain_key)
    signer = PKCS1_v1_5.new(key)
    signature = base64.urlsafe_b64encode(signer.sign(h)).decode()
    auth_data = {
        'platform': LOCAL_DOMAIN,
        'timestamp': timestamp,
        'signature': signature,
    }
    return await s.post('authenticate', data=encoding.encode(auth_data), headers=CT_HEADER)


PUBLISH_KWARGS = {
    'creator': 'sender@node8000.com',
    'expiration': None,
    'messages': [
        {
            'author': 'sender@node8000.com',
            'body': 'this is the message',
            'id': '0cc69e92575798d4ba3418bdfe82a26ac0749b6',
            'parent': None,
            'timestamp': datetime(2017, 3, 19, 18, 19, 12, 742000, tzinfo=timezone.utc)
        }
    ],
    'participants': [
        ['sender@node8000.com', 'full'],
        ['samuel@node9000.com', 'write']
    ],
    'ref': 'foo bar',
    'status': 'active',
    'subject': 'foo bar'
}


@command
async def publish(s):
    response = await auth(s)
    verb = Verbs.ADD
    component = Components.CONVERSATIONS
    address = 'sender@node8000.com'
    ts = datetime.utcnow().replace(tzinfo=timezone.utc)
    conv = hash_id(address, to_unix_ms(ts), 'foo bar', sha256=True)
    data = {
        'address': address,
        'timestamp': ts,
        'event_id': hash_id(to_unix_ms(ts), address, conv, verb, component, None),
        'kwargs': {'data': PUBLISH_KWARGS},
    }
    url = f'{conv}/{component}/{verb}/'

    headers = dict(Authorization=response['key'], **CT_HEADER)
    await s.post(url, data=encoding.encode(data), headers=headers)


@click.command()
@click.argument('command', type=click.Choice(list(caller.command_lookup.keys())))
def cli(command, **kwargs):
    assert command in caller.command_lookup
    print(f'running {command}, kwargs = {kwargs}...')
    caller(command, **kwargs)


if __name__ == '__main__':
    cli()
