import sys
from pathlib import Path

domain = sys.argv[-2]
filename = sys.argv[-1]
public_key = Path(filename).read_text()
public_key = public_key.replace('-----BEGIN PUBLIC KEY-----', '')
public_key = public_key.replace('-----END PUBLIC KEY-----', '').replace('\n', '')
print('{} TXT v=em2key p={}'.format(domain, public_key))
