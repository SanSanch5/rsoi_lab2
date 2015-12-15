from pathlib import Path
from pydblite import Base

if not Path('db').exists():
    Path('db').mkdir()

client = Base('db/client.pdl')
if client.exists():
    client.open()
else:
    client.create('secret', 'redirect_uri', 'name')

authorization_code = Base('db/authorization_code.pdl')
if authorization_code.exists():
    authorization_code.open()
else:
    authorization_code.create('user_id', 'code', 'expire_time')

token = Base('db/token.pdl')
if token.exists():
    token.open()
else:
    token.create('user_id', 'access', 'expire_time', 'refresh')

user = Base('db/user.pdl')
if user.exists():
    user.open()
else:
    user.create('login', 'password_hash', 'name', 'email', 'phone')

clothes = Base('db/clothes.pdl')
if clothes.exists():
    clothes.open()
else:
    clothes.create('name', 'price')

order = Base('db/order.pdl')
if order.exists():
    order.open()
else:
    order.create('user_id', 'clothes', 'delivery_location', 'time_placed', 'time_delivered')

