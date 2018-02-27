# use Python 3.6 secrets package
import hashlib
import math
import secrets
import sys

# Create random hexadecimal token of default size (32 bytes, 64 hex digits)
token_hex = secrets.token_hex()
print( "token: " + token_hex + "; length = " + str( len( token_hex ) ) )

# convert to integer
token_int = int( token_hex, 16 )
print( "Default token int: " + str( token_int ) )

# get bit count
token_bit_count = token_int.bit_length()
print( "token bit count = " + str( token_bit_count ) )

# get byte count
token_byte_count = token_bit_count / 8
token_byte_count = math.ceil( token_byte_count )
token_byte_count = int( token_byte_count )
print( "token byte count = " + str( token_byte_count ) )

# convert to bytes
token_bytes = token_int.to_bytes( token_byte_count, byteorder = sys.byteorder )
print( "token bytes = " + str( token_bytes ) )

# hash to create salt value
salt_hash = hashlib.sha256( token_bytes )
salt = salt_hash.hexdigest()
print( "salt (not including quotation marks): \"" + str( salt ) + "\"; type = " + str( type( salt ) ) )