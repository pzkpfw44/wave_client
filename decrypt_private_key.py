import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from wave_api import derive_key

# Your username and password (must match those used to create your backup)
username = "testuser"
password = "test123"

# Paste your encrypted private key & salt from your backup JSON file here
encrypted_key_b64 = "YSY5PY0on3qERVJx90YbYC9ywUK7LJMO8qF86AIIGwAsHSe0M2X7iX0k8Oyhc-s1Onrhq8PdhC957nd27lDBJNpDyipzMDvIy6HETwGess3PBNPOvj3ndST7cM20VLYluOCJBQbwzljFAp_MEk4KzcoiKDESDdofUsJgH9KQWhtNaL9X5eMB0a4GONAyPqxQvp_MJmIKVSvCPBgRugCtZKbLvxwFWb7l_VdiI_I3i3MOsoXwvt9IlI25mm_N9pmrgMbo0hGHpYbtaDF_D8YR2SJUCC8VJrTERxaIkz1Wu8efH2hoNI6x2FpWh-BJZ1NMA8o0Q4mbdlIELsrzFLwT7cM7uDZDPZv6mgXxlHJZUCYFD9YGEbZBGf9m8128gJDkzEKDaU436X_pmz5vechQCMGJhLuvKglLCRcpuUGQoZPu1M"
salt_b64 = "dmNYSY5PY0on3qERVJx90Y=="

# Decode Base64
encrypted_key = base64.urlsafe_b64decode(encrypted_key_b64 + '==')
salt = base64.urlsafe_b64decode(salt + '==')

# Derive AES key using your password and salt
key = derive_key(password, salt)

# Decrypt your private key (salt is used as the nonce)
aesgcm = AESGCM(key)
try:
    private_key = aesgcm.decrypt(salt, encrypted_key, None)
    print("Your decrypted private key (Base64):")
    print(base64.urlsafe_b64encode(private_key).decode())
except Exception as e:
    print("Decryption error:", e)