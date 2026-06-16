import os, base64
for name in ("RORSCHACH_SECRET_EVEN", "RORSCHACH_SECRET_ODD"):
    print(f'{name}={base64.urlsafe_b64encode(os.urandom(64)).decode().rstrip("=")}')

