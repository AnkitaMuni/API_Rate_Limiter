"""
A simple command-line script to monitor Redis keys with the
'rate_limit:' prefix in real-time.

Shows new keys, expired keys, and keys that are expiring soon.
"""

import os
import time

import redis

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
r = redis.Redis.from_url(redis_url)

print("Monitoring Redis rate limit keys... (Ctrl+C to stop)")

last_keys = set()

try:
    while True:
        current_keys = set(r.keys("rate_limit:*"))

        new_keys = current_keys - last_keys
        if new_keys:
            for key in new_keys:
                value = r.get(key)
                ttl = r.ttl(key)
                print(f"🆕 NEW KEY: {key.decode()} = {value.decode()} (TTL: {ttl}s)")

        expired_keys = last_keys - current_keys
        if expired_keys:
            for key in expired_keys:
                print(f"❌ EXPIRED: {key.decode()}")

        for key in current_keys:
            ttl = r.ttl(key)
            if 0 < ttl < 5:
                print(f"⚠️  EXPIRING SOON: {key.decode()} in {ttl}s")

        last_keys = current_keys
        time.sleep(2)

except KeyboardInterrupt:
    print("\nMonitoring stopped.")
