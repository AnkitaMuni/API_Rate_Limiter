"""
Core rate limiter logic using a Fixed Window algorithm.

Supports both a Redis backend (for distributed systems) and a local
memory fallback (for single-instance or development).
"""

import time
from typing import Dict, Any, Tuple

try:
    import redis
except ImportError:
    redis = None

UserData = Dict[str, Any]
ConfigData = Dict[str, int]
UserStateKey = Tuple[str, str]


class ConfigurableFixedWindowRateLimiter:
    """
    Fixed Window Rate Limiter with enhanced Redis backend for QC-5.

    Supports distributed counters with connection pooling and better
    error handling.
    """

    # pylint: disable=too-many-arguments, too-many-positional-arguments
    def __init__(
        self,
        configs: Dict[str, ConfigData],
        redis_url: str | None = None,
        redis_pool_size: int = 10,
        redis_socket_timeout: int = 5,
        redis_retry_on_timeout: bool = True,
    ):
        self.configs = configs
        self.user_data: Dict[UserStateKey, UserData] = {}

        self.redis_client = None
        if redis_url and redis:
            try:
                connection_pool = redis.ConnectionPool.from_url(
                    redis_url,
                    max_connections=redis_pool_size,
                    socket_timeout=redis_socket_timeout,
                    retry_on_timeout=redis_retry_on_timeout,
                    health_check_interval=30,
                    decode_responses=True,
                )
                self.redis_client = redis.Redis(connection_pool=connection_pool)

                self.redis_client.ping()
                print(f"Successfully connected to Redis backend: {redis_url}")
                print(
                    f"Redis pool size: {redis_pool_size}"
                    f"timeout: {redis_socket_timeout}s"
                )

            except redis.ConnectionError as e:
                print(f"Redis connection failed, falling back to local memory: {e}")
                self.redis_client = None
        elif redis_url and not redis:
            print(
                "Redis URL provided but 'redis' package not installed. "
                "Install with: pip install redis"
            )
            self.redis_client = None

        print("Rate Limiter Initialized with configurations:")
        for key, conf in self.configs.items():
            print(
                f"  - {key}: {conf['max_requests']} requests per "
                f"{conf['window_seconds']} seconds."
            )
        backend = (
            "Redis (Distributed)" if self.redis_client else "Local Memory"
        )
        print(f"  - Storage Backend: {backend}")

    def get_config(self, config_key: str) -> ConfigData:
        """
        Safely retrieves a configuration by key, providing a default.
        """
        config = self.configs.get(config_key)
        if not config:
            print(f"Warning: Missing config '{config_key}', using default.")
            return {"max_requests": 1, "window_seconds": 60}
        return config

    def _redis_key(self, user_id: str, config_key: str) -> str:
        """Generate Redis key with proper namespace"""
        return f"rate_limit:{user_id}:{config_key}"

    def allow_request(self, user_id: str, config_key: str) -> bool:
        """
        Checks if a request is allowed for a given user and config.

        Uses Redis backend if available, otherwise falls back to local memory.
        """
        config = self.get_config(config_key)
        max_requests = config["max_requests"]
        window_seconds = config["window_seconds"]

        if self.redis_client:
            try:
                key = self._redis_key(user_id, config_key)

                pipe = self.redis_client.pipeline()

                pipe.incr(key)
                pipe.ttl(key)
                results = pipe.execute()

                count = results[0]
                ttl = results[1]

                if ttl == -1:
                    self.redis_client.expire(key, window_seconds)

                return count <= max_requests

            except redis.RedisError as e:
                print(f"Redis error, falling back to local memory: {e}")
                self.redis_client = None

        current_time = time.time()
        user_state_key = (user_id, config_key)

        if user_state_key not in self.user_data:
            self.user_data[user_state_key] = {
                "count": 0,
                "window_start_time": current_time,
            }

        user_state = self.user_data[user_state_key]

        if current_time > user_state["window_start_time"] + window_seconds:
            user_state["count"] = 0
            user_state["window_start_time"] = current_time

        if user_state["count"] < max_requests:
            user_state["count"] += 1
            return True
        return False

    def get_user_status(self, user_id: str, config_key: str) -> tuple[int, int, float]:
        """
        Retrieves the current rate limit status for a user.

        Returns (current_count, max_requests, time_remaining_in_seconds)
        """
        config = self.get_config(config_key)
        max_requests = config["max_requests"]
        window_seconds = config["window_seconds"]

        if self.redis_client:
            try:
                key = self._redis_key(user_id, config_key)
                count_str = self.redis_client.get(key)
                count = int(count_str) if count_str else 0
                ttl = self.redis_client.ttl(key)

                retry_after = float(ttl if ttl > 0 else window_seconds)
                return (count, max_requests, retry_after)

            except redis.RedisError as e:
                print(
                    f"Redis error in get_user_status, falling back to local memory: {e}"
                )
                self.redis_client = None

        user_state_key = (user_id, config_key)
        state = self.user_data.get(
            user_state_key, {"count": 0, "window_start_time": time.time()}
        )
        time_remaining = max(
            0.0, (state["window_start_time"] + window_seconds) - time.time()
        )
        return (state["count"], max_requests, time_remaining)
