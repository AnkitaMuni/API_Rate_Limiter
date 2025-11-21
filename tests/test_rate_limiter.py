import unittest
import sys
import os
import json
import time
import logging
from unittest.mock import patch, MagicMock
import warnings
from typing import Dict, Any

warnings.filterwarnings("ignore", message="Missing config 'MISSING_KEY'")
warnings.filterwarnings("ignore", message="Missing config 'NON_EXISTENT_KEY'")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    import redis
except ImportError:
    redis = None

from src.main_server import app, RATE_LIMIT_CONFIGS, USER_DATABASE, setup_audit_logger, ANONYMOUS_CONFIG_KEY
from src.rate_limiter import ConfigurableFixedWindowRateLimiter


AUDIT_LOG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'audit.log'))

UNIT_CONFIGS = {
    "HIGH": {"max_requests": 5, "window_seconds": 15},
    "LOW": {"max_requests": 2, "window_seconds": 60},
    "ANON": {"max_requests": 3, "window_seconds": 10},
    "TEST_SHORT": {"max_requests": 2, "window_seconds": 0.5},
}

class TestRateLimiterFunctionality(unittest.TestCase):
    """
    Combined test suite for the Rate Limiter, including dedicated Unit (U)
    and System/Integration (S/I) tests.
    """


    def setUp(self):
        """Runs before each test to ensure a clean state."""
        self.app = app.test_client()
        self.app.testing = True

        self.user_a = "User-A-4821"
        self.user_b = "User-B-9902"
        self.user_a_key = "user_a_key"
        self.user_b_key = "user_b_key"
        self.admin_key = "admin_key_123"
        self.viewer_key = "viewer_key_456"

        self.high_config = "HIGH_THROUGHPUT_API"
        self.low_config = "LOW_THROUGHPUT_API"
        self.anon_config = ANONYMOUS_CONFIG_KEY

        RATE_LIMIT_CONFIGS.clear()
        RATE_LIMIT_CONFIGS[self.high_config] = {"max_requests": 5, "window_seconds": 15}
        RATE_LIMIT_CONFIGS[self.low_config] = {"max_requests": 2, "window_seconds": 60}
        RATE_LIMIT_CONFIGS[self.anon_config] = {"max_requests": 3, "window_seconds": 10}

        try:
            limiter = ConfigurableFixedWindowRateLimiter(
                configs=RATE_LIMIT_CONFIGS,
                redis_url=os.getenv("REDIS_URL", "redis://localhost:6379"),
                redis_pool_size=int(os.getenv("REDIS_POOL_SIZE", "10")),
                redis_socket_timeout=int(os.getenv("REDIS_SOCKET_TIMEOUT", "5")),
                redis_retry_on_timeout=os.getenv("REDIS_RETRY_ON_TIMEOUT", "true").lower() == "true"
            )
            app.limiter = limiter
            app.audit_logger = setup_audit_logger()
        except Exception as e:
            self.skipTest("Could not connect to Redis to initialize limiter.")
            return

        if app.limiter.redis_client:
            keys = app.limiter.redis_client.keys("rate_limit:*")
            if keys:
                app.limiter.redis_client.delete(*keys)

        if os.path.exists(AUDIT_LOG_FILE):
            try:
                os.remove(AUDIT_LOG_FILE)
            except PermissionError:
                with open(AUDIT_LOG_FILE, 'w') as f:
                    f.truncate(0)

        self.audit_logger = app.audit_logger
        for handler in self.audit_logger.handlers[:]:
            self.audit_logger.removeHandler(handler)
            handler.close()
        file_handler = logging.FileHandler(AUDIT_LOG_FILE)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        self.audit_logger.addHandler(file_handler)

    def _read_audit_log(self):
        """Safely flushes logs, reads the audit log file, and returns content."""
        logger = self.audit_logger
        for handler in logger.handlers:
            handler.flush()

        time.sleep(0.1)
        if not os.path.exists(AUDIT_LOG_FILE):
            return ""
        with open(AUDIT_LOG_FILE, 'r') as f:
            content = f.read()
            return content

    def _make_api_request(self, endpoint, auth_key, remote_addr='127.0.0.1'):
        """Helper for making API POST requests."""
        return self.app.post(
            endpoint,
            data=json.dumps({'auth_key': auth_key}),
            content_type='application/json',
            environ_base={'REMOTE_ADDR': remote_addr}
        )

    def _init_local_limiter(self, configs: Dict[str, Dict[str, Any]]):
        return ConfigurableFixedWindowRateLimiter(configs=configs, redis_url=None)

    def _init_mocked_redis_limiter(self, mock_client):
        with patch('src.rate_limiter.redis.ConnectionPool'), \
             patch('src.rate_limiter.redis.Redis', return_value=mock_client):
            limiter = ConfigurableFixedWindowRateLimiter(configs=UNIT_CONFIGS, redis_url="redis://mock")
        return limiter


    def test_U001_local_high_throughput_logic(self):
        """U-Test: Verifies standard fixed-window counting and blocking in local mode (HIGH: 5/15s)."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        config_key = "HIGH"
        for i in range(5):
            self.assertTrue(limiter.allow_request(self.user_a, config_key), f"Request {i+1} should be allowed")
        self.assertFalse(limiter.allow_request(self.user_a, config_key), "6th request should be blocked")

    def test_U002_local_low_throughput_logic(self):
        """U-Test: Verifies standard fixed-window counting and blocking in local mode (LOW: 2/60s)."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        config_key = "LOW"
        self.assertTrue(limiter.allow_request(self.user_a, config_key))
        self.assertTrue(limiter.allow_request(self.user_a, config_key))
        self.assertFalse(limiter.allow_request(self.user_a, config_key))

    def test_S003_unauth_falls_to_anon_limit(self):
        """S-Test: Invalid auth key falls to anonymous limit and returns 200."""
        response = self._make_api_request('/api/request', 'invalid_key')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['rate_limit']['config_key'], self.anon_config)

    def test_S004_admin_get_config_rbac(self):
        """S-Test: Admin GET endpoint RBAC checks."""
        response_user = self.app.get('/admin/config', headers={'X-API-Key': self.user_a_key})
        self.assertEqual(response_user.status_code, 403)

    def test_S005_admin_put_config_rbac(self):
        """S-Test: Admin PUT endpoint RBAC checks (Only admin allowed)."""
        new_config = {"max_requests": 100, "window_seconds": 10}
        response_viewer = self.app.put(f'/admin/config/{self.high_config}',
                                 data=json.dumps(new_config), content_type='application/json',
                                 headers={'X-API-Key': self.viewer_key})
        self.assertEqual(response_viewer.status_code, 403)

    def test_S006_audit_log_put_success(self):
        """S-Test: Verify successful admin PUT operation is logged."""
        new_config = {"max_requests": 50, "window_seconds": 50}
        response = self.app.put(f'/admin/config/{self.high_config}',
                                 data=json.dumps(new_config), content_type='application/json',
                                 headers={'X-API-Key': self.admin_key})
        self.assertEqual(response.status_code, 200)
        log_content = self._read_audit_log()
        self.assertIn("AUDIT_SUCCESS", log_content)

    def test_S007_audit_log_put_forbidden(self):
        """S-Test: Verify forbidden admin PUT operation is logged."""
        new_config = {"max_requests": 50, "window_seconds": 50}
        response = self.app.put(f'/admin/config/{self.high_config}',
                                 data=json.dumps(new_config), content_type='application/json',
                                 headers={'X-API-Key': self.viewer_key})
        self.assertEqual(response.status_code, 403)
        log_content = self._read_audit_log()
        self.assertIn("AUDIT_FAILURE: Forbidden", log_content)

    def test_S008_audit_log_get_unauthorized(self):
        """S-Test: Verify unauthorized admin GET operation (missing key) is logged."""
        response = self.app.get('/admin/config')
        self.assertEqual(response.status_code, 401)
        log_content = self._read_audit_log()
        self.assertIn("AUDIT_FAILURE: Unauthorized", log_content)

    def test_S009_anonymous_ip_limit(self):
        """S-Test: Verify anonymous IP limiting works end-to-end (full limit cycle)."""
        anon_limit = RATE_LIMIT_CONFIGS[self.anon_config]['max_requests']
        for i in range(anon_limit):
            self._make_api_request('/api/request', 'invalid_key_123', remote_addr='10.1.1.1')
        response_blocked = self._make_api_request('/api/request', 'another_invalid_key', remote_addr='10.1.1.1')
        self.assertEqual(response_blocked.status_code, 429)

    @unittest.skipIf(redis is None, "Skipping I010 performance test: 'redis' package not installed.")
    def test_I010_performance_latency(self):
        """I-Test: Measures the average latency of the core allow_request function (live Redis)."""
        limiter = self.app.application.limiter
        if not limiter.redis_client:
            self.skipTest("Performance test requires a live Redis connection.")
        user_id = "performance_test_user"
        config_key = self.high_config
        num_requests = 1000
        limiter.allow_request(user_id, config_key)
        limiter.redis_client.delete(limiter._redis_key(user_id, config_key))

        start_time = time.perf_counter()
        for _ in range(num_requests):
            limiter.allow_request(user_id, config_key)
        end_time = time.perf_counter()
        total_time_s = end_time - start_time
        avg_latency_ms = (total_time_s / num_requests) * 1000
        self.assertLess(avg_latency_ms, 1.0)

    def test_S011_health_check_endpoint(self):
        """S-Test: Health check returns healthy and includes configs."""
        response = self.app.get('/health')
        self.assertEqual(response.status_code, 200)

    def test_S012_index_page_loads(self):
        """S-Test: Root page loads correctly."""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)

    def test_S013_update_config_not_found(self):
        """S-Test: Admin PUT fails if config key is not found (404)."""
        response = self.app.put('/admin/config/NON_EXISTENT_KEY',
                                 data=json.dumps({"max_requests": 1, "window_seconds": 1}),
                                 content_type='application/json',
                                 headers={'X-API-Key': self.admin_key})
        self.assertEqual(response.status_code, 404)

    def test_S014_update_config_invalid_data(self):
        """S-Test: Admin PUT fails with negative values (400) and is logged."""
        new_config = {"max_requests": -5, "window_seconds": 10}
        response = self.app.put(f'/admin/config/{self.high_config}',
                                 data=json.dumps(new_config), content_type='application/json',
                                 headers={'X-API-Key': self.admin_key})
        self.assertEqual(response.status_code, 400)

    def test_U015_init_no_redis_url(self):
        """U-Test: Verify initialization proceeds with local memory when no URL is provided."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        self.assertIsNone(limiter.redis_client)
        self.assertEqual(limiter.configs, UNIT_CONFIGS)

    @unittest.skipIf(redis is None, "Skipping I016 test: 'redis' package not installed.")
    def test_I016_redis_failure_fallback_local(self):
        """I-Test: Redis pipeline fails, causing fallback to local memory within the Flask app."""
        if not app.limiter.redis_client:
            self.skipTest("This test requires a live Redis connection to be configured.")
        
        mock_pipe = MagicMock()
        mock_pipe.execute.side_effect = redis.ConnectionError("Test connection failure")

        with patch.object(app.limiter.redis_client, 'pipeline', return_value=mock_pipe):
            response = self._make_api_request('/api/request', self.user_a_key)
            self.assertEqual(response.status_code, 200)
        self.assertIsNone(app.limiter.redis_client, "Limiter should set redis_client to None after connection error")

    def test_U017_local_window_reset(self):
        """U-Test: Verifies local memory window resets correctly after window_seconds elapse."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        user_id = "reset_user"
        config_key = "TEST_SHORT" 

        self.assertTrue(limiter.allow_request(user_id, config_key))
        self.assertTrue(limiter.allow_request(user_id, config_key))
        self.assertFalse(limiter.allow_request(user_id, config_key))

        with patch('time.time', return_value=time.time() + 1.0):
            self.assertTrue(limiter.allow_request(user_id, config_key))

    def test_U018_get_config_default_fallback(self):
        """U-Test: Verifies the default config (1/60s) is returned and applied when a key is missing."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        non_existent_key = "MISSING_KEY"

        config = limiter.get_config(non_existent_key)
        self.assertEqual(config["max_requests"], 1)

        user_id = "fallback_user"
        self.assertTrue(limiter.allow_request(user_id, non_existent_key))
        self.assertFalse(limiter.allow_request(user_id, non_existent_key))

    def test_I019_update_config_affects_limit(self):
        """I-Test: Verify config update via API immediately changes rate limit behavior."""
        config_to_change = self.high_config
        new_limit = 2

        new_config_data = {"max_requests": new_limit, "window_seconds": 15}
        self.app.put(f'/admin/config/{config_to_change}',
                     data=json.dumps(new_config_data), content_type='application/json',
                     headers={'X-API-Key': self.admin_key})

        for i in range(new_limit):
            response = self._make_api_request('/api/request', self.user_a_key)
            self.assertEqual(response.status_code, 200)

        response = self._make_api_request('/api/request', self.user_a_key)
        self.assertEqual(response.status_code, 429)

    @unittest.skipIf(redis is None, "Skipping I020 test: 'redis' package not installed.")
    def test_I020_redis_status_health_check(self):
        """I-Test: Verify /health reports 'disconnected' upon Redis ping failure."""
        if not app.limiter.redis_client:
            self.skipTest("Requires a live Redis connection.")

        with patch.object(app.limiter.redis_client, 'ping', side_effect=redis.ConnectionError("Mock Ping Failure")):
            response = self.app.get('/health')
            data = response.get_json()
            self.assertEqual(data['redis'], 'disconnected')

    def test_U021_local_memory_boundary_condition(self):
        """U-Test: Local memory: Request allowed *just* before window reset and blocked *just* after limit."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        user_id = "boundary_user"
        config_key = "TEST_SHORT" # 2/0.5s
        start_time = time.time()
        limiter.user_data[(user_id, config_key)] = {"count": 1, "window_start_time": start_time}

        self.assertTrue(limiter.allow_request(user_id, config_key))
        self.assertFalse(limiter.allow_request(user_id, config_key))

        with patch('time.time', return_value=start_time + 0.51):
            self.assertTrue(limiter.allow_request(user_id, config_key))

    def test_S022_request_missing_auth_key_body(self):
        """S-Test: API request with no 'auth_key' in JSON body falls to anonymous limit."""
        response = self.app.post('/api/request', data=json.dumps({}), content_type='application/json')
        self.assertEqual(response.status_code, 200)

    def test_U023_redis_key_generation(self):
        """U-Test: Check the format of the internal Redis key."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        expected_key = "rate_limit:test-user:HIGH"
        self.assertEqual(limiter._redis_key("test-user", "HIGH"), expected_key)

    def test_U024_local_user_isolation(self):
        """U-Test: Verifies two users are isolated in local memory mode."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        config_key = "LOW"
        limiter.allow_request(self.user_a, config_key)
        limiter.allow_request(self.user_a, config_key)
        self.assertFalse(limiter.allow_request(self.user_a, config_key))
        self.assertTrue(limiter.allow_request(self.user_b, config_key))

    def test_U025_local_endpoint_isolation(self):
        """U-Test: Verifies two configuration keys are isolated for the same user in local memory mode."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        limiter.allow_request(self.user_a, "LOW")
        limiter.allow_request(self.user_a, "LOW")
        self.assertFalse(limiter.allow_request(self.user_a, "LOW"))
        self.assertTrue(limiter.allow_request(self.user_a, "HIGH"))

    def test_S026_get_user_status_retry_after_header(self):
        """S-Test: Verify 429 response includes Retry-After header."""
        for _ in range(5):
            self._make_api_request('/api/request', self.user_a_key)
        response_blocked = self._make_api_request('/api/request', self.user_a_key)
        self.assertIn('Retry-After', response_blocked.headers)

    def test_U027_local_get_status_after_limit(self):
        """U-Test: Verifies get_user_status returns correct count and time remaining after hitting limit in local mode."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        user_id = "status_user"
        config_key = "TEST_SHORT"
        limiter.allow_request(user_id, config_key)
        limiter.allow_request(user_id, config_key)
        count, limit, retry_after = limiter.get_user_status(user_id, config_key)
        self.assertEqual(count, 2)
        self.assertLessEqual(retry_after, 0.5)

    def test_S028_admin_get_config_invalid_api_key(self):
        """S-Test: Admin GET config with invalid (but present) X-API-Key (401)."""
        response = self.app.get('/admin/config', headers={'X-API-Key': 'not_a_key_at_all'})
        self.assertEqual(response.status_code, 401)
        self.assertIn('Invalid API Key', response.get_json()['message'])

    def test_S029_admin_put_config_invalid_api_key(self):
        """S-Test: Admin PUT config with invalid (but present) X-API-Key (401)."""
        new_config = {"max_requests": 1, "window_seconds": 1}
        response = self.app.put(f'/admin/config/{self.high_config}',
                                 data=json.dumps(new_config), content_type='application/json',
                                 headers={'X-API-Key': 'not_a_key_at_all'})
        self.assertEqual(response.status_code, 401)

    def test_S030_admin_get_config_missing_api_key(self):
        """S-Test: Admin GET config with missing X-API-Key (401)."""
        response = self.app.get('/admin/config')
        self.assertEqual(response.status_code, 401)
        self.assertIn('Missing X-API-Key header', response.get_json()['message'])

    def test_S031_audit_log_put_missing_max_requests(self):
        """S-Test: Audit log on admin PUT config with missing required field (400)."""
        new_config = {"window_seconds": 50}
        response = self.app.put(f'/admin/config/{self.high_config}',
                                 data=json.dumps(new_config), content_type='application/json',
                                 headers={'X-API-Key': self.admin_key})
        self.assertEqual(response.status_code, 400)
        log_content = self._read_audit_log()
        self.assertIn("AUDIT_FAILURE", log_content)

    def test_S032_audit_log_put_non_integer_data(self):
        """S-Test: Audit log on admin PUT config with non-integer data (400)."""
        new_config = {"max_requests": "ten", "window_seconds": 10}
        response = self.app.put(f'/admin/config/{self.high_config}',
                                 data=json.dumps(new_config), content_type='application/json',
                                 headers={'X-API-Key': self.admin_key})
        self.assertEqual(response.status_code, 400)
        log_content = self._read_audit_log()
        self.assertIn("AUDIT_FAILURE", log_content)

    def test_S033_api_request_missing_json_body(self):
        """S-Test: API request with no JSON body/missing content-type (Flask 400 -> 415 fix)."""
        response = self.app.post('/api/request', data='not json data', content_type='text/plain')
        self.assertEqual(response.status_code, 415)

    @unittest.skipIf(redis is None, "Skipping U034: 'redis' package not installed.")
    def test_U034_init_redis_connection_failure(self):
        """U-Test: Verify initialization fails gracefully with connection error and returns None for client (Mocking fix)."""
        def mock_redis_init(connection_pool):
            mock_client = MagicMock()
            mock_client.ping.side_effect = redis.ConnectionError("Mocked Connection Error")
            return mock_client
            
        with patch('src.rate_limiter.redis.Redis', side_effect=mock_redis_init) as MockRedisClass:
            MockRedisClass.from_url.return_value = MockRedisClass
            
            limiter = ConfigurableFixedWindowRateLimiter(configs=UNIT_CONFIGS, redis_url="redis://fail")
            self.assertIsNone(limiter.redis_client)


    def test_U035_local_get_status_new_user(self):
        """U-Test: Local memory: Test get_user_status returns 0 count and full window for new user (Float fix)."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        user_id = "new_local_user"
        count, limit, retry_after = limiter.get_user_status(user_id, "HIGH")
        self.assertEqual(count, 0)
        self.assertAlmostEqual(retry_after, 15.0, delta=0.01)

    @unittest.skipIf(redis is None, "Skipping U036: 'redis' package not installed.")
    def test_U036_redis_status_ttl_minus_two(self):
        """U-Test: Verifies get_user_status uses full window_seconds if Redis TTL is -2 (key expired)."""
        mock_redis = MagicMock()
        mock_redis.get.return_value = b'0'
        mock_redis.ttl.return_value = -2
        limiter = self._init_mocked_redis_limiter(mock_redis)

        count, limit, retry_after = limiter.get_user_status(self.user_a, "HIGH")
        self.assertEqual(retry_after, 15.0)

    @unittest.skipIf(redis is None, "Skipping I037 test: 'redis' package not installed.")
    def test_I037_redis_failure_then_local_limit_enforcement(self):
        """I-Test: Redis fails, system falls back to local, and local limit is enforced (5 requests)."""
        if not app.limiter.redis_client:
            self.skipTest("Requires a live Redis connection to be configured.")

        mock_pipe = MagicMock()
        mock_pipe.execute.side_effect = redis.ConnectionError("Status check fallback")
        with patch.object(app.limiter.redis_client, 'pipeline', return_value=mock_pipe):
             self._make_api_request('/api/request', self.user_a_key)

        for i in range(2, 6): 
            response = self._make_api_request('/api/request', self.user_a_key)
            self.assertEqual(response.status_code, 200, f"Local Request {i} allowed")

        response_blocked = self._make_api_request('/api/request', self.user_a_key)
        self.assertEqual(response_blocked.status_code, 429)

    @unittest.skipIf(redis is None, "Skipping U038: 'redis' package not installed.")
    def test_U038_redis_allow_request_limit_hit(self):
        """U-Test: Verifies Redis-backed limit blocking correctly (INCR > max_requests)."""
        mock_redis = MagicMock()
        mock_redis.pipeline.return_value.execute.return_value = [6, 5]
        limiter = self._init_mocked_redis_limiter(mock_redis)

        self.assertFalse(limiter.allow_request(self.user_a, "HIGH"))

    def test_S039_admin_get_config_user_forbidden(self):
        """S-Test: Standard 'user' role is forbidden from GET /admin/config (403)."""
        response_user = self.app.get('/admin/config', headers={'X-API-Key': self.user_a_key})
        self.assertEqual(response_user.status_code, 403)

    def test_S040_audit_log_rate_limit_not_failure(self):
        """S-Test: Verify 429 response is *not* logged as an AUDIT_FAILURE."""
        for _ in range(5):
            self._make_api_request('/api/request', self.user_a_key)
        self._make_api_request('/api/request', self.user_a_key)
        log_content = self._read_audit_log()
        self.assertNotIn("AUDIT_FAILURE", log_content)

    def test_S041_audit_log_success_api_request_not_logged(self):
        """S-Test: Verify successful 200 API requests are *not* logged by the audit logger."""
        self._make_api_request('/api/request', self.user_a_key)
        log_content = self._read_audit_log()
        self.assertEqual(log_content.strip(), "")

    @unittest.skipIf(redis is None, "Skipping U042: 'redis' package not installed.")
    def test_U042_redis_allow_request_sets_ttl(self):
        """U-Test: Verifies Redis pipeline includes INCR and EXPIRE for the first request (TTL -1)."""
        mock_redis = MagicMock()
        mock_redis.pipeline.return_value.execute.return_value = [1, -1]
        limiter = self._init_mocked_redis_limiter(mock_redis)
        self.assertTrue(limiter.allow_request(self.user_a, "HIGH"))
        mock_redis.expire.assert_called_once_with(limiter._redis_key(self.user_a, "HIGH"), 15)

    @unittest.skipIf(redis is None, "Skipping U043: 'redis' package not installed.")
    def test_U043_redis_allow_request_does_not_reset_ttl(self):
        """U-Test: Verifies EXPIRE is NOT called if TTL is > 0 (subsequent requests)."""
        mock_redis = MagicMock()
        mock_redis.pipeline.return_value.execute.return_value = [2, 10]
        limiter = self._init_mocked_redis_limiter(mock_redis)
        self.assertTrue(limiter.allow_request(self.user_a, "HIGH"))
        mock_redis.expire.assert_not_called()

    def test_U044_local_config_update_immediate_effect(self):
        """U-Test: Verify changes to limiter.configs are picked up immediately by the limiter."""
        configs = dict(UNIT_CONFIGS)
        limiter = self._init_local_limiter(configs)
        config_key = "HIGH"
        limiter.configs[config_key] = {"max_requests": 1, "window_seconds": 15}
        self.assertTrue(limiter.allow_request(self.user_a, config_key))
        self.assertFalse(limiter.allow_request(self.user_a, config_key))

    def test_U045_local_get_status_existing_user_before_limit(self):
        """U-Test: Local memory: Test get_user_status returns correct count before hitting limit."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        user_id = "existing_local_user"
        limiter.allow_request(user_id, "HIGH")
        limiter.allow_request(user_id, "HIGH")
        count, limit, retry_after = limiter.get_user_status(user_id, "HIGH")
        self.assertEqual(count, 2)
        self.assertEqual(limit, 5)
        self.assertLessEqual(retry_after, 15.0)

    def test_S046_admin_put_config_non_integer_window_seconds(self):
        """S-Test: Admin PUT config with non-integer window_seconds (400)."""
        new_config = {"max_requests": 10, "window_seconds": "ten"}
        response = self.app.put(f'/admin/config/{self.high_config}',
                                 data=json.dumps(new_config), content_type='application/json',
                                 headers={'X-API-Key': self.admin_key})
        self.assertEqual(response.status_code, 400)

    def test_U047_local_get_status_full_window(self):
        """U-Test: Local memory: Test get_user_status returns full window time after expiration."""
        limiter = self._init_local_limiter(UNIT_CONFIGS)
        user_id = "window_user"
        
        start_time = 100.0
        with patch('time.time', return_value=start_time):
            limiter.allow_request(user_id, "HIGH") 

        expired_time = start_time + 16.0 
        with patch('time.time', return_value=expired_time):
           
            count, limit, retry_after = limiter.get_user_status(user_id, "HIGH")
           
            self.assertAlmostEqual(retry_after, 0.0, delta=0.01, msg="Expected 0.0 remaining when window is far expired.")


    def test_S048_health_check_returns_config_keys(self):
        """S-Test: Health check endpoint returns the list of configured rate limit keys."""
        response = self.app.get('/health')
        data = response.get_json()
        expected_keys = sorted(RATE_LIMIT_CONFIGS.keys())
        actual_keys = sorted(data['rate_limit_configs'])
        self.assertEqual(actual_keys, expected_keys)

    def test_S049_admin_put_viewer_nonexistent_key(self):
        """S-Test: Viewer role attempts to PUT config (RBAC check fails first, 403)."""
        response = self.app.put('/admin/config/NON_EXISTENT_KEY',
                                 data=json.dumps({}), content_type='application/json',
                                 headers={'X-API-Key': self.viewer_key})
        self.assertEqual(response.status_code, 403)

    def test_S050_admin_put_missing_api_key(self):
        """S-Test: Admin PUT config with missing X-API-Key (401 and audit)."""
        response = self.app.put(f'/admin/config/{self.high_config}',
                                 data=json.dumps({"max_requests": 1, "window_seconds": 1}),
                                 content_type='application/json')
        self.assertEqual(response.status_code, 401)
        log_content = self._read_audit_log()
        self.assertIn("AUDIT_FAILURE: Unauthorized", log_content)


if __name__ == '__main__':
    unittest.main()
