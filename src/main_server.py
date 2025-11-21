"""
Flask web server for the API Rate Limiter.

Provides API endpoints to test rate limiting, an admin dashboard to view
and update configurations, and a health check endpoint.
"""

import os
import logging
from functools import wraps
import redis
from flask import Flask, jsonify, request, render_template_string, g

from .rate_limiter import ConfigurableFixedWindowRateLimiter


def setup_audit_logger():
    """
    Configures the audit logger to write to 'audit.log' in the project root.
    """
    logger = logging.getLogger("audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        log_file_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "audit.log")
        )
        file_handler = logging.FileHandler(log_file_path)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


audit_logger = setup_audit_logger()

RATE_LIMIT_CONFIGS = {
    "HIGH_THROUGHPUT_API": {"max_requests": 5, "window_seconds": 15},
    "LOW_THROUGHPUT_API": {"max_requests": 2, "window_seconds": 60},
    "ANONYMOUS_IP_LIMIT": {"max_requests": 10, "window_seconds": 60},
}
DEFAULT_CONFIG_KEY = "HIGH_THROUGHPUT_API"
ANONYMOUS_CONFIG_KEY = "ANONYMOUS_IP_LIMIT"

USER_DATABASE = {
    "admin_key_123": {"id": "Admin-User", "role": "admin"},
    "viewer_key_456": {"id": "Viewer-User", "role": "viewer"},
    "user_a_key": {"id": "User-A-4821", "role": "user"},
    "user_b_key": {"id": "User-B-9902", "role": "user"},
}

app = Flask(__name__)
app.audit_logger = audit_logger

REDIS_URL = os.getenv("REDIS_URL", None)
REDIS_POOL_SIZE = int(os.getenv("REDIS_POOL_SIZE", "10"))
REDIS_SOCKET_TIMEOUT = int(os.getenv("REDIS_SOCKET_TIMEOUT", "5"))
REDIS_RETRY_ON_TIMEOUT = os.getenv("REDIS_RETRY_ON_TIMEOUT", "true").lower() == "true"

limiter = ConfigurableFixedWindowRateLimiter(
    configs=RATE_LIMIT_CONFIGS,
    redis_url=REDIS_URL,
    redis_pool_size=REDIS_POOL_SIZE,
    redis_socket_timeout=REDIS_SOCKET_TIMEOUT,
    redis_retry_on_timeout=REDIS_RETRY_ON_TIMEOUT,
)
app.limiter = limiter


def get_user_from_key(api_key: str) -> dict | None:
    """Gets the full user object (id, role) from the database."""
    return USER_DATABASE.get(api_key)


def authenticate_and_get_user_id(auth_key: str) -> str | None:
    """
    Simulates auth step to get a unique User ID.
    Returns None if key is invalid or not a 'user' role.
    """
    if not auth_key:
        return None
    user = get_user_from_key(auth_key)
    if user and user["role"] == "user":
        return user["id"]
    return None


def require_role(required_roles: list[str]):
    """
    Decorator to protect an endpoint, requiring a specific user role.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = request.headers.get("X-API-Key")
            if not api_key:
                audit_logger.warning(
                    "AUDIT_FAILURE: Unauthorized access attempt to '%s'. "
                    "Reason: Missing X-API-Key.",
                    request.path,
                )
                return (
                    jsonify({"message": "Unauthorized. Missing X-API-Key header."}),
                    401,
                )

            user = get_user_from_key(api_key)
            if not user:
                audit_logger.warning(
                    "AUDIT_FAILURE: Unauthorized access attempt to '%s'. "
                    "Reason: Invalid X-API-Key.",
                    request.path,
                )
                return jsonify({"message": "Unauthorized. Invalid API Key."}), 401

            if user["role"] not in required_roles:
                audit_logger.warning(
                    "AUDIT_FAILURE: Forbidden access by User '%s' (Role: %s) "
                    "to '%s'. Req roles: %s.",
                    user["id"],
                    user["role"],
                    request.path,
                    required_roles,
                )
                return (
                    jsonify(
                        {"message": "Forbidden. You do not have the required role."}
                    ),
                    403,
                )

            g.user = user
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def create_rate_limit_response(
    user_id: str, config_key: str, allowed: bool, message: str, status_code: int = 200
):
    """
    Builds a consistent JSON response for a rate-limited endpoint.
    """
    count, limit, retry_after = app.limiter.get_user_status(user_id, config_key)
    remaining = limit - count if allowed else 0

    if config_key != ANONYMOUS_CONFIG_KEY:
        user_identifier = user_id
    else:
        user_identifier = f"Anonymous IP ({user_id})"

    endpoint_name = f"/api/{config_key.lower().replace('_', '-')}"
    response_data = {
        "message": message,
        "data": (
            {"user": user_identifier, "endpoint": endpoint_name} if allowed else None
        ),
        "rate_limit": {
            "config_key": config_key,
            "limit": limit,
            "count": count,
            "remaining": remaining,
            "retry_after": retry_after,
        },
    }
    response = jsonify(response_data)
    response.status_code = status_code
    if status_code == 429:
        response.headers["Retry-After"] = int(retry_after)
    return response


def handle_rate_limited_request(auth_key: str, endpoint_config_key: str):
    """
    [QC-8] Handles an incoming request, applying limits based on user_id
    if authenticated, or based on IP address if anonymous.
    """
    user_id = authenticate_and_get_user_id(auth_key)

    if user_id:
        id_to_limit = user_id
        config_to_use = endpoint_config_key
    else:
        id_to_limit = request.remote_addr
        config_to_use = ANONYMOUS_CONFIG_KEY

    if app.limiter.allow_request(id_to_limit, config_to_use):
        return create_rate_limit_response(
            id_to_limit, config_to_use, True, "API Call Successful.", 200
        )

    return create_rate_limit_response(
        id_to_limit,
        config_to_use,
        False,
        "Too Many Requests. Rate limit exceeded.",
        429,
    )


@app.route("/api/request", methods=["POST"])
def handle_high_throughput_request():
    """Endpoint for high-throughput (default) API requests."""
    data = request.get_json()
    auth_key = data.get("auth_key")
    return handle_rate_limited_request(auth_key, DEFAULT_CONFIG_KEY)


@app.route("/api/low_priority_request", methods=["POST"])
def handle_low_throughput_request():
    """Endpoint for low-throughput API requests."""
    data = request.get_json()
    auth_key = data.get("auth_key")
    return handle_rate_limited_request(auth_key, "LOW_THROUGHPUT_API")


@app.route("/health", methods=["GET"])
def health_check():
    """Provides a simple health check for the service and Redis."""
    redis_status = "connected"
    try:
        if not app.limiter.redis_client or not app.limiter.redis_client.ping():
            redis_status = "disconnected"
    except redis.RedisError:
        redis_status = "disconnected"

    return jsonify(
        {
            "status": "healthy",
            "redis": redis_status,
            "rate_limit_configs": list(RATE_LIMIT_CONFIGS.keys()),
        }
    )


@app.route("/admin/config", methods=["GET"])
@require_role(["admin", "viewer"])
def get_all_configs():
    """Admin endpoint to retrieve all current rate limit configurations."""
    user_id = g.user.get("id", "unknown")
    audit_logger.info("User '%s' successfully retrieved all configurations.", user_id)

    return (
        jsonify(
            {
                "status": "success",
                "message": "Current rate limit configurations retrieved.",
                "configs": RATE_LIMIT_CONFIGS,
            }
        ),
        200,
    )


@app.route("/admin/config/<config_key>", methods=["PUT"])
@require_role(["admin"])
def update_config(config_key):
    """Admin endpoint to update a specific rate limit configuration."""
    user_id = g.user.get("id", "unknown")

    if config_key not in RATE_LIMIT_CONFIGS:
        audit_logger.warning(
            "User '%s' failed to update config '%s'. " "Reason: Config key not found.",
            user_id,
            config_key,
        )
        return jsonify({"message": f"Configuration key '{config_key}' not found."}), 404

    try:
        data = request.get_json()
        max_requests = int(data.get("max_requests"))
        window_seconds = int(data.get("window_seconds"))

        if max_requests <= 0 or window_seconds <= 0:
            raise ValueError(
                "max_requests and window_seconds must be positive integers."
            )

        new_config = {"max_requests": max_requests, "window_seconds": window_seconds}
        RATE_LIMIT_CONFIGS[config_key] = new_config

        audit_logger.info(
            "AUDIT_SUCCESS: User '%s' updated config '%s' to %s",
            user_id,
            config_key,
            new_config,
        )

        return (
            jsonify(
                {
                    "status": "success",
                    "message": f"Configuration '{config_key}' updated successfully.",
                    "new_config": RATE_LIMIT_CONFIGS[config_key],
                }
            ),
            200,
        )

    except (ValueError, TypeError, AttributeError) as e:
        audit_logger.warning(
            "AUDIT_FAILURE: User '%s' failed to update config '%s'. "
            "Invalid data: %s. Error: %s",
            user_id,
            config_key,
            request.data,
            e,
        )
        return jsonify({"message": f"Invalid input or server error: {e}"}), 400


@app.route("/", methods=["GET"])
def index():
    """Serves the single-page HTML interface."""
    limit_info_high = (  # pylint: disable=implicit-str-concat
        f"{RATE_LIMIT_CONFIGS['HIGH_THROUGHPUT_API']['max_requests']} "
        f"requests per "
        f"{RATE_LIMIT_CONFIGS['HIGH_THROUGHPUT_API']['window_seconds']}s"
    )
    limit_info_low = (
        f"{RATE_LIMIT_CONFIGS['LOW_THROUGHPUT_API']['max_requests']} "
        f"requests per "
        f"{RATE_LIMIT_CONFIGS['LOW_THROUGHPUT_API']['window_seconds']}s"
    )
    limit_info_anon = (
        f"{RATE_LIMIT_CONFIGS[ANONYMOUS_CONFIG_KEY]['max_requests']} "
        f"requests per "
        f"{RATE_LIMIT_CONFIGS[ANONYMOUS_CONFIG_KEY]['window_seconds']}s"
    )

    redis_status_text = "Connected"
    try:
        if not app.limiter.redis_client or not app.limiter.redis_client.ping():
            redis_status_text = "Not Connected"
    except redis.RedisError:
        redis_status_text = "Not Connected"

    redis_info = f"(Redis: {redis_status_text})"

    admin_demo_key = "admin_key_123"
    viewer_demo_key = "viewer_key_456"

    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Rate Limiter</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @keyframes pulse-red {
            0%, 100% { background-color: #fee2e2; }
            50% { background-color: #ef4444; }
        }
        .pulse-red-animation {
            animation: pulse-red 0.5s ease-in-out;
        }
        .container-shadow {
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1),
                        0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }
    </style>
</head>
<body class="bg-gray-50 min-h-screen flex items-center justify-center p-4
             font-sans">

    <div class="w-full max-w-4xl bg-white rounded-xl p-8 container-shadow
                border border-gray-200">

        <h1 class="text-3xl font-extrabold text-gray-900 mb-2">
            API Rate Limiter
        </h1>
        <p class="text-lg text-gray-600 mb-6">
            <span class="font-bold text-indigo-600">HIGH_THROUGHPUT_API:</span>
            <span id="limit-info-high">{{ limit_info_high }}</span> |
            <span class="font-bold text-green-600">LOW_THROUGHPUT_API:</span>
            <span id="limit-info-low">{{ limit_info_low }}</span>
            <br>
            <span class="font-bold text-gray-600">ANONYMOUS_IP_API:</span>
            <span id="limit-info-anon">{{ limit_info_anon }}</span>
            <span class="font-bold text-purple-600 ml-2">{{ redis_info }}</span>
            <br>
            <span class="text-sm font-semibold text-red-500">
                Admin Key: {{ admin_demo_key }}
            </span>
            <br>
            <span class="text-sm font-semibold text-blue-500">
                Viewer Key: {{ viewer_demo_key }}
            </span>
        </p>

        <div class="bg-gray-100 p-4 mb-8 rounded-lg">
            <h2 class="text-xl font-semibold text-gray-800 mb-3">
                Rate Limit Status (Per User & Per API Tracking)
            </h2>
            <div class="grid grid-cols-2 gap-4">

                <div class="bg-indigo-50 border-l-4 border-indigo-500 p-3
                            rounded-lg shadow-sm">
                    <h3 class="font-bold text-indigo-800 mb-2">
                        User A (<span class="text-xs font-mono">User-A-4821</span>)
                    </h3>
                    <div class="space-y-2 text-sm">
                        <div id="card-a-high" class="flex justify-between
                                    items-center text-gray-700 p-2
                                    bg-white rounded-md">
                            <span class="font-medium text-indigo-600">
                                High-Throughput API
                            </span>
                            <span id="status-a-high"
                                  class="font-bold text-gray-500">
                                Awaiting...
                            </span>
                        </div>
                        <div id="card-a-low" class="flex justify-between
                                   items-center text-gray-700 p-2
                                   bg-white rounded-md">
                            <span class="font-medium text-green-600">
                                Low-Throughput API
                            </span>
                            <span id="status-a-low"
                                  class="font-bold text-gray-500">
                                Awaiting...
                            </span>
                        </div>
                    </div>
                </div>

                <div class="bg-green-50 border-l-4 border-green-500 p-3
                            rounded-lg shadow-sm">
                    <h3 class="font-bold text-green-800 mb-2">
                        User B (<span class="text-xs font-mono">User-B-9902</span>)
                    </h3>
                    <div class="space-y-2 text-sm">
                        <div id="card-b-high" class="flex justify-between
                                    items-center text-gray-700 p-2
                                    bg-white rounded-md">
                            <span class="font-medium text-indigo-600">
                                High-Throughput API
                            </span>
                            <span id="status-b-high"
                                  class="font-bold text-gray-500">
                                Awaiting...
                            </span>
                        </div>
                        <div id="card-b-low" class="flex justify-between
                                   items-center text-gray-700 p-2
                                   bg-white rounded-md">
                            <span class="font-medium text-green-600">
                                Low-Throughput API
                            </span>
                            <span id="status-b-low"
                                  class="font-bold text-gray-500">
                                Awaiting...
                            </span>
                        </div>
                    </div>
                </div>

            </div>
        </div>

        <div class="space-y-4 mb-8">
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-4">
                    <button onclick="sendRequest('user_a_key', 'User-A-4821',
                                'HIGH_THROUGHPUT_API', '/api/request',
                                'card-a-high', 'status-a-high')"
                            class="w-full py-3 px-6 bg-indigo-600 text-white
                                   font-semibold rounded-lg
                                   hover:bg-indigo-700 transition
                                   duration-150 ease-in-out shadow-md
                                   hover:shadow-lg focus:outline-none
                                   focus:ring-4 focus:ring-indigo-500
                                   focus:ring-opacity-50">
                        User A: High-Throughput Request
                    </button>
                    <button onclick="sendRequest('user_a_key', 'User-A-4821',
                                'LOW_THROUGHPUT_API',
                                '/api/low_priority_request', 'card-a-low',
                                'status-a-low')"
                            class="w-full py-3 px-6 bg-green-600 text-white
                                   font-semibold rounded-lg
                                   hover:bg-green-700 transition
                                   duration-150 ease-in-out shadow-md
                                   hover:shadow-lg focus:outline-none
                                   focus:ring-4 focus:ring-green-500
                                   focus:ring-opacity-50">
                        User A: Low-Throughput Request
                    </button>
                </div>
                <div class="space-y-4">
                    <button onclick="sendRequest('user_b_key', 'User-B-9902',
                                'HIGH_THROUGHPUT_API', '/api/request',
                                'card-b-high', 'status-b-high')"
                            class="w-full py-3 px-6 bg-indigo-600 text-white
                                   font-semibold rounded-lg
                                   hover:bg-indigo-700 transition
                                   duration-150 ease-in-out shadow-md
                                   hover:shadow-lg focus:outline-none
                                   focus:ring-4 focus:ring-indigo-500
                                   focus:ring-opacity-50">
                        User B: High-Throughput Request
                    </button>
                    <button onclick="sendRequest('user_b_key', 'User-B-9902',
                                'LOW_THROUGHPUT_API',
                                '/api/low_priority_request', 'card-b-low',
                                'status-b-low')"
                            class="w-full py-3 px-6 bg-green-600 text-white
                                   font-semibold rounded-lg
                                   hover:bg-green-700 transition
                                   duration-150 ease-in-out shadow-md
                                   hover:shadow-lg focus:outline-none
                                   focus:ring-4 focus:ring-green-500
                                   focus:ring-opacity-50">
                        User B: Low-Throughput Request
                    </button>
                </div>
            </div>

            <button onclick="sendRequest('invalid_key', 'Anonymous IP',
                        'ANONYMOUS_IP_LIMIT', '/api/request', null, null)"
                    class="w-full py-3 px-6 bg-gray-700 text-white
                           font-semibold rounded-lg hover:bg-gray-800
                           transition duration-150 ease-in-out shadow-md
                           hover:shadow-lg focus:outline-none focus:ring-4
                           focus:ring-gray-500 focus:ring-opacity-50">
                Send Anonymous Request (Uses IP Limit)
            </button>
        </div>

        <div class="mt-8 pt-4 border-t border-gray-200">
            <h2 class="text-xl font-semibold text-gray-900 mb-3">
                Admin Configuration Management
            </h2>
            <p class="text-sm text-gray-600 mb-4">
                Use the keys above (in the 'X-API-Key' header) to test
                RBAC and check `audit.log`.
            </p>
            <div class="grid grid-cols-2 gap-4">
                <button onclick="sendAdminGetConfig('{{ admin_demo_key }}')"
                        class="w-full py-2 px-4 bg-purple-600 text-white
                               font-semibold rounded-lg hover:bg-purple-700
                               transition duration-150 ease-in-out shadow-md
                               focus:outline-none focus:ring-4
                               focus:ring-purple-500 focus:ring-opacity-50">
                    GET /config (as Admin)
                </button>
                <button onclick="sendAdminUpdateConfig('{{ admin_demo_key }}')"
                        class="w-full py-2 px-4 bg-orange-600 text-white
                               font-semibold rounded-lg hover:bg-orange-700
                               transition duration-150 ease-in-out shadow-md
                               focus:outline-none focus:ring-4
                               focus:ring-orange-500 focus:ring-opacity-50">
                    PUT /config/HIGH... (as Admin)
                </button>
            </div>
            <div class="grid grid-cols-2 gap-4 mt-4">
                <button onclick="sendAdminGetConfig('{{ viewer_demo_key }}')"
                        class="w-full py-2 px-4 bg-blue-600 text-white
                               font-semibold rounded-lg hover:bg-blue-700
                               transition duration-150 ease-in-out shadow-md
                               focus:outline-none focus:ring-4
                               focus:ring-blue-500 focus:ring-opacity-50">
                    GET /config (as Viewer)
                </button>
                <button onclick="sendAdminUpdateConfig('{{ viewer_demo_key }}')"
                        class="w-full py-2 px-4 bg-red-600 text-white
                               font-semibold rounded-lg hover:bg-red-700
                               transition duration-150 ease-in-out shadow-md
                               focus:outline-none focus:ring-4
                               focus:ring-red-500 focus:ring-opacity-50">
                    PUT /config/HIGH... (as Viewer)
                </button>
            </div>
        </div>

        <div class="mt-8">
            <h2 class="text-xl font-semibold text-gray-900 mb-3">
                API Response Console
            </h2>
            <div id="console" class="bg-gray-800 text-white p-4 h-48
                                  overflow-y-scroll rounded-lg font-mono
                                  text-sm border border-gray-700">
                <div class="text-gray-400">
                    [System] Click a button to send an API request.
                </div>
            </div>
        </div>

    </div>

    <script>
        const consoleEl = document.getElementById('console');
        const ADMIN_ENDPOINT = "/admin/config";

        function log(message, colorClass = 'text-gray-300') {
            const time = new Date().toLocaleTimeString();
            const logEntry = document.createElement('div');
            logEntry.className = colorClass;
            logEntry.innerHTML = `[${time}] ${message}`;
            consoleEl.prepend(logEntry);
            while (consoleEl.children.length > 50) {
                consoleEl.removeChild(consoleEl.lastChild);
            }
        }

        function updateStatus(
                userId, configKey, count, limit,
                retryAfter, statusElId, cardElId) {
            // Check if statusElId and cardElId are provided
            // (they are null for anonymous calls)
            if (!statusElId || !cardElId) {
                return;
            }

            const statusEl = document.getElementById(statusElId);
            const statusCard = document.getElementById(cardElId);

            // Ensure elements exist
            if (!statusEl || !statusCard) {
                log(`[Debug] Could not find status elements: ${statusElId}, ` +
                    `${cardElId}`, 'text-orange-400');
                return;
            }

            const remaining = limit - count;

            statusEl.textContent = `Used: ${count}/${limit}. ` +
                                   `Reset in: ${retryAfter.toFixed(1)}s`;

            statusEl.className = 'font-bold transition-colors duration-200 ' +
                                 (remaining === 0 ? 'text-red-600' :
                                  remaining <= 1 ? 'text-yellow-600' :
                                  'text-green-600');

            if (remaining === 0 && statusCard) {
                statusCard.classList.add('pulse-red-animation');
                setTimeout(() => {
                    statusCard.classList.remove('pulse-red-animation');
                }, 500);
            }
        }

        async function sendRequest(
                key, userId, configKey, endpoint, cardElId, statusElId) {
            log(`Attempting ${configKey} request as ${userId}...`);

            try {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ 'auth_key': key })
                });

                const data = await response.json();

                // Use the actual config_key returned by the server
                const actualConfigKey = data.rate_limit.config_key || configKey;
                const actualUserId = data.data ? data.data.user : userId;

                if (response.status === 200) {
                    log(`[${actualUserId} | ${actualConfigKey}] 200 OK - ` +
                        `SUCCESS!`, 'text-green-400');
                } else if (response.status === 429) {
                    log(`[${actualUserId} | ${actualConfigKey}] 429 - ` +
                        `BLOCKED! Retry: ` +
                        `${data.rate_limit.retry_after.toFixed(1)}s.`,
                        'text-red-400');
                } else {
                    log(`[${actualUserId} | ${actualConfigKey}] ERROR ` +
                        `${response.status}: ${data.message}`,
                        'text-orange-400');
                }

                const rateLimit = data.rate_limit;
                updateStatus(
                    actualUserId,
                    rateLimit.config_key,
                    rateLimit.count,
                    rateLimit.limit,
                    rateLimit.retry_after,
                    statusElId,
                    cardElId
                );

            } catch (error) {
                log(`[FETCH ERROR] Could not connect to API: ${error}`,
                    'text-orange-400');
            }
        }

        async function sendAdminGetConfig(apiKey) {
            const role = (apiKey === '{{ admin_demo_key }}') ? 'Admin' : 'Viewer';
            log(`[${role}] Attempting GET ${ADMIN_ENDPOINT}...`);
            try {
                const response = await fetch(ADMIN_ENDPOINT, {
                    method: 'GET',
                    headers: { 'X-API-Key': apiKey }
                });
                const data = await response.json();

                if (response.status === 200) {
                    log(`[${role}] 200 OK. Configs: ` +
                        `${JSON.stringify(data.configs)}`, 'text-purple-400');
                } else {
                    log(`[${role}] ERROR ${response.status}: ${data.message}`,
                        'text-red-400');
                }

            } catch (error) {
                log(`[ADMIN FETCH ERROR] Could not connect to API: ${error}`,
                    'text-orange-400');
            }
        }

        async function sendAdminUpdateConfig(apiKey) {
            const role = (apiKey === '{{ admin_demo_key }}') ? 'Admin' : 'Viewer';
            log(`[${role}] Attempting PUT ${ADMIN_ENDPOINT}` +
                `/HIGH_THROUGHPUT_API to 2/30s...`);

            const newConfig = { max_requests: 2, window_seconds: 30 };

            try {
                const response = await fetch(
                    `${ADMIN_ENDPOINT}/HIGH_THROUGHPUT_API`, {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-API-Key': apiKey
                        },
                        body: JSON.stringify(newConfig)
                    });
                const data = await response.json();

                if (response.status === 200) {
                    log(`[${role}] 200 OK. Config set to 2/30s.`,
                        'text-orange-400');
                    document.getElementById('limit-info-high')
                            .textContent = '2 requests per 30s';
                } else {
                    log(`[${role}] ERROR ${response.status}: ${data.message}`,
                        'text-red-400');
                }

            } catch (error) {
                log(`[ADMIN FETCH ERROR] Could not connect to API: ${error}`,
                    'text-orange-400');
            }
        }

    </script>
</body>
</html>
"""
    return render_template_string(
        html_template,
        limit_info_high=limit_info_high,
        limit_info_low=limit_info_low,
        limit_info_anon=limit_info_anon,
        redis_info=redis_info,
        admin_demo_key=admin_demo_key,
        viewer_demo_key=viewer_demo_key,
    )


if __name__ == "__main__":

    IS_DEBUG = os.getenv("FLASK_DEBUG", "true").lower() == "true"
    HOST_TO_RUN = os.getenv("FLASK_HOST", "127.0.0.1")
    PORT_TO_RUN = int(os.getenv("FLASK_PORT", "5000"))

    print("---")
    print(
        f"--- Starting Flask development server on "
        f"http://{HOST_TO_RUN}:{PORT_TO_RUN} ---"
    )
    print(
        "--- (This server is for DEVELOPMENT only. "
        "Use Gunicorn/Waitress for production) ---"
    )
    print("---")

    app.run(debug=IS_DEBUG, host=HOST_TO_RUN, port=PORT_TO_RUN)
