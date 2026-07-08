from fastapi import APIRouter

from app import runtime

router = APIRouter()

router.add_api_route("/api/logs/ingest", runtime.ingest_logs, methods=["POST"])
router.add_api_route(
    "/api/logs/ingest-json",
    runtime.ingest_json,
    methods=["POST"],
    openapi_extra={
        "requestBody": {
            "content": {
                "application/json": {
                    "example": {
                        "lines": [
                            {
                                "ts": "2026-05-08T10:15:00Z",
                                "ip": "203.0.113.10",
                                "method": "POST",
                                "path": "/login",
                                "status_code": 401,
                                "user_agent": "Mozilla/5.0",
                                "message": "failed login",
                            }
                        ]
                    }
                }
            }
        }
    },
)
router.add_api_route("/api/logs", runtime.get_logs, methods=["GET"])
router.add_api_route("/api/export/logs.csv", runtime.export_logs_csv, methods=["GET"])
router.add_api_route("/api/export/alerts.csv", runtime.export_alerts_csv, methods=["GET"])
router.add_api_route("/api/live-tail/start", runtime.start_live_tail, methods=["POST"])
router.add_api_route("/api/live-tail/stop", runtime.stop_live_tail, methods=["POST"])
router.add_api_route("/api/live-tail/status", runtime.live_tail_status, methods=["GET"])
router.add_api_websocket_route("/ws/live", runtime.websocket_live)
