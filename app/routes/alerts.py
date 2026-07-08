from fastapi import APIRouter

from app import runtime

router = APIRouter()

router.add_api_route(
    "/api/alerts",
    runtime.get_alerts,
    methods=["GET"],
    openapi_extra={
        "parameters": [
            {
                "name": "dsl",
                "in": "query",
                "schema": {"type": "string"},
                "example": "ip:203.0.113.10 code:401 method:POST",
            }
        ]
    },
)
router.add_api_route("/api/stats", runtime.get_stats, methods=["GET"])
router.add_api_route("/api/alerts/{alert_id}", runtime.update_alert, methods=["PATCH"])
router.add_api_route("/api/risk/entities", runtime.risk_entities, methods=["GET"])
router.add_api_route("/api/analytics/overview", runtime.analytics_overview, methods=["GET"])
router.add_api_route("/api/playbook/{alert_type}", runtime.playbook, methods=["GET"])
router.add_api_route("/api/alerts/{alert_id}/context", runtime.alert_context, methods=["GET"])
router.add_api_route("/api/alerts/{alert_id}/investigation", runtime.alert_investigation, methods=["GET"])
