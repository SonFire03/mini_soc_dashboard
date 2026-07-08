from fastapi import APIRouter

from app import runtime

router = APIRouter()

router.add_api_route("/api/cases", runtime.get_cases, methods=["GET"])
router.add_api_route(
    "/api/cases",
    runtime.create_case,
    methods=["POST"],
    openapi_extra={
        "requestBody": {
            "content": {
                "application/json": {
                    "example": {
                        "title": "Investigate repeated login failures",
                        "priority": "high",
                        "status": "open",
                        "owner": "soc-analyst",
                        "description": "Multiple suspicious auth failures from same source.",
                    }
                }
            }
        }
    },
)
router.add_api_route("/api/cases/{case_id}", runtime.update_case, methods=["PATCH"])
router.add_api_route("/api/cases/{case_id}/alerts/{alert_id}", runtime.link_case_alert, methods=["POST"])
router.add_api_route("/api/cases/{case_id}/alerts/{alert_id}", runtime.unlink_case_alert, methods=["DELETE"])
router.add_api_route("/api/cases/{case_id}", runtime.case_detail, methods=["GET"])
router.add_api_route("/api/cases/{case_id}/comments", runtime.get_case_comments, methods=["GET"])
router.add_api_route("/api/cases/{case_id}/comments", runtime.create_case_comment, methods=["POST"])
router.add_api_route("/api/cases/{case_id}/comments/{comment_id}", runtime.delete_case_comment, methods=["DELETE"])
router.add_api_route("/api/sla", runtime.sla_metrics, methods=["GET"])
router.add_api_route("/api/saved-views", runtime.get_saved_views, methods=["GET"])
router.add_api_route("/api/saved-views", runtime.create_saved_view, methods=["POST"])
router.add_api_route("/api/saved-views/{view_id}", runtime.delete_saved_view, methods=["DELETE"])
router.add_api_route("/api/incidents/timeline", runtime.incidents_timeline, methods=["GET"])
