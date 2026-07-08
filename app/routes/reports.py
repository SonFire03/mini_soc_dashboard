from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from app import runtime

router = APIRouter()

router.add_api_route("/api/reports/daily", runtime.daily_report_data, methods=["GET"])
router.add_api_route("/reports/daily", runtime.daily_report_page, methods=["GET"], response_class=HTMLResponse)
router.add_api_route("/api/reports/schedules", runtime.report_schedules, methods=["GET"])
router.add_api_route("/api/reports/schedules", runtime.create_report_schedule, methods=["POST"])
router.add_api_route("/api/reports/schedules/{schedule_id}", runtime.update_report_schedule, methods=["PATCH"])
router.add_api_route("/api/reports/schedules/{schedule_id}", runtime.delete_report_schedule, methods=["DELETE"])
router.add_api_route("/api/reports/schedules/{schedule_id}/run", runtime.run_report_schedule_now, methods=["POST"])
router.add_api_route("/api/reports/runs", runtime.report_runs, methods=["GET"])
router.add_api_route("/api/reports/delta", runtime.delta_report_data, methods=["GET"])
