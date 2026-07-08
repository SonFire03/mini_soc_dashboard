from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from app import runtime

router = APIRouter()

router.add_api_route("/login", runtime.login_page, methods=["GET"], response_class=HTMLResponse)
router.add_api_route("/login", runtime.login, methods=["POST"])
router.add_api_route("/logout", runtime.logout, methods=["POST"])
router.add_api_route("/", runtime.index, methods=["GET"], response_class=HTMLResponse)
router.add_api_route("/overview", runtime.overview_page, methods=["GET"], response_class=HTMLResponse)
router.add_api_route("/investigations", runtime.investigations_page, methods=["GET"], response_class=HTMLResponse)
router.add_api_route("/operations", runtime.operations_page, methods=["GET"], response_class=HTMLResponse)
router.add_api_route("/reports", runtime.reports_page, methods=["GET"], response_class=HTMLResponse)
router.add_api_route("/admin", runtime.admin_page, methods=["GET"], response_class=HTMLResponse)
router.add_api_route("/wallboard", runtime.wallboard, methods=["GET"], response_class=HTMLResponse)
router.add_api_route("/api/health", runtime.health, methods=["GET"])
router.add_api_route("/api/settings", runtime.settings, methods=["GET"])
router.add_api_route("/api/metrics", runtime.metrics, methods=["GET"])
