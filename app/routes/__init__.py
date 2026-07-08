from app.routes.admin import router as admin_router
from app.routes.alerts import router as alerts_router
from app.routes.auth import router as auth_router
from app.routes.cases import router as cases_router
from app.routes.logs import router as logs_router
from app.routes.reports import router as reports_router

__all__ = [
    "admin_router",
    "alerts_router",
    "auth_router",
    "cases_router",
    "logs_router",
    "reports_router",
]
