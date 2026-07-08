from fastapi import APIRouter

from app import runtime

router = APIRouter()

router.add_api_route("/api/iocs", runtime.get_iocs, methods=["GET"])
router.add_api_route("/api/iocs", runtime.create_ioc, methods=["POST"])
router.add_api_route("/api/iocs/{ioc_id}", runtime.update_ioc, methods=["PATCH"])
router.add_api_route("/api/iocs/{ioc_id}", runtime.delete_ioc, methods=["DELETE"])
router.add_api_route("/api/policies", runtime.get_policies, methods=["GET"])
router.add_api_route("/api/policies", runtime.create_policy, methods=["POST"])
router.add_api_route("/api/policies/{policy_id}", runtime.update_policy, methods=["PATCH"])
router.add_api_route("/api/policies/{policy_id}", runtime.delete_policy, methods=["DELETE"])
router.add_api_route("/api/assets", runtime.get_assets, methods=["GET"])
router.add_api_route("/api/assets", runtime.create_asset, methods=["POST"])
router.add_api_route("/api/assets/{asset_id}", runtime.delete_asset, methods=["DELETE"])
router.add_api_route("/api/suppressions", runtime.get_suppressions, methods=["GET"])
router.add_api_route("/api/suppressions", runtime.create_suppression, methods=["POST"])
router.add_api_route("/api/suppressions/{suppression_id}", runtime.delete_suppression, methods=["DELETE"])
router.add_api_route("/api/admin/backups", runtime.list_backups, methods=["GET"])
router.add_api_route("/api/admin/backup", runtime.create_backup, methods=["POST"])
router.add_api_route("/api/admin/restore", runtime.restore_backup, methods=["POST"])
router.add_api_route("/api/admin/reset", runtime.reset_data, methods=["POST"])
