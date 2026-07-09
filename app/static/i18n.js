const SOC_TRANSLATIONS = {
  en: {
    meta: { label: "English", flag: "🇺🇸", dir: "ltr" },
    "title.app": "Mini SOC Dashboard",
    "title.login": "Login - Mini SOC Dashboard",
    "hero.eyebrow": "Security Operations Center",
    "hero.subtitle": "Ingestion, detection, and investigation of suspicious events in real time.",
    "status.online": "ONLINE",
    "action.wallboard": "Wallboard",
    "action.logout": "Logout",
    "action.login": "Login",
    "action.close": "Close",
    "action.apply": "Apply",
    "action.saveView": "Save View",
    "action.refreshNow": "Refresh Now",
    "action.dailyReport": "Daily Report",
    "action.import": "Import",
    "action.resetData": "Reset Data",
    "action.logsCsv": "Logs CSV",
    "action.alertsCsv": "Alerts CSV",
    "action.start": "Start",
    "action.stop": "Stop",
    "action.addAsset": "Add Asset",
    "action.addSuppression": "Add Suppression",
    "action.addIoc": "Add IOC",
    "action.addPolicy": "Add Policy",
    "action.createBackup": "Create Backup",
    "action.restoreLatest": "Restore Latest",
    "action.createCase": "Create Case",
    "action.addComment": "Add Comment",
    "action.loadComments": "Load Comments",
    "action.addSchedule": "Add Schedule",
    "action.refreshDelta": "Refresh Delta",
    "action.top": "Top",
    "action.leftPanel": "Left Panel",
    "action.rightPanel": "Right Panel",
    "action.commandPalette": "Command Palette",
    "action.investigate": "Investigate",
    "action.resolve": "Resolve",
    "action.falsePositive": "FP",
    "action.playbook": "Playbook",
    "action.drill": "Drill",
    "action.linkCase": "Link Case",
    "action.delete": "Delete",
    "action.disable": "Disable",
    "action.enable": "Enable",
    "action.restore": "Restore",
    "action.load": "Load",
    "action.runNow": "Run now",
    "nav.overview": "Overview",
    "nav.investigations": "Investigations",
    "nav.operations": "Operations",
    "nav.reports": "Reports",
    "nav.admin": "Admin",
    "quick.openAlerts": "Open Alerts",
    "quick.highSeverity": "High Severity",
    "quick.compromiseFlags": "Compromise Flags",
    "quick.criticalAssetsOpen": "Critical Assets Open",
    "section.controlCenter": "Control Center",
    "section.liveTail": "Live Tail",
    "section.workspace": "Workspace",
    "section.huntFilters": "Hunt Filters",
    "section.incidentTimeline": "Incident Timeline",
    "section.ingestion": "Ingestion",
    "section.assets": "Assets",
    "section.suppressions": "Suppressions",
    "section.iocWatchlist": "IOC Watchlist",
    "section.policyEngine": "Policy Engine",
    "section.cases": "Cases",
    "section.caseComments": "Case Comments",
    "section.scheduledReports": "Scheduled Reports",
    "section.deltaReport": "Delta Report",
    "section.backupRestore": "Backup & Restore",
    "section.operationsToolkit": "Operations Toolkit",
    "section.investigationWorkspace": "Investigation Workspace",
    "section.riskRadar": "Risk Radar",
    "section.sla": "SLA",
    "section.timeline": "Timeline (logs/hour)",
    "section.liveStatus": "Live Status",
    "section.alerts": "Alerts",
    "section.investigation": "Investigation",
    "section.logs": "Logs",
    "label.denseTables": "Dense Tables",
    "label.autoRefresh": "Auto-refresh",
    "label.start": "Start",
    "label.end": "End",
    "label.windowFull": "window: full",
    "label.methodAll": "Method (all)",
    "label.severityAll": "Severity (all)",
    "label.alertStatusAll": "Alert status (all)",
    "label.searchDetails": "Search (path/message/details)",
    "label.exactIp": "Exact IP",
    "label.savedViewName": "Saved view name",
    "label.caseTitle": "Case title",
    "label.owner": "Owner",
    "label.caseId": "Case ID",
    "label.author": "Author",
    "label.commentMessage": "Comment message",
    "label.scheduleName": "Schedule name",
    "label.hourUtc": "Hour UTC",
    "label.minuteUtc": "Minute UTC",
    "label.sinceHours": "Since hours",
    "label.filePath": "Log path (ex: data/sample.log)",
    "label.fromStart": "From start",
    "label.assetName": "Asset name",
    "label.assetIpCidr": "IP/CIDR (ex 10.0.0.0/24)",
    "label.assetPathPrefix": "Path prefix (ex /admin)",
    "label.ipOptional": "IP (optional)",
    "label.alertTypeOptional": "Alert type (optional)",
    "label.pathPatternOptional": "Path pattern (optional)",
    "label.reason": "Reason",
    "label.ttlMin": "TTL min",
    "label.iocValue": "IOC value",
    "label.policyName": "Policy name",
    "label.policyCondition": "Condition ex: severity==high AND alert_type==possible-bruteforce",
    "label.policyPayload": "Payload JSON ex: {\"owner\":\"soc-auto\",\"priority\":\"critical\"}",
    "label.paletteSearch": "Type command...",
    "label.username": "Username",
    "label.password": "Password",
    "label.language": "Language",
    "label.dashboardNavigation": "Dashboard Navigation",
    "label.investigationNavigation": "Investigation Navigation",
    "label.operationsNavigation": "Operations Navigation",
    "label.reportsNavigation": "Reports Navigation",
    "label.adminNavigation": "Admin Navigation",
    "login.required": "Authentication required.",
    "login.hint": "Default: Change_me / Change_me (change with env vars).",
    "status.shortcuts": "Shortcuts: Ctrl+K palette, / search, r refresh, t tail.",
    "status.workspaceHelp": "Drag separators to resize Alerts, Investigation, and Logs.",
    "status.noRiskData": "No risk data.",
    "status.noSlaData": "No SLA data.",
    "status.connecting": "ws: connecting...",
    "status.connected": "ws: connected",
    "status.disconnected": "ws: disconnected",
    "status.error": "ws: error",
    "status.unavailable": "ws: unavailable",
    "status.lastSync": "last sync: {time}",
    "status.noDelta": "No delta report loaded.",
    "status.noAlertSelected": "No alert selected.",
    "status.noCommand": "No command.",
    "status.noAssets": "No assets configured.",
    "status.noSuppressions": "No suppression rules.",
    "status.noIocs": "No IOC configured.",
    "status.noPolicies": "No policy configured.",
    "status.noBackups": "No backup run yet.",
    "status.noSavedViews": "No saved views yet.",
    "status.noCases": "No cases yet.",
    "status.noComments": "No comments.",
    "status.noSchedules": "No schedules yet.",
    "status.noAlertsForFilters": "No alerts for current filters.",
    "status.noLogsForFilters": "No logs for current filters.",
    "status.noIncidentEvents": "No incident events yet.",
    "status.noData": "No data",
    "status.noTrendData": "No trend data",
    "status.noSeverityData": "No severity data",
    "status.noTypeData": "No type data",
    "status.noIpData": "No IP data",
    "status.noLinkedCases": "No linked cases.",
    "status.noIocMatch": "No IOC match in local window.",
    "status.noPlaybook": "No playbook.",
    "status.selectLinkedCase": "Select a linked case to inspect it here.",
    "status.noRelatedLogs": "No related logs.",
    "status.noRelatedEvents": "No related events.",
    "status.none": "none",
    "status.liveTailRunning": "Live tail: RUNNING | file={file} | ingested={count}",
    "status.liveTailStopped": "Live tail: STOPPED{suffix}",
    "status.liveTailErrorSuffix": " | error={error}",
    "status.liveTailStatusError": "Live tail status error: {error}",
    "status.startFailed": "Start failed: {error}",
    "status.stopFailed": "Stop failed: {error}",
    "status.ingestResult": "Logs ingested: {ingested}, batch alerts: {batch}, inserted alerts: {inserted}",
    "status.dataResetDone": "Data reset completed.",
    "status.windowRange": "window: {start}-{end} / {total}",
    "toast.ingestionCompleted": "Ingestion completed",
    "toast.ingestionFailed": "Ingestion failed: {error}",
    "toast.dashboardRefreshed": "Dashboard refreshed",
    "toast.autoRefreshEnabled": "Auto-refresh enabled",
    "toast.autoRefreshPaused": "Auto-refresh paused",
    "toast.refreshInterval": "Refresh interval: {seconds}s",
    "toast.refreshFailed": "Refresh failed: {error}",
    "toast.resetDone": "All data reset",
    "toast.resetFailed": "Reset failed: {error}",
    "toast.assetAdded": "Asset added",
    "toast.assetAddFailed": "Add asset failed: {error}",
    "toast.suppressionAdded": "Suppression rule added",
    "toast.suppressionAddFailed": "Add suppression failed: {error}",
    "toast.iocAdded": "IOC added",
    "toast.iocAddFailed": "Add IOC failed: {error}",
    "toast.policyAdded": "Policy added",
    "toast.policyAddFailed": "Add policy failed: {error}",
    "toast.backupCreated": "Backup created",
    "toast.backupFailed": "Backup failed: {error}",
    "toast.backupRestored": "Backup restored",
    "toast.restoreFailed": "Restore failed: {error}",
    "toast.deltaRefreshed": "Delta report refreshed",
    "toast.deltaFailed": "Delta report failed: {error}",
    "toast.caseCreated": "Case created",
    "toast.caseCreateFailed": "Create case failed: {error}",
    "toast.scheduleCreated": "Schedule created",
    "toast.scheduleCreateFailed": "Create schedule failed: {error}",
    "toast.enterDslFirst": "Enter DSL query first",
    "toast.savedViewCreated": "Saved view created",
    "toast.saveViewFailed": "Save view failed: {error}",
    "toast.alertUpdated": "Alert {id} -> {status}",
    "toast.alertUpdateFailed": "Alert update failed: {error}",
    "toast.playbookLoadFailed": "Playbook load failed: {error}",
    "toast.investigationLoadFailed": "Investigation load failed: {error}",
    "toast.alertLinkedCase": "Alert {alertId} linked to case {caseId}",
    "toast.linkCaseFailed": "Link case failed: {error}",
    "toast.caseLoaded": "Loaded case {caseId}",
    "toast.caseDetailLoadFailed": "Case detail load failed: {error}",
    "toast.assetDeleted": "Asset {id} deleted",
    "toast.assetDeleteFailed": "Delete asset failed: {error}",
    "toast.suppressionDeleted": "Suppression {id} deleted",
    "toast.suppressionDeleteFailed": "Delete suppression failed: {error}",
    "toast.iocDeleted": "IOC {id} deleted",
    "toast.iocUpdated": "IOC {id} updated",
    "toast.iocActionFailed": "IOC action failed: {error}",
    "toast.policyDeleted": "Policy {id} deleted",
    "toast.policyUpdated": "Policy {id} updated",
    "toast.policyActionFailed": "Policy action failed: {error}",
    "toast.backupFileRestored": "Backup {file} restored",
    "toast.savedViewLoaded": "Saved view loaded",
    "toast.savedViewDeleted": "Saved view {id} deleted",
    "toast.deleteViewFailed": "Delete view failed: {error}",
    "toast.commentsLoaded": "Loaded comments for case {caseId}",
    "toast.loadCommentsFailed": "Load comments failed: {error}",
    "toast.caseUpdated": "Case {caseId} -> {status}",
    "toast.caseUpdateFailed": "Case update failed: {error}",
    "toast.caseIdRequired": "Case ID is required",
    "toast.commentMessageRequired": "Comment message is required",
    "toast.commentAdded": "Comment added to case {caseId}",
    "toast.commentAddFailed": "Add comment failed: {error}",
    "toast.commentDeleted": "Comment {commentId} deleted",
    "toast.commentDeleteFailed": "Delete comment failed: {error}",
    "toast.scheduleExecuted": "Schedule {id} executed",
    "toast.scheduleUpdated": "Schedule {id} updated",
    "toast.scheduleDeleted": "Schedule {id} deleted",
    "toast.scheduleActionFailed": "Schedule action failed: {error}",
    "toast.liveTailStarted": "Live tail started",
    "toast.liveTailStopped": "Live tail stopped",
    "toast.liveTailStartFailed": "Live tail start failed: {error}",
    "toast.liveTailStopFailed": "Live tail stop failed: {error}",
    "toast.manualRefresh": "Manual refresh",
    "toast.investigationLoaded": "Loaded investigation for alert {alertId}",
    "prompt.resolutionNote": "Resolution note (optional):",
    "prompt.caseIdToLink": "Case ID to link:",
    "confirm.resetData": "Delete all logs and alerts?",
    "confirm.restoreLatest": "Restore latest backup and overwrite current DB?",
    "confirm.restoreBackup": "Restore backup {file}?",
    "table.time": "Time",
    "table.severity": "Severity",
    "table.type": "Type",
    "table.mitre": "MITRE",
    "table.asset": "Asset",
    "table.ip": "IP",
    "table.occ": "Occ.",
    "table.status": "Status",
    "table.assignee": "Assignee",
    "table.actions": "Actions",
    "table.details": "Details",
    "table.method": "Method",
    "table.path": "Path",
    "table.ua": "UA",
    "table.id": "ID",
    "table.title": "Title",
    "table.priority": "Priority",
    "table.owner": "Owner",
    "table.alerts": "Alerts",
    "table.enabled": "Enabled",
    "table.lastRun": "Last Run",
    "table.timeUtc": "Time (UTC)",
    "table.actor": "Actor",
    "context.stats": "Stats",
    "context.totalLogs": "Total Logs",
    "context.totalAlerts": "Total Alerts",
    "context.highAlerts": "High Alerts",
    "context.failedLogins": "Failed Logins",
    "context.bruteforce": "Bruteforce",
    "context.compromise": "Compromise",
    "context.uniqueIps": "Unique IPs",
    "context.http5xx": "HTTP 5xx",
    "context.openAlerts": "Open Alerts",
    "context.resolvedAlerts": "Resolved Alerts",
    "context.criticalOpenAssets": "Critical Open Assets",
    "context.topIps": "Top IPs",
    "context.topUserAgents": "Top User-Agents",
    "context.topRiskyIps": "Top Risky IPs",
    "context.trafficTrend": "Traffic Trend",
    "context.window": "Window",
    "context.volume": "Volume",
    "context.openCritical": "Open/Critical",
    "context.generated": "Generated",
    "context.bySeverity": "By Severity",
    "context.byType": "By Type",
    "context.casesTotal": "Cases Total",
    "context.alertsTotal": "Alerts Total",
    "context.mtta": "MTTA (min avg)",
    "context.mttr": "MTTR (min avg)",
    "context.openHighAlerts": "Open High Alerts",
    "context.topRiskyUsers": "Top Risky Users",
    "context.topRiskyAssets": "Top Risky Assets",
    "context.alertSummary": "Alert Summary",
    "context.linkedCases": "Linked Cases",
    "context.iocMatches": "IOC Matches",
    "context.caseDetail": "Case Detail",
    "context.relatedLogs": "Related Logs",
    "context.relatedEvents": "Related Events",
    "context.assetBox": "Asset",
    "context.playbook": "Playbook",
    "context.time": "Time",
    "context.user": "User",
    "context.occurrences": "Occurrences",
    "context.why": "Why",
    "context.name": "Name",
    "context.criticality": "Criticality",
    "context.pathScope": "Path Scope",
    "context.ipScope": "IP Scope",
    "context.description": "Description",
    "context.comments": "Comments",
    "context.caseActions": "Actions",
    "context.lastHoursFrom": "Last {hours}h from {ts}",
    "context.logsAlertsVolume": "Logs={logs} Alerts={alerts}",
    "context.openCriticalHigh": "Open={open} Critical={critical} High={high}",
    "context.lastHours": "Last {hours}h",
    "context.yes": "yes",
    "context.no": "no",
    "palette.refreshDashboard": "Refresh dashboard",
    "palette.focusSearch": "Focus search",
    "palette.openDailyReport": "Open daily report",
    "palette.toggleDenseTables": "Toggle dense tables",
    "palette.toggleLeftPanel": "Toggle left panel",
    "palette.toggleRightPanel": "Toggle right panel",
    "palette.gotoAlerts": "Go to alerts",
    "palette.gotoTimeline": "Go to timeline",
    "palette.gotoRiskRadar": "Go to risk radar",
  },
};

for (const code of ["fr", "de", "es", "ja", "zh", "hi", "ar", "ru"]) {
  SOC_TRANSLATIONS[code] = { ...SOC_TRANSLATIONS.en, meta: { ...SOC_TRANSLATIONS.en.meta } };
}

Object.assign(SOC_TRANSLATIONS.fr, { meta: { label: "Français", flag: "🇫🇷", dir: "ltr" }, "title.login": "Connexion - Mini SOC Dashboard", "hero.subtitle": "Ingestion, détection et investigation des événements suspects en temps réel.", "action.logout": "Déconnexion", "action.login": "Connexion", "action.apply": "Appliquer", "action.refreshNow": "Rafraîchir", "action.import": "Importer", "action.saveView": "Sauvegarder la vue", "action.createCase": "Créer un cas", "action.addComment": "Ajouter un commentaire", "action.loadComments": "Charger les commentaires", "nav.overview": "Vue d’ensemble", "nav.investigations": "Investigations", "nav.operations": "Opérations", "nav.reports": "Rapports", "quick.openAlerts": "Alertes ouvertes", "quick.highSeverity": "Haute sévérité", "quick.compromiseFlags": "Indicateurs de compromission", "quick.criticalAssetsOpen": "Actifs critiques ouverts", "section.huntFilters": "Filtres de chasse", "section.investigationWorkspace": "Espace d’investigation", "section.scheduledReports": "Rapports planifiés", "section.deltaReport": "Rapport delta", "section.backupRestore": "Sauvegarde et restauration", "section.liveStatus": "Statut temps réel", "label.denseTables": "Tables compactes", "label.autoRefresh": "Rafraîchissement auto", "label.searchDetails": "Recherche (path/message/details)", "login.required": "Authentification requise.", "status.shortcuts": "Raccourcis : palette Ctrl+K, recherche /, rafraîchir r, tail t.", "status.workspaceHelp": "Faites glisser les séparateurs pour redimensionner Alertes, Investigation et Logs.", "status.noRiskData": "Aucune donnée de risque.", "status.noSlaData": "Aucune donnée SLA.", "status.noDelta": "Aucun rapport delta chargé.", "status.noAlertSelected": "Aucune alerte sélectionnée.", "prompt.resolutionNote": "Note de résolution (optionnel) :", "prompt.caseIdToLink": "ID du cas à lier :", "confirm.resetData": "Supprimer toutes les logs et alertes ?", "confirm.restoreLatest": "Restaurer la dernière sauvegarde et écraser la base actuelle ?", "context.stats": "Statistiques" });
Object.assign(SOC_TRANSLATIONS.de, { meta: { label: "Deutsch", flag: "🇩🇪", dir: "ltr" }, "hero.subtitle": "Erfassung, Erkennung und Untersuchung verdächtiger Ereignisse in Echtzeit.", "action.logout": "Abmelden", "action.login": "Anmelden", "action.apply": "Anwenden", "action.refreshNow": "Jetzt aktualisieren", "nav.overview": "Übersicht", "nav.reports": "Berichte", "quick.openAlerts": "Offene Alarme", "quick.highSeverity": "Hohe Priorität", "quick.compromiseFlags": "Kompromittierungsmarker", "quick.criticalAssetsOpen": "Offene kritische Assets", "section.huntFilters": "Hunt-Filter", "section.liveStatus": "Live-Status", "label.autoRefresh": "Auto-Aktualisierung", "login.required": "Authentifizierung erforderlich." });
Object.assign(SOC_TRANSLATIONS.es, { meta: { label: "Español", flag: "🇪🇸", dir: "ltr" }, "hero.subtitle": "Ingesta, detección e investigación de eventos sospechosos en tiempo real.", "action.logout": "Cerrar sesión", "action.login": "Iniciar sesión", "action.apply": "Aplicar", "action.refreshNow": "Actualizar ahora", "nav.overview": "Resumen", "nav.reports": "Informes", "quick.openAlerts": "Alertas abiertas", "quick.highSeverity": "Alta severidad", "quick.compromiseFlags": "Indicadores de compromiso", "quick.criticalAssetsOpen": "Activos críticos abiertos", "section.huntFilters": "Filtros de caza", "section.liveStatus": "Estado en vivo", "label.autoRefresh": "Autoactualización", "login.required": "Autenticación requerida." });
Object.assign(SOC_TRANSLATIONS.ja, { meta: { label: "日本語", flag: "🇯🇵", dir: "ltr" }, "hero.eyebrow": "セキュリティオペレーションセンター", "hero.subtitle": "不審イベントの取り込み、検知、調査をリアルタイムで実行します。", "action.wallboard": "ウォールボード", "action.logout": "ログアウト", "action.login": "ログイン", "action.apply": "適用", "action.refreshNow": "今すぐ更新", "nav.overview": "概要", "nav.investigations": "調査", "nav.operations": "運用", "nav.reports": "レポート", "quick.openAlerts": "未解決アラート", "quick.highSeverity": "高重大度", "quick.compromiseFlags": "侵害フラグ", "quick.criticalAssetsOpen": "対応中の重要資産", "section.liveStatus": "ライブ状態", "label.autoRefresh": "自動更新", "login.required": "認証が必要です。" });
Object.assign(SOC_TRANSLATIONS.zh, { meta: { label: "中文", flag: "🇨🇳", dir: "ltr" }, "hero.eyebrow": "安全运营中心", "hero.subtitle": "实时摄取、检测并调查可疑事件。", "action.wallboard": "大屏", "action.logout": "退出登录", "action.login": "登录", "action.apply": "应用", "action.refreshNow": "立即刷新", "nav.overview": "总览", "nav.investigations": "调查", "nav.operations": "运维", "nav.reports": "报告", "quick.openAlerts": "未关闭告警", "quick.highSeverity": "高危等级", "quick.compromiseFlags": "失陷标记", "quick.criticalAssetsOpen": "开放中的关键资产", "section.liveStatus": "实时状态", "label.autoRefresh": "自动刷新", "login.required": "需要身份验证。" });
Object.assign(SOC_TRANSLATIONS.hi, { meta: { label: "हिन्दी", flag: "🇮🇳", dir: "ltr" }, "hero.subtitle": "संदिग्ध घटनाओं का इनजेशन, डिटेक्शन और जांच रीयल-टाइम में।", "action.logout": "लॉगआउट", "action.login": "लॉगिन", "action.apply": "लागू करें", "action.refreshNow": "अभी रिफ्रेश करें", "nav.overview": "ओवरव्यू", "nav.investigations": "जांच", "nav.operations": "ऑपरेशंस", "nav.reports": "रिपोर्ट्स", "quick.openAlerts": "खुले अलर्ट", "quick.highSeverity": "उच्च गंभीरता", "quick.compromiseFlags": "समझौता संकेत", "quick.criticalAssetsOpen": "खुले महत्वपूर्ण एसेट", "section.liveStatus": "लाइव स्थिति", "label.autoRefresh": "ऑटो-रिफ्रेश", "login.required": "प्रमाणीकरण आवश्यक है।" });
Object.assign(SOC_TRANSLATIONS.ar, { meta: { label: "العربية", flag: "🇸🇦", dir: "rtl" }, "hero.eyebrow": "مركز عمليات الأمن", "hero.subtitle": "استيعاب وكشف والتحقيق في الأحداث المشبوهة في الوقت الفعلي.", "action.wallboard": "لوحة الحائط", "action.logout": "تسجيل الخروج", "action.login": "تسجيل الدخول", "action.apply": "تطبيق", "action.refreshNow": "تحديث الآن", "nav.overview": "نظرة عامة", "nav.investigations": "التحقيقات", "nav.operations": "العمليات", "nav.reports": "التقارير", "quick.openAlerts": "التنبيهات المفتوحة", "quick.highSeverity": "شدة عالية", "quick.compromiseFlags": "مؤشرات اختراق", "quick.criticalAssetsOpen": "الأصول الحرجة المفتوحة", "section.liveStatus": "الحالة المباشرة", "label.autoRefresh": "تحديث تلقائي", "login.required": "المصادقة مطلوبة." });
Object.assign(SOC_TRANSLATIONS.ru, { meta: { label: "Русский", flag: "🇷🇺", dir: "ltr" }, "hero.subtitle": "Прием, обнаружение и расследование подозрительных событий в реальном времени.", "action.logout": "Выйти", "action.login": "Войти", "action.apply": "Применить", "action.refreshNow": "Обновить", "nav.overview": "Обзор", "nav.investigations": "Расследования", "nav.operations": "Операции", "nav.reports": "Отчеты", "quick.openAlerts": "Открытые алерты", "quick.highSeverity": "Высокая критичность", "quick.compromiseFlags": "Признаки компрометации", "quick.criticalAssetsOpen": "Открытые критичные активы", "section.liveStatus": "Статус в реальном времени", "label.autoRefresh": "Автообновление", "login.required": "Требуется аутентификация." });

const STATIC_BINDINGS = [
  [".hero-title .eyebrow", "hero.eyebrow"],
  [".hero-title h1", "title.app"],
  [".hero-sub", "hero.subtitle"],
  [".live-dot", "status.online"],
  [".page-tab[href='/overview']", "nav.overview"],
  [".page-tab[href='/investigations']", "nav.investigations"],
  [".page-tab[href='/operations']", "nav.operations"],
  [".page-tab[href='/reports']", "nav.reports"],
  [".page-tab[href='/admin']", "nav.admin"],
  ["#quickOpenAlerts", null],
  [".quick-item:nth-of-type(1) p", "quick.openAlerts"],
  [".quick-item:nth-of-type(2) p", "quick.highSeverity"],
  [".quick-item:nth-of-type(3) p", "quick.compromiseFlags"],
  [".quick-item:nth-of-type(4) p", "quick.criticalAssetsOpen"],
  ["button.secondary[type='submit']", "action.logout"],
  ["a[href='/wallboard']", "action.wallboard"],
  ["#toggleLeftSidebar", "action.leftPanel"],
  ["#toggleRightSidebar", "action.rightPanel"],
  ["#openPalette", "action.commandPalette"],
  ["label[for='denseModeToggle']", "label.denseTables"],
  ["#refreshNow", "action.refreshNow"],
  ["#applyFilters", "action.apply"],
  ["#saveView", "action.saveView"],
  ["#scrollTopButton", "action.top"],
  ["#closePalette", "action.close"],
  [".login-card h1", "title.app"],
  [".login-card p:not(.hint):not(.error)", "login.required"],
  [".login-card button[type='submit']", "action.login"],
  [".login-card .hint", "login.hint"],
];

const PLACEHOLDER_BINDINGS = [
  ["#tailPath", "label.filePath"],
  ["#q", "label.searchDetails"],
  ["#ip", "label.exactIp"],
  ["#savedViewName", "label.savedViewName"],
  ["#assetName", "label.assetName"],
  ["#assetIpCidr", "label.assetIpCidr"],
  ["#assetPathPrefix", "label.assetPathPrefix"],
  ["#assetOwner", "label.owner"],
  ["#supIp", "label.ipOptional"],
  ["#supType", "label.alertTypeOptional"],
  ["#supPath", "label.pathPatternOptional"],
  ["#supReason", "label.reason"],
  ["#supTtl", "label.ttlMin"],
  ["#iocValue", "label.iocValue"],
  ["#policyName", "label.policyName"],
  ["#policyCondition", "label.policyCondition"],
  ["#policyPayload", "label.policyPayload"],
  ["#caseTitle", "label.caseTitle"],
  ["#caseOwner", "label.owner"],
  ["#commentCaseId", "label.caseId"],
  ["#commentAuthor", "label.author"],
  ["#commentMessage", "label.commentMessage"],
  ["#schedName", "label.scheduleName"],
  ["#schedHour", "label.hourUtc"],
  ["#schedMinute", "label.minuteUtc"],
  ["#deltaSinceHours", "label.sinceHours"],
  ["#paletteSearch", "label.paletteSearch"],
  ["input[name='username']", "label.username"],
  ["input[name='password']", "label.password"],
];

function interpolate(template, vars = {}) {
  return String(template).replace(/\{(\w+)\}/g, (_, key) => String(vars[key] ?? `{${key}}`));
}

function getLanguage() {
  const raw = window.localStorage.getItem("soc_lang") || "en";
  return SOC_TRANSLATIONS[raw] ? raw : "en";
}

function getDictionary(lang = getLanguage()) {
  return SOC_TRANSLATIONS[lang] || SOC_TRANSLATIONS.en;
}

function t(key, vars = {}, lang = getLanguage()) {
  const dict = getDictionary(lang);
  const base = SOC_TRANSLATIONS.en[key] ?? key;
  const value = dict[key] ?? base;
  return interpolate(value, vars);
}

function setText(selector, value) {
  const node = document.querySelector(selector);
  if (node) node.textContent = value;
}

function setLabelText(selector, value) {
  const node = document.querySelector(selector);
  if (!node) return;
  const input = node.querySelector("input, select");
  if (!input) {
    node.textContent = value;
    return;
  }
  const textNode = Array.from(node.childNodes).find((child) => child.nodeType === Node.TEXT_NODE);
  if (textNode) {
    textNode.textContent = ` ${value}`;
  } else {
    node.append(document.createTextNode(` ${value}`));
  }
}

function applyStaticBindings(lang = getLanguage()) {
  STATIC_BINDINGS.forEach(([selector, key]) => {
    if (!key) return;
    setText(selector, t(key, {}, lang));
  });
  PLACEHOLDER_BINDINGS.forEach(([selector, key]) => {
    const node = document.querySelector(selector);
    if (node) node.setAttribute("placeholder", t(key, {}, lang));
  });
}

function applyOptionTranslations(lang = getLanguage()) {
  const map = [
    ["#method option[value='']", "label.methodAll"],
    ["#severity option[value='']", "label.severityAll"],
    ["#alertStatus option[value='']", "label.alertStatusAll"],
  ];
  map.forEach(([selector, key]) => setText(selector, t(key, {}, lang)));
}

function applyHeadings(lang = getLanguage()) {
  const body = document.body;
  const leftNavTitle = document.querySelector(".panel-left .side-nav-card h2");
  const rightNavTitle = document.querySelector(".panel-right .side-nav-card h2");
  const byId = {
    "sec-ingestion": "section.ingestion",
    "sec-live-tail": "section.liveTail",
    "sec-assets": "section.assets",
    "sec-suppressions": "section.suppressions",
    "sec-iocs": "section.iocWatchlist",
    "sec-policies": "section.policyEngine",
    "sec-backups": "section.backupRestore",
    "sec-control": "section.controlCenter",
    "sec-ops-tools": "section.operationsToolkit",
    "sec-workspace": "section.investigationWorkspace",
    "sec-hunt": "section.huntFilters",
    "sec-risk": "section.riskRadar",
    "sec-sla": "section.sla",
    "sec-timeline": "section.timeline",
    "sec-incidents": "section.incidentTimeline",
    "sec-cases": "section.cases",
    "sec-case-comments": "section.caseComments",
    "sec-schedules": "section.scheduledReports",
    "sec-delta": "section.deltaReport",
  };
  Object.entries(byId).forEach(([id, key]) => {
    const section = document.getElementById(id);
    if (!section) return;
    const title = section.querySelector("h2, h3");
    if (title) title.textContent = t(key, {}, lang);
  });
  if (document.querySelector("#sec-alerts h3")) setText("#sec-alerts h3", t("section.alerts", {}, lang));
  if (document.querySelector("#sec-drilldown h3")) setText("#sec-drilldown h3", t("section.investigation", {}, lang));
  if (document.querySelector("#sec-logs h3")) setText("#sec-logs h3", t("section.logs", {}, lang));
  const sideNavMap = {
    "#sec-control": "section.controlCenter",
    "#sec-live-tail": "section.liveTail",
    "#sec-workspace": "section.workspace",
    "#sec-hunt": "section.huntFilters",
    "#sec-incidents": "section.incidentTimeline",
    "#sec-ingestion": "section.ingestion",
    "#sec-assets": "section.assets",
    "#sec-suppressions": "section.suppressions",
    "#sec-iocs": "section.iocWatchlist",
    "#sec-policies": "section.policyEngine",
    "#sec-cases": "section.cases",
    "#sec-case-comments": "section.caseComments",
    "#sec-schedules": "section.scheduledReports",
    "#sec-delta": "section.deltaReport",
    "#sec-backups": "section.backupRestore",
    "#sec-alerts": "section.alerts",
    "#sec-drilldown": "section.investigation",
    "#sec-logs": "section.logs",
    "#sec-risk": "section.riskRadar",
    "#sec-sla": "section.sla",
  };
  document.querySelectorAll(".section-nav-link").forEach((link) => {
    const href = link.getAttribute("href");
    if (!href) return;
    const key = sideNavMap[href];
    if (key) link.textContent = t(key, {}, lang);
  });
  const tableHeaders = [
    ["#sec-alerts thead th:nth-of-type(1)", "table.time"],
    ["#sec-alerts thead th:nth-of-type(2)", "table.severity"],
    ["#sec-alerts thead th:nth-of-type(3)", "table.type"],
    ["#sec-alerts thead th:nth-of-type(4)", "table.mitre"],
    ["#sec-alerts thead th:nth-of-type(5)", "table.asset"],
    ["#sec-alerts thead th:nth-of-type(6)", "table.ip"],
    ["#sec-alerts thead th:nth-of-type(7)", "table.occ"],
    ["#sec-alerts thead th:nth-of-type(8)", "table.status"],
    ["#sec-alerts thead th:nth-of-type(9)", "table.assignee"],
    ["#sec-alerts thead th:nth-of-type(10)", "table.actions"],
    ["#sec-alerts thead th:nth-of-type(11)", "table.details"],
    ["#sec-logs thead th:nth-of-type(1)", "table.time"],
    ["#sec-logs thead th:nth-of-type(2)", "table.ip"],
    ["#sec-logs thead th:nth-of-type(3)", "table.method"],
    ["#sec-logs thead th:nth-of-type(4)", "table.path"],
    ["#sec-logs thead th:nth-of-type(5)", "table.status"],
    ["#sec-cases thead th:nth-of-type(1)", "table.id"],
    ["#sec-cases thead th:nth-of-type(2)", "table.title"],
    ["#sec-cases thead th:nth-of-type(3)", "table.priority"],
    ["#sec-cases thead th:nth-of-type(4)", "table.status"],
    ["#sec-cases thead th:nth-of-type(5)", "table.owner"],
    ["#sec-cases thead th:nth-of-type(6)", "table.alerts"],
    ["#sec-cases thead th:nth-of-type(7)", "table.actions"],
    ["#sec-schedules thead th:nth-of-type(1)", "table.id"],
    ["#sec-schedules thead th:nth-of-type(2)", "table.name"],
    ["#sec-schedules thead th:nth-of-type(3)", "table.timeUtc"],
    ["#sec-schedules thead th:nth-of-type(4)", "table.enabled"],
    ["#sec-schedules thead th:nth-of-type(5)", "table.lastRun"],
    ["#sec-schedules thead th:nth-of-type(6)", "table.actions"],
    ["#sec-incidents thead th:nth-of-type(1)", "table.time"],
    ["#sec-incidents thead th:nth-of-type(2)", "table.type"],
    ["#sec-incidents thead th:nth-of-type(3)", "table.severity"],
    ["#sec-incidents thead th:nth-of-type(4)", "table.ip"],
    ["#sec-incidents thead th:nth-of-type(5)", "table.title"],
    ["#sec-incidents thead th:nth-of-type(6)", "table.actor"],
    ["#sec-incidents thead th:nth-of-type(7)", "table.details"],
  ];
  tableHeaders.forEach(([selector, key]) => setText(selector, t(key, {}, lang)));
  setLabelText("#sec-control .check:nth-of-type(1)", t("label.denseTables", {}, lang));
  setLabelText("#sec-control .check:nth-of-type(2)", t("label.autoRefresh", {}, lang));
  setLabelText("#sec-live-tail .check", t("label.fromStart", {}, lang));
  setLabelText("#sec-timeline .check:nth-of-type(1)", t("label.start", {}, lang));
  setLabelText("#sec-timeline .check:nth-of-type(2)", t("label.end", {}, lang));
  setText(".workspace-head .status-line", t("status.workspaceHelp", {}, lang));
  setText("#sec-control .status-line", t("status.shortcuts", {}, lang));
  setText("#riskPanel .status-line", t("status.noRiskData", {}, lang));
  setText("#slaPanel .status-line", t("status.noSlaData", {}, lang));
  setText("#deltaReportPanel .status-line", t("status.noDelta", {}, lang));
  setText("#alertContextPanel .status-line", t("status.noAlertSelected", {}, lang));
  if (body.classList.contains("page-investigations")) {
    if (leftNavTitle) leftNavTitle.textContent = t("label.investigationNavigation", {}, lang);
    if (rightNavTitle) rightNavTitle.textContent = t("label.investigationNavigation", {}, lang);
  } else if (body.classList.contains("page-operations")) {
    if (leftNavTitle) leftNavTitle.textContent = t("label.operationsNavigation", {}, lang);
  } else if (body.classList.contains("page-reports")) {
    if (leftNavTitle) leftNavTitle.textContent = t("label.reportsNavigation", {}, lang);
  } else if (body.classList.contains("page-admin")) {
    if (leftNavTitle) leftNavTitle.textContent = t("label.adminNavigation", {}, lang);
  } else {
    if (rightNavTitle) rightNavTitle.textContent = t("label.dashboardNavigation", {}, lang);
  }
}

function applyReportLinks(lang = getLanguage()) {
  document.querySelectorAll("[data-report-link]").forEach((link) => {
    const baseHref = link.getAttribute("data-report-link") || "/reports/daily";
    link.setAttribute("href", `${baseHref}?lang=${encodeURIComponent(lang)}`);
    if (!link.dataset.i18nBound) {
      link.dataset.i18nBound = "1";
      link.textContent = t("action.dailyReport", {}, lang);
    } else {
      link.textContent = t("action.dailyReport", {}, lang);
    }
  });
}

function applyTitle(lang = getLanguage()) {
  const isLogin = document.querySelector(".login-card");
  document.title = isLogin ? t("title.login", {}, lang) : t("title.app", {}, lang);
}

function syncDocumentLanguage(lang = getLanguage()) {
  const meta = getDictionary(lang).meta || {};
  document.documentElement.lang = lang;
  document.documentElement.dir = meta.dir || "ltr";
}

function populateLanguageSelects() {
  const current = getLanguage();
  document.querySelectorAll("[data-language-select]").forEach((select) => {
    if (!(select instanceof HTMLSelectElement)) return;
    select.innerHTML = Object.entries(SOC_TRANSLATIONS)
      .map(([code, dict]) => `<option value="${code}">${dict.meta.flag} ${dict.meta.label}</option>`)
      .join("");
    select.value = current;
    select.onchange = () => setLanguage(select.value);
  });
}

function applyTranslations(lang = getLanguage()) {
  syncDocumentLanguage(lang);
  populateLanguageSelects();
  applyStaticBindings(lang);
  applyOptionTranslations(lang);
  applyHeadings(lang);
  applyReportLinks(lang);
  applyTitle(lang);
  setText("[data-language-label]", t("label.language", {}, lang));
  setText("#timelineRangeLabel[data-pristine='true']", t("label.windowFull", {}, lang));
}

function setLanguage(lang) {
  const next = SOC_TRANSLATIONS[lang] ? lang : "en";
  window.localStorage.setItem("soc_lang", next);
  applyTranslations(next);
  window.dispatchEvent(new CustomEvent("soc:languagechange", { detail: { lang: next } }));
}

window.SOC_I18N = {
  t,
  getLanguage,
  setLanguage,
  applyTranslations,
};

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => applyTranslations());
} else {
  applyTranslations();
}
