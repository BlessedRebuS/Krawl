# Graph Report - Krawl  (2026-10-04)

## Corpus Check
- 270 files · ~387,129 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 13 file(s) not represented in the graph (top: (none) 7, .conf 2, .tpl 1)

## Summary
- 2187 nodes · 4915 edges · 122 communities (90 shown, 32 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 479 edges (avg confidence: 0.89)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- SQLAlchemy Models & Hot Cache
- IP Stats Repository
- DatabaseManager Core
- APScheduler Task Runner
- CI/CD Workflows
- App Lifespan & Startup
- Cached Paginated Tables
- Deception Attack Responses
- Helm Chart & Deployment
- Banlist & Campaign Panels
- Attack Map Frontend
- Config & Server IP
- Database Package & Ban Cleanup
- Request Metadata Extraction
- Cloudflare Webhooks
- Dashboard Auth & Sessions
- Access Log Repo & Pagination
- Analytics Repository
- Banlist Source Refresh
- Test Fixtures & Conftest
- Metrics Counters
- Payload Repo & Clustering
- Generated Page Model & Auth
- Dashboard JS Controller
- Cache Batch Tests
- Task Lock Tests
- Write Buffer Metrics
- Auth Attempt Store
- Fake File Generators
- FastAPI App Factory
- Dashboard Cache Reads
- Dashboard API Routes
- Campaign Charts JS
- Templating & Brand Dependencies
- Config Env Overrides
- Ban Cache Tests
- DB Engine & Maintenance
- Banlist Federation via Redis
- Attack Types Screenshots
- Cloudflare & Deception Screenshots
- Fake Login Pages
- SQLite to Postgres Migration
- Buffer Recovery Tests
- Scheduled Maintenance Tasks
- Fake IP Insert Tests
- TLSH Payload Similarity
- Suspicious Activity Fragments
- Geolocation Utilities
- Payload Hashing Task
- Architecture Docs
- IP Insight Screenshots
- SQLi Deception Screenshots
- Generated Page Repository
- IP Detail Fragments
- Domain Link Map
- Banlist Formatting & CDN Exclusion
- Dashboard Navigation JS
- Banlist Publish Tests
- SQL Injection Deception
- Request Memory Bound Tests
- AI Deception Pages
- Middleware Pipeline Docs
- Credential Capture
- Dashboard Design Docs
- Dashboard API Docs
- Logger Manager
- IP Utilities & Ignore Lists
- Backup & Page Limit Tests
- Threat Data Seeder
- Dashboard Cache Writes
- Generated Content-Type Tests
- Live Attack Map Tests
- Database Dump Task
- Metrics & Grafana Docs
- Cloudflare Sync Docs
- Grafana Dashboard Builder
- In-Process Ban Cache
- Ban Check Middleware
- Raw Request Attachments
- Raw Request Viewer JS
- Upload Tracking Tests
- Dashboard Page Templates
- Tarpit & Canary Tokens
- Firewall Exporter Docs
- Threat Capture Tests
- XSS Deception
- Firewall Banlist Formatters
- IP Enrichment APIs
- Request Body Size Cap
- Cached Count Tests
- Dashboard Route Tests
- Fake DB Test Helper
- Auth Dependency
- Tracked IP Model
- Captured Payload Model
- Attack Test Script
- Settings & Upload Modals
- Task Lease Claims
- Field Visibility Helpers
- Design Tokens JS
- Wordlists Loader
- Ignored IP Bypass Test
- Auth Modal JS
- Zip Upload Processing
- Container Entrypoint
- Krawl Logo
- iptables Plugin Script
- nftables Plugin Script
- Age Format Filter
- Size Format Filter
- Timestamp Format Filter
- Day Parsing Helper
- Export URL Helpers
- Timeout Countdown JS
- Task Runner JS
- Credentials Test Script
- Stats Cards

## God Nodes (most connected - your core abstractions)
1. `get_app_logger()` - 109 edges
2. `get_config()` - 100 edges
3. `get()` - 91 edges
4. `get_db()` - 68 edges
5. `get_database()` - 56 edges
6. `get_templates()` - 50 edges
7. `DatabaseManager` - 47 edges
8. `IpStatsRepo` - 45 edges
9. `sanitize_ip()` - 45 edges
10. `AccessLog` - 41 edges

## Surprising Connections (you probably didn't know these)
- `test_advanced_search_combines_fields_headers_and_pagination()` --uses--> `AccessLog`  [INFERRED]
  tests/test_advanced_search.py → src/models.py
- `_map_tiles()` --shares_data_with--> `window.__MAP_TILES__ Server-Side Tile Config`  [INFERRED]
  src/routes/dashboard.py → src/templates/jinja2/base.html
- `htmx_top_ua()` --references--> `Top User-Agents Table`  [INFERRED]
  src/routes/htmx.py → src/templates/jinja2/dashboard/partials/top_ua_table.html
- `main()` --references--> `Honeypot robots.txt Disallow List`  [AMBIGUOUS]
  src/tasks/analyze_ips.py → src/templates/html/robots.txt
- `PR Build Docker Job` --semantically_similar_to--> `Standalone Dev Compose Stack`  [INFERRED] [semantically similar]
  .github/workflows/pr-checks.yml → docker/dev/docker-compose.standalone.dev.yaml

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Chart appVersion-driven image and chart release sync** — _github_workflows_docker_build_push_build_and_push, _github_workflows_helm_package_push_package_and_push, _github_workflows_kubernetes_validation_validate_helm, helm_chart_yaml_appversion [EXTRACTED 1.00]
- **Firewall integrations consuming export-ips API** — readme_export_ips_api, plugins_iptables_readme_iptables_integration, plugins_nftables_readme_nftables_integration, plugins_fail2ban_readme_fail2ban_integration, _github_workflows_update_banlist_fetch_and_pr [EXTRACTED 1.00]
- **Scalable mode deployment variants (Postgres + Redis)** — readme_scalable_mode, docker_compose_scalable_stack, docker_docker_compose_scalable_stack, docker_dev_docker_compose_scalable_dev_stack, kubernetes_krawl_all_in_one_deploy_krawl_deployment [INFERRED 0.95]
- **Scalable Mode Shared State via Redis** — docs_deployment_modes_scalable_mode, docs_deployment_modes_redis_cache_tiers, docs_deployment_modes_single_pod_task_lease, docs_deployment_modes_max_aggregation_metrics, docs_dashboard_dashboard_authentication [INFERRED 0.85]
- **Banlist Distribution to Edge/Firewalls** — docs_architecture_ip_categories, docs_dashboard_api_export_ips_endpoint, docs_firewall_exporters_formats_registry, docs_architecture_sync_cloudflare_task, docs_cloudflare_banlist_cloudflare_account_ip_list, docs_firewall_exporters_cdn_exclusion [INFERRED 0.85]
- **Crawler Resource-Wasting Mechanisms** — docs_tarpit_tarpit, docs_tarpit_word_salad, docs_tarpit_infinite_pages_for_malicious, docs_ai_generation_ai_generated_deception_pages, docs_honeypot_sqli_xss_detection [INFERRED 0.75]
- **Scalable mode stack: Deployment + bundled PostgreSQL + Redis** — helm_templates_deployment, helm_templates_postgres, helm_templates_redis, helm_templates_deployment_wait_for_postgres, helm_templates_deployment_wait_for_redis, helm_readme_scalable_mode [INFERRED 0.85]
- **Standalone-to-scalable migration flow** — helm_templates_pvc, helm_templates_migration_job, helm_templates_migration_job_migrate_sqlite_to_postgres, helm_templates_postgres [EXTRACTED 1.00]
- **Observability tied to fixed dashboard secret_path** — helm_templates_servicemonitor, helm_templates_servicemonitor_metrics_endpoint, helm_templates_deployment_startup_probe, helm_readme_dashboard_secret_path, helm_templates_grafana_dashboard [INFERRED 0.85]
- **Honeypot credential capture flow** — src_templates_html_login_form, src_templates_html_wp_login, src_templates_html_phpmyadmin, src_routes_honeypot_credential_capture_post, src_templates_html_login_error [INFERRED 0.85]
- **IP detail page composition** — src_templates_jinja2_dashboard_ip, src_templates_jinja2_base, src_templates_jinja2_dashboard_partials__ip_detail, src_templates_jinja2_dashboard_partials__brand, src_templates_jinja2_dashboard_partials__contact [EXTRACTED 1.00]
- **Ban Management UI** — src_templates_jinja2_dashboard_partials_banlist_panel, src_templates_jinja2_dashboard_partials_ban_attackers_table, src_templates_jinja2_dashboard_partials_ban_overrides_table, src_templates_jinja2_dashboard_partials_ban_override [EXTRACTED 1.00]
- **Deception Templates Management UI** — src_templates_jinja2_dashboard_partials_deception_panel, src_templates_jinja2_dashboard_partials_deception_panel_with_message, src_templates_jinja2_dashboard_partials_generated_pages_table, src_templates_jinja2_dashboard_partials_generated_pages_table_readonly [EXTRACTED 1.00]
- **Campaign Investigation Drill-down Flow** — src_templates_jinja2_dashboard_partials_pattern_clusters_table, src_templates_jinja2_dashboard_partials_expand_overlay, src_templates_jinja2_dashboard_partials_cluster_events_table, src_templates_jinja2_dashboard_partials_raw_request_modal, src_templates_jinja2_dashboard_partials_file_view_modal [INFERRED 0.85]
- **Threats tab artifact tables** — src_templates_jinja2_dashboard_partials_request_assets_table, src_templates_jinja2_dashboard_partials_targeted_domains_table, src_templates_jinja2_dashboard_partials_artifact_sort_header_header, src_templates_jinja2_dashboard_partials_threat_pager_pager, artifact_investigation [INFERRED 0.75]
- **Timeout management UI** — src_templates_jinja2_dashboard_partials_timedout_panel, src_templates_jinja2_dashboard_partials_timedout_ips_table, src_templates_jinja2_dashboard_partials_timeout_exempt_table, src_routes_htmx_htmx_timedout_active, src_routes_htmx_htmx_timeout_exempt [INFERRED 0.85]
- **Dashboard Top-N sortable tables** — src_templates_jinja2_dashboard_partials_top_ips_table, src_templates_jinja2_dashboard_partials_top_paths_table, src_templates_jinja2_dashboard_partials_top_ua_table [INFERRED 0.85]
- **Attack Type Analytics Views** — img_attack_types_attack_trends_chart, img_attack_types_detected_attack_types_table, img_attack_types_dashboard_most_recurring_attack_types_chart, img_attack_types_dashboard_most_recurring_attack_patterns_table, img_attack_types_attack_type_taxonomy [INFERRED 0.85]
- **Ban Override Management Flow** — img_banlist_attackers_dashboard_ip_banlist_force_ban, img_banlist_attackers_dashboard_detected_attackers_table, img_banlist_overrides_dashboard_active_ban_overrides_table, img_banlist_attackers_dashboard_banlist_export_cycle [INFERRED 0.85]
- **Krawl banlist export enforced via Cloudflare WAF** — img_geoip_dashboard_export_ips_banlist, img_cloudflare_banlist_krawl_banlist, img_cloudflare_waf_rules_krawl_banlist_block_rule [INFERRED 0.75]
- **Krawl honeypot deception surfaces** — img_deception_page_random_link_maze, img_directory_page_fake_directory_listing, img_geoip_dashboard_navigation_tabs [INFERRED 0.65]
- **IP threat profiling UI (category scoring, timeline, reputation)** — img_ip_reputation_category_score_radar, img_ip_insight_dashboard_category_analysis, img_ip_reputation_behavior_timeline, img_ip_reputation_ip_category_classification [INFERRED 0.85]
- **Dashboard attacker monitoring views** — img_top_attackers_dashboard_attackers_by_total_requests, img_tracked_ips_dashboard_tracked_ips_panel, img_tracked_ips_dashboard_ip_insight_page, img_use_case_krawl_dashboard [INFERRED 0.85]
- **Reverse proxy routes root to honeypot, secret paths to dashboard and real services** — img_use_case_nginx_reverse_proxy, img_use_case_honeypot_deception_server, img_use_case_krawl_dashboard, img_use_case_secret_path_services [EXTRACTED 1.00]

## Communities (122 total, 32 thin omitted)

### Community 0 - "SQLAlchemy Models & Hot Cache"
Cohesion: 0.07
Nodes (15): delete_cached_short(), get_cached_short(), set_cached_short(), AccessLog, AttackDetection, Base, CategoryHistory, IpStats (+7 more)

### Community 2 - "DatabaseManager Core"
Cohesion: 0.05
Nodes (13): _ban_multiplier_for(), _buffer_access_log_entry(), DatabaseManager, _entry_bytes(), size(), _trim_write_buffer(), CredentialRepo, CredentialAttempt (+5 more)

### Community 3 - "APScheduler Task Runner"
Cohesion: 0.05
Nodes (18): TasksMaster, test_flags_match_intent(), FakeRedis, test_failure_is_recorded_as_such(), test_job_listener_records_the_run(), test_record_keys_stay_out_of_the_cache_namespace(), test_record_then_read_round_trips(), test_unrun_task_has_no_record() (+10 more)

### Community 4 - "CI/CD Workflows"
Cohesion: 0.06
Nodes (55): Docker Build and Push Workflow, Helm Package and Push Workflow, Helm Chart Validation Job, Kubernetes Manifest Validation Job, PR Build Docker Job, PR Lint & Dependency Checks Job, Security Scan Job (Bandit + pip-audit), Weekly Banlist Update Workflow (+47 more)

### Community 5 - "App Lifespan & Startup"
Cohesion: 0.06
Nodes (24): lifespan(), _phase(), initialize_cache(), _call_api(), call_openai(), call_openrouter(), can_generate_today(), close_aiohttp_session() (+16 more)

### Community 6 - "Cached Paginated Tables"
Cohesion: 0.16
Nodes (38): get_cached_table(), set_cached_table(), get_db(), get_templates(), get(), verify_auth(), _dashboard_path(), htmx_access_logs_by_ip() (+30 more)

### Community 7 - "Deception Attack Responses"
Cohesion: 0.08
Nodes (25): detect_and_respond_deception(), detect_command_injection(), detect_path_traversal(), detect_xxe_injection(), generate_command_injection_response(), generate_fake_config_file(), generate_fake_directory_listing(), generate_fake_passwd() (+17 more)

### Community 8 - "Helm Chart & Deployment"
Cohesion: 0.09
Nodes (36): Krawl Helm Chart (Chart.yaml), Helm NOTES.txt (root), Krawl Helm Chart README, Banlist Federation, CloudFlare WAF/Banlist Sync, Dashboard Secret Path, Ignored IPs (never tracked/banned), Scalable Mode (PostgreSQL + Redis) (+28 more)

### Community 9 - "Banlist & Campaign Panels"
Cohesion: 0.07
Nodes (41): Sortable Header Macro, Ban Attackers Table (HTMX fragment), Ban Overrides Table (HTMX fragment), Banlist Export Cycle (5 min), IP Banlist Management Panel, Cluster Events Table (campaign drill-down), Deception Templates Panel, Deception Panel With Message (+33 more)

### Community 10 - "Attack Map Frontend"
Cohesion: 0.09
Nodes (45): allIps, _animateNewSuspiciousRows(), buildMapMarkers(), categoryColors, cityCoordinates, countryCoordinates, createClusterIcon(), _createIpMarker() (+37 more)

### Community 11 - "Config & Server IP"
Cohesion: 0.07
Nodes (20): Config, _map_tiles(), brand(), test_contact_email_becomes_mailto(), test_contact_plain_text_is_not_linked(), test_contact_url_stays_a_link(), test_defaults_are_krawls_own(), test_hostile_values_never_reach_an_href() (+12 more)

### Community 12 - "Database Package & Ban Cleanup"
Cohesion: 0.09
Nodes (13): get_database(), clear_expired_bans(), purge_ignored_ips(), purge_ipv6_rows(), run_startup_cleanup(), on_skip(), main(), main() (+5 more)

### Community 13 - "Request Metadata Extraction"
Cohesion: 0.07
Nodes (5): extract_request_metadata(), extract_request_referer(), normalize_target_host(), main(), AccessTracker

### Community 14 - "Cloudflare Webhooks"
Cohesion: 0.11
Nodes (24): is_valid_public_ip(), webhook_cloudflare_delete(), webhook_cloudflare_save(), webhook_cloudflare_sync(), webhook_status(), main(), _apply_cf_env(), cf_create_list() (+16 more)

### Community 15 - "Dashboard Auth & Sessions"
Cohesion: 0.07
Nodes (16): destroy_session(), get_banlist_sources(), _acquire_run_lock(), auth_check(), banlist_sources(), build_campaign_stats(), _campaign_slot_hours(), _campaign_window() (+8 more)

### Community 16 - "Access Log Repo & Pagination"
Cohesion: 0.08
Nodes (3): paginate_cached_list(), pagination(), AccessLogRepo

### Community 17 - "Analytics Repository"
Cohesion: 0.07
Nodes (3): AnalyticsRepo, MetricsSummary, _bump_deleted_tally()

### Community 18 - "Banlist Source Refresh"
Cohesion: 0.08
Nodes (8): refresh(), refresh_banlist_sources(), get_config(), main(), main(), main(), on_skip(), test_ignored_ip_never_reads_the_body()

### Community 19 - "Test Fixtures & Conftest"
Cohesion: 0.09
Nodes (9): _matches_headers(), test_advanced_search_combines_fields_headers_and_pagination(), test_header_matching_ignores_body_and_other_headers(), test_queue_rotates_and_drains(), _attack(), _db(), test_campaigns_rank_and_total_by_hits_inside_the_window(), test_filename_index_keeps_names_shared_by_two_or_more_ips() (+1 more)

### Community 20 - "Metrics Counters"
Cohesion: 0.10
Nodes (15): _acquire_reconcile_lock(), bootstrap(), get_all(), get_many(), increment(), _key(), migrate_legacy_sets(), needs_seed() (+7 more)

### Community 21 - "Payload Repo & Clustering"
Cohesion: 0.08
Nodes (3): PayloadRepo, _request_body(), _scalar_min_max()

### Community 22 - "Generated Page Model & Auth"
Cohesion: 0.09
Nodes (18): invalidate_table_cache(), GeneratedPage, authenticate(), AuthRequest, ban_override(), BanOverrideRequest, CloudflareSaveRequest, delete_generated_pages() (+10 more)

### Community 23 - "Dashboard JS Controller"
Cohesion: 0.07
Nodes (10): _allowedUploadExts, collapseSearch(), forceBan(), KRAWL_ICONS, loadConfig(), openIpInsight(), refreshList(), refreshOverrides() (+2 more)

### Community 24 - "Cache Batch Tests"
Cohesion: 0.07
Nodes (12): RedisLists, execute(), __getattr__(), test_batches_publish_atomically_and_clean_staging(), test_failed_serialization_leaves_previous_cache_intact(), test_geo_shared(), test_ignore_ipv6_policy(), test_paths_set_is_bounded() (+4 more)

### Community 25 - "Task Lock Tests"
Cohesion: 0.11
Nodes (13): FakeRedis, test_different_jobs_do_not_collide(), test_holder_is_recorded(), test_lease_expiry_frees_the_job(), test_lock_keys_stay_out_of_the_cache_namespace(), test_one_pod_wins(), test_reconcile_lock_delegates(), test_release_frees_the_job() (+5 more)

### Community 26 - "Write Buffer Metrics"
Cohesion: 0.10
Nodes (13): get_dropped_rows(), get_write_buffer_bytes(), get_write_buffer_size(), get_seen_ledger_size(), get_local_set_size(), _enabled(), KrawlMetricsCollector, observe_warmup_step() (+5 more)

### Community 27 - "Auth Attempt Store"
Cohesion: 0.12
Nodes (8): clear_attempts(), count_locked(), create_session(), get_attempts(), is_valid_session(), _prune_expired(), _redis(), save_attempts()

### Community 28 - "Fake File Generators"
Cohesion: 0.10
Nodes (17): generate_server_error(), api_keys_json(), directory_listing(), fake_api_keys(), fake_config_json(), fake_directory_listing(), fake_env(), fake_passwords() (+9 more)

### Community 29 - "FastAPI App Factory"
Cohesion: 0.11
Nodes (10): create_app(), access_log_middleware(), server_header_middleware(), build_raw_request(), get_client_ip(), get_access_logger(), BanCheckMiddleware, DeceptionMiddleware (+2 more)

### Community 30 - "Dashboard Cache Reads"
Cohesion: 0.11
Nodes (14): get_cached(), get_cached_list_page(), is_warm(), all_ips(), dashboard_page(), _get_krawl_version(), healthz(), ip_page() (+6 more)

### Community 31 - "Dashboard API Routes"
Cohesion: 0.18
Nodes (20): get_app_logger(), all_ip_stats(), attack_types(), attack_types_daily(), attack_types_stats(), attackers(), campaign_stats(), credentials() (+12 more)

### Community 32 - "Campaign Charts JS"
Cohesion: 0.16
Nodes (22): _atkStyle(), _bindCampaignActivity(), CAMPAIGN_ROW_OPTIONS, _campaignEndDate(), _campaignLabel(), _campaignName(), _campaignShade(), _campaignSlotText() (+14 more)

### Community 33 - "Templating & Brand Dependencies"
Cohesion: 0.11
Nodes (5): build_brand(), get_client_ip_from_scope(), _safe_url(), is_ignored_ip(), DropIgnoredMiddleware

### Community 34 - "Config Env Overrides"
Cohesion: 0.10
Nodes (11): __get_env_from_config(), override_config_from_env(), _config_fields(), _config_section(), get_current_config(), _is_sensitive(), _is_unset(), _json_safe() (+3 more)

### Community 35 - "Ban Cache Tests"
Cohesion: 0.16
Nodes (10): FakeDB, FakeRepo, reset(), test_local_add_enforces_cap_without_copying(), test_local_ban_takes_effect_immediately(), test_lookup_is_sanitized(), test_not_ready_before_first_refresh(), test_overflow_disables_the_fast_path() (+2 more)

### Community 36 - "DB Engine & Maintenance"
Cohesion: 0.13
Nodes (5): analyze_tables(), bootstrap_analyze(), _is_postgres(), _reloptions(), run_migrations()

### Community 37 - "Banlist Federation via Redis"
Cohesion: 0.14
Nodes (10): load_published(), publish(), get_backend(), get_redis_client(), add_to_set(), record_distinct(), get_last_run(), is_held() (+2 more)

### Community 38 - "Attack Types Screenshots"
Cohesion: 0.13
Nodes (18): Fake Admin Panel Login Form, Admin Panel Login Page (screenshot), Attack Trends Time-Series Chart, Attack Type Taxonomy (common_probes, command_injection, sql_injection, xss_attempt, path_traversal, ldap_injection, lfi_rfi), Detected Attack Types Table (wp-login probes), Most Recurring Attack Patterns Table, Most Recurring Attack Types Donut Chart, Attack Types Dashboard (screenshot) (+10 more)

### Community 39 - "Cloudflare & Deception Screenshots"
Cohesion: 0.12
Nodes (17): krawl_banlist IP List, Cloudflare Custom Lists Screenshot, Krawl banlist WAF Block Rule (ip.src in $krawl_banlist), Cloudflare WAF Security Rules Screenshot, Krawl me! Deception Page Screenshot, Fake Directory Listing Screenshot (Index of /uploads/), Export IPs Banlist Button, IP Category Classification (+9 more)

### Community 40 - "Fake Login Pages"
Cohesion: 0.14
Nodes (14): fake_login(), fake_phpmyadmin(), fake_wordpress(), fake_wp_login(), robots_txt(), Fake Directory Listing Template, Directory Row Template, Krawl Main Crawler Page Template (+6 more)

### Community 41 - "SQLite to Postgres Migration"
Cohesion: 0.16
Nodes (8): create_postgres_engine(), create_sqlite_engine(), get_row_count(), main(), migrate_table(), table_exists(), main(), seed()

### Community 42 - "Buffer Recovery Tests"
Cohesion: 0.17
Nodes (11): initialize_database(), empty_buffer(), entry(), test_failed_batch_requeue_stays_bounded(), concurrent_arrivals_then_fail(), test_failed_transaction_does_not_publish_a_ban(), test_flush_respects_exact_run_limit(), test_retry_preserves_timestamp_detections_and_files() (+3 more)

### Community 43 - "Scheduled Maintenance Tasks"
Cohesion: 0.16
Nodes (15): dashboard_warmup Task, db_dump Task, db_retention Task, refresh_banlist Task, TasksMaster (APScheduler task orchestrator), Data Retention Job, Database Backups, PostgreSQL pg_dump Backup (+7 more)

### Community 44 - "Fake IP Insert Tests"
Cohesion: 0.15
Nodes (7): _build_fake_raw_request(), _build_multipart_raw_request(), _build_raw_body_request(), fetch_geolocation_from_api(), generate_analyzed_metrics(), generate_category_scores(), generate_fake_data()

### Community 45 - "TLSH Payload Similarity"
Cohesion: 0.15
Nodes (6): extract_file_payloads(), _is_file_content_type(), is_similar(), sha256_hash(), tlsh_diff(), tlsh_hash()

### Community 46 - "Suspicious Activity Fragments"
Cohesion: 0.18
Nodes (16): IP Insight drill-down (openIpInsight), Raw request viewer (viewRawRequest), htmx_timeout_exempt(), htmx_tracked_ips_list(), Search Results Fragment, Similar Threats Table (TLSH), Suspicious Activity Expand Table, Suspicious Activity Rows (+8 more)

### Community 47 - "Geolocation Utilities"
Cohesion: 0.21
Nodes (7): extract_geolocation_from_ip(), extract_geolocation_shared(), fetch_blocklist_data(), fetch_ip_geolocation(), _geo_cache_key(), sanitize_dict(), main()

### Community 48 - "Payload Hashing Task"
Cohesion: 0.18
Nodes (9): PayloadHashWatermark, _advance_watermark(), _digest_for(), _hash_attack_bodies(), _hash_files(), main(), _parse_raw_request(), _pending_log_ids() (+1 more)

### Community 49 - "Architecture Docs"
Cohesion: 0.13
Nodes (12): analyze_ips Task, config.yaml with KRAWL_* env overrides, Dashboard Load Data Flow, Database Schema (AccessLog, AttackDetection, IpStats, CredentialAttempt, CategoryHistory), IP Categorization Model, Krawl Architecture, Rotating Loggers (krawl.app, krawl.access, krawl.credentials), Krawl Coding Standards (+4 more)

### Community 50 - "IP Insight Screenshots"
Cohesion: 0.15
Nodes (16): Attack Types Donut Chart, Category Analysis Radar, Geo & Network / Reputation Info, IP Insight Dashboard, Behavior Timeline (Unknown -> Attacker), Listed On Blocklists (cidr_report_bogons), Category Score Radar Chart, IP Category Classification (Good Bot/User/Unknown/Bad Bot/Attacker) (+8 more)

### Community 51 - "SQLi Deception Screenshots"
Cohesion: 0.15
Nodes (15): Fake SQL/NoSQL Injection Error Responses, Honeypot Search Form, SQL Injection Deception, Attackers by Total Requests Table, Attacker IP Geolocation, Attacker Category Badge, IP Insight Page, IP Tracking / Watchlist (+7 more)

### Community 53 - "IP Detail Fragments"
Cohesion: 0.21
Nodes (13): Artifact investigation (openArtifactInvestigation), IP Insight (openIpInsight), Raw Request Viewer (viewRawRequest), htmx_attacks(), Shared IP Detail Partial, Access Logs by IP Table Fragment, Advanced Search Results Fragment, Artifact Matching Requests Fragment (+5 more)

### Community 54 - "Domain Link Map"
Cohesion: 0.17
Nodes (7): build_domain_map(), measure(), place(), root_domain(), test_empty_link_map_has_directional_empty_state(), test_link_map_centers_a_root_and_branches_by_dns_level(), test_root_domain_groups_common_suffixes_and_rejects_non_domains()

### Community 55 - "Banlist Formatting & CDN Exclusion"
Cohesion: 0.14
Nodes (7): get_global_banlist(), format_banlist(), _cdn_networks(), get_cdn_networks(), is_cdn_ip(), export_ips(), public_banlist_handler()

### Community 56 - "Dashboard Navigation JS"
Cohesion: 0.13
Nodes (15): closeFileModal(), closeRawModal(), init(), initAll(), logout(), switchToAdvancedSearch(), switchToAttacks(), switchToDeception() (+7 more)

### Community 57 - "Banlist Publish Tests"
Cohesion: 0.25
Nodes (9): clear_follower_state(), FakeRedis, seed_leader_state(), test_adopted_list_answers_the_membership_check(), test_load_published_is_false_when_nothing_was_published(), test_publish_then_adopt_round_trips(), test_published_key_avoids_the_flushed_cache_prefix(), test_standalone_never_publishes() (+1 more)

### Community 58 - "SQL Injection Deception"
Cohesion: 0.19
Nodes (9): detect_sql_injection_pattern(), generate_sql_error_response(), get_sql_response_with_data(), fake_api_catchall(), fake_product_search(), _safe_body(), sql_endpoint_get(), sql_endpoint_post() (+1 more)

### Community 60 - "AI Deception Pages"
Cohesion: 0.19
Nodes (11): AI-Generated Deception Pages, AI Custom Prompt Template ({path}{query_part}), llama.cpp, Ollama, OpenAI Provider, OpenRouter Provider, Self-Hosted LLM (llama.cpp / Ollama), Dashboard Deception Tab (+3 more)

### Community 61 - "Middleware Pipeline Docs"
Cohesion: 0.26
Nodes (12): BanCheckMiddleware, DeceptionMiddleware, ServerHeaderMiddleware, Command Injection Detection, Fake .env Leakage, Fake Directory Listing, Fake Login Pages (/admin, /wp-admin, /phpMyAdmin), Honeypot Capabilities (+4 more)

### Community 62 - "Credential Capture"
Cohesion: 0.30
Nodes (7): get_credential_logger(), credential_capture_post(), Fake Login Error Page, Fake Admin Login Form, Fake phpMyAdmin Login Page, Fake WordPress Blog Page, Fake WordPress Login Page

### Community 63 - "Dashboard Design Docs"
Cohesion: 0.18
Nodes (11): IP Categories (attacker, bad_crawler, good_crawler, regular_user, unknown), Dashboard Branding Config, hash-payloads Task, IP Insight Tab, IP Origins Map (Leaflet, clustered), Krawl Dashboard, Map Tile Provider Config, Overview Tab (+3 more)

### Community 64 - "Dashboard API Docs"
Cohesion: 0.18
Nodes (10): Attachment Extraction from Raw Requests, Cloudflare Webhook Endpoints, Dashboard API, Deception Page Endpoints, OpenAPI Schema + Swagger UI, Dashboard Session Authentication (12h HTTP-only cookie), Attacks Tab, Dashboard Authentication (brute-force backoff) (+2 more)

### Community 66 - "IP Utilities & Ignore Lists"
Cohesion: 0.20
Nodes (5): _cidrs_in(), defer_persist(), _parse_ignored_networks(), _prune_seen(), seen_before()

### Community 68 - "Threat Data Seeder"
Cohesion: 0.29
Nodes (6): main(), _now(), _raw(), _sql_inj_body(), _xss_body(), main()

### Community 69 - "Dashboard Cache Writes"
Cohesion: 0.22
Nodes (6): _json_serializer(), set_cached(), set_cached_list(), main(), _timed(), _warm_pages()

### Community 70 - "Generated Content-Type Tests"
Cohesion: 0.22
Nodes (5): _content_type_for_path(), test_data_paths_are_not_html(), test_pages_stay_html(), test_route_sends_the_content_type(), test_wrapping_is_limited_to_html()

### Community 71 - "Live Attack Map Tests"
Cohesion: 0.22
Nodes (3): _FakeDb, test_live_attack_limit_is_applied(), test_live_attackers_are_geolocated_attackers_newest_first()

### Community 72 - "Database Dump Task"
Cohesion: 0.24
Nodes (3): _dump_pg(), _dump_sqlite(), main()

### Community 73 - "Metrics & Grafana Docs"
Cohesion: 0.22
Nodes (9): flush_access_logs Task (write buffer drain), metrics_flush Task, Per-Pod Ungated Tasks (flush-access-logs, metrics-flush, refresh-ban-cache), Cumulative Counters (krawl_*_total), Current-State Gauges, Grafana Dashboard (generated by build_grafana_dashboard.py), Metrics & Monitoring, Prometheus Operator ServiceMonitor (+1 more)

### Community 74 - "Cloudflare Sync Docs"
Cohesion: 0.24
Nodes (7): sync_cloudflare Task, Cloudflare Account IP List, Cloudflare Banlist Sync, Dashboard Webhooks Tab, NGINX Reverse Proxy Configuration, Client IP Proxy Header Priority (CF-Connecting-IP, X-Forwarded-For, X-Real-IP), Deploying Behind a Reverse Proxy or CDN

### Community 75 - "Grafana Dashboard Builder"
Cohesion: 0.36
Nodes (6): bargauge(), base(), multistat(), stat(), target(), timeseries()

### Community 76 - "In-Process Ban Cache"
Cohesion: 0.20
Nodes (4): add(), is_banned(), is_ready(), needs_lookup()

### Community 78 - "Raw Request Attachments"
Cohesion: 0.24
Nodes (5): _extract_headers(), _get_attachment_content(), _is_file_content_type(), _parse_attachments(), _path_to_filename()

### Community 79 - "Raw Request Viewer JS"
Cohesion: 0.20
Nodes (10): confirm(), _create(), error(), escapeHtml(), fetchAttachments(), formatBytes(), highlightRawRequest(), success() (+2 more)

### Community 80 - "Upload Tracking Tests"
Cohesion: 0.22
Nodes (3): _multipart_request(), test_unmatched_uploads_are_captured_with_tlsh_disabled(), _Tracker

### Community 81 - "Dashboard Page Templates"
Cohesion: 0.36
Nodes (9): brand Template Global, Dashboard Base Layout, window.__MAP_TILES__ Server-Side Tile Config, Dashboard Index Page, dashboardApp Alpine Component, Standalone IP Detail Page, Brand Wordmark Partial, Brand Contact Partial (+1 more)

### Community 82 - "Tarpit & Canary Tokens"
Cohesion: 0.22
Nodes (7): AccessTracker (tracker.record), Honeypot Router (catch-all), Canary Token Integration, canarytokens.org, Infinite Pages for Malicious Crawlers, Tarpit, Word Salad Padding

### Community 83 - "Firewall Exporter Docs"
Cohesion: 0.32
Nodes (6): /api/export-ips Endpoint, IP Banlist Tab, Admin Ban Override (ban_override), Firewall Exporters, Firewall Output Formats (raw, iptables, nftables), COLUMNS / INDEXES Migration Registry

### Community 84 - "Threat Capture Tests"
Cohesion: 0.29
Nodes (3): tlsh_available(), build_raw_request(), main()

### Community 85 - "XSS Deception"
Cohesion: 0.29
Nodes (5): detect_xss_pattern(), generate_xss_response(), contact_post(), fake_input_form(), Fake Contact Form Template

### Community 86 - "Firewall Banlist Formatters"
Cohesion: 0.25
Nodes (3): _iptables(), _nftables(), _raw()

### Community 87 - "IP Enrichment APIs"
Cohesion: 0.43
Nodes (7): External APIs, ip-api.com Geolocation, iprep.lcrawl.com IP Reputation, Nominatim Reverse Geocoding, Server Public IP Discovery (ipify, ident.me, ifconfig.me), fetch_ip_rep Background Task, IP Enrichment Pipeline

### Community 88 - "Request Body Size Cap"
Cohesion: 0.38
Nodes (3): body_too_large(), read_body_capped(), test_chunked_body_is_capped()

### Community 90 - "Dashboard Route Tests"
Cohesion: 0.53
Nodes (3): _normalise(), _referenced(), test_every_referenced_endpoint_is_routed()

### Community 94 - "Captured Payload Model"
Cohesion: 0.40
Nodes (3): CapturedPayload, _raw(), test_request_metadata_pipeline()

### Community 95 - "Attack Test Script"
Cohesion: 0.70
Nodes (4): request_info(), response_info(), test_all_attacks.sh script, test_header()

### Community 98 - "Field Visibility Helpers"
Cohesion: 0.50
Nodes (4): anyVisible(), formatValue(), isEmpty(), visibleFields()

### Community 100 - "Design Tokens JS"
Cohesion: 0.83
Nodes (3): krawlAttackColor(), krawlCategoryColors(), krawlToken()

### Community 103 - "Auth Modal JS"
Cohesion: 0.67
Nodes (3): closeAuthModal(), submitAuth(), switchToBanlist()

### Community 104 - "Zip Upload Processing"
Cohesion: 0.67
Nodes (3): _loadJSZip(), _processUploadFile(), _processZipFile()

## Ambiguous Edges - Review These
- `main()` → `Honeypot robots.txt Disallow List`  [AMBIGUOUS]
  src/templates/html/robots.txt · relation: references
- `Fake Admin Panel Login Form` → `Dashboard Password Unlock Modal`  [AMBIGUOUS]
  img/admin-page.png · relation: conceptually_related_to

## Knowledge Gaps
- **93 isolated node(s):** `entrypoint.sh script`, `krawl-iptables.sh script`, `krawl-nftables.sh script`, `CAMPAIGN_ROW_OPTIONS`, `_allowedUploadExts` (+88 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 841 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **32 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `main()` and `Honeypot robots.txt Disallow List`?**
  _Edge tagged AMBIGUOUS (relation: references) - confidence is low._
- **What is the exact relationship between `Fake Admin Panel Login Form` and `Dashboard Password Unlock Modal`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **Why does `get_config()` connect `Banlist Source Refresh` to `SQLAlchemy Models & Hot Cache`, `DatabaseManager Core`, `App Lifespan & Startup`, `Cached Paginated Tables`, `Deception Attack Responses`, `Config & Server IP`, `Database Package & Ban Cleanup`, `Request Metadata Extraction`, `Cloudflare Webhooks`, `Dashboard Auth & Sessions`, `Access Log Repo & Pagination`, `Analytics Repository`, `Payload Repo & Clustering`, `Write Buffer Metrics`, `Auth Attempt Store`, `Fake File Generators`, `FastAPI App Factory`, `Dashboard Cache Reads`, `Dashboard API Routes`, `Templating & Brand Dependencies`, `Config Env Overrides`, `Fake Login Pages`, `Buffer Recovery Tests`, `Payload Hashing Task`, `IP Utilities & Ignore Lists`, `Dashboard Cache Writes`, `Database Dump Task`, `Upload Tracking Tests`, `Threat Capture Tests`?**
  _High betweenness centrality (0.091) - this node is a cross-community bridge._
- **Why does `get_app_logger()` connect `Dashboard API Routes` to `SQLAlchemy Models & Hot Cache`, `APScheduler Task Runner`, `App Lifespan & Startup`, `Config & Server IP`, `Database Package & Ban Cleanup`, `Request Metadata Extraction`, `Cloudflare Webhooks`, `Dashboard Auth & Sessions`, `Banlist Source Refresh`, `Generated Page Model & Auth`, `Write Buffer Metrics`, `Auth Attempt Store`, `Fake File Generators`, `FastAPI App Factory`, `Dashboard Cache Reads`, `Config Env Overrides`, `DB Engine & Maintenance`, `Banlist Federation via Redis`, `Fake Login Pages`, `Fake IP Insert Tests`, `Geolocation Utilities`, `Payload Hashing Task`, `Banlist Formatting & CDN Exclusion`, `SQL Injection Deception`, `Logger Manager`, `IP Utilities & Ignore Lists`, `Database Dump Task`, `In-Process Ban Cache`, `Ban Check Middleware`, `Raw Request Attachments`, `XSS Deception`, `Wordlists Loader`?**
  _High betweenness centrality (0.078) - this node is a cross-community bridge._
- **Why does `IpStatsRepo` connect `IP Stats Repository` to `SQLAlchemy Models & Hot Cache`, `DatabaseManager Core`, `Cached Paginated Tables`, `Live Attack Map Tests`, `Banlist Source Refresh`, `Fake DB Test Helper`, `Tracked IP Model`?**
  _High betweenness centrality (0.039) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `get_config()` (e.g. with `test_ignored_ip_never_reads_the_body()` and `test_cleanup_progresses_past_suspicious_batch_and_preserves_evidence()`) actually correct?**
  _`get_config()` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 15 inferred relationships involving `get_database()` (e.g. with `seed()` and `main()`) actually correct?**
  _`get_database()` has 15 INFERRED edges - model-reasoned connections that need verification._