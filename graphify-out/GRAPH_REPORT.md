# Graph Report - Krawl  (2026-10-04)

## Corpus Check
- 146 files · ~387,919 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 13 file(s) not represented in the graph (top: (none) 7, .conf 2, .tpl 1)

## Summary
- 2193 nodes · 4965 edges · 113 communities (85 shown, 28 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 479 edges (avg confidence: 0.89)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `4ba6d79d`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- core.py
- IpStatsRepo
- .persist_access
- TasksMaster
- Krawl config.yaml
- generative_ai.py
- get
- get_wordlists
- Krawl Helm Chart README
- IP Banlist Management Panel
- map.js
- Config
- RequestAsset
- AccessTracker
- webhooks.py
- lifespan
- pagination
- AnalyticsRepo
- banlist_sync.py
- pathlib
- get_backend
- PayloadRepo
- api.py
- dashboard.js
- test_ipv6_flood.py
- test_task_lock.py
- get_config
- _redis
- honeypot.py
- app.py
- dashboard.py
- get_app_logger
- charts.js
- dependencies.py
- _config_fields
- test_ban_cache.py
- maintenance.py
- get_redis_client
- Detected Attack Types Table
- Krawl Dashboard GeoIP Screenshot
- load_template
- migrate_sqlite_to_postgres.py
- get_database
- Deployment Modes
- test_insert_fake_ips.py
- tlsh_utils.py
- Krawl Web Honeypot
- geo_utils.py
- hash_payloads.py
- Krawl Architecture
- IP Insight Dashboard
- Tracked IPs Panel
- GeneratedPageRepo
- test_config_endpoint.py
- domain_map.py
- export_ips
- init
- test_banlist_publish.py
- contact_post
- test_request_memory_bounds.py
- AI-Generated Deception Pages
- Honeypot Capabilities
- sanitizer.py
- Krawl Dashboard
- Dashboard API
- Logger
- ip_utils.py
- test_pg_dump_preserves_previous_backup
- build_campaign_stats
- main
- test_generated_content_type.py
- trap_page
- db_dump.py
- ._insert_access_log_batch
- Krawl Deployment (k8s)
- build_grafana_dashboard.py
- ban_cache.py
- purge.py
- _get_attachment_content
- error
- _Tracker
- test_brand.py
- Tarpit
- Krawl Runtime Dependencies
- main
- sanitize_path
- firewall/__init__.py
- External APIs
- is_ignored_ip
- FakeRedis
- banlist_sources
- _FakeDb
- CloudflareSaveRequest
- test_all_attacks.sh
- Settings Modal Panel
- dashboard_cache.py
- formatValue
- tokens.js
- wordlists.py
- test_ignored_ip_cannot_bypass_drop_with_prefix_lookalike
- switchToBanlist
- entrypoint.sh
- Krawl Spider Logo (raster)
- krawl-iptables.sh
- krawl-nftables.sh
- _formatRemaining
- test_credentials.sh
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
- `krawl-config ConfigMap` --semantically_similar_to--> `Krawl config.yaml`  [INFERRED] [semantically similar]
  kubernetes/krawl-all-in-one-deploy.yaml → config.yaml
- `Krawl Deployment (k8s)` --semantically_similar_to--> `Root Scalable Compose Stack`  [INFERRED] [semantically similar]
  kubernetes/krawl-all-in-one-deploy.yaml → docker-compose.yaml
- `test_advanced_search_combines_fields_headers_and_pagination()` --uses--> `AccessLog`  [INFERRED]
  tests/test_advanced_search.py → src/models.py
- `_map_tiles()` --shares_data_with--> `window.__MAP_TILES__ Server-Side Tile Config`  [INFERRED]
  src/routes/dashboard.py → src/templates/jinja2/base.html
- `main()` --references--> `Honeypot robots.txt Disallow List`  [AMBIGUOUS]
  src/tasks/analyze_ips.py → src/templates/html/robots.txt

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Ban Management UI** — src_templates_jinja2_dashboard_partials_banlist_panel, src_templates_jinja2_dashboard_partials_ban_attackers_table, src_templates_jinja2_dashboard_partials_ban_overrides_table, src_templates_jinja2_dashboard_partials_ban_override [EXTRACTED 1.00]
- **Deception Templates Management UI** — src_templates_jinja2_dashboard_partials_deception_panel, src_templates_jinja2_dashboard_partials_deception_panel_with_message, src_templates_jinja2_dashboard_partials_generated_pages_table, src_templates_jinja2_dashboard_partials_generated_pages_table_readonly [EXTRACTED 1.00]
- **Firewall integrations consuming export-ips API** — readme_export_ips_api, plugins_iptables_readme_iptables_integration, plugins_nftables_readme_nftables_integration, plugins_fail2ban_readme_fail2ban_integration, _github_workflows_update_banlist_fetch_and_pr [EXTRACTED 1.00]
- **Standalone-to-scalable migration flow** — helm_templates_pvc, helm_templates_migration_job, helm_templates_migration_job_migrate_sqlite_to_postgres, helm_templates_postgres [EXTRACTED 1.00]
- **IP detail page composition** — src_templates_jinja2_dashboard_ip, src_templates_jinja2_base, src_templates_jinja2_dashboard_partials__ip_detail, src_templates_jinja2_dashboard_partials__brand, src_templates_jinja2_dashboard_partials__contact [EXTRACTED 1.00]
- **Reverse proxy routes root to honeypot, secret paths to dashboard and real services** — img_use_case_nginx_reverse_proxy, img_use_case_honeypot_deception_server, img_use_case_krawl_dashboard, img_use_case_secret_path_services [EXTRACTED 1.00]
- **Chart appVersion-driven image and chart release sync** — _github_workflows_docker_build_push_build_and_push, _github_workflows_helm_package_push_package_and_push, _github_workflows_kubernetes_validation_validate_helm, helm_chart_yaml_appversion [EXTRACTED 1.00]
- **Krawl honeypot deception surfaces** — img_deception_page_random_link_maze, img_directory_page_fake_directory_listing, img_geoip_dashboard_navigation_tabs [INFERRED 0.65]
- **Crawler Resource-Wasting Mechanisms** — docs_tarpit_tarpit, docs_tarpit_word_salad, docs_tarpit_infinite_pages_for_malicious, docs_ai_generation_ai_generated_deception_pages, docs_honeypot_sqli_xss_detection [INFERRED 0.75]
- **Krawl banlist export enforced via Cloudflare WAF** — img_geoip_dashboard_export_ips_banlist, img_cloudflare_banlist_krawl_banlist, img_cloudflare_waf_rules_krawl_banlist_block_rule [INFERRED 0.75]
- **Threats tab artifact tables** — src_templates_jinja2_dashboard_partials_request_assets_table, src_templates_jinja2_dashboard_partials_targeted_domains_table, src_templates_jinja2_dashboard_partials_artifact_sort_header_header, src_templates_jinja2_dashboard_partials_threat_pager_pager, artifact_investigation [INFERRED 0.75]
- **Attack Type Analytics Views** — img_attack_types_attack_trends_chart, img_attack_types_detected_attack_types_table, img_attack_types_dashboard_most_recurring_attack_types_chart, img_attack_types_dashboard_most_recurring_attack_patterns_table, img_attack_types_attack_type_taxonomy [INFERRED 0.85]
- **Ban Override Management Flow** — img_banlist_attackers_dashboard_ip_banlist_force_ban, img_banlist_attackers_dashboard_detected_attackers_table, img_banlist_overrides_dashboard_active_ban_overrides_table, img_banlist_attackers_dashboard_banlist_export_cycle [INFERRED 0.85]
- **Campaign Investigation Drill-down Flow** — src_templates_jinja2_dashboard_partials_pattern_clusters_table, src_templates_jinja2_dashboard_partials_expand_overlay, src_templates_jinja2_dashboard_partials_cluster_events_table, src_templates_jinja2_dashboard_partials_raw_request_modal, src_templates_jinja2_dashboard_partials_file_view_modal [INFERRED 0.85]
- **Dashboard Top-N sortable tables** — src_templates_jinja2_dashboard_partials_top_ips_table, src_templates_jinja2_dashboard_partials_top_paths_table, src_templates_jinja2_dashboard_partials_top_ua_table [INFERRED 0.85]
- **Banlist Distribution to Edge/Firewalls** — docs_architecture_ip_categories, docs_dashboard_api_export_ips_endpoint, docs_firewall_exporters_formats_registry, docs_architecture_sync_cloudflare_task, docs_cloudflare_banlist_cloudflare_account_ip_list, docs_firewall_exporters_cdn_exclusion [INFERRED 0.85]
- **Observability tied to fixed dashboard secret_path** — helm_templates_servicemonitor, helm_templates_servicemonitor_metrics_endpoint, helm_templates_deployment_startup_probe, helm_readme_dashboard_secret_path, helm_templates_grafana_dashboard [INFERRED 0.85]
- **Scalable mode stack: Deployment + bundled PostgreSQL + Redis** — helm_templates_deployment, helm_templates_postgres, helm_templates_redis, helm_templates_deployment_wait_for_postgres, helm_templates_deployment_wait_for_redis, helm_readme_scalable_mode [INFERRED 0.85]
- **Honeypot credential capture flow** — src_templates_html_login_form, src_templates_html_wp_login, src_templates_html_phpmyadmin, src_routes_honeypot_credential_capture_post, src_templates_html_login_error [INFERRED 0.85]
- **IP threat profiling UI (category scoring, timeline, reputation)** — img_ip_reputation_category_score_radar, img_ip_insight_dashboard_category_analysis, img_ip_reputation_behavior_timeline, img_ip_reputation_ip_category_classification [INFERRED 0.85]
- **Dashboard attacker monitoring views** — img_top_attackers_dashboard_attackers_by_total_requests, img_tracked_ips_dashboard_tracked_ips_panel, img_tracked_ips_dashboard_ip_insight_page, img_use_case_krawl_dashboard [INFERRED 0.85]
- **Scalable Mode Shared State via Redis** — docs_deployment_modes_scalable_mode, docs_deployment_modes_redis_cache_tiers, docs_deployment_modes_single_pod_task_lease, docs_deployment_modes_max_aggregation_metrics, docs_dashboard_dashboard_authentication [INFERRED 0.85]
- **Timeout management UI** — src_templates_jinja2_dashboard_partials_timedout_panel, src_templates_jinja2_dashboard_partials_timedout_ips_table, src_templates_jinja2_dashboard_partials_timeout_exempt_table, src_routes_htmx_htmx_timedout_active, src_routes_htmx_htmx_timeout_exempt [INFERRED 0.85]
- **Scalable mode deployment variants (Postgres + Redis)** — readme_scalable_mode, docker_compose_scalable_stack, docker_docker_compose_scalable_stack, docker_dev_docker_compose_scalable_dev_stack, kubernetes_krawl_all_in_one_deploy_krawl_deployment [INFERRED 0.95]

## Communities (113 total, 28 thin omitted)

### Community 0 - "core.py"
Cohesion: 0.06
Nodes (20): DatabaseManager, purge_ignored_ips(), AccessLog, AttackDetection, Base, CapturedPayload, CategoryHistory, CredentialAttempt (+12 more)

### Community 1 - "IpStatsRepo"
Cohesion: 0.04
Nodes (4): IpStatsRepo, _publish_ban_change(), sanitize_ip(), main()

### Community 2 - ".persist_access"
Cohesion: 0.11
Nodes (3): delete_cached_short(), _ban_multiplier_for(), _buffer_access_log_entry()

### Community 3 - "TasksMaster"
Cohesion: 0.05
Nodes (18): TasksMaster, test_flags_match_intent(), FakeRedis, test_failure_is_recorded_as_such(), test_job_listener_records_the_run(), test_record_keys_stay_out_of_the_cache_namespace(), test_record_then_read_round_trips(), test_unrun_task_has_no_record() (+10 more)

### Community 4 - "Krawl config.yaml"
Cohesion: 0.15
Nodes (24): Docker Build and Push Workflow, Helm Package and Push Workflow, Helm Chart Validation Job, PR Build Docker Job, AI Deception Prompt Template, Ignored IPs, IPv6 Ignore, Krawl config.yaml (+16 more)

### Community 5 - "generative_ai.py"
Cohesion: 0.08
Nodes (18): _call_api(), call_openai(), call_openrouter(), can_generate_today(), close_aiohttp_session(), content_type_for_path(), generate_html_for_path(), _get_aiohttp_session() (+10 more)

### Community 6 - "get"
Cohesion: 0.05
Nodes (95): Artifact investigation (openArtifactInvestigation), brand Template Global, IP Insight (openIpInsight), Raw Request Viewer (viewRawRequest), IP Insight drill-down (openIpInsight), Raw request viewer (viewRawRequest), get_cached(), get_cached_list_page() (+87 more)

### Community 7 - "get_wordlists"
Cohesion: 0.09
Nodes (20): detect_and_respond_deception(), detect_command_injection(), detect_path_traversal(), detect_sql_injection_pattern(), detect_xxe_injection(), generate_command_injection_response(), generate_fake_config_file(), generate_fake_directory_listing() (+12 more)

### Community 8 - "Krawl Helm Chart README"
Cohesion: 0.09
Nodes (36): Krawl Helm Chart (Chart.yaml), Helm NOTES.txt (root), Krawl Helm Chart README, Banlist Federation, CloudFlare WAF/Banlist Sync, Dashboard Secret Path, Ignored IPs (never tracked/banned), Scalable Mode (PostgreSQL + Redis) (+28 more)

### Community 9 - "IP Banlist Management Panel"
Cohesion: 0.07
Nodes (41): Sortable Header Macro, Ban Attackers Table (HTMX fragment), Ban Overrides Table (HTMX fragment), Banlist Export Cycle (5 min), IP Banlist Management Panel, Cluster Events Table (campaign drill-down), Deception Templates Panel, Deception Panel With Message (+33 more)

### Community 10 - "map.js"
Cohesion: 0.09
Nodes (45): allIps, _animateNewSuspiciousRows(), buildMapMarkers(), categoryColors, cityCoordinates, countryCoordinates, createClusterIcon(), _createIpMarker() (+37 more)

### Community 11 - "Config"
Cohesion: 0.11
Nodes (7): Config, test_dataclass_defaults_match_from_yaml_fallbacks(), test_shipped_config_is_reflected_as_custom_only_where_it_differs(), test_default_is_keyless(), test_key_encoding_custom_parameter_and_fragment(), test_key_is_appended(), test_operator_override()

### Community 12 - "RequestAsset"
Cohesion: 0.13
Nodes (8): RequestAsset, extract_request_metadata(), extract_request_referer(), normalize_target_host(), main(), _is_honeypot_path(), _is_still_suspicious(), main()

### Community 14 - "webhooks.py"
Cohesion: 0.11
Nodes (24): is_valid_public_ip(), webhook_cloudflare_delete(), webhook_cloudflare_save(), webhook_cloudflare_sync(), webhook_status(), main(), _apply_cf_env(), cf_create_list() (+16 more)

### Community 15 - "lifespan"
Cohesion: 0.13
Nodes (7): lifespan(), _acquire_run_lock(), _is_running(), list_tasks(), _release_run_lock(), run_task(), get_tasksmaster()

### Community 16 - "pagination"
Cohesion: 0.07
Nodes (4): pagination(), AccessLogRepo, _matches_headers(), test_header_matching_ignores_body_and_other_headers()

### Community 18 - "banlist_sync.py"
Cohesion: 0.27
Nodes (5): load_published(), publish(), refresh_banlist_sources(), main(), on_skip()

### Community 19 - "pathlib"
Cohesion: 0.11
Nodes (6): isolate_services(), test_on_skip_is_discoverable_by_the_guard(), _normalise(), _referenced(), test_every_referenced_endpoint_is_routed(), test_cache_still_works_without_it()

### Community 20 - "get_backend"
Cohesion: 0.11
Nodes (16): get_backend(), _acquire_reconcile_lock(), add_to_set(), bootstrap(), increment(), _key(), migrate_legacy_sets(), needs_seed() (+8 more)

### Community 22 - "api.py"
Cohesion: 0.09
Nodes (19): destroy_session(), invalidate_table_cache(), GeneratedPage, authenticate(), AuthRequest, ban_override(), BanOverrideRequest, download_generated_pages_zip() (+11 more)

### Community 23 - "dashboard.js"
Cohesion: 0.06
Nodes (17): _allowedUploadExts, collapseSearch(), copyExportUrl(), exportUrl(), forceBan(), KRAWL_ICONS, load(), loadConfig() (+9 more)

### Community 24 - "test_ipv6_flood.py"
Cohesion: 0.07
Nodes (12): RedisLists, execute(), __getattr__(), test_batches_publish_atomically_and_clean_staging(), test_failed_serialization_leaves_previous_cache_intact(), test_geo_shared(), test_ignore_ipv6_policy(), test_paths_set_is_bounded() (+4 more)

### Community 25 - "test_task_lock.py"
Cohesion: 0.11
Nodes (13): FakeRedis, test_different_jobs_do_not_collide(), test_holder_is_recorded(), test_lease_expiry_frees_the_job(), test_lock_keys_stay_out_of_the_cache_namespace(), test_one_pod_wins(), test_reconcile_lock_delegates(), test_release_frees_the_job() (+5 more)

### Community 26 - "get_config"
Cohesion: 0.09
Nodes (17): refresh(), get_config(), get_dropped_rows(), get_write_buffer_bytes(), get_write_buffer_size(), get_seen_ledger_size(), get_local_set_size(), _enabled() (+9 more)

### Community 27 - "_redis"
Cohesion: 0.14
Nodes (9): clear_attempts(), count_locked(), create_session(), get_attempts(), is_valid_session(), _prune_expired(), _redis(), save_attempts() (+1 more)

### Community 28 - "honeypot.py"
Cohesion: 0.09
Nodes (18): generate_server_error(), api_keys_json(), api_response(), credentials_txt(), directory_listing(), passwords_txt(), random_api_key(), random_database_name() (+10 more)

### Community 29 - "app.py"
Cohesion: 0.08
Nodes (11): create_app(), access_log_middleware(), server_header_middleware(), _phase(), get_client_ip_from_scope(), random_server_header(), get_access_logger(), initialize_logging() (+3 more)

### Community 30 - "dashboard.py"
Cohesion: 0.22
Nodes (4): _get_krawl_version(), ip_page(), _map_tiles(), metrics_endpoint()

### Community 31 - "get_app_logger"
Cohesion: 0.18
Nodes (18): get_app_logger(), attack_types(), attack_types_stats(), attackers(), credentials(), delete_generated_pages(), download_attachment(), download_credentials() (+10 more)

### Community 32 - "charts.js"
Cohesion: 0.16
Nodes (22): _atkStyle(), _bindCampaignActivity(), CAMPAIGN_ROW_OPTIONS, _campaignEndDate(), _campaignLabel(), _campaignName(), _campaignShade(), _campaignSlotText() (+14 more)

### Community 33 - "dependencies.py"
Cohesion: 0.11
Nodes (9): body_too_large(), build_brand(), build_raw_request(), get_client_ip(), read_body_capped(), _safe_url(), DeceptionMiddleware, _track_honeypot_request() (+1 more)

### Community 34 - "_config_fields"
Cohesion: 0.13
Nodes (8): __get_env_from_config(), override_config_from_env(), _config_fields(), _config_section(), get_current_config(), _is_sensitive(), _is_unset(), _json_safe()

### Community 35 - "test_ban_cache.py"
Cohesion: 0.16
Nodes (10): FakeDB, FakeRepo, reset(), test_local_add_enforces_cap_without_copying(), test_local_ban_takes_effect_immediately(), test_lookup_is_sanitized(), test_not_ready_before_first_refresh(), test_overflow_disables_the_fast_path() (+2 more)

### Community 36 - "maintenance.py"
Cohesion: 0.13
Nodes (5): analyze_tables(), bootstrap_analyze(), _is_postgres(), _reloptions(), run_migrations()

### Community 37 - "get_redis_client"
Cohesion: 0.14
Nodes (7): get_redis_client(), get_all(), get_many(), get_last_run(), is_held(), record_run(), release()

### Community 38 - "Detected Attack Types Table"
Cohesion: 0.13
Nodes (18): Fake Admin Panel Login Form, Admin Panel Login Page (screenshot), Attack Trends Time-Series Chart, Attack Type Taxonomy (common_probes, command_injection, sql_injection, xss_attempt, path_traversal, ldap_injection, lfi_rfi), Detected Attack Types Table (wp-login probes), Most Recurring Attack Patterns Table, Most Recurring Attack Types Donut Chart, Attack Types Dashboard (screenshot) (+10 more)

### Community 39 - "Krawl Dashboard GeoIP Screenshot"
Cohesion: 0.12
Nodes (17): krawl_banlist IP List, Cloudflare Custom Lists Screenshot, Krawl banlist WAF Block Rule (ip.src in $krawl_banlist), Cloudflare WAF Security Rules Screenshot, Krawl me! Deception Page Screenshot, Fake Directory Listing Screenshot (Index of /uploads/), Export IPs Banlist Button, IP Category Classification (+9 more)

### Community 40 - "load_template"
Cohesion: 0.10
Nodes (23): get_credential_logger(), credential_capture_post(), fake_input_form(), fake_login(), fake_phpmyadmin(), fake_wordpress(), fake_wp_login(), robots_txt() (+15 more)

### Community 41 - "migrate_sqlite_to_postgres.py"
Cohesion: 0.31
Nodes (6): create_postgres_engine(), create_sqlite_engine(), get_row_count(), main(), migrate_table(), table_exists()

### Community 42 - "get_database"
Cohesion: 0.05
Nodes (28): main(), seed(), main(), _now(), _raw(), _sql_inj_body(), _xss_body(), main() (+20 more)

### Community 43 - "Deployment Modes"
Cohesion: 0.14
Nodes (18): db_dump Task, db_retention Task, flush_access_logs Task (write buffer drain), metrics_flush Task, refresh_banlist Task, TasksMaster (APScheduler task orchestrator), Data Retention Job, Database Backups (+10 more)

### Community 44 - "test_insert_fake_ips.py"
Cohesion: 0.15
Nodes (7): _build_fake_raw_request(), _build_multipart_raw_request(), _build_raw_body_request(), fetch_geolocation_from_api(), generate_analyzed_metrics(), generate_category_scores(), generate_fake_data()

### Community 45 - "tlsh_utils.py"
Cohesion: 0.16
Nodes (4): extract_file_payloads_from_body(), _is_file_content_type(), is_similar(), sha256_hash()

### Community 46 - "Krawl Web Honeypot"
Cohesion: 0.17
Nodes (17): Weekly Banlist Update Workflow, Community Banlist (banlist.txt), Analyzer Thresholds Config, Fail2Ban Integration, Iptables Integration, Nftables Integration, Banlist Federation, Canary Token Integration (+9 more)

### Community 47 - "geo_utils.py"
Cohesion: 0.27
Nodes (4): extract_geolocation_from_ip(), extract_geolocation_shared(), fetch_ip_geolocation(), _geo_cache_key()

### Community 48 - "hash_payloads.py"
Cohesion: 0.14
Nodes (12): PayloadHashWatermark, _advance_watermark(), _digest_for(), _hash_attack_bodies(), _hash_files(), main(), _parse_raw_request(), _pending_log_ids() (+4 more)

### Community 49 - "Krawl Architecture"
Cohesion: 0.13
Nodes (12): analyze_ips Task, config.yaml with KRAWL_* env overrides, Dashboard Load Data Flow, Database Schema (AccessLog, AttackDetection, IpStats, CredentialAttempt, CategoryHistory), IP Categorization Model, Krawl Architecture, Rotating Loggers (krawl.app, krawl.access, krawl.credentials), Krawl Coding Standards (+4 more)

### Community 50 - "IP Insight Dashboard"
Cohesion: 0.15
Nodes (16): Attack Types Donut Chart, Category Analysis Radar, Geo & Network / Reputation Info, IP Insight Dashboard, Behavior Timeline (Unknown -> Attacker), Listed On Blocklists (cidr_report_bogons), Category Score Radar Chart, IP Category Classification (Good Bot/User/Unknown/Bad Bot/Attacker) (+8 more)

### Community 51 - "Tracked IPs Panel"
Cohesion: 0.15
Nodes (15): Fake SQL/NoSQL Injection Error Responses, Honeypot Search Form, SQL Injection Deception, Attackers by Total Requests Table, Attacker IP Geolocation, Attacker Category Badge, IP Insight Page, IP Tracking / Watchlist (+7 more)

### Community 53 - "test_config_endpoint.py"
Cohesion: 0.15
Nodes (7): _payload(), test_every_field_is_accounted_for(), test_false_positives_stay_visible(), test_no_secret_survives_serialization(), test_pattern_catches_an_unlisted_secret(), test_sections_follow_config_yaml(), test_unset_secret_is_not_badged_custom()

### Community 54 - "domain_map.py"
Cohesion: 0.17
Nodes (7): build_domain_map(), measure(), place(), root_domain(), test_empty_link_map_has_directional_empty_state(), test_link_map_centers_a_root_and_branches_by_dns_level(), test_root_domain_groups_common_suffixes_and_rejects_non_domains()

### Community 55 - "export_ips"
Cohesion: 0.13
Nodes (7): get_global_banlist(), format_banlist(), _cdn_networks(), get_cdn_networks(), is_cdn_ip(), export_ips(), public_banlist_handler()

### Community 56 - "init"
Cohesion: 0.15
Nodes (20): _bindShortcuts(), closeFileModal(), closePalette(), closeRawModal(), go(), init(), initAll(), logout() (+12 more)

### Community 57 - "test_banlist_publish.py"
Cohesion: 0.25
Nodes (9): clear_follower_state(), FakeRedis, seed_leader_state(), test_adopted_list_answers_the_membership_check(), test_load_published_is_false_when_nothing_was_published(), test_publish_then_adopt_round_trips(), test_published_key_avoids_the_flushed_cache_prefix(), test_standalone_never_publishes() (+1 more)

### Community 58 - "contact_post"
Cohesion: 0.17
Nodes (10): detect_xss_pattern(), generate_sql_error_response(), generate_xss_response(), contact_post(), fake_api_catchall(), fake_product_search(), _safe_body(), sql_endpoint_get() (+2 more)

### Community 60 - "AI-Generated Deception Pages"
Cohesion: 0.16
Nodes (13): AI-Generated Deception Pages, AI Custom Prompt Template ({path}{query_part}), llama.cpp, Ollama, OpenAI Provider, OpenRouter Provider, Self-Hosted LLM (llama.cpp / Ollama), Deception Page Endpoints (+5 more)

### Community 61 - "Honeypot Capabilities"
Cohesion: 0.26
Nodes (12): BanCheckMiddleware, DeceptionMiddleware, ServerHeaderMiddleware, Command Injection Detection, Fake .env Leakage, Fake Directory Listing, Fake Login Pages (/admin, /wp-admin, /phpMyAdmin), Honeypot Capabilities (+4 more)

### Community 62 - "sanitizer.py"
Cohesion: 0.22
Nodes (7): fetch_blocklist_data(), sanitize_attack_pattern(), sanitize_credential(), sanitize_dict(), sanitize_for_storage(), sanitize_user_agent(), main()

### Community 63 - "Krawl Dashboard"
Cohesion: 0.14
Nodes (15): dashboard_warmup Task, IP Categories (attacker, bad_crawler, good_crawler, regular_user, unknown), Dashboard Session Authentication (12h HTTP-only cookie), Dashboard Branding Config, Dashboard Cache Warmup, Dashboard Authentication (brute-force backoff), hash-payloads Task, IP Insight Tab (+7 more)

### Community 64 - "Dashboard API"
Cohesion: 0.10
Nodes (20): sync_cloudflare Task, Cloudflare Account IP List, Cloudflare Banlist Sync, Attachment Extraction from Raw Requests, Cloudflare Webhook Endpoints, Dashboard API, /api/export-ips Endpoint, OpenAPI Schema + Swagger UI (+12 more)

### Community 66 - "ip_utils.py"
Cohesion: 0.24
Nodes (4): _cidrs_in(), defer_persist(), _prune_seen(), seen_before()

### Community 68 - "build_campaign_stats"
Cohesion: 0.18
Nodes (8): build_campaign_stats(), _campaign_slot_hours(), _campaign_window(), _parse_day(), _attack(), _db(), test_campaigns_rank_and_total_by_hits_inside_the_window(), test_filename_index_keeps_names_shared_by_two_or_more_ips()

### Community 69 - "main"
Cohesion: 0.14
Nodes (8): get_cached_short(), _json_serializer(), set_cached(), set_cached_list(), set_cached_short(), main(), _timed(), _warm_pages()

### Community 70 - "test_generated_content_type.py"
Cohesion: 0.22
Nodes (5): _content_type_for_path(), test_data_paths_are_not_html(), test_pages_stay_html(), test_route_sends_the_content_type(), test_wrapping_is_limited_to_html()

### Community 71 - "trap_page"
Cohesion: 0.17
Nodes (7): get_model(), get_provider(), _generate_page(), _get_random_error_code(), _should_return_error(), _tarpit_text(), trap_page()

### Community 72 - "db_dump.py"
Cohesion: 0.22
Nodes (3): _dump_pg(), _dump_sqlite(), main()

### Community 73 - "._insert_access_log_batch"
Cohesion: 0.22
Nodes (3): _entry_bytes(), size(), _trim_write_buffer()

### Community 74 - "Krawl Deployment (k8s)"
Cohesion: 0.31
Nodes (10): Kubernetes Manifest Validation Job, krawl-config ConfigMap, Krawl Deployment (k8s), krawl-postgres StatefulSet, krawl-redis StatefulSet, Krawl All-in-One Kubernetes Manifest, Krawl NetworkPolicy, Externally-Managed Secrets (+2 more)

### Community 75 - "build_grafana_dashboard.py"
Cohesion: 0.36
Nodes (6): bargauge(), base(), multistat(), stat(), target(), timeseries()

### Community 76 - "ban_cache.py"
Cohesion: 0.10
Nodes (6): add(), is_banned(), is_ready(), needs_lookup(), is_globally_banned(), test_global_ban_and_dashboard_path_boundary()

### Community 77 - "purge.py"
Cohesion: 0.27
Nodes (4): clear_expired_bans(), purge_ipv6_rows(), run_startup_cleanup(), main()

### Community 78 - "_get_attachment_content"
Cohesion: 0.24
Nodes (5): _extract_headers(), _get_attachment_content(), _is_file_content_type(), _parse_attachments(), _path_to_filename()

### Community 79 - "error"
Cohesion: 0.20
Nodes (10): confirm(), _create(), error(), escapeHtml(), fetchAttachments(), formatBytes(), highlightRawRequest(), success() (+2 more)

### Community 80 - "_Tracker"
Cohesion: 0.22
Nodes (3): _multipart_request(), test_unmatched_uploads_are_captured_with_tlsh_disabled(), _Tracker

### Community 81 - "test_brand.py"
Cohesion: 0.36
Nodes (8): brand(), test_contact_email_becomes_mailto(), test_contact_plain_text_is_not_linked(), test_contact_url_stays_a_link(), test_defaults_are_krawls_own(), test_hostile_values_never_reach_an_href(), test_no_url_means_no_anchor(), test_version_hidden_when_disabled()

### Community 82 - "Tarpit"
Cohesion: 0.15
Nodes (10): AccessTracker (tracker.record), Honeypot Router (catch-all), Canary Token Integration, canarytokens.org, NGINX Reverse Proxy Configuration, Client IP Proxy Header Priority (CF-Connecting-IP, X-Forwarded-For, X-Real-IP), Deploying Behind a Reverse Proxy or CDN, Infinite Pages for Malicious Crawlers (+2 more)

### Community 83 - "Krawl Runtime Dependencies"
Cohesion: 0.47
Nodes (4): PR Lint & Dependency Checks Job, Security Scan Job (Bandit + pip-audit), Dev Dependencies (pytest, httpx, ruff), Krawl Runtime Dependencies

### Community 84 - "main"
Cohesion: 0.18
Nodes (5): _scalar_min_max(), PayloadCluster, tlsh_diff(), build_raw_request(), main()

### Community 86 - "firewall/__init__.py"
Cohesion: 0.25
Nodes (3): _iptables(), _nftables(), _raw()

### Community 87 - "External APIs"
Cohesion: 0.43
Nodes (7): External APIs, ip-api.com Geolocation, iprep.lcrawl.com IP Reputation, Nominatim Reverse Geocoding, Server Public IP Discovery (ipify, ident.me, ifconfig.me), fetch_ip_rep Background Task, IP Enrichment Pipeline

### Community 95 - "test_all_attacks.sh"
Cohesion: 0.70
Nodes (4): request_info(), response_info(), test_all_attacks.sh script, test_header()

### Community 97 - "dashboard_cache.py"
Cohesion: 0.13
Nodes (4): initialize_cache(), paginate_cached_list(), claim(), _local_claim()

### Community 98 - "formatValue"
Cohesion: 0.50
Nodes (4): anyVisible(), formatValue(), isEmpty(), visibleFields()

### Community 100 - "tokens.js"
Cohesion: 0.83
Nodes (3): krawlAttackColor(), krawlCategoryColors(), krawlToken()

### Community 103 - "switchToBanlist"
Cohesion: 0.67
Nodes (3): closeAuthModal(), submitAuth(), switchToBanlist()

## Ambiguous Edges - Review These
- `main()` → `Honeypot robots.txt Disallow List`  [AMBIGUOUS]
  src/templates/html/robots.txt · relation: references
- `Fake Admin Panel Login Form` → `Dashboard Password Unlock Modal`  [AMBIGUOUS]
  img/admin-page.png · relation: conceptually_related_to

## Knowledge Gaps
- **93 isolated node(s):** `entrypoint.sh script`, `krawl-iptables.sh script`, `krawl-nftables.sh script`, `CAMPAIGN_ROW_OPTIONS`, `_allowedUploadExts` (+88 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 842 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **28 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `main()` and `Honeypot robots.txt Disallow List`?**
  _Edge tagged AMBIGUOUS (relation: references) - confidence is low._
- **What is the exact relationship between `Fake Admin Panel Login Form` and `Dashboard Password Unlock Modal`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **Why does `Krawl Web Honeypot` connect `Krawl Web Honeypot` to `Dashboard API`, `Krawl config.yaml`, `Krawl Helm Chart README`, `Krawl Deployment (k8s)`, `Deployment Modes`, `Krawl Architecture`, `Tarpit`, `External APIs`, `AI-Generated Deception Pages`, `Honeypot Capabilities`, `Krawl Dashboard`?**
  _High betweenness centrality (0.102) - this node is a cross-community bridge._
- **Why does `get_config()` connect `get_config` to `core.py`, `IpStatsRepo`, `.persist_access`, `generative_ai.py`, `get`, `Config`, `RequestAsset`, `AccessTracker`, `webhooks.py`, `lifespan`, `pagination`, `AnalyticsRepo`, `banlist_sync.py`, `PayloadRepo`, `api.py`, `honeypot.py`, `app.py`, `dashboard.py`, `get_app_logger`, `dependencies.py`, `_config_fields`, `load_template`, `get_database`, `hash_payloads.py`, `ip_utils.py`, `main`, `trap_page`, `db_dump.py`, `purge.py`, `_Tracker`, `main`, `is_ignored_ip`?**
  _High betweenness centrality (0.093) - this node is a cross-community bridge._
- **Why does `get_app_logger()` connect `get_app_logger` to `core.py`, `IpStatsRepo`, `TasksMaster`, `get`, `Config`, `RequestAsset`, `webhooks.py`, `lifespan`, `banlist_sync.py`, `api.py`, `get_config`, `honeypot.py`, `app.py`, `dashboard.py`, `dependencies.py`, `_config_fields`, `maintenance.py`, `load_template`, `get_database`, `test_insert_fake_ips.py`, `geo_utils.py`, `hash_payloads.py`, `export_ips`, `contact_post`, `sanitizer.py`, `Logger`, `ip_utils.py`, `trap_page`, `db_dump.py`, `ban_cache.py`, `purge.py`, `_get_attachment_content`, `is_ignored_ip`, `wordlists.py`?**
  _High betweenness centrality (0.080) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `get_config()` (e.g. with `test_ignored_ip_never_reads_the_body()` and `test_cleanup_progresses_past_suspicious_batch_and_preserves_evidence()`) actually correct?**
  _`get_config()` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 15 inferred relationships involving `get_database()` (e.g. with `seed()` and `main()`) actually correct?**
  _`get_database()` has 15 INFERRED edges - model-reasoned connections that need verification._