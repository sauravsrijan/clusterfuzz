# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""server.py initialises the appengine server for ClusterFuzz."""
from __future__ import absolute_import

import webapp2
from base import utils
from config import local_config
from handlers import (base_handler, bots, commit_range, configuration, corpora,
                      coverage_report, crash_stats, domain_verifier, download,
                      fuzzer_stats, fuzzers, gcs_redirector, help_redirector,
                      home, issue_redirector, jobs, login, report_csp_failure,
                      revisions_info, testcase_list, upload_testcase, viewer)
from handlers.cron import (backup, build_crash_stats, cleanup, corpus_backup,
                           fuzz_strategy_selection, fuzzer_and_job_weights,
                           fuzzer_coverage, load_bigquery_stats, manage_vms,
                           ml_train, oss_fuzz_apply_ccs, oss_fuzz_build_status,
                           oss_fuzz_generate_certs, predator_pull,
                           project_setup, recurring_tasks,
                           schedule_corpus_pruning, sync_admins, triage)
from handlers.performance_report import show as show_performance_report
from handlers.reproduce_tool import get_config, testcase_info
from handlers.testcase_detail import crash_stats as crash_stats_on_testcase
from handlers.testcase_detail import (create_issue, delete, download_testcase,
                                      find_similar_issues, mark_fixed,
                                      mark_security, mark_unconfirmed, redo,
                                      remove_duplicate, remove_group,
                                      remove_issue)
from handlers.testcase_detail import show as show_testcase
from handlers.testcase_detail import (testcase_variants, update_from_trunk,
                                      update_issue)
from metrics import logs
from webapp2_extras import routes

_is_chromium = utils.is_chromium()
_is_oss_fuzz = utils.is_oss_fuzz()


class _TrailingSlashRemover(webapp2.RequestHandler):
    def get(self, url):
        self.redirect(url)


def redirect_to(to_domain):
    """Create a redirect handler to a domain."""

    class RedirectHandler(webapp2.RequestHandler):
        """Handler to redirect to domain."""

        def get(self, _):
            self.redirect("https://" + to_domain + self.request.path_qs, permanent=True)

    return RedirectHandler


# Add item to the navigation menu. Order is important.
base_handler.add_menu("Testcases", "/testcases")
base_handler.add_menu("Fuzzer Statistics", "/fuzzer-stats")
base_handler.add_menu("Crash Statistics", "/crash-stats")
base_handler.add_menu("Upload Testcase", "/upload-testcase")

if _is_chromium:
    base_handler.add_menu("Crashes by range", "/commit-range")

if not _is_oss_fuzz:
    base_handler.add_menu("Fuzzers", "/fuzzers")
    base_handler.add_menu("Corpora", "/corpora")
    base_handler.add_menu("Bots", "/bots")

base_handler.add_menu("Jobs", "/jobs")
base_handler.add_menu("Configuration", "/configuration")
base_handler.add_menu("Report Bug", "/report-bug")
base_handler.add_menu("Documentation", "/docs")

# We need to separate routes for cron to avoid redirection.
_CRON_ROUTES = [
    ("/backup", backup.Handler),
    ("/build-crash-stats", build_crash_stats.Handler),
    ("/cleanup", cleanup.Handler),
    ("/corpus-backup/make-public", corpus_backup.MakePublicHandler),
    ("/fuzzer-coverage", fuzzer_coverage.Handler),
    ("/fuzzer-stats/cache", fuzzer_stats.RefreshCacheHandler),
    ("/fuzzer-stats/preload", fuzzer_stats.PreloadHandler),
    ("/fuzzer-and-job-weights", fuzzer_and_job_weights.Handler),
    ("/fuzz-strategy-selection", fuzz_strategy_selection.Handler),
    ("/home-cache", home.RefreshCacheHandler),
    ("/load-bigquery-stats", load_bigquery_stats.Handler),
    ("/manage-vms", manage_vms.Handler),
    ("/oss-fuzz-apply-ccs", oss_fuzz_apply_ccs.Handler),
    ("/oss-fuzz-build-status", oss_fuzz_build_status.Handler),
    ("/oss-fuzz-generate-certs", oss_fuzz_generate_certs.Handler),
    ("/project-setup", project_setup.Handler),
    ("/predator-pull", predator_pull.Handler),
    ("/schedule-corpus-pruning", schedule_corpus_pruning.Handler),
    ("/schedule-impact-tasks", recurring_tasks.ImpactTasksScheduler),
    ("/schedule-ml-train-tasks", ml_train.Handler),
    ("/schedule-progression-tasks", recurring_tasks.ProgressionTasksScheduler),
    ("/schedule-upload-reports-tasks", recurring_tasks.UploadReportsTaskScheduler),
    ("/sync-admins", sync_admins.Handler),
    ("/testcases/cache", testcase_list.CacheHandler),
    ("/triage", triage.Handler),
]

_ROUTES = [
    ("/", home.Handler if _is_oss_fuzz else testcase_list.Handler),
    (r"(.*)/$", _TrailingSlashRemover),
    (r"/(google.+\.html)$", domain_verifier.Handler),
    ("/bots", bots.Handler),
    ("/bots/dead", bots.DeadBotsHandler),
    ("/commit-range", commit_range.Handler),
    ("/commit-range/load", commit_range.JsonHandler),
    ("/configuration", configuration.Handler),
    ("/add-external-user-permission", configuration.AddExternalUserPermission),
    ("/delete-external-user-permission", configuration.DeleteExternalUserPermission),
    ("/coverage-report/([^/]+)/([^/]+)/([^/]+)(/.*)?", coverage_report.Handler),
    ("/crash-stats/load", crash_stats.JsonHandler),
    ("/crash-stats", crash_stats.Handler),
    ("/corpora", corpora.Handler),
    ("/corpora/create", corpora.CreateHandler),
    ("/corpora/delete", corpora.DeleteHandler),
    ("/docs", help_redirector.DocumentationHandler),
    ("/download/?([^/]+)?", download.Handler),
    ("/fuzzers", fuzzers.Handler),
    ("/fuzzers/create", fuzzers.CreateHandler),
    ("/fuzzers/delete", fuzzers.DeleteHandler),
    ("/fuzzers/edit", fuzzers.EditHandler),
    ("/fuzzers/log/([^/]+)", fuzzers.LogHandler),
    ("/fuzzer-stats/load", fuzzer_stats.LoadHandler),
    ("/fuzzer-stats/load-filters", fuzzer_stats.LoadFiltersHandler),
    ("/fuzzer-stats", fuzzer_stats.Handler),
    ("/fuzzer-stats/.*", fuzzer_stats.Handler),
    ("/gcs-redirect", gcs_redirector.Handler),
    ("/issue/([0-9]+)", issue_redirector.Handler),
    ("/jobs", jobs.Handler),
    ("/jobs/delete-job", jobs.DeleteJobHandler),
    ("/login", login.Handler),
    ("/logout", login.LogoutHandler),
    ("/update-job", jobs.UpdateJob),
    ("/update-job-template", jobs.UpdateJobTemplate),
    ("/performance-report/(.+)/(.+)/(.+)", show_performance_report.Handler),
    ("/report-csp-failure", report_csp_failure.ReportCspFailureHandler),
    ("/reproduce-tool/get-config", get_config.Handler),
    ("/reproduce-tool/testcase-info", testcase_info.Handler),
    ("/session-login", login.SessionLoginHandler),
    ("/testcase", show_testcase.DeprecatedHandler),
    ("/testcase-detail/([0-9]+)", show_testcase.Handler),
    ("/testcase-detail/crash-stats", crash_stats_on_testcase.Handler),
    ("/testcase-detail/create-issue", create_issue.Handler),
    ("/testcase-detail/delete", delete.Handler),
    ("/testcase-detail/download-testcase", download_testcase.Handler),
    ("/testcase-detail/find-similar-issues", find_similar_issues.Handler),
    ("/testcase-detail/mark-fixed", mark_fixed.Handler),
    ("/testcase-detail/mark-security", mark_security.Handler),
    ("/testcase-detail/mark-unconfirmed", mark_unconfirmed.Handler),
    ("/testcase-detail/redo", redo.Handler),
    ("/testcase-detail/refresh", show_testcase.RefreshHandler),
    ("/testcase-detail/remove-duplicate", remove_duplicate.Handler),
    ("/testcase-detail/remove-issue", remove_issue.Handler),
    ("/testcase-detail/remove-group", remove_group.Handler),
    ("/testcase-detail/testcase-variants", testcase_variants.Handler),
    ("/testcase-detail/update-from-trunk", update_from_trunk.Handler),
    ("/testcase-detail/update-issue", update_issue.Handler),
    ("/testcases", testcase_list.Handler),
    ("/testcases/load", testcase_list.JsonHandler),
    ("/upload-testcase", upload_testcase.Handler),
    ("/upload-testcase/get-url-oauth", upload_testcase.UploadUrlHandlerOAuth),
    ("/upload-testcase/prepare", upload_testcase.PrepareUploadHandler),
    ("/upload-testcase/load", upload_testcase.JsonHandler),
    ("/upload-testcase/upload", upload_testcase.UploadHandler),
    ("/upload-testcase/upload-oauth", upload_testcase.UploadHandlerOAuth),
    ("/revisions", revisions_info.Handler),
    ("/report-bug", help_redirector.ReportBugHandler),
    ("/viewer", viewer.Handler),
]

logs.configure("appengine")

config = local_config.GAEConfig()
main_domain = config.get("domains.main")
redirect_domains = config.get("domains.redirects")
_DOMAIN_ROUTES = []
if main_domain and redirect_domains:
    for redirect_domain in redirect_domains:
        _DOMAIN_ROUTES.append(
            routes.DomainRoute(
                redirect_domain, [webapp2.Route("<:.*>", redirect_to(main_domain)),]
            )
        )

app = webapp2.WSGIApplication(_CRON_ROUTES + _DOMAIN_ROUTES + _ROUTES, debug=False)
