# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "httpx",
#   "pyyaml",
#   "tenacity",
# ]
# ///
"""Unit tests for approval counting.

Run: python -m unittest discover -s agent-approval-check -p 'test_*.py'
"""

from __future__ import annotations

import unittest

from agent_approval_check import (
    AgentConfig,
    count_approvers,
    find_stale_approvals,
    iter_approve_commands,
)

HEAD_SHA = "abcdef1234567890abcdef1234567890abcdef12"
OLD_SHA = "1234567890abcdef1234567890abcdef12345678"
AGENT_LOGIN = "claude[bot]"
EXCLUDED_LOGIN = "release-bot"


def make_config() -> AgentConfig:
    return AgentConfig(
        agent_emails=[],
        agent_app_logins=[AGENT_LOGIN],
        excluded_approver_logins=[EXCLUDED_LOGIN],
        exempt_head_branches=[],
    )


def make_review(login: str, state: str = "APPROVED") -> dict:
    return {
        "user": {"login": login},
        "state": state,
        "commit_id": HEAD_SHA,
        "submitted_at": "2026-11-13T00:00:00Z",
    }


def make_comment(login: str, body: str, comment_id: int = 1) -> dict:
    return {
        "id": comment_id,
        "node_id": f"IC_{comment_id}",
        "user": {"login": login},
        "body": body,
    }


class RecordingPermissionCheck:
    """Grants write to `writers` and records every login it was asked about."""

    def __init__(self, writers: set[str]) -> None:
        self.writers = frozenset(writers)
        self.calls: list[str] = []

    def __call__(self, login: str) -> bool:
        self.calls.append(login)
        return login in self.writers


class CountApproversTests(unittest.TestCase):
    def test_counts_review_from_writer_without_association_data(self) -> None:
        # Regression for #1700: private org members arrive with association
        # NONE; the permission API is the only gate.
        check = RecordingPermissionCheck({"alice"})

        approvers = count_approvers(
            HEAD_SHA, [make_review("alice")], [], make_config(), check
        )

        self.assertEqual(approvers, {"alice"})
        self.assertEqual(check.calls, ["alice"])

    def test_counts_approve_comment_from_writer(self) -> None:
        check = RecordingPermissionCheck({"carol"})
        comments = [make_comment("carol", f"/approve {HEAD_SHA}")]

        approvers = count_approvers(HEAD_SHA, [], comments, make_config(), check)

        self.assertEqual(approvers, {"carol"})

    def test_rejects_approvals_without_write_permission(self) -> None:
        check = RecordingPermissionCheck(set())
        comments = [make_comment("dave", f"/approve {HEAD_SHA}")]

        approvers = count_approvers(
            HEAD_SHA, [make_review("bob")], comments, make_config(), check
        )

        self.assertEqual(approvers, set())

    def test_skips_permission_call_for_non_approving_reviews(self) -> None:
        check = RecordingPermissionCheck({"erin"})
        reviews = [make_review("erin", state="CHANGES_REQUESTED")]

        approvers = count_approvers(HEAD_SHA, reviews, [], make_config(), check)

        self.assertEqual(approvers, set())
        self.assertEqual(check.calls, [])

    def test_skips_permission_call_for_agent_and_excluded_reviewers(self) -> None:
        check = RecordingPermissionCheck({AGENT_LOGIN, EXCLUDED_LOGIN})
        reviews = [make_review(AGENT_LOGIN), make_review(EXCLUDED_LOGIN)]

        approvers = count_approvers(HEAD_SHA, reviews, [], make_config(), check)

        self.assertEqual(approvers, set())
        self.assertEqual(check.calls, [])

    def test_ignores_approve_comment_for_non_head_sha(self) -> None:
        check = RecordingPermissionCheck({"frank"})
        comments = [make_comment("frank", f"/approve {OLD_SHA}")]

        approvers = count_approvers(HEAD_SHA, [], comments, make_config(), check)

        self.assertEqual(approvers, set())


class IterApproveCommandsTests(unittest.TestCase):
    def test_skips_permission_call_for_ordinary_comments(self) -> None:
        check = RecordingPermissionCheck({"grace"})
        comments = [make_comment("grace", "LGTM, nice work")]

        commands = list(iter_approve_commands(comments, make_config(), check))

        self.assertEqual(commands, [])
        self.assertEqual(check.calls, [])

    def test_skips_deleted_authors(self) -> None:
        check = RecordingPermissionCheck(set())
        comments = [make_comment("", f"/approve {HEAD_SHA}")]

        commands = list(iter_approve_commands(comments, make_config(), check))

        self.assertEqual(commands, [])
        self.assertEqual(check.calls, [])


class FindStaleApprovalsTests(unittest.TestCase):
    def test_reports_writer_whose_approve_targets_older_commit(self) -> None:
        check = RecordingPermissionCheck({"heidi"})
        comments = [make_comment("heidi", f"/approve {OLD_SHA}")]
        commits = [{"sha": OLD_SHA}, {"sha": HEAD_SHA}]

        stale = find_stale_approvals(
            comments, HEAD_SHA, make_config(), commits, check
        )

        self.assertEqual(stale, [{"user": "heidi", "sha": OLD_SHA}])


if __name__ == "__main__":
    unittest.main()
