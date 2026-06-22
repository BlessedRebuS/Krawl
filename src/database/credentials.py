"""Credential-attempt queries.

Writes (persist_credential) stay on DatabaseManager as a hot path.
"""

from typing import TYPE_CHECKING, Any

from sqlalchemy import distinct, func

from logger import get_app_logger
from models import CredentialAttempt
from sanitizer import sanitize_ip

if TYPE_CHECKING:
    from database.core import DatabaseManager

applogger = get_app_logger()


class CredentialRepo:
    """Reads over the credential_attempts table."""

    def __init__(self, db: "DatabaseManager") -> None:
        self._db = db

    def get_list(
        self, limit: int = 100, offset: int = 0, ip_filter: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Retrieve credential attempts with optional filtering.

        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            ip_filter: Filter by IP address

        Returns:
            List of credential attempt dictionaries
        """
        session = self._db.session
        try:
            query = session.query(CredentialAttempt).order_by(
                CredentialAttempt.timestamp.desc()
            )

            if ip_filter:
                query = query.filter(CredentialAttempt.ip == sanitize_ip(ip_filter))

            attempts = query.offset(offset).limit(limit).all()

            return [
                {
                    "id": attempt.id,
                    "ip": attempt.ip,
                    "path": attempt.path,
                    "username": attempt.username,
                    "password": attempt.password,
                    "timestamp": attempt.timestamp.isoformat(),
                }
                for attempt in attempts
            ]
        finally:
            self._db.close_session()

    def get_paginated(
        self,
        page: int = 1,
        page_size: int = 5,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        """
        Retrieve paginated list of credential attempts.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (timestamp, ip, username)
            sort_order: Sort order (asc or desc)

        Returns:
            Dictionary with credentials list and pagination info
        """
        session = self._db.session
        try:
            offset = (page - 1) * page_size

            # Validate sort parameters
            valid_sort_fields = {"timestamp", "ip", "username"}
            sort_by = sort_by if sort_by in valid_sort_fields else "timestamp"
            sort_order = (
                sort_order.lower() if sort_order.lower() in {"asc", "desc"} else "desc"
            )

            total_credentials = (
                session.query(func.count(CredentialAttempt.id)).scalar() or 0
            )

            # Build query with sorting
            query = session.query(CredentialAttempt)

            if sort_by == "timestamp":
                query = query.order_by(
                    CredentialAttempt.timestamp.desc()
                    if sort_order == "desc"
                    else CredentialAttempt.timestamp.asc()
                )
            elif sort_by == "ip":
                query = query.order_by(
                    CredentialAttempt.ip.desc()
                    if sort_order == "desc"
                    else CredentialAttempt.ip.asc()
                )
            elif sort_by == "username":
                query = query.order_by(
                    CredentialAttempt.username.desc()
                    if sort_order == "desc"
                    else CredentialAttempt.username.asc()
                )

            credentials = query.offset(offset).limit(page_size).all()
            total_pages = (total_credentials + page_size - 1) // page_size

            return {
                "credentials": [
                    {
                        "ip": c.ip,
                        "username": c.username,
                        "password": c.password,
                        "path": c.path,
                        "timestamp": c.timestamp.isoformat() if c.timestamp else None,
                    }
                    for c in credentials
                ],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total_credentials,
                    "total_pages": total_pages,
                },
            }
        finally:
            self._db.close_session()

    def get_unique_credentials(self) -> dict[str, list[str]]:
        """Get all unique usernames and passwords (no duplicates, no None/empty).

        Returns:
            Dictionary with 'usernames' and 'passwords' lists.
        """
        session = self._db.session
        try:
            usernames = [
                row[0]
                for row in session.query(distinct(CredentialAttempt.username))
                .filter(CredentialAttempt.username.isnot(None))
                .filter(CredentialAttempt.username != "")
                .all()
                if row[0]
            ]
            passwords = [
                row[0]
                for row in session.query(distinct(CredentialAttempt.password))
                .filter(CredentialAttempt.password.isnot(None))
                .filter(CredentialAttempt.password != "")
                .all()
                if row[0]
            ]
            return {"usernames": usernames, "passwords": passwords}
        except Exception as e:
            applogger.error(f"Error fetching unique credentials: {e}")
            return {"usernames": [], "passwords": []}
        finally:
            self._db.close_session()

    def count(self) -> int:
        """Count the total number of captured credential attempts."""
        session = self._db.session
        try:
            return session.query(CredentialAttempt).count() or 0
        except Exception as e:
            applogger.error(f"Error counting credentials: {e}")
            return 0
        finally:
            self._db.close_session()
