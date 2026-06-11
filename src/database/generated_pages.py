"""Generated-page (AI honeypot HTML cache) queries and maintenance."""

from datetime import date, datetime
from typing import TYPE_CHECKING, Any

from logger import get_app_logger
from models import GeneratedPage

if TYPE_CHECKING:
    from database.core import DatabaseManager

applogger = get_app_logger()


class GeneratedPageRepo:
    """Reads, counts, and deletions over the generated_pages table."""

    def __init__(self, db: "DatabaseManager") -> None:
        self._db = db

    def get_paginated(
        self,
        page: int = 1,
        page_size: int = 10,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        """
        Retrieve paginated list of generated deception template pages.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (created_at, last_accessed, path, or access_count)
            sort_order: Sort order (asc or desc)

        Returns:
            Dictionary with generated pages list and pagination info
        """
        session = self._db.session
        try:
            offset = (page - 1) * page_size

            # Get total number of generated pages
            total_pages_count = session.query(GeneratedPage).count()

            # Build query with sorting
            query = session.query(GeneratedPage)

            if sort_by == "created_at":
                order_expr = (
                    GeneratedPage.created_at.desc()
                    if sort_order == "desc"
                    else GeneratedPage.created_at.asc()
                )
            elif sort_by == "last_accessed":
                order_expr = (
                    GeneratedPage.last_accessed.desc()
                    if sort_order == "desc"
                    else GeneratedPage.last_accessed.asc()
                )
            elif sort_by == "access_count":
                order_expr = (
                    GeneratedPage.access_count.desc()
                    if sort_order == "desc"
                    else GeneratedPage.access_count.asc()
                )
            else:  # path
                order_expr = (
                    GeneratedPage.path.desc()
                    if sort_order == "desc"
                    else GeneratedPage.path.asc()
                )

            results = query.order_by(order_expr).offset(offset).limit(page_size).all()
            total_pages = max(1, (total_pages_count + page_size - 1) // page_size)

            return {
                "generated_pages": [
                    {
                        "id": row.path,
                        "path": row.path,
                        "html_preview": (
                            row.html_content_b64[:100] + "..."
                            if row.html_content_b64 and len(row.html_content_b64) > 100
                            else (row.html_content_b64 or "No preview available")
                        ),
                        "html_content_b64": row.html_content_b64 or "",
                        "created_at": (
                            row.created_at.isoformat() if row.created_at else None
                        ),
                        "last_accessed": (
                            row.last_accessed.isoformat() if row.last_accessed else None
                        ),
                        "access_count": row.access_count,
                    }
                    for row in results
                ],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total_pages_count,
                    "total_pages": total_pages,
                },
            }
        except Exception as e:
            applogger.error(f"Error fetching generated pages: {e}")
            return {
                "generated_pages": [],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": 0,
                    "total_pages": 0,
                },
            }
        finally:
            self._db.close_session()

    def count_created_today(self) -> int:
        """Count how many generated pages were created today.

        Returns:
            Number of pages created today
        """
        session = self._db.session
        try:
            today = date.today()
            today_start = datetime.combine(today, datetime.min.time())
            today_end = datetime.combine(today, datetime.max.time())

            count = (
                session.query(GeneratedPage)
                .filter(
                    GeneratedPage.created_at >= today_start,
                    GeneratedPage.created_at <= today_end,
                )
                .count()
            )
            return count
        except Exception as e:
            applogger.error(f"Error counting generated pages created today: {e}")
            return 0
        finally:
            self._db.close_session()

    def delete_all(self) -> int:
        """Delete all generated deception pages from database.

        Returns:
            Number of pages deleted
        """
        session = self._db.session
        try:
            deleted_count = session.query(GeneratedPage).delete(
                synchronize_session=False
            )
            session.flush()  # Flush to ensure DELETE is executed
            session.commit()
            applogger.debug(f"Deleted {deleted_count} all generated pages")
            return deleted_count
        except Exception as e:
            applogger.error(f"Error deleting all generated pages: {e}")
            session.rollback()
            return 0
        finally:
            self._db.close_session()

    def delete_before(self, date_str: str) -> int:
        """Delete generated pages created before a specific date.

        Args:
            date_str: Date string in format YYYY-MM-DD

        Returns:
            Number of pages deleted

        Raises:
            ValueError: If date format is invalid
        """
        session = self._db.session
        try:
            # Parse the date string
            target_date = datetime.fromisoformat(date_str)

            # Delete all pages created before this date
            deleted_count = (
                session.query(GeneratedPage)
                .filter(GeneratedPage.created_at < target_date)
                .delete(synchronize_session=False)
            )
            session.flush()  # Flush to ensure DELETE is executed
            session.commit()
            applogger.debug(
                f"Deleted {deleted_count} generated pages created before {date_str}"
            )
            return deleted_count
        except ValueError as e:
            raise ValueError(
                f"Invalid date format. Use YYYY-MM-DD (got: {date_str})"
            ) from e
        except Exception as e:
            applogger.error(f"Error deleting generated pages before {date_str}: {e}")
            session.rollback()
            return 0
        finally:
            self._db.close_session()

    def delete_by_ids(self, page_ids: list) -> int:
        """Delete specific generated pages by their IDs (paths).

        Args:
            page_ids: List of page paths to delete

        Returns:
            Number of pages deleted
        """
        session = self._db.session
        try:
            # Execute DELETE query with explicit flush to get accurate count
            deleted_count = (
                session.query(GeneratedPage)
                .filter(GeneratedPage.path.in_(page_ids))
                .delete(synchronize_session=False)
            )
            session.flush()  # Flush to ensure DELETE is executed
            session.commit()
            applogger.debug(f"Deleted {deleted_count} generated pages: {page_ids}")
            return deleted_count
        except Exception as e:
            applogger.error(f"Error deleting pages by paths: {e}")
            session.rollback()
            return 0
        finally:
            self._db.close_session()

    def get_before(self, date_str: str) -> list:
        """Get generated pages created before a specific date.

        Returns:
            List of GeneratedPage objects (with eager-loaded content) created
            before the specified date

        Raises:
            ValueError: If date format is invalid
        """
        session = self._db.session
        try:
            # Parse the date string
            target_date = datetime.fromisoformat(date_str)

            # Query all pages created before this date
            pages = (
                session.query(GeneratedPage)
                .filter(GeneratedPage.created_at < target_date)
                .all()
            )

            # Force load the html_content_b64 for all pages before closing session
            # This prevents lazy-loading issues after session is closed
            for page in pages:
                _ = page.html_content_b64

            applogger.debug(
                f"Retrieved {len(pages)} generated pages created before {date_str}"
            )
            return pages
        except ValueError as e:
            raise ValueError(
                f"Invalid date format. Use YYYY-MM-DD (got: {date_str})"
            ) from e
        except Exception as e:
            applogger.error(f"Error querying generated pages before {date_str}: {e}")
            return []
        finally:
            self._db.close_session()
