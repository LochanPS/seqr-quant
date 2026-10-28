"""Operator CLI: link a GitHub App installation to a SeQr org (PRD 07, CI-4).

The webhook carries a numeric ``installation_id`` but no SeQr identity, so a PR scan can
only sync into a customer's CBOM once an operator maps the installation to an org. This is
that one manual step (see docs/GITHUB_APP_OPERATIONS.md §4), as a CLI so it runs on the VM
with no auth dance:

    docker compose --env-file deploy/oracle/.env -f docker-compose.oracle.yml \\
        exec backend python -m app.github_app.link set \\
        --installation-id 4242 --org-email pokkalilochan@gmail.com --account-login acme

    ... link list
    ... link unset --installation-id 4242

The org is resolved by exactly one of ``--org-id`` / ``--org-email`` (an existing user's
email → their org) / ``--org-name`` (unique match). ``set`` is idempotent — re-linking an
installation updates the mapping rather than erroring.
"""
from __future__ import annotations

import argparse
import sys
import uuid


def _resolve_org_id(db, args) -> uuid.UUID:
    from app.models.organisation import Organisation
    from app.models.user import User

    given = [x for x in (args.org_id, args.org_email, args.org_name) if x]
    if len(given) != 1:
        raise SystemExit("error: give exactly one of --org-id / --org-email / --org-name")

    if args.org_id:
        try:
            oid = uuid.UUID(args.org_id)
        except ValueError:
            raise SystemExit(f"error: --org-id is not a valid UUID: {args.org_id!r}")
        if not db.get(Organisation, oid):
            raise SystemExit(f"error: no organisation with id {oid}")
        return oid

    if args.org_email:
        user = db.query(User).filter(User.email == args.org_email.lower().strip()).first()
        if not user:
            raise SystemExit(f"error: no user with email {args.org_email!r}")
        return user.org_id

    matches = db.query(Organisation).filter(Organisation.name == args.org_name).all()
    if not matches:
        raise SystemExit(f"error: no organisation named {args.org_name!r}")
    if len(matches) > 1:
        ids = ", ".join(str(o.id) for o in matches)
        raise SystemExit(f"error: {len(matches)} orgs named {args.org_name!r} — use --org-id ({ids})")
    return matches[0].id


def _cmd_set(db, args) -> int:
    from app.models.github_installation import GitHubInstallation

    org_id = _resolve_org_id(db, args)
    link = db.get(GitHubInstallation, args.installation_id)
    action = "updated" if link else "created"
    if link is None:
        link = GitHubInstallation(installation_id=args.installation_id)
        db.add(link)
    link.org_id = org_id
    if args.account_login is not None:
        link.account_login = args.account_login
    if args.account_type is not None:
        link.account_type = args.account_type
    db.commit()
    print(f"{action}: installation {args.installation_id} -> org {org_id}"
          + (f" ({link.account_login})" if link.account_login else ""))
    return 0


def _cmd_unset(db, args) -> int:
    from app.models.github_installation import GitHubInstallation

    link = db.get(GitHubInstallation, args.installation_id)
    if not link:
        print(f"no link for installation {args.installation_id}")
        return 1
    db.delete(link)
    db.commit()
    print(f"removed: installation {args.installation_id}")
    return 0


def _cmd_list(db, args) -> int:
    from app.models.github_installation import GitHubInstallation

    rows = db.query(GitHubInstallation).order_by(GitHubInstallation.created_at).all()
    if not rows:
        print("(no installations linked)")
        return 0
    for r in rows:
        login = r.account_login or "?"
        print(f"{r.installation_id}\t{r.org_id}\t{login}\t{r.account_type or ''}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m app.github_app.link",
        description="Link a GitHub App installation to a SeQr org (CI-4).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("set", help="create or update a link (idempotent)")
    s.add_argument("--installation-id", type=int, required=True)
    s.add_argument("--org-id", help="SeQr org UUID")
    s.add_argument("--org-email", help="email of a user in the target org")
    s.add_argument("--org-name", help="exact org name (must be unique)")
    s.add_argument("--account-login", help="GitHub org/user login the App is installed on")
    s.add_argument("--account-type", help="Organization | User")
    s.set_defaults(func=_cmd_set)

    u = sub.add_parser("unset", help="remove a link")
    u.add_argument("--installation-id", type=int, required=True)
    u.set_defaults(func=_cmd_unset)

    lst = sub.add_parser("list", help="list all links")
    lst.set_defaults(func=_cmd_list)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from app.database import SyncSessionLocal

    db = SyncSessionLocal()
    try:
        return args.func(db, args)
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
