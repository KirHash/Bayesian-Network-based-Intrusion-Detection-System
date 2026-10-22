"""
Manage dashboard accounts from the command line.

    python manage_users.py add alice --role admin
    python manage_users.py list
    python manage_users.py passwd alice
    python manage_users.py role alice analyst
    python manage_users.py 2fa-reset alice        (a lost phone: turns two-factor sign-in off)
    python manage_users.py disable alice          (enable to undo)
    python manage_users.py remove alice

Works on the same database as the server (IDS_DB, default ids.db), also
while it is running. This is how the first admin account is created: there
is deliberately no "first visitor becomes admin" page.
"""
import argparse
import getpass
import os
import sys

from accounts import ROLES, AccountError, Accounts
from storage import Store


def read_password(prompt="Password: "):

    first = getpass.getpass(prompt)

    if first != getpass.getpass("Repeat it: "):
        sys.exit("The two passwords differ.")

    return first


def run(args, accounts, password_reader=read_password, out=print):
    """Execute one command; returns a process exit code."""

    try:

        if args.command == "add":
            name = accounts.create(args.username, password_reader(), args.role)
            out(f"Created {name} ({args.role}).")

        elif args.command == "list":

            users = accounts.users()

            if not users:
                out("No accounts yet: the dashboard is open to anyone who can reach it.")

            for user in users:
                out(
                    f"{user['username']:20s} {user['role']:8s} "
                    f"{'disabled' if user['disabled'] else 'enabled':9s} "
                    f"last login {user['last_login'] or 'never'}"
                )

        elif args.command == "passwd":
            accounts.set_password(args.username, password_reader("New password: "))
            out("Password changed; that user's sessions were ended.")

        elif args.command == "2fa-reset":
            accounts.disable_two_factor(args.username)
            out(f"Two-factor sign-in is off for {args.username}; they can set it up again.")

        elif args.command == "role":
            accounts.set_role(args.username, args.role)
            out(f"{args.username} is now {args.role}.")

        elif args.command in ("disable", "enable"):
            accounts.set_disabled(args.username, args.command == "disable")
            out(f"{args.username} {args.command}d.")

        elif args.command == "remove":
            accounts.delete(args.username)
            out(f"Removed {args.username}.")

    except AccountError as error:
        out(f"Error: {error}")
        return 1

    return 0


def parser():

    p = argparse.ArgumentParser(description="Manage Bayesian IDS accounts.")

    commands = p.add_subparsers(dest="command", required=True)

    add = commands.add_parser("add", help="create an account")
    add.add_argument("username")
    add.add_argument("--role", choices=ROLES, default="viewer")

    commands.add_parser("list", help="show accounts")

    for name in ("passwd", "disable", "enable", "remove", "2fa-reset"):
        commands.add_parser(name).add_argument("username")

    role = commands.add_parser("role", help="change an account's role")
    role.add_argument("username")
    role.add_argument("role", choices=ROLES)

    return p


def main(argv=None):

    args = parser().parse_args(argv)

    store = Store(os.environ.get("IDS_DB", "ids.db"))

    try:
        return run(args, Accounts(store))
    finally:
        store.close()


if __name__ == "__main__":

    sys.exit(main())
