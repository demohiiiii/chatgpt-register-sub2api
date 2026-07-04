"""CLI entry point for chatgpt-register-sub2api.

Subcommands:
  init             Write default config.yaml
  register         Register N ChatGPT accounts
  join-workspace   Join registered accounts to K12 workspace
  login-team       Re-login with Team space selection
  login-export     Login selected existing accounts and export sub2api JSON
  login-run        Login selected accounts, join workspace, export sub2api JSON
  export           Export to sub2api JSON
  run              Full pipeline (register → join → login → export)
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from chatgpt_register_sub2api import __version__
from chatgpt_register_sub2api.config import (
    DEFAULT_CONFIG_FILE,
    generate_default_config,
    load_config,
)
from chatgpt_register_sub2api.pipeline import (
    load_accounts,
    run_export,
    run_full_pipeline,
    run_join_workspace,
    run_login_join_export,
    run_login_export,
    run_re_login,
    run_register,
    save_accounts,
)


def setup_logging(config: dict, verbose: bool = False) -> None:
    """Configure Python logging based on config + CLI verbosity."""
    log_cfg = config.get("logging", {})
    level_name = "DEBUG" if verbose else str(log_cfg.get("level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)

    fmt = "%(asctime)s [%(levelname)-5s] %(message)s"
    datefmt = "%H:%M:%S"

    log_file = str(log_cfg.get("file", "")).strip()
    if log_file:
        logging.basicConfig(
            level=level,
            format=fmt,
            datefmt=datefmt,
            handlers=[
                logging.FileHandler(log_file, encoding="utf-8"),
                logging.StreamHandler(sys.stderr),
            ],
        )
    else:
        logging.basicConfig(
            level=level,
            format=fmt,
            datefmt=datefmt,
            stream=sys.stderr,
        )


def cmd_init(args) -> int:
    """Write default config.yaml."""
    path = Path(args.config) if args.config else DEFAULT_CONFIG_FILE
    try:
        output = generate_default_config(path)
        print(f"Config written to {output}")
        return 0
    except FileExistsError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_register(args) -> int:
    """Register N ChatGPT accounts."""
    config = load_config(args.config)
    setup_logging(config, args.verbose)
    logger = logging.getLogger(__name__)

    config_dir = Path(config.get("_config_dir", "."))
    accounts_file = config_dir / "registered_accounts.json"

    results = run_register(
        config=config,
        accounts_file=accounts_file,
        count=args.count,
    )

    print(f"\nRegistered: {len(results)} accounts")
    for acc in results:
        print(f"  {acc['email']}")
    return 0


def cmd_join_workspace(args) -> int:
    """Join registered accounts to K12 workspace."""
    config = load_config(args.config)
    setup_logging(config, args.verbose)
    logger = logging.getLogger(__name__)

    # Override workspace IDs from CLI
    if args.workspace_id:
        config.setdefault("workspace", {})["ids"] = args.workspace_id

    config_dir = Path(config.get("_config_dir", "."))
    input_file = Path(args.input) if args.input else config_dir / "registered_accounts.json"
    accounts = load_accounts(input_file)

    if not accounts:
        print(f"No accounts found in {input_file}", file=sys.stderr)
        return 1

    accounts = run_join_workspace(config, accounts)
    save_accounts(input_file, accounts)

    joined = sum(1 for a in accounts if a.get("join_status") == "ok")
    print(f"\nJoined: {joined}/{len(accounts)} accounts")
    return 0


def cmd_login_team(args) -> int:
    """Re-login with Team space selection."""
    config = load_config(args.config)
    setup_logging(config, args.verbose)
    logger = logging.getLogger(__name__)

    config_dir = Path(config.get("_config_dir", "."))
    input_file = Path(args.input) if args.input else config_dir / "registered_accounts.json"
    accounts = load_accounts(input_file)

    if not accounts:
        print(f"No accounts found in {input_file}", file=sys.stderr)
        return 1

    accounts = run_re_login(config, accounts)
    save_accounts(input_file, accounts)

    team_logged = sum(1 for a in accounts if a.get("team_login_status") == "ok")
    print(f"\nTeam logged: {team_logged}/{len(accounts)} accounts")
    return 0


def cmd_export(args) -> int:
    """Export to sub2api JSON."""
    config = load_config(args.config)
    setup_logging(config, args.verbose)
    logger = logging.getLogger(__name__)

    config_dir = Path(config.get("_config_dir", "."))
    input_file = Path(args.input) if args.input else config_dir / "registered_accounts.json"
    accounts = load_accounts(input_file)

    if not accounts:
        print(f"No accounts found in {input_file}", file=sys.stderr)
        return 1

    output_file = Path(args.output) if args.output else None
    json_str = run_export(config, accounts, output_file)

    if args.stdout or not output_file:
        print(json_str)
    else:
        print(f"Exported to {output_file}")

    return 0


def cmd_login_export(args) -> int:
    """Login selected existing accounts and export successful logins."""
    config = load_config(args.config)
    setup_logging(config, args.verbose)

    accounts_file = Path(args.accounts) if args.accounts else Path("registered_accounts.json")
    output_file = Path(args.output) if args.output else None

    summary = run_login_export(
        config=config,
        emails=args.emails,
        output_file=output_file,
        accounts_file=accounts_file,
    )

    print(f"\nLogin-export summary:")
    print(f"  Requested: {len(summary['requested'])}")
    print(f"  Succeeded: {len(summary['succeeded'])}")
    print(f"  Exported:  {summary['exported']}")
    print(f"  Output:    {summary['output_file']}")

    if summary["missing"]:
        print("  Not found:")
        for email in summary["missing"]:
            print(f"    - {email}")

    if summary["missing_password"]:
        print("  Missing password:")
        for email in summary["missing_password"]:
            print(f"    - {email}")

    if summary["failed"]:
        print("  Login failed:")
        for item in summary["failed"]:
            print(f"    - {item['email']}: {item['error']}")

    return 0 if summary["exported"] > 0 else 1


def cmd_login_run(args) -> int:
    """Login selected accounts, join workspace, refresh, and export."""
    config = load_config(args.config)
    setup_logging(config, args.verbose)

    if args.workspace_id:
        config.setdefault("workspace", {})["ids"] = args.workspace_id

    accounts_file = Path(args.accounts) if args.accounts else Path("registered_accounts.json")
    output_file = Path(args.output) if args.output else None

    summary = run_login_join_export(
        config=config,
        emails=args.emails,
        output_file=output_file,
        accounts_file=accounts_file,
    )

    print(f"\nLogin-run summary:")
    print(f"  Requested: {len(summary['requested'])}")
    print(f"  Succeeded: {len(summary['succeeded'])}")
    print(f"  Joined:    {summary['joined']}")
    print(f"  K12 Refreshed: {summary['refreshed']}")
    print(f"  Exported:  {summary['exported']}")
    print(f"  Output:    {summary['output_file']}")
    print(f"  Accounts:  {summary['accounts_file']}")

    if summary["missing"]:
        print("  Not found:")
        for email in summary["missing"]:
            print(f"    - {email}")

    if summary["missing_password"]:
        print("  Missing password:")
        for email in summary["missing_password"]:
            print(f"    - {email}")

    if summary["failed"]:
        print("  Login failed:")
        for item in summary["failed"]:
            print(f"    - {item['email']}: {item['error']}")

    return 0 if summary["exported"] > 0 else 1


def cmd_run(args) -> int:
    """Run the full pipeline."""
    config = load_config(args.config)
    setup_logging(config, args.verbose)

    # Override workspace IDs from CLI
    if args.workspace_id:
        config.setdefault("workspace", {})["ids"] = args.workspace_id

    summary = run_full_pipeline(
        config=config,
        count=args.count,
        output_file=args.output,
        accounts_file=args.accounts,
    )

    print(f"\n{'='*40}")
    print(f"Pipeline Summary:")
    print(f"  Registered:  {summary['registered']}")
    print(f"  Joined:      {summary['joined']}")
    print(f"  K12 Refreshed: {summary['refreshed']}")
    print(f"  Exported:    {summary['exported']}")
    print(f"  Accounts:    {summary['accounts_file']}")

    return 0 if summary["registered"] > 0 else 1


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="chatgpt-register",
        description="ChatGPT 账号注册 + K12 母号加入 + Sub2API JSON 导出",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── init ──
    p_init = sub.add_parser("init", help="Write default config.yaml")
    p_init.add_argument("--config", "-c", default=None, help="Config file path")
    p_init.set_defaults(func=cmd_init)

    # ── register ──
    p_reg = sub.add_parser("register", help="Register ChatGPT accounts")
    p_reg.add_argument("--config", "-c", default=None, help="Config file path")
    p_reg.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p_reg.add_argument("--count", "-n", type=int, default=None, help="Number of accounts")
    p_reg.set_defaults(func=cmd_register)

    # ── join-workspace ──
    p_join = sub.add_parser("join-workspace", help="Join workspace")
    p_join.add_argument("--config", "-c", default=None, help="Config file path")
    p_join.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p_join.add_argument("--workspace-id", action="append", default=None, help="Workspace UUID (repeatable)")
    p_join.add_argument("--input", "-i", default=None, help="Input accounts JSON")
    p_join.set_defaults(func=cmd_join_workspace)

    # ── login-team ──
    p_login = sub.add_parser("login-team", help="Re-login with Team space")
    p_login.add_argument("--config", "-c", default=None, help="Config file path")
    p_login.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p_login.add_argument("--input", "-i", default=None, help="Input accounts JSON")
    p_login.set_defaults(func=cmd_login_team)

    # ── export ──
    p_export = sub.add_parser("export", help="Export sub2api JSON")
    p_export.add_argument("--config", "-c", default=None, help="Config file path")
    p_export.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p_export.add_argument("--output", "-o", default=None, help="Output file path")
    p_export.add_argument("--input", "-i", default=None, help="Input accounts JSON")
    p_export.add_argument("--stdout", action="store_true", help="Print to stdout")
    p_export.set_defaults(func=cmd_export)

    # ── login-export ──
    p_login_export = sub.add_parser(
        "login-export",
        help="Login selected existing accounts and export sub2api JSON",
    )
    p_login_export.add_argument("emails", nargs="+", help="Email address to login and export")
    p_login_export.add_argument("--config", "-c", default=None, help="Config file path")
    p_login_export.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p_login_export.add_argument("--output", "-o", default=None, help="Output sub2api JSON file")
    p_login_export.add_argument(
        "--accounts",
        default=None,
        help="Accounts store JSON file (default: ./registered_accounts.json)",
    )
    p_login_export.set_defaults(func=cmd_login_export)

    # ── login-run ──
    p_login_run = sub.add_parser(
        "login-run",
        help="Login selected accounts, join workspace, and export sub2api JSON",
    )
    p_login_run.add_argument("emails", nargs="+", help="Email address to login, join, and export")
    p_login_run.add_argument("--config", "-c", default=None, help="Config file path")
    p_login_run.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p_login_run.add_argument("--workspace-id", action="append", default=None, help="Workspace UUID (repeatable)")
    p_login_run.add_argument("--output", "-o", default=None, help="Output sub2api JSON file")
    p_login_run.add_argument(
        "--accounts",
        default=None,
        help="Accounts store JSON file (default: ./registered_accounts.json)",
    )
    p_login_run.set_defaults(func=cmd_login_run)

    # ── run ──
    p_run = sub.add_parser("run", help="Full pipeline")
    p_run.add_argument("--config", "-c", default=None, help="Config file path")
    p_run.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p_run.add_argument("--count", "-n", type=int, default=None, help="Number of accounts")
    p_run.add_argument("--workspace-id", action="append", default=None, help="Workspace UUID (repeatable)")
    p_run.add_argument("--output", "-o", default=None, help="Output sub2api JSON file")
    p_run.add_argument("--accounts", default=None, help="Accounts store JSON file")
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        sys.exit(1)

    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
