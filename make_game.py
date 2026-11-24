"""S5.2 lexical planner; metadata inspection and execution remain HOLD."""
import argparse
import json
import os
from pathlib import PurePath
import re
import sys
import unicodedata

STAGES = {"check": (), "shaders": ("python", "llvm-mc", "spirv-as", "spirv-val"),
          "assets": ("python", "dotnet", "rpf9dump", "ffmpeg"),
          "runtime": ("powershell", "msvc", "cmake", "ninja"),
          "pipelines": ("vk_pipeline_check", "vulkan-loader", "gpu-driver")}


class PolicyError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise PolicyError("INVALID_ARGUMENTS")


class Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if hasattr(namespace, self.dest):
            raise PolicyError("DUPLICATE_ARGUMENT")
        setattr(namespace, self.dest, values)


def lexical_path(raw, windows=None):
    """Return a conservative lexical comparison key; never inspect storage."""
    if windows is None:
        windows = os.name == "nt"
    if (not raw or len(raw) > 4096 or unicodedata.normalize("NFC", raw) != raw
            or any(unicodedata.category(c).startswith("C") for c in raw)):
        raise PolicyError("INVALID_PATH")
    if windows:
        raw = raw.replace("\\", "/")
        if not re.match(r"^[A-Za-z]:/", raw):
            raise PolicyError("LOCAL_DRIVE_SYNTAX_REQUIRED")
        anchor, tail = raw[:2].casefold(), raw[3:]
    else:
        if not raw.startswith("/") or "\\" in raw:
            raise PolicyError("ABSOLUTE_NONROOT_REQUIRED")
        anchor, tail = "/", raw[1:]
    parts = tail.split("/")
    if len(parts) > 64 or any(not p or p in (".", "..") or len(p) > 255 for p in parts):
        raise PolicyError("AMBIGUOUS_PATH")
    if windows:
        for part in parts:
            if (part.endswith((".", " ")) or any(c in part for c in ':<>"|?*~')
                    or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|CLOCK\$|COM[1-9¹²³]|LPT[1-9¹²³])",
                                    part.split(".")[0].rstrip())):
                raise PolicyError("AMBIGUOUS_PATH")
    # Conservative on case-sensitive filesystems too. This is not an identity test.
    return (anchor, *(unicodedata.normalize("NFC", p.casefold()) for p in parts))


def overlaps(a, b):
    n = min(len(a), len(b))
    return a[:n] == b[:n]


def make_plan(game, out, work, stages, jobs):
    selected = stages.split(",")
    if any(s not in STAGES for s in selected) or len(set(selected)) != len(selected):
        raise PolicyError("INVALID_STAGES")
    if not 1 <= jobs <= 4:
        raise PolicyError("INVALID_JOB_LIMIT")
    roots = [lexical_path(raw) for raw in (game, out, work, str(PurePath(__file__).parent))]
    if any(overlaps(a, b) for i, a in enumerate(roots) for b in roots[i+1:]):
        raise PolicyError("OVERLAPPING_ROOTS")
    return {"schema": 2, "operation": "plan", "status": "HOLD",
            "stages": [s for s in STAGES if s in selected], "requested_jobs": jobs,
            "required_tools": sorted({t for s in selected for t in STAGES[s]}),
            "path_validation": "LEXICAL_ONLY", "metadata": "NOT_INSPECTED",
            "locality": "UNVERIFIED", "path_identity": "UNVERIFIED",
            "tool_identity": "UNVERIFIED", "dependency_policy": "S4_CI_ONLY",
            "resource_enforcement": "NOT_AVAILABLE", "isolation": "NOT_APPROVED",
            "execution_authorized": False, "host_execution": "HOLD"}


def main(argv=None):
    parser = Parser(prog="make_game.py", description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="operation", required=True, parser_class=Parser)
    for name in ("plan", "inspect"):
        command = commands.add_parser(name, allow_abbrev=False)
        for flag in ("--game", "--out", "--work", "--stages"):
            command.add_argument(flag, required=True, action=Once, default=argparse.SUPPRESS)
        command.add_argument("--jobs", type=int, action=Once, default=argparse.SUPPRESS)
    for name in ("prepare", "build"):
        commands.add_parser(name, help="disabled pending independent approval", allow_abbrev=False)
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) > 24 or any(len(x) > 4096 for x in args):
            raise PolicyError("ARGUMENT_LIMIT")
        a = parser.parse_args(args)
        if a.operation in ("prepare", "build"):
            print("HOLD: execution and dependency preparation disabled", file=sys.stderr)
            return 3
        result = make_plan(a.game, a.out, a.work, a.stages, getattr(a, "jobs", 1))
        if a.operation == "inspect":
            print("HOLD: metadata inspection not authorized", file=sys.stderr)
            return 3
        print(json.dumps(result, sort_keys=True))
        return 0
    except PolicyError as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, OverflowError):
        print("REJECTED: PATH_POLICY_FAILED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
