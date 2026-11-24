"""S5.2 metadata-only planner. All execution remains HOLD."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

STAGES = {"check": (), "shaders": ("python", "llvm-mc", "spirv-as", "spirv-val"),
          "assets": ("python", "dotnet", "rpf9dump", "ffmpeg"),
          "runtime": ("powershell", "msvc", "cmake", "ninja"),
          "pipelines": ("vk_pipeline_check", "vulkan-loader", "gpu-driver")}


class PolicyError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise PolicyError("INVALID_ARGUMENTS")


def checked_path(raw, existing):
    """Inspect named components only; not an isolation boundary."""
    if not raw or any(ord(c) < 32 for c in raw):
        raise PolicyError("INVALID_PATH")
    p = Path(raw)
    if not p.is_absolute() or p == Path(p.anchor):
        raise PolicyError("ABSOLUTE_NONROOT_REQUIRED")
    if any(x in (".", "..") for x in raw.replace("\\", "/").split("/")):
        raise PolicyError("AMBIGUOUS_PATH")
    if os.name == "nt":
        if not re.fullmatch(r"[A-Za-z]:\\", p.anchor):
            raise PolicyError("LOCAL_DRIVE_REQUIRED")
        for part in p.parts[1:]:
            if (part.endswith((".", " ")) or any(c in part for c in ':<>"|?*')
                    or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])", part.split(".")[0].rstrip())):
                raise PolicyError("AMBIGUOUS_PATH")
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(p.anchor)) != 3:
            raise PolicyError("LOCAL_FIXED_DRIVE_REQUIRED")
    elif raw.startswith("//"):
        raise PolicyError("AMBIGUOUS_PATH")
    current = Path(p.anchor)
    for i, part in enumerate(p.parts[1:]):
        current = current / part
        leaf = i == len(p.parts) - 2
        try:
            info = current.lstat()
        except FileNotFoundError:
            if leaf and not existing:
                break
            raise PolicyError("MISSING_PATH_COMPONENT") from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PolicyError("LINK_OR_REPARSE_POINT")
        if not stat.S_ISDIR(info.st_mode):
            raise PolicyError("DIRECTORY_REQUIRED")
        if leaf and not existing:
            raise PolicyError("FRESH_DESTINATION_REQUIRED")
    return Path(os.path.realpath(current if existing else current.parent)) / ("" if existing else current.name)


def overlaps(a, b):
    try:
        common = os.path.normcase(os.path.commonpath((a, b)))
    except ValueError:
        return False
    return common in (os.path.normcase(str(a)), os.path.normcase(str(b)))


def make_plan(game, out, work, stages, jobs):
    selected = stages.split(",")
    if any(s not in STAGES for s in selected) or len(set(selected)) != len(selected):
        raise PolicyError("INVALID_STAGES")
    if not 1 <= jobs <= 4:
        raise PolicyError("INVALID_JOB_LIMIT")
    roots = [checked_path(game, True), checked_path(out, False),
             checked_path(work, False), Path(__file__).resolve().parent]
    if any(overlaps(a, b) for i, a in enumerate(roots) for b in roots[i+1:]):
        raise PolicyError("OVERLAPPING_ROOTS")
    return {"schema": 1, "operation": "plan", "status": "HOLD",
            "stages": [s for s in STAGES if s in selected], "requested_jobs": jobs,
            "required_tools": sorted({t for s in selected for t in STAGES[s]}),
            "tool_identity": "UNVERIFIED", "dependency_policy": "S4_CI_ONLY",
            "resource_enforcement": "NOT_AVAILABLE", "isolation": "NOT_APPROVED",
            "execution_authorized": False, "host_execution": "HOLD"}


def main(argv=None):
    parser = Parser(prog="make_game.py", description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="operation", required=True, parser_class=Parser)
    plan = commands.add_parser("plan", help="metadata-only planning", allow_abbrev=False)
    for flag in ("--game", "--out", "--work", "--stages"):
        plan.add_argument(flag, required=True)
    plan.add_argument("--jobs", type=int, default=1)
    for name in ("prepare", "build"):
        commands.add_parser(name, help="disabled pending independent approval", allow_abbrev=False)
    try:
        a = parser.parse_args(argv)
        if a.operation != "plan":
            print("HOLD: execution and dependency preparation disabled", file=sys.stderr)
            return 3
        print(json.dumps(make_plan(a.game, a.out, a.work, a.stages, a.jobs), sort_keys=True))
        return 0
    except PolicyError as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, OverflowError):
        print("REJECTED: PATH_INSPECTION_FAILED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
