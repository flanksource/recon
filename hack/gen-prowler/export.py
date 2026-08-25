#!/usr/bin/env python3
"""Export Prowler's argparse model as deterministic, dependency-neutral JSON."""

import argparse
import importlib
import inspect
import json
import pathlib
import sys
from enum import Enum


BUILT_IN_PROVIDERS = (
    "alibabacloud",
    "aws",
    "azure",
    "cloudflare",
    "e2enetworks",
    "gcp",
    "github",
    "googleworkspace",
    "huaweicloud",
    "iac",
    "image",
    "kubernetes",
    "linode",
    "llm",
    "m365",
    "mongodbatlas",
    "nhn",
    "okta",
    "openstack",
    "oraclecloud",
    "scaleway",
    "stackit",
    "vercel",
)

SOURCE_ROOT = None


def json_value(value):
    if isinstance(value, str):
        if SOURCE_ROOT is not None:
            source = str(SOURCE_ROOT)
            if value == source:
                return "${PROWLER_SOURCE}"
            if value.startswith(source + "/"):
                return "${PROWLER_SOURCE}/" + value[len(source) + 1 :]
        return value
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, Enum):
        return json_value(value.value)
    if isinstance(value, pathlib.Path):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    raise TypeError(f"unsupported argparse JSON value {value!r} ({type(value).__name__})")


def action_name(action):
    if isinstance(action, argparse._StoreTrueAction):
        return "store_true"
    if isinstance(action, argparse._AppendAction):
        return "append"
    if isinstance(action, argparse._StoreAction):
        return "store"
    raise TypeError(f"unsupported argparse action {type(action).__name__} for {action.dest}")


def nargs_name(action, kind):
    if kind == "store_true":
        if action.nargs != 0:
            raise ValueError(f"store_true action {action.dest} has nargs {action.nargs!r}")
        return "0"
    if action.nargs is None:
        return "1"
    if action.nargs in ("?", "+", "*"):
        return action.nargs
    raise ValueError(f"unsupported nargs {action.nargs!r} for {action.dest}")


def value_type(action, kind):
    if kind == "store_true":
        return "boolean"
    if action.type is int:
        return "integer"
    if action.type is float:
        return "number"
    if action.type in (None, str):
        return "string"
    default = action.default
    if isinstance(default, bool):
        return "boolean"
    if isinstance(default, int):
        return "integer"
    if isinstance(default, float):
        return "number"
    annotation = inspect.signature(action.type).return_annotation
    if annotation in (int, "int"):
        return "integer"
    if annotation in (float, "float"):
        return "number"
    return "string"


def canonical_flag(flags, kind, nargs):
    long_flags = [flag for flag in flags if flag.startswith("--")]
    if not long_flags:
        raise ValueError(f"argument aliases {flags!r} have no long option")
    if kind == "append" or nargs in ("+", "*"):
        for flag in long_flags:
            if flag.endswith("s"):
                return flag
    return long_flags[0]


def argument_document(action, group, order):
    flags = list(action.option_strings)
    kind = action_name(action)
    nargs = nargs_name(action, kind)
    canonical = canonical_flag(flags, kind, nargs)
    help_text = "" if action.help in (None, argparse.SUPPRESS) else str(action.help)
    metavar = action.metavar
    if isinstance(metavar, tuple):
        metavar = " ".join(str(item) for item in metavar)
    choices = []
    if action.choices is not None:
        choices = json_value(list(action.choices))
        if isinstance(action.choices, (set, frozenset)):
            choices.sort()
    return {
        "key": canonical[2:],
        "destination": action.dest,
        "flags": flags,
        "canonical": canonical,
        "order": order,
        "group": group,
        "action": kind,
        "nargs": nargs,
        "type": value_type(action, kind),
        "choices": choices,
        "default": json_value(action.default),
        "required": bool(action.required),
        "help": help_text,
        "metavar": "" if metavar is None else str(metavar),
    }


def parser_actions(parser, excluded):
    documents = []
    by_destination = {}
    action_destinations = {}
    for group in parser._action_groups:
        for action in group._group_actions:
            if id(action) in excluded or isinstance(action, argparse._HelpAction):
                continue
            if not action.option_strings:
                continue
            candidate = argument_document(action, group.title, len(documents))
            existing = by_destination.get(action.dest)
            if existing is None:
                documents.append(candidate)
                by_destination[action.dest] = candidate
            else:
                merge_compatible_alias(existing, candidate)
            action_destinations[id(action)] = action.dest
    action_keys = {
        action_id: by_destination[destination]["key"]
        for action_id, destination in action_destinations.items()
    }
    return documents, action_keys


def merge_compatible_alias(existing, candidate):
    compatible = ("group", "action", "nargs", "type", "choices", "default", "required", "metavar")
    mismatched = [key for key in compatible if existing[key] != candidate[key]]
    if mismatched:
        raise ValueError(
            f"duplicate destination {existing['destination']!r} has incompatible "
            f"{', '.join(mismatched)}"
        )
    existing["flags"].extend(
        flag for flag in candidate["flags"] if flag not in existing["flags"]
    )
    existing["canonical"] = canonical_flag(
        existing["flags"], existing["action"], existing["nargs"]
    )
    existing["key"] = existing["canonical"][2:]
    if not existing["help"]:
        existing["help"] = candidate["help"]


def mutual_exclusions(parser, scope, action_keys, arguments):
    groups_by_key = {argument["key"]: argument["group"] for argument in arguments}
    documents = []
    for group in parser._mutually_exclusive_groups:
        keys = []
        for action in group._group_actions:
            key = action_keys.get(id(action))
            if key is None or key in keys:
                continue
            keys.append(key)
        if len(keys) < 2:
            continue
        documents.append(
            {
                "name": f"{scope}-mutex-{len(documents) + 1}",
                "title": mutex_title(group, keys, groups_by_key),
                "keys": keys,
                "required": bool(group.required),
            }
        )
    return documents


def mutex_title(group, keys, groups_by_key):
    """Names the group after the argparse section its members were declared in.

    argparse gives a mutually exclusive group no title of its own, so the only
    label a reader recognises is the surrounding section — the same string that
    already heads the form. Preferring the members' unanimous group over the
    container keeps the parser's catch-all ("options") from becoming a heading.
    """
    titles = {groups_by_key.get(key, "") for key in keys}
    if len(titles) == 1:
        title = titles.pop()
        if title:
            return title
    return getattr(getattr(group, "_container", None), "title", "") or ""


def sensitive_flags(provider_names):
    common = importlib.import_module("prowler.lib.cli.sensitive").SENSITIVE_ARGUMENTS
    result = {"common": sorted(common)}
    for provider in provider_names:
        module = importlib.import_module(
            f"prowler.providers.{provider}.lib.arguments.arguments"
        )
        result[provider] = sorted(getattr(module, "SENSITIVE_ARGUMENTS", frozenset()))
    return result


def export(source):
    global SOURCE_ROOT
    SOURCE_ROOT = source
    sys.path.insert(0, str(source))
    parser_module = importlib.import_module("prowler.lib.cli.parser")
    prowler_parser = parser_module.ProwlerArgumentParser()
    failures = getattr(prowler_parser, "_builtin_load_failures", {})
    if failures:
        details = ", ".join(f"{name}: {error!r}" for name, error in sorted(failures.items()))
        raise RuntimeError(f"failed to import built-in provider arguments: {details}")

    provider_type = importlib.import_module(
        "prowler.providers.common.provider"
    ).Provider
    discovered_builtins = {
        name
        for name in provider_type.get_available_providers()
        if provider_type.is_builtin(name)
    }
    expected_builtins = set(BUILT_IN_PROVIDERS)
    if discovered_builtins != expected_builtins:
        missing = sorted(expected_builtins - discovered_builtins)
        unknown = sorted(discovered_builtins - expected_builtins)
        raise RuntimeError(
            f"built-in provider drift: missing={missing!r}, unknown={unknown!r}"
        )

    available = set(prowler_parser.subparsers.choices)
    missing = sorted(set(BUILT_IN_PROVIDERS) - available)
    if missing:
        raise RuntimeError(f"missing built-in provider parsers: {', '.join(missing)}")

    common, common_keys = parser_actions(prowler_parser.common_providers_parser, set())
    providers = []
    for provider in BUILT_IN_PROVIDERS:
        provider_parser = prowler_parser.subparsers.choices[provider]
        arguments, action_keys = parser_actions(provider_parser, set(common_keys))
        providers.append(
            {
                "name": provider,
                "arguments": arguments,
                "mutualExclusions": mutual_exclusions(
                    provider_parser, provider, action_keys, common + arguments
                ),
            }
        )
    return {
        "common": common,
        "commonMutualExclusions": mutual_exclusions(
            prowler_parser.common_providers_parser, "common", common_keys, common
        ),
        "providers": providers,
        "sensitiveFlags": sensitive_flags(BUILT_IN_PROVIDERS),
    }


def main():
    command = argparse.ArgumentParser()
    command.add_argument("--source", type=pathlib.Path, required=True)
    args = command.parse_args()
    document = export(args.source.resolve())
    json.dump(document, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
