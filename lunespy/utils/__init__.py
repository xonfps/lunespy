class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def flat_map(listOfLists):
    from itertools import chain
    return list(chain.from_iterable(listOfLists))


def log_data(data: dict) -> None:
    list(map(
        lambda tuple: print(
            f"{tuple[0]}{bcolors.OKGREEN} ─> {str(tuple[1])}{bcolors.ENDC}"
        ),
        data.items()
        )
    )


def export_json(data: dict, name: str, path: str) -> bool:
    import json
    path = path.replace("//", "/")
    full_path = f"{path}{name}.json"
    try:
        with open(full_path, 'w') as file:
            file.write( json.dumps(data) )
    except Exception as msg:
        raise Exception(
            bcolors.FAIL + f"[Error] File Don't Saved Because:\n└──{msg}" + bcolors.ENDC
        )

    return f"file save in {full_path}"


def semantic_version() -> str:
    from subprocess import check_output

    def get_logs() -> list[str]:
        return check_output(
            'git log --pretty="%s"',
            shell=True
        ).decode().split('\n')

    major, minor, patch = 0,0,0

    for commit in get_logs():
        if commit.startswith("deprecated"):
            patch = 0
            minor = 0
            major += 1
        elif  commit.startswith("Merge" or "issued" or "merged"):
            patch = 0
            minor += 1
        elif  commit.startswith("fixed" or "fix" or "Update"):
            patch += 1
    print(
        bcolors.OKGREEN + f"v{major}.{minor}.{patch}" + bcolors.ENDC
    )
    return f"v{major}.{minor}.{patch}"


def changelog():
    from subprocess import check_output
    from os import system

    deprecated = ["## Deprecated"]
    merged_issued = ["## Issued"]
    fixed = ["## Fixed"]
    refactored = ["## Refactored"]
    removed = ["## Removed"]
    other = ["## Others"]
    changelog = [
        [f"# Changelog {semantic_version()}"],
        deprecated, merged_issued, fixed, refactored, removed, other
    ]

    def get_logs() -> list[str]:
        return check_output(
            'git log --pretty="- [%h](%H) %s"',
            shell=True
        ).decode().split('\n')

    for commit in get_logs():
        if len(commit.split(" ")) > 3:
            test = commit.split(" ")[2]

            if test.startswith("deprecated"):
                deprecated.append(commit)
            elif  test.startswith("Merge" or "issued" or "merged" or "merg"):
                merged_issued.append(commit)
            elif  test.startswith("fixed" or "fix" or "Update"):
                fixed.append(commit)
            elif  test.startswith("refact" or "chang"):
                refactored.append(commit)
            elif  test.startswith("remov"):
                removed.append(commit)
        else:
            other.append(commit)

    with open('./CHANGELOG.md', 'w') as file:
        for line in flat_map(changelog):
            file.write(line + "\n")


def now() -> int:
    from time import time

    return int(
        time() * 1000
    )


def lunes_to_unes(lunes: float or int) -> int:
    return int(lunes * 10e7)


def unes_to_lunes(unes: int) -> float:
    return float(unes / 10e7)


def sha256(object: object) -> str:
    from hashlib import sha256

    return sha256(
        str(object).encode()
    ).hexdigest()


def drop_none(data: dict) -> dict:
    validate_keys = list(filter(
        lambda key: data[key] != None,
        data.keys()
    ))

    return {
        key: data[key]
        for key in data.keys()
        if key in validate_keys
    }
