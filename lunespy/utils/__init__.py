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


def generate_log() -> None:
    from subprocess import check_output

    def get_logs() -> list:
        return check_output(
            'git log --pretty="- [%h](%H) %s [%ai]"',
            shell=True
        ).decode().split('\n')
    
    def logs_to_changelog(logs: list) -> list:
        range_date = {}
        for line in logs:
            range_date[line[-27:-17]] = []
            for commit in logs:
                if line[-27:-17] == commit[-27:-17]:
                    range_date[line[-27:-17]].append(commit)

        changelog = ['# Changelog\n']
        for date in range_date.keys():
            changelog.append(f"\n## {date}\n")
            for commit in range_date[date]:
                edited_commit = commit[:-29] + '\n'
                changelog.append(edited_commit)
        
        return changelog

    def save_changelog(changelog: list) -> None:
        with open('./CHANGELOG.md', 'w') as file:
            file.writelines(changelog)

    save_changelog(
        logs_to_changelog(
            get_logs()
            )
    )


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
