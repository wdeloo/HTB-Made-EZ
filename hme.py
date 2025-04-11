#!/usr/bin/env python3

import os
import json
import sys
import time

OS = {
    "label": "OS",
    "windows": {
        "emoji": "🪟",
        "text": "Windows",
    },
    "linux": {
        "emoji": "🐧",
        "text": "Linux",
    },
    "freebsd": {
        "emoji": "👿",
        "text": "FreeBSD",
    },
    "openbsd": {
        "emoji": "🐡",
        "text": "OpenBSD",
    },
}

DIFFICULTY_EMOJIS = {
    "easy": "🟢",
    "medium": "🟠",
    "hard": "🔴",
    "insane": "⚫",
}

EN = {
    "link": "### HackTheBox Walkthroughs in [English](${_lang_}) 🇬🇧",
    "lang": "English",
    "title": "HackTheBox Walkthroughs in English 🇬🇧",
    "body": """The writeups in this repository are mainly aimed at beginner pentesters.

The intention is to create writeups for `HackTheBox` in a more understandable way.

If you find my work usefull, consider giving a star to the project. Thank you, and good luck with your pentester career ❤️.""",
    "latest": "Latest Machine",
    "index": "Index",
    "table": {
        "name": "Name",
        "os": OS,
        "difficulty": {
            "label": "Difficulty",
            "easy": {
                "text": "Easy",
                "emoji": DIFFICULTY_EMOJIS["easy"],
            },
            "medium": {
                "text": "Medium",
                "emoji": DIFFICULTY_EMOJIS["medium"],
            },
            "hard": {
                "text": "Hard",
                "emoji": DIFFICULTY_EMOJIS["hard"],
            },
            "insane": {
                "text": "Insane",
                "emoji": DIFFICULTY_EMOJIS["insane"],
            },
        },
    },
}

ES = {
    "link": "### Tutoriales de HackTheBox en [Español](${_lang_}) 🇪🇸",
    "lang": "Spanish",
    "title": "Tutoriales de HackTheBox en Español 🇪🇸",
    "body": """Los writeups de este repositorio están principalmente dirigidos a pentesters de nivel **principiante**.

La intención es hacer writeups de `HackTheBox` de una manera más comprensible, especialmente para hablantes de **Español**, ya sean **latinos** 🇲🇽, **españoles** 🇪🇸 o **ecuatoguineanos** 🇬🇶 (si quereis practicar inglés mientras haceis maquinas tambien las he traducido: [English](../en) 🇬🇧).

Si mi trabajo te parece útil, considera dejar una estrella al proyecto. Gracias y mucha suerte en tu carrera como pentester ❤️.""",
    "latest": "Última Máquina",
    "index": "Índice",
    "table": {
        "name": "Nombre",
        "os": OS,
        "difficulty": {
            "label": "Dificultad",
            "easy": {
                "text": "Fácil",
                "emoji": DIFFICULTY_EMOJIS["easy"],
            },
            "medium": {
                "text": "Media",
                "emoji": DIFFICULTY_EMOJIS["medium"],
            },
            "hard": {
                "text": "Dificil",
                "emoji": DIFFICULTY_EMOJIS["hard"],
            },
            "insane": {
                "text": "Extrema",
                "emoji": DIFFICULTY_EMOJIS["insane"],
            },
        },
    },
}

CONTENTS = {
    "en": EN,
    "es": ES,
}

TEXT_COLORS = {
    "black":   "\033[30m",
    "red":     "\033[31m",
    "green":   "\033[32m",
    "yellow":  "\033[33m",
    "blue":    "\033[34m",
    "magenta": "\033[35m",
    "cyan":    "\033[36m",
    "white":   "\033[37m",
    "default": "\033[39m",
}

BACKGROUND_COLORS = {
    "black":   "\033[40m",
    "red":     "\033[41m",
    "green":   "\033[42m",
    "yellow":  "\033[43m",
    "blue":    "\033[44m",
    "magenta": "\033[45m",
    "cyan":    "\033[46m",
    "white":   "\033[47m",
    "default": "\033[49m",
}

TEXT_STYLES = {
    "reset":     "\033[0m",
    "bold":      "\033[1m",
    "dim":       "\033[2m",
    "italic":    "\033[3m",
    "underline": "\033[4m",
    "blink":     "\033[5m",
    "reverse":   "\033[7m",
    "hidden":    "\033[8m",
}

DATA_PATH = 'data'
DATA_FILE = 'data.json'

README_FILE = 'README.md'

TEMPLATES_PATH = 'templates'
TEMPLATES_README_FILE = f'{README_FILE}.tpl'
TEMPLATES_LANG_README_FILE = f'lang/{README_FILE}.tpl'

def getVariableName(string: str):
    return f"${{_{string.lower().replace(' ', '_')}_}}"

def getData(machineName=None):
    if machineName:
        path = os.path.join(DATA_PATH, machineName, DATA_FILE)
    else:
        path = os.path.join(DATA_PATH, DATA_FILE)

    with open(path, "r") as file:
        return json.load(file)

def getTableLine(tableContent, machineName=None):
    if not machineName:
        return [
            f"|{tableContent["name"]}|{tableContent["os"]["label"]}|{tableContent["difficulty"]["label"]}|",
            "|-|-|-|"
        ]

    data = getData(machineName)

    name = { "text": machineName, "emoji": data["emoji"] }
    os = tableContent["os"][data["os"]]
    difficulty = tableContent["difficulty"][data["difficulty"]]

    return f"|{name["emoji"]} {name["text"]}|{os["emoji"]} {os["text"]}|{difficulty["emoji"]} {difficulty["text"]}|"

def getLangLink(lang):
    return CONTENTS[lang]["link"].replace(getVariableName("lang"), lang)

def compileReadme(template, link):
    readme = template

    links = "\n\n".join(link.values())
    readme = readme.replace(getVariableName("links"), links)

    return readme

def compileLangReadme(template, lang, latest, index):
    readme = template

    readme = readme.replace(getVariableName("title"), CONTENTS[lang]["title"])
    readme = readme.replace(getVariableName("body"), CONTENTS[lang]["body"])

    latestTable = "\n".join(latest[lang])
    readme = readme.replace(getVariableName("latest label"), CONTENTS[lang]["latest"])
    readme = readme.replace(getVariableName("latest"), latestTable)

    indexTable = "\n".join(index[lang])
    readme = readme.replace(getVariableName("index label"), CONTENTS[lang]["index"])
    readme = readme.replace(getVariableName("index"), indexTable)

    return readme

def writeReadme(content, lang=None):
    if lang:
        path = os.path.join(lang, README_FILE)
    else:
        path = README_FILE

    with open(path, 'w') as file:
        file.write(content)

def createLangReadmes():
    index = {}
    latest = {}
    link = {}

    data =  getData()
    latestMachine = data["latest"]

    for lang in CONTENTS:
        initialTableLines = getTableLine(CONTENTS[lang]["table"])

        index[lang] = [*initialTableLines]
        latest[lang] = [*initialTableLines, getTableLine(CONTENTS[lang]["table"], latestMachine)]

    for machine in sorted(os.listdir(DATA_PATH)):
        path = os.path.join(DATA_PATH, machine)
        if not os.path.isdir(path):
            continue

        for lang in CONTENTS:
            index[lang].append(getTableLine(CONTENTS[lang]["table"], machine))

    with open(os.path.join(TEMPLATES_PATH, TEMPLATES_LANG_README_FILE), "r") as file:
        template = file.read()

    for lang in CONTENTS:
        if not os.path.exists(lang):
            print(f"{TEXT_COLORS["red"]}{TEXT_STYLES["bold"]}! Directory {TEXT_STYLES["underline"]}{TEXT_COLORS['default']}{lang}{TEXT_STYLES["reset"]}{TEXT_COLORS["red"]}{TEXT_STYLES["bold"]} does not exist{TEXT_STYLES['reset']}")
            continue

        link[lang] = getLangLink(lang)

        content = compileLangReadme(template, lang, latest, index)
        writeReadme(content, lang)

        print(f"{TEXT_COLORS['green']}+ Created {TEXT_STYLES['underline']}{TEXT_COLORS['default']}{os.path.join(lang, README_FILE)}{TEXT_STYLES['reset']}{TEXT_COLORS['green']} for language {TEXT_STYLES['underline']}{TEXT_COLORS['default']}{CONTENTS[lang]["lang"]}{TEXT_STYLES['reset']}")

    with open(os.path.join(TEMPLATES_PATH, TEMPLATES_README_FILE), "r") as file:
        template = file.read()

    content = compileReadme(template, link)
    writeReadme(content)

    print(f"{TEXT_COLORS['green']}+ Created {TEXT_STYLES['underline']}{TEXT_COLORS['default']}{README_FILE}{TEXT_STYLES['reset']}")

if __name__ == '__main__':
    timeStart = time.perf_counter()

    argv = sys.argv
    script = argv[0]

    USAGE = f"Usage: {TEXT_COLORS['green']}{script} {TEXT_COLORS['blue']}command [parameters]{TEXT_COLORS['default']}"

    if not len(argv) > 1:
        print(USAGE)
        sys.exit(1)

    command = argv[1]
    
    match command:
        case "r" | "readmes":
            createLangReadmes()
        case _:
            print(USAGE)
            sys.exit(1)

    print(f"Executed in {(time.perf_counter() - timeStart) * 1000:.3f}ms")