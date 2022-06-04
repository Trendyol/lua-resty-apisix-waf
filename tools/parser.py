#!/usr/bin/env python3
import git
import os
import subprocess
import sys

CRS_PATH = "./coreruleset"
CRS_GIT = "https://github.com/coreruleset/coreruleset.git"
CRS_RULE_PATH = os.path.join(CRS_PATH, "rules/")


def clone_project():
    print("=== git clone %s" % CRS_GIT)
    git.Git().clone(CRS_GIT)
    print("=== git clone done !")


def path_id(path):
    return int(path.split("-")[1])


def get_rules_paths(path) -> list[str]:
    paths = []
    for p in os.listdir(path):
        if p.startswith("REQUEST-") and p.endswith(".conf"):
            paths.append(os.path.join(CRS_RULE_PATH, p))
    paths.sort(key=path_id)
    return paths


def group(fn, l):
    result = list(filter(fn, l));
    result1 = list(filter(lambda x: not fn(x), l));
    return result, result1


def transformPath(path, outPath):
    dir = os.path.dirname(path)
    name = os.path.basename(path)
    outPath = os.path.join(outPath, f'{name}.json')
    with os.popen(f'./tools/modsec2lua-resty-waf.pl {path} -p {dir}  -P > {outPath}') as f:
        print(f.read())
    # subprocess.call(f'./tools/modsec2lua-resty-waf.pl {path} -p {dir}  -P > {outPath}')
    # subprocess.call(['./tools/modsec2lua-resty-waf.pl',path,'-p',dir,'-P','>',outPath],shell=False)


def transform(paths, name):
    name = f'./transform_coreruleset/{name}/'
    if not os.path.exists(name):
        os.mkdir(name)
    for path in paths:
        transformPath(path, name)


if __name__ == '__main__':
    if not os.path.exists(CRS_PATH):
        clone_project()
    else:
        subprocess.call("cd ./coreruleset/ && git pull", shell=True)
    paths = get_rules_paths(CRS_RULE_PATH)
    attackPaths, paths = group(lambda x: path_id(x) >= 910 and path_id(x) != 949, paths)
    attackMaxID = path_id(attackPaths[-1])
    startPaths, endPaths = group(lambda x: path_id(x) < attackMaxID, paths)
    transform(startPaths, "start")
    transform(attackPaths, "attack")
    transform(endPaths, "end")
