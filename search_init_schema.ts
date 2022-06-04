import fsPromise from 'fs/promises';
import fs, {existsSync} from 'fs';
import {WAF} from './Waf';
import linq from 'linq';
import {promisify} from 'util';
import {assert} from 'console';
import path from 'path';
import * as crypto from 'crypto';

function deep_clone<T>(obj: T): T {
    return JSON.parse(JSON.stringify(obj));
}

function isNumberString(x: string | number | bigint | boolean) {
    try {
        BigInt(x);
        return true;
    } catch {
        return false;
    }
}

namespace benchmark {
    export function calcHitCount(l: Array<WAF.Rule>) {
        let count = 0;
        for (const r of l) {
            count += r.vars.length;
        }
        return count;
    }

    export function calcHitCountMap<T>(l: Map<string, Map<string, T>>) {
        let count = 0;
        for (const [_, rs] of l) {
            count += rs.size;
        }
        return count;
    }
}

function mergeByVars(
    splitRules: Map<string, WAF.Rule[]>,
    originRules: WAF.Rule[]
) {
    const varsInfo = new Map<string, WAF.Rule.Var>();
    const newSplitRules = new Map<string, Map<string, WAF.Rule[]>>();

    for (const [k, sameTransformRules] of splitRules) {
        let mergedVarsRules = new Map<string, WAF.Rule[]>();
        for (const rule of sameTransformRules) {
            for (const _var of rule.vars) {
                const t = JSON.stringify(_var);
                if (varsInfo.has(t)) {
                    console.assert(JSON.stringify(_var) === JSON.stringify(varsInfo.get(t)));
                }
                varsInfo.set(t, _var);
                if (mergedVarsRules.has(t)) mergedVarsRules.get(t)?.push(rule);
                else mergedVarsRules.set(t, [rule]);
            }
        }
        mergedVarsRules = new Map(
            linq.from(mergedVarsRules.entries()).where((x) => x[1].length > 1)
        );

        newSplitRules.set(k, mergedVarsRules);
    }

    //删除无效的优化
    const result = new Map(linq
        .from(newSplitRules.entries())
        .where(x => x[1].size > 0).toArray());

    //删除合并了的vars
    for (const [transform, rules] of result) {
        for (const [varK, rulesArr] of rules) {
            const var1 = varsInfo.get(varK) as WAF.Rule.Var;
            for (let rule of rulesArr) {
                rule = linq.from(originRules).first((x) => x.id === rule.id);
                rule.vars = linq
                    .from(rule.vars)
                    .skipWhile((x) => x.type === var1.type)
                    .toArray();
            }
        }
    }

    return new Map([...result.entries()].map(x => {
        const r1 = new Map([...x[1].entries()].map(y => {
            const md5 = crypto.createHash('md5');
            md5.update(x[0]);
            md5.update(y[0]);
            return [y[0], y[1].reduce((obj, rule) => {
                if (rule.pattern instanceof Array) {
                    rule.pattern.forEach(x => {
                        obj.patterns.push(x);
                        obj.ids.push(rule.id);
                    });
                } else {
                    obj.patterns.push(rule.pattern);
                    obj.ids.push(rule.id);
                }
                return obj;
            }, {patterns: [] as string[], ids: [] as string[], operator: y[1][0].operator, id: md5.digest('hex')})];
        }));
        return [x[0], r1];
    }));
}

function mergeByTransform(rules: Array<WAF.Rule>): Map<string, WAF.Rule[]> {
    const result = new Map<string, WAF.Rule[]>();
    for (const rule of rules) {
        const h = JSON.stringify(rule.opts?.transform || []);
        if (!result.has(h)) {
            result.set(h, [rule]);
        } else result.get(h)?.push(rule);
    }
    return result;
}

function transformLabel(rule: WAF.Rule) {
    return rule.id;
}

const nondisrupt_re = new RegExp('%{([._\\dA-Za-z]+)}');

function transformSetVar(v: WAF.Rule.Nondisrupt) {
    assert(v.data.col.match('[_\\dA-Za-z]+'));
    assert(v.data.key.match('[_\\dA-Za-z]+'));
    let value = v.data.value;
    if (typeof (value) == 'string' && !isNumberString(value)) {
        const all_name: string[] = [];
        value = value.replace(nondisrupt_re, x => {
            all_name.push(`collections.${x}`);
            return '%s';
        });
        if (value !== v.data.value)
            value = `string.format(${value},${all_name.join(',')})`;
    }
    const operator = v.data.inc ? '+=' : '=';
    return `ctx.storage.${v.data.col}.${v.data.key}${operator}${value}`;
}

function transformSetRule(rule: WAF.Rule) {

}

function transformVar(s: string) {
    return s.replace(nondisrupt_re, x => `collections.${x}`);
}

function transformInit(rules: WAF.Rule[]): [string, WAF.Rule[]] {
    const skip_rule_id = [
        '901001',
        '901318',
        '901321',
        '901340',
        '901350',
        '901400',
        '901410',
        '901450',
        'END-SAMPLING',
        '901500',
    ];
    //丢弃版本号检测
    rules = rules.filter((x, _1, _2) => !skip_rule_id.includes(x.id));
    //读取所有初始化的规则SetRule
    let luaBlocks = linq.from(rules).where(x => x.actions.disrupt === 'IGNORE' && !!x.opts?.nolog && !!x.opts?.parsepattern && x.pattern === '0' && x.operator === 'EQUALS').where(x => {
        if (x.actions.nondisrupt?.length === 1 && x.vars.length === 1) {
            const nondisrupt = x.actions.nondisrupt[0];
            const vars = x.vars[0];
            if (nondisrupt.action === 'setvar' && vars.length === 1 && vars.storage === 1 && vars.parse?.length === 2) {
            }
            const parse = vars.parse;
            if (parse[0] === 'specific' && nondisrupt.data.key === parse[1] && vars.type === nondisrupt.data.col) {
                return true;
            }
        }
        return false;
    });
    rules = linq.from(rules).except(luaBlocks).toArray();

    let s = luaBlocks.select(x => {
        const data = x.actions.nondisrupt[0].data;
        console.assert(!data.inc);
        console.assert(!!x.vars[0].type);
        let defaultValue = data.value;
        if (typeof (defaultValue) !== 'number') {
            console.assert(x.vars[0].type === 'TX');
            defaultValue = defaultValue.replace(nondisrupt_re, (_, p1) => p1);
            if (defaultValue === data.value)
                defaultValue = `[[${defaultValue}]]`;
        }
        console.assert(data.col === 'TX');
        const value = `${data.col}.${data.key}`;
        return `${value}= ${value} or ${defaultValue}\n`;
    }).aggregate('ctx.storage.TX = ctx.storage.TX or tab_new(0,48)\n local TX = ctx.storage.TX\n TX.CRS_SETUP_VERSION=TX.CRS_SETUP_VERSION or 340\n', (l, r) => l + r);
    //读取SetAction初始化
    luaBlocks = linq.from(rules).where(x => {
        if (x.opts?.nolog && x.vars.length === 1 && x.vars[0].unconditional === 1 && x.actions.disrupt === 'IGNORE') {
            return linq.from(x.actions.nondisrupt).all(v => v.action === 'setvar');
        }
        return false;
    });
    s += luaBlocks.select(x => {
        let s = '';
        for (const {action, data} of x.actions.nondisrupt) {
            s = `${s}${data.col}.${data.key}=${data.value}\n`;
        }
        return s;
    }).aggregate('', (l, r) => l + r);
    s = `return function (_,ctx,tab_new) \n ${s} return TX \n end`;
    rules = linq.from(rules).except(luaBlocks).toArray();
    return [s, rules];
}

function transformRule(rule: WAF.Rule) {
    if (rule.vars.length === 1 && rule.vars[0].unconditional === 1) {
        transformLabel(rule);
    } else if (rule.actions.disrupt === WAF.Rule.DisruptAction.IGNORE &&
        WAF.Rule.isTestOperator(rule.operator) &&
        rule.opts.parsepattern) {
        transformSetRule(rule);
    }
}

const transformRuleSet = {
    'REQUEST-911-METHOD-ENFORCEMENT': 'attack-generic',
    'REQUEST-913-SCANNER-DETECTION': 'attack-generic',
    'REQUEST-920-PROTOCOL-ENFORCEMENT': 'attack-protocol',
    'REQUEST-921-PROTOCOL-ATTACK': 'attack-protocol',
    'REQUEST-930-APPLICATION-ATTACK-LFI': 'attack-webshell',
    'REQUEST-931-APPLICATION-ATTACK-RFI': 'attack-webshell',
    'REQUEST-932-APPLICATION-ATTACK-RCE': 'attack-webshell',
    'REQUEST-933-APPLICATION-ATTACK-PHP': 'attack-virtualpatch',
    'REQUEST-934-APPLICATION-ATTACK-GENERIC': 'attack-generic',
    'REQUEST-941-APPLICATION-ATTACK-XSS': 'attack-xss',
    'REQUEST-942-APPLICATION-ATTACK-SQLI': 'attack-sqli',
    'REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION': 'attack-generic',
    'REQUEST-944-APPLICATION-ATTACK-JAVA': 'attack-virtualpatch',
} as { [key: string]: string };

async function readAllRules(dirPath: string, phase: string) {
    const files = await fsPromise.readdir(dirPath);
    const rules = [];
    for (const file of files) {
        const ruleset = JSON.parse(await fsPromise.readFile(path.join(dirPath, file), 'utf8'))[phase] as WAF.Rule[];
        const rulesetName = path.basename(file, 'json').split('.')[0];
        const attack_tag = transformRuleSet[rulesetName];
        if (attack_tag) {
            for (const rule of ruleset) {
                rule.attack_tag = attack_tag;
            }
        }
        for (const rule of ruleset) {
            rule.paranoia_level = Number(rule.tag?.find(x => x.startsWith('paranoia-level/'))?.split('/')[1]);
            rule.paranoia_level = isNaN(rule.paranoia_level) ? undefined : rule.paranoia_level;
            rule.tag = rule.tag?.filter(x => !x.startsWith('attack'));
            rule.tag = rule.tag?.filter(x => !x.startsWith('paranoia-level/'));
        }
        rules.push(ruleset);
    }
    return linq.from(rules).selectMany(x => x).toArray();
}

function isDETECTION_PARANOIA_LEVEL_Label(rule: WAF.Rule): boolean {
    if (rule.actions.disrupt === WAF.Rule.DisruptAction.IGNORE && !!rule.skip_after && rule.vars.length === 1 && rule.vars[0].type === 'TX' && rule.vars[0].parse[1] === 'DETECTION_PARANOIA_LEVEL') {
        isDETECTION_PARANOIA_LEVEL_Label.skip_afters.add(rule.skip_after);
        return true;
    }
    return isDETECTION_PARANOIA_LEVEL_Label.skip_afters.has(rule.id);
}

isDETECTION_PARANOIA_LEVEL_Label.skip_afters = new Set<string>();

function jsonstringifyMap<T>(value: Map<string, Map<string, T>>) {
    return Object.fromEntries(Array.from(value.entries()).map(x => [x[0], Object.fromEntries(x[1].entries())]));
}

function transform(dir: string, k: number, allRules: WAF.Rule[])
    : [
    WAF.Rule[],
    Map<string, Map<string, { patterns: string[]; ids: string[]; id: string; operator: WAF.Rule.operator }>>,
    Map<string, Map<string, { patterns: string[]; ids: string[]; id: string; operator: WAF.Rule.operator }>>] {
    console.log(`rules len:${allRules.length},hit:${benchmark.calcHitCount(allRules)}`);
    const pmRules: Array<WAF.Rule> = [];
    const refindRules: Array<WAF.Rule> = [];

    allRules.forEach((rule) => {
        if (rule.operator === 'PM') {
            console.assert(!rule.opts?.parsepattern);
            console.assert(linq.from(rule.vars).all(v => !v.unconditional));
            console.assert(!rule.op_negated);
            pmRules.push(deep_clone(rule));
            return false;
        }
        if (rule.operator === 'REFIND' && rule.opts?.parsepattern === undefined) {
            console.assert(linq.from(rule.vars).all(v => !v.unconditional));
            if (!rule.op_negated) {
                refindRules.push(deep_clone(rule));
                return false;
            }
        }
        return true;
    });

    const refindRulesSplit = mergeByVars(mergeByTransform(refindRules), refindRules);
    const PmRulesSplit = mergeByVars(mergeByTransform(pmRules), pmRules);
    //过滤掉已经完全优化的规则
    allRules = linq.from(allRules)
        .except(refindRules.filter(x => x.vars.length <= 0), x => x.id)
        .except(pmRules.filter(x => x.vars.length <= 0), x => x.id)
        .toArray();
    //对更新优化过的规则集
    for (const rule of refindRules.filter(x => x.vars.length > 0).concat(pmRules.filter(x => x.vars.length > 0))) {
        const updateRule = linq.from(allRules).single(x => x.id === rule.id);
        updateRule.vars = rule.vars;
    }

    console.log(`merge rules len:${allRules.length}, pm rules hit:${benchmark.calcHitCountMap(PmRulesSplit) + benchmark.calcHitCountMap(refindRulesSplit) + benchmark.calcHitCount(allRules)}`);

    return [allRules, refindRulesSplit, PmRulesSplit];
}

function Powerset<T>(input: T[]) {
    return input.reduce(function (powerset, item, index) {
        const next = [item];
        return powerset.reduce(function (powerset, item) {
            powerset.push(item.concat(next));
            return powerset;
        }, powerset);
    }, [[]] as T[][]);
}

const allMap = new Map<string, object>();

function appendFileJson(path: string, v: any, phase: string) {
    if (allMap.has(path)) {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        allMap.get(path)[phase] = v;
    } else {
        allMap.set(path, {[phase]: v});
    }
}

async function main(phase: string) {
    let allRules = await readAllRules('./transform_coreruleset/attack', phase);
    {
        const initRules = await readAllRules('./transform_coreruleset/start', phase);
        const [s, rules] = transformInit(initRules);
        console.assert(rules.length == 2);
        appendFileJson('./rules/initialize.json', rules, phase);
        await fsPromise.writeFile('./rules/initialize.lua', s);
    }

    allRules = linq.from(allRules)
        .where(x => !isDETECTION_PARANOIA_LEVEL_Label(x))// 删除所有判断等级的规则
        .toArray();

    //提取chain规则
    const subChain = linq.from(allRules).where(x => isNumberString(x.id)).groupBy(x => x.id).where(x => x.count() > 1).toDictionary(x => x.key(), x => x.skip(1).toArray());
    allRules = linq.from(allRules).except(subChain.toEnumerable().selectMany(x => x.value)).toArray();

    appendFileJson('./rules/allRules.json', allRules.filter(x => {
        return !isNaN(parseInt(x.id));
    }), phase);
    let arr = linq.from(allRules).groupBy(x => x.attack_tag ?? '').select(x => x.key()).toArray();
    //暂时不用协议攻击
    arr = arr.filter(x => !x.includes('protocol'));
    arr = arr.filter(x => !x.includes('generic'));

    const indexss = linq.from(Powerset(linq.range(0, arr.length).toArray())).skip(1).toArray();

    for (const indexs of indexss) {
        //先根据规则集来划分
        const select_tags = linq.from(indexs).select(i => arr[i]).toArray();
        select_tags.push('attack_generic');
        select_tags.push('attack_protocol');
        const select_rules = allRules.filter(x => select_tags.includes(x.attack_tag ?? ''));
        const mask = linq.from(indexs).aggregate(0, (l, c) => l | 1 << c);
        const dir = `./rules/${mask}`;
        await fsPromise.mkdir(dir, {recursive: true});
        //根据检测等级来划分规则
        const paranoiaRules = linq.from(select_rules).groupBy(x => x.paranoia_level ?? -1).toDictionary(x => x.key(), x => x.toArray());

        const levelRules = linq.range(1, 4).select((i): [number, WAF.Rule[]] =>
            [
                i,
                linq.range(1, i).select(j => paranoiaRules.get(j)).selectMany(x => x).toArray()
            ]
        ).toArray();

        for (const [k, rules1] of levelRules) {
            // eslint-disable-next-line prefer-const
            let [rules, refindRulesSplit, PmRulesSplit] = transform(dir, k, deep_clone(rules1));
            //重新合并chain规则
            for (const {key, value} of subChain.toEnumerable()) {
                const index = rules.findIndex(x => x.id === key);
                if (index !== -1) {
                    rules = linq.from(rules).insert(index, value).toArray();
                }
            }

            appendFileJson(`${dir}/${k}_REFIND.json`, jsonstringifyMap(refindRulesSplit), phase);
            appendFileJson(`${dir}/${k}_PM.json`, jsonstringifyMap(PmRulesSplit), phase);
            appendFileJson(`${dir}/${k}.json`, rules, phase);
        }

    }

    appendFileJson('./rules/subchain.json', subChain.toEnumerable().toObject(x => x.key, x => x.value), phase);
    // write files
    for (const [key, value] of allMap) {
        await fsPromise.writeFile(key, JSON.stringify(value));
    }
}

promisify(main)('access');


