/* eslint-disable no-unused-vars */
export namespace WAF {
    export interface Rule {
        actions: Rule.Actions;
        id: string;
        operator: Rule.operator;
        op_negated?: boolean;
        opts: Rule.Opts;
        pattern: string | string[];
        vars: Rule.Var[];
        ver: string;
        skip_after?: string;
        tag?: string[];
        attack_tag?: string;
        paranoia_level?:number;
    }
    export namespace Rule {
        export enum transform {
            base64_decode = 'base64_decode',
            base64_encode = 'base64_encode',
            css_decode = 'css_decode',
            cmd_line = 'cmd_line',
            compress_whitespace = 'compress_whitespace',
            hex_decode = 'hex_decode',
            hex_encode = 'hex_encode',
            html_decode = 'html_decode',
            js_decode = 'js_decode',
            length = 'length',
            lowercase = 'lowercase',
            md5 = 'md5',
            normalise_path = 'normalise_path',
            normalise_path_win = 'normalise_path_win',
            remove_comments = 'remove_comments',
            remove_comments_char = 'remove_comments_char',
            remove_nulls = 'remove_nulls',
            remove_whitespace = 'remove_whitespace',
            replace_comments = 'replace_comments',
            replace_nulls = 'replace_nulls',
            sha1 = 'sha1',
            sql_hex_decode = 'sql_hex_decode',
            trim = 'trim',
            trim_left = 'trim_left',
            trim_right = 'trim_right',
            uri_decode = 'uri_decode',
        }
        export enum operator {
            REGEX = 'REGEX',
            REFIND = 'REFIND',
            EQUALS = 'EQUALS',
            GREATER = 'GREATER',
            LESS = 'LESS',
            GREATER_EQ = 'GREATER_EQ',
            LESS_EQ = 'LESS_EQ',
            EXISTS = 'EXISTS',
            CONTAINS = 'CONTAINS',
            STR_EXISTS = 'STR_EXISTS',
            STR_CONTAINS = 'STR_CONTAINS',
            PM = 'PM',
            CIDR_MATCH = 'CIDR_MATCH',
            RBL_LOOKUP = 'RBL_LOOKUP',
            DETECT_SQLI = 'DETECT_SQLI',
            DETECT_XSS = 'DETECT_XSS',
            STR_MATCH = 'STR_MATCH',
            VERIFY_CC = 'VERIFY_CC',
            VALIDATE_BYTE_RANGE = 'VALIDATE_BYTE_RANGE',
        }
        export function isTestOperator (op: operator): boolean {
            switch (op) {
            case operator.EQUALS:
            case operator.GREATER:
            case operator.LESS:
            case operator.GREATER_EQ:
            case operator.LESS_EQ:
                return true
            }
            return false
        }
        export interface Data {
            col: string;
            key: string;
            inc?: string;
            value: string | number;
        }

        export interface Opts {
            nolog?: number;
            parsepattern?: number;
            transform?: transform[];
        }

        export interface Ignore {
            [index: number]: string;
        }
        export interface Var {
            length: number;
            parse: string[2];
            storage: number;
            type: string;
            ignore: Ignore[]
            unconditional: number;
        }
        export enum NondisruptAction {
            deletevar = 'deletevar',
            expirevar = 'expirevar',
            initcol = 'initcol',
            setvar = 'setvar',
            sleep = 'sleep',
            status = 'status',
            rule_remove_id = 'rule_remove_id',
            rule_remove_by_meta = 'rule_remove_by_meta',
            mode_update = 'mode_update',
        }
        export interface Nondisrupt {
            action: NondisruptAction;
            data: Data;
        }
        export const enum DisruptAction {
            ACCEPT = 'ACCEPT',
            CHAIN = 'CHAIN',
            DENY = 'DENY',
            DROP = 'DROP',
            IGNORE = 'IGNORE',
            SCORE = 'SCORE',
        }
        export interface Actions {
            disrupt: DisruptAction;
            nondisrupt: Nondisrupt[];
        }

    }

}
