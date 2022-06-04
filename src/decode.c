#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

#ifdef __GNUC__
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x)   __builtin_expect(!!(x), 0)
#else  /* __GNUC__ */
#define likely(x)   (x)
#define unlikely(x)   (x)
#endif /* __GNUC__ */

#define VALID_HEX(X) (((X >= '0')&&(X <= '9')) || ((X >= 'a')&&(X <= 'f')) || \
    ((X >= 'A')&&(X <= 'F')))
#define ISODIGIT(X) ((X >= '0')&&(X <= '7'))

static unsigned char x2c(unsigned char *what) {
    register unsigned char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));

    return digit;
}

static unsigned char *c2x(unsigned what, unsigned char *where) {
    static const char c2x_table[] = "0123456789abcdef";

    what = what & 0xff;
    *where++ = c2x_table[what >> 4];
    *where++ = c2x_table[what & 0x0f];

    return where;
}

static unsigned char xsingle2c(unsigned char *what) {
    register unsigned char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));

    return digit;
}

int js_decode(unsigned char *input, long int input_len) {

    unsigned char *d = (unsigned char *) input;
    long int i, count;

    if (input == NULL) return -1;

    i = count = 0;
    while (i < input_len) {
        if (input[i] == '\\') {
            /* Character is an escape. */

            if ((i + 5 < input_len) && (input[i + 1] == 'u')
                && (VALID_HEX(input[i + 2])) && (VALID_HEX(input[i + 3]))
                && (VALID_HEX(input[i + 4])) && (VALID_HEX(input[i + 5]))) {
                /* \uHHHH */

                /* Use only the lower byte. */
                *d = x2c(&input[i + 4]);

                /* Full width ASCII (ff01 - ff5e) needs 0x20 added */
                if ((*d > 0x00) && (*d < 0x5f)
                    && ((input[i + 2] == 'f') || (input[i + 2] == 'F'))
                    && ((input[i + 3] == 'f') || (input[i + 3] == 'F'))) {
                    (*d) += 0x20;
                }

                d++;
                count++;
                i += 6;
            } else if ((i + 3 < input_len) && (input[i + 1] == 'x')
                       && VALID_HEX(input[i + 2]) && VALID_HEX(input[i + 3])) {
                /* \xHH */
                *d++ = x2c(&input[i + 2]);
                count++;
                i += 4;
            } else if ((i + 1 < input_len) && ISODIGIT(input[i + 1])) {
                unsigned char *orig_input = input;
                /* \OOO (only one byte, \000 - \377) */
                char input[4];
                int j = 0;

                while ((i + 1 + j < input_len) && (j < 3)) {
                    input[j] = orig_input[i + 1 + j];
                    j++;
                    if (!ISODIGIT(orig_input[i + 1 + j])) break;
                }
                input[j] = '\0';

                if (j > 0) {
                    if ((j == 3) && (input[0] > '3')) {
                        j = 2;
                        input[j] = '\0';
                    }
                    *d++ = (unsigned char) strtol(input, NULL, 8);
                    i += 1 + j;
                    count++;
                }
            } else if (i + 1 < input_len) {
                /* \C */
                unsigned char c = input[i + 1];
                switch (input[i + 1]) {
                    case 'a' :
                        c = '\a';
                        break;
                    case 'b' :
                        c = '\b';
                        break;
                    case 'f' :
                        c = '\f';
                        break;
                    case 'n' :
                        c = '\n';
                        break;
                    case 'r' :
                        c = '\r';
                        break;
                    case 't' :
                        c = '\t';
                        break;
                    case 'v' :
                        c = '\v';
                        break;
                        /* The remaining (\?,\\,\',\") are just a removal
                         * of the escape char which is default.
                         */
                }

                *d++ = c;
                i += 2;
                count++;
            } else {
                /* Not enough bytes */
                while (i < input_len) {
                    *d++ = input[i++];
                    count++;
                }
            }
        } else {
            *d++ = input[i++];
            count++;
        }
    }

    *d = '\0';

    return d - input;
}

int css_decode(unsigned char *input, long int input_len) {
    unsigned char *d = (unsigned char *) input;
    int64_t i, j, count;

    if (input == NULL) {
        return -1;
    }

    i = count = 0;
    while (i < input_len) {
        /* Is the character a backslash? */
        if (input[i] == '\\') {
            /* Is there at least one more byte? */
            if (i + 1 < input_len) {
                i++; /* We are not going to need the backslash. */

                /* Check for 1-6 hex characters following the backslash */
                j = 0;
                while ((j < 6)
                       && (i + j < input_len)
                       && (VALID_HEX(input[i + j]))) {
                    j++;
                }

                if (j > 0) {
                    /* We have at least one valid hexadecimal character. */
                    int fullcheck = 0;

                    /* For now just use the last two bytes. */
                    switch (j) {
                        /* Number of hex characters */
                        case 1:
                            *d++ = xsingle2c(&input[i]);
                            break;

                        case 2:
                        case 3:
                            /* Use the last two from the end. */
                            *d++ = x2c(&input[i + j - 2]);
                            break;

                        case 4:
                            /* Use the last two from the end, but request
                             * a full width check.
                             */
                            *d = x2c(&input[i + j - 2]);
                            fullcheck = 1;
                            break;

                        case 5:
                            /* Use the last two from the end, but request
                             * a full width check if the number is greater
                             * or equal to 0xFFFF.
                             */
                            *d = x2c(&input[i + j - 2]);
                            /* Do full check if first byte is 0 */
                            if (input[i] == '0') {
                                fullcheck = 1;
                            } else {
                                d++;
                            }
                            break;

                        case 6:
                            /* Use the last two from the end, but request
                             * a full width check if the number is greater
                             * or equal to 0xFFFF.
                             */
                            *d = x2c(&input[i + j - 2]);

                            /* Do full check if first/second bytes are 0 */
                            if ((input[i] == '0')
                                && (input[i + 1] == '0')) {
                                fullcheck = 1;
                            } else {
                                d++;
                            }
                            break;
                    }

                    /* Full width ASCII (0xff01 - 0xff5e) needs 0x20 added */
                    if (fullcheck) {
                        if ((*d > 0x00) && (*d < 0x5f)
                            && ((input[i + j - 3] == 'f') ||
                                (input[i + j - 3] == 'F'))
                            && ((input[i + j - 4] == 'f') ||
                                (input[i + j - 4] == 'F'))) {
                            (*d) += 0x20;
                        }

                        d++;
                    }

                    /* We must ignore a single whitespace after a hex escape */
                    if ((i + j < input_len) && isspace(input[i + j])) {
                        j++;
                    }

                    /* Move over. */
                    count++;
                    i += j;
                } else if (input[i] == '\n') {
                    /* No hexadecimal digits after backslash */
                    /* A newline character following backslash is ignored. */
                    i++;
                } else {
                    /* The character after backslash is not a hexadecimal digit,
                     * nor a newline. */
                    /* Use one character after backslash as is. */
                    *d++ = input[i++];
                    count++;
                }
            } else {
                /* No characters after backslash. */
                /* Do not include backslash in output
                 *(continuation to nothing) */
                i++;
            }
        } else {
            /* Character is not a backslash. */
            /* Copy one normal character to output. */
            *d++ = input[i++];
            count++;
        }
    }

    /* Terminate output string. */
    *d = '\0';

    return count;
}

int validate_url_encoding(const char *input,
                          uint64_t input_length) {
    int i;

    if ((input == NULL) || (input_length == 0)) {
        return -1;
    }

    i = 0;
    while (i < input_length) {
        if (input[i] == '%') {
            if (i + 2 >= input_length) {
                /* Not enough bytes. */
                return -3;
            } else {
                /* Here we only decode a %xx combination if it is valid,
                 * leaving it as is otherwise.
                 */
                char c1 = input[i + 1];
                char c2 = input[i + 2];

                if ((((c1 >= '0') && (c1 <= '9'))
                     || ((c1 >= 'a') && (c1 <= 'f'))
                     || ((c1 >= 'A') && (c1 <= 'F')))
                    && (((c2 >= '0') && (c2 <= '9'))
                        || ((c2 >= 'a') && (c2 <= 'f'))
                        || ((c2 >= 'A') && (c2 <= 'F')))) {
                    i += 3;
                } else {
                    /* Non-hexadecimal characters used in encoding. */
                    return -2;
                }
            }
        } else {
            i++;
        }
    }

    return 1;
}

#define UNICODE_ERROR_CHARACTERS_MISSING    -1
#define UNICODE_ERROR_INVALID_ENCODING      -2
#define UNICODE_ERROR_OVERLONG_CHARACTER    -3
#define UNICODE_ERROR_RESTRICTED_CHARACTER  -4
#define UNICODE_ERROR_DECODING_ERROR        -5

int detect_utf8_character(
        const unsigned char *p_read, unsigned int length) {
    int unicode_len = 0;
    unsigned int d = 0;
    unsigned char c;

    if (p_read == NULL) {
        return UNICODE_ERROR_DECODING_ERROR;
    }
    c = *p_read;

    /* If first byte begins with binary 0 it is single byte encoding */
    if ((c & 0x80) == 0) {
        /* single byte unicode (7 bit ASCII equivilent) has no validation */
        return 1;
    } else if ((c & 0xE0) == 0xC0) {
        /* If first byte begins with binary 110 it is two byte encoding*/
        /* check we have at least two bytes */
        if (length < 2) {
            unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
        } else if (((*(p_read + 1)) & 0xC0) != 0x80) {
            /* check second byte starts with binary 10 */
            unicode_len = UNICODE_ERROR_INVALID_ENCODING;
        } else {
            unicode_len = 2;
            /* compute character number */
            d = ((c & 0x1F) << 6) | (*(p_read + 1) & 0x3F);
        }
    } else if ((c & 0xF0) == 0xE0) {
        /* If first byte begins with binary 1110 it is three byte encoding */
        /* check we have at least three bytes */
        if (length < 3) {
            unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
        } else if (((*(p_read + 1)) & 0xC0) != 0x80) {
            /* check second byte starts with binary 10 */
            unicode_len = UNICODE_ERROR_INVALID_ENCODING;
        } else if (((*(p_read + 2)) & 0xC0) != 0x80) {
            /* check third byte starts with binary 10 */
            unicode_len = UNICODE_ERROR_INVALID_ENCODING;
        } else {
            unicode_len = 3;
            /* compute character number */
            d = ((c & 0x0F) << 12) | ((*(p_read + 1) & 0x3F) << 6)
                | (*(p_read + 2) & 0x3F);
        }
    } else if ((c & 0xF8) == 0xF0) {
        /* If first byte begins with binary 11110 it is four byte encoding */
        /* restrict characters to UTF-8 range (U+0000 - U+10FFFF)*/
        if (c >= 0xF5) {
            return UNICODE_ERROR_RESTRICTED_CHARACTER;
        }
        /* check we have at least four bytes */
        if (length < 4) {
            unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
        } else if (((*(p_read + 1)) & 0xC0) != 0x80) {
            unicode_len = UNICODE_ERROR_INVALID_ENCODING;
        } else if (((*(p_read + 2)) & 0xC0) != 0x80) {
            unicode_len = UNICODE_ERROR_INVALID_ENCODING;
        } else if (((*(p_read + 3)) & 0xC0) != 0x80) {
            unicode_len = UNICODE_ERROR_INVALID_ENCODING;
        } else {
            unicode_len = 4;
            /* compute character number */
            d = ((c & 0x07) << 18) | ((*(p_read + 1) & 0x3F) << 12)
                | ((*(p_read + 2) & 0x3F) << 6) | (*(p_read + 3) & 0x3F);
        }
    } else {
        /* any other first byte is invalid (RFC 3629) */
        return UNICODE_ERROR_INVALID_ENCODING;
    }

    /* invalid UTF-8 character number range (RFC 3629) */
    if ((d >= 0xD800) && (d <= 0xDFFF)) {
        return UNICODE_ERROR_RESTRICTED_CHARACTER;
    }

    /* check for overlong */
    if ((unicode_len == 4) && (d < 0x010000)) {
        /* four byte could be represented with less bytes */
        return UNICODE_ERROR_OVERLONG_CHARACTER;
    } else if ((unicode_len == 3) && (d < 0x0800)) {
        /* three byte could be represented with less bytes */
        return UNICODE_ERROR_OVERLONG_CHARACTER;
    } else if ((unicode_len == 2) && (d < 0x80)) {
        /* two byte could be represented with less bytes */
        return UNICODE_ERROR_OVERLONG_CHARACTER;
    }

    return unicode_len;
}

int validate_utf8_encoding(const char *str_c, size_t len, char *err_char) {
    unsigned int i;
    int rc = 0;
    size_t bytes_left = len;

    for (i = 0; i < len;) {
        rc = detect_utf8_character((unsigned char *) &str_c[i], bytes_left);

        if (rc <= 0) {
            if (err_char) {
                *err_char = str_c[i];
            }
            return rc;
        }

        i += rc;
        bytes_left -= rc;
    }
    return rc;
}

#define NBSP 160

int normalize_path_inplace(char *input, int input_len,
                           int win, int *changed) {
    char *src;
    char *dst;
    char *end;
    int ldst = 0;
    int hitroot = 0;
    int done = 0;
    int relative;
    int trailing;

    *changed = 0;

    /* Need at least one byte to normalize */
    if (unlikely(input_len <= 0)) return 0;

    /*
     * ENH: Deal with UNC and drive letters?
     */

    src = dst = input;
    end = input + (input_len - 1);
    ldst = 1;

    relative = ((*input == '/') || (win && (*input == '\\'))) ? 0 : 1;
    trailing = ((*end == '/') || (win && (*end == '\\'))) ? 1 : 0;


    while (!done && (src <= end) && (dst <= end)) {
        /* Convert backslash to forward slash on Windows only. */
        if (win) {
            if (*src == '\\') {
                *src = '/';
                *changed = 1;
            }
            if ((src < end) && (*(src + 1) == '\\')) {
                *(src + 1) = '/';
                *changed = 1;
            }
        }

        /* Always normalize at the end of the input. */
        if (src == end) {
            done = 1;
        } else if (*(src + 1) != '/') {
            /* Skip normalization if this is NOT the
             *end of the path segment. */
            goto copy; /* Skip normalization. */
        }

        /*** Normalize the path segment. ***/

        /* Could it be an empty path segment? */
        if ((src != end) && *src == '/') {
            /* Ignore */
            *changed = 1;
            goto copy; /* Copy will take care of this. */
        } else if (*src == '.') {
            /* Could it be a back or self reference? */
            /* Back-reference? */
            if ((dst > input) && (*(dst - 1) == '.')) {
                /* If a relative path and either our normalization has
                 * already hit the rootdir, or this is a backref with no
                 * previous path segment, then mark that the rootdir was hit
                 * and just copy the backref as no normilization is possible.
                 */
                if (relative && (hitroot || ((dst - 2) <= input))) {
                    hitroot = 1;

                    goto copy; /* Skip normalization. */
                }

                /* Remove backreference and the previous path segment. */
                dst -= 3;
                while ((dst > input) && (*dst != '/')) {
                    dst--;
                }

                /* But do not allow going above rootdir. */
                if (dst <= input) {
                    hitroot = 1;
                    dst = input;

                    /* Need to leave the root slash if this
                     * is not a relative path and the end was reached
                     * on a backreference.
                     */
                    if (!relative && (src == end)) {
                        dst++;
                    }
                }

                if (done) goto length; /* Skip the copy. */
                src++;

                *changed = 1;
            } else if (dst == input) {
                /* Relative Self-reference? */
                *changed = 1;

                /* Ignore. */

                if (done) goto length; /* Skip the copy. */
                src++;
            } else if (*(dst - 1) == '/') {
                /* Self-reference? */
                *changed = 1;

                /* Ignore. */

                if (done) goto length; /* Skip the copy. */
                dst--;
                src++;
            }
        } else if (dst > input) {
            /* Found a regular path segment. */
            hitroot = 0;
        }

        copy:
        /*** Copy the byte if required. ***/

        /* Skip to the last forward slash when multiple are used. */
        if (*src == '/') {
            char *oldsrc = src;

            while ((src < end)
                   && ((*(src + 1) == '/') || (win && (*(src + 1) == '\\')))) {
                src++;
            }
            if (oldsrc != src) *changed = 1;

            /* Do not copy the forward slash to the root
             * if it is not a relative path.  Instead
             * move over the slash to the next segment.
             */
            if (relative && (dst == input)) {
                src++;
                goto length; /* Skip the copy */
            }
        }

        *(dst++) = *(src++);

        length:
        ldst = (dst - input);
    }
    /* Make sure that there is not a trailing slash in the
     * normalized form if there was not one in the original form.
     */
    if (!trailing && (dst > input) && *(dst - 1) == '/') {
        ldst--;
        dst--;
    }

    /* Always NUL terminate */
    *dst = '\0';

    return ldst;
}


static const char *const NamedEntities[][2] = {
	{ "AElig","Æ" },
	{ "Aacute","Á" },
	{ "Acirc","Â" },
	{ "Agrave","À" },
	{ "Alpha","Α" },
	{ "Aring","Å" },
	{ "Atilde","Ã" },
	{ "Auml","Ä" },
	{ "Beta","Β" },
	{ "Ccedil","Ç" },
	{ "Chi","Χ" },
	{ "Dagger","‡" },
	{ "Delta","Δ" },
	{ "ETH","Ð" },
	{ "Eacute","É" },
	{ "Ecirc","Ê" },
	{ "Egrave","È" },
	{ "Epsilon","Ε" },
	{ "Eta","Η" },
	{ "Euml","Ë" },
	{ "Gamma","Γ" },
	{ "Iacute","Í" },
	{ "Icirc","Î" },
	{ "Igrave","Ì" },
	{ "Iota","Ι" },
	{ "Iuml","Ï" },
	{ "Kappa","Κ" },
	{ "Lambda","Λ" },
	{ "Mu","Μ" },
	{ "Ntilde","Ñ" },
	{ "Nu","Ν" },
	{ "OElig","Œ" },
	{ "Oacute","Ó" },
	{ "Ocirc","Ô" },
	{ "Ograve","Ò" },
	{ "Omega","Ω" },
	{ "Omicron","Ο" },
	{ "Oslash","Ø" },
	{ "Otilde","Õ" },
	{ "Ouml","Ö" },
	{ "Phi","Φ" },
	{ "Pi","Π" },
	{ "Prime","″" },
	{ "Psi","Ψ" },
	{ "Rho","Ρ" },
	{ "Scaron","Š" },
	{ "Sigma","Σ" },
	{ "THORN","Þ" },
	{ "Tau","Τ" },
	{ "Theta","Θ" },
	{ "Uacute","Ú" },
	{ "Ucirc","Û" },
	{ "Ugrave","Ù" },
	{ "Upsilon","Υ" },
	{ "Uuml","Ü" },
	{ "Xi","Ξ" },
	{ "Yacute","Ý" },
	{ "Yuml","Ÿ" },
	{ "Zeta","Ζ" },
	{ "aacute","á" },
	{ "acirc","â" },
	{ "acute","´" },
	{ "aelig","æ" },
	{ "agrave","à" },
	{ "alefsym","ℵ" },
	{ "alpha","α" },
	{ "amp","&" },
	{ "and","∧" },
	{ "ang","∠" },
	{ "apos","'" },
	{ "aring","å" },
	{ "asymp","≈" },
	{ "atilde","ã" },
	{ "auml","ä" },
	{ "bdquo","„" },
	{ "beta","β" },
	{ "brvbar","¦" },
	{ "bull","•" },
	{ "cap","∩" },
	{ "ccedil","ç" },
	{ "cedil","¸" },
	{ "cent","¢" },
	{ "chi","χ" },
	{ "circ","ˆ" },
	{ "clubs","♣" },
	{ "cong","≅" },
	{ "copy","©" },
	{ "crarr","↵" },
	{ "cup","∪" },
	{ "curren","¤" },
	{ "dArr","⇓" },
	{ "dagger","†" },
	{ "darr","↓" },
	{ "deg","°" },
	{ "delta","δ" },
	{ "diams","♦" },
	{ "divide","÷" },
	{ "eacute","é" },
	{ "ecirc","ê" },
	{ "egrave","è" },
	{ "empty","∅" },
	{ "emsp","\xE2\x80\x83" },
	{ "ensp","\xE2\x80\x82" },
	{ "epsilon","ε" },
	{ "equiv","≡" },
	{ "eta","η" },
	{ "eth","ð" },
	{ "euml","ë" },
	{ "euro","€" },
	{ "exist","∃" },
	{ "fnof","ƒ" },
	{ "forall","∀" },
	{ "frac12","½" },
	{ "frac14","¼" },
	{ "frac34","¾" },
	{ "frasl","⁄" },
	{ "gamma","γ" },
	{ "ge","≥" },
	{ "gt",">" },
	{ "hArr","⇔" },
	{ "harr","↔" },
	{ "hearts","♥" },
	{ "hellip","…" },
	{ "iacute","í" },
	{ "icirc","î" },
	{ "iexcl","¡" },
	{ "igrave","ì" },
	{ "image","ℑ" },
	{ "infin","∞" },
	{ "int","∫" },
	{ "iota","ι" },
	{ "iquest","¿" },
	{ "isin","∈" },
	{ "iuml","ï" },
	{ "kappa","κ" },
	{ "lArr","⇐" },
	{ "lambda","λ" },
	{ "lang","〈" },
	{ "laquo","«" },
	{ "larr","←" },
	{ "lceil","⌈" },
	{ "ldquo","“" },
	{ "le","≤" },
	{ "lfloor","⌊" },
	{ "lowast","∗" },
	{ "loz","◊" },
	{ "lrm","\xE2\x80\x8E" },
	{ "lsaquo","‹" },
	{ "lsquo","‘" },
	{ "lt","<" },
	{ "macr","¯" },
	{ "mdash","—" },
	{ "micro","µ" },
	{ "middot","·" },
	{ "minus","−" },
	{ "mu","μ" },
	{ "nabla","∇" },
	{ "nbsp","\xA0" },
	{ "ndash","–" },
	{ "ne","≠" },
	{ "ni","∋" },
	{ "not","¬" },
	{ "notin","∉" },
	{ "nsub","⊄" },
	{ "ntilde","ñ" },
	{ "nu","ν" },
	{ "oacute","ó" },
	{ "ocirc","ô" },
	{ "oelig","œ" },
	{ "ograve","ò" },
	{ "oline","‾" },
	{ "omega","ω" },
	{ "omicron","ο" },
	{ "oplus","⊕" },
	{ "or","∨" },
	{ "ordf","ª" },
	{ "ordm","º" },
	{ "oslash","ø" },
	{ "otilde","õ" },
	{ "otimes","⊗" },
	{ "ouml","ö" },
	{ "para","¶" },
	{ "part","∂" },
	{ "permil","‰" },
	{ "perp","⊥" },
	{ "phi","φ" },
	{ "pi","π" },
	{ "piv","ϖ" },
	{ "plusmn","±" },
	{ "pound","£" },
	{ "prime","′" },
	{ "prod","∏" },
	{ "prop","∝" },
	{ "psi","ψ" },
	{ "quot","\"" },
	{ "rArr","⇒" },
	{ "radic","√" },
	{ "rang","〉" },
	{ "raquo","»" },
	{ "rarr","→" },
	{ "rceil","⌉" },
	{ "rdquo","”" },
	{ "real","ℜ" },
	{ "reg","®" },
	{ "rfloor","⌋" },
	{ "rho","ρ" },
	{ "rlm","\xE2\x80\x8F" },
	{ "rsaquo","›" },
	{ "rsquo","’" },
	{ "sbquo","‚" },
	{ "scaron","š" },
	{ "sdot","⋅" },
	{ "sect","§" },
	{ "shy","\xC2\xAD" },
	{ "sigma","σ" },
	{ "sigmaf","ς" },
	{ "sim","∼" },
	{ "spades","♠" },
	{ "sub","⊂" },
	{ "sube","⊆" },
	{ "sum","∑" },
	{ "sup1","¹" },
	{ "sup2","²" },
	{ "sup3","³" },
	{ "sup","⊃" },
	{ "supe","⊇" },
	{ "szlig","ß" },
	{ "tau","τ" },
	{ "there4","∴" },
	{ "theta","θ" },
	{ "thetasym","ϑ" },
	{ "thinsp","\xE2\x80\x89" },
	{ "thorn","þ" },
	{ "tilde","˜" },
	{ "times","×" },
	{ "trade","™" },
	{ "uArr","⇑" },
	{ "uacute","ú" },
	{ "uarr","↑" },
	{ "ucirc","û" },
	{ "ugrave","ù" },
	{ "uml","¨" },
	{ "upsih","ϒ" },
	{ "upsilon","υ" },
	{ "uuml","ü" },
	{ "weierp","℘" },
	{ "xi","ξ" },
	{ "yacute","ý" },
	{ "yen","¥" },
	{ "yuml","ÿ" },
	{ "zeta","ζ" },
	{ "zwj","\xE2\x80\x8D" },
	{ "zwnj","\xE2\x80\x8C" }
};

static int stringCompare(const void *key,const void *value) {
	return strncmp(
				(const char *) key,
				*(const char *const *) value,
				strlen(*(const char *const *)value)
			);
}

static const char *getNamedEntity(const char *name) {
	const char *const *entity = (const char *const *)
			bsearch(
				name,
				NamedEntities,sizeof NamedEntities / sizeof *NamedEntities,
				sizeof *NamedEntities,stringCompare
			);
	return entity ? entity[1] : NULL;
}

int html_entity_decode(unsigned char *input, uint64_t input_len) {
    unsigned char *d = input;
    int i, count;

    if (unlikely((input == NULL) || (input_len == 0))) {
        return 0;
    }

    i = count = 0;
    while ((i < input_len) && (count < input_len)) {
        int z, copy = 1;

        /* Require an ampersand and at least one character to
         * start looking into the entity.
         */
        if ((input[i] == '&') && (i + 1 < input_len)) {
            int k, j = i + 1;

            if (input[j] == '#') {
                /* Numerical entity. */
                copy++;

                if (!(j + 1 < input_len)) {
                    goto HTML_ENT_OUT; /* Not enough bytes. */
                }
                j++;

                if ((input[j] == 'x') || (input[j] == 'X')) {
                    /* Hexadecimal entity. */
                    copy++;

                    if (!(j + 1 < input_len)) {
                        goto HTML_ENT_OUT; /* Not enough bytes. */
                    }
                    j++; /* j is the position of the first digit now. */

                    k = j;
                    while ((j < input_len) && (isxdigit(input[j]))) {
                        j++;
                    }
                    if (j > k) { /* Do we have at least one digit? */
                        /* Decode the entity. */
                        char *x;
                        x = (char *) (calloc(sizeof(char),
                                             ((j - k) + 1)));
                        memcpy(x, (const char *) &input[k], j - k);
                        *d++ = (unsigned char) strtol(x, NULL, 16);
                        free(x);
                        count++;

                        /* Skip over the semicolon if it's there. */
                        if ((j < input_len) && (input[j] == ';')) {
                            i = j + 1;
                        } else {
                            i = j;
                        }
                        continue;
                    } else {
                        goto HTML_ENT_OUT;
                    }
                } else {
                    /* Decimal entity. */
                    k = j;
                    while ((j < input_len) && (isdigit(input[j]))) {
                        j++;
                    }
                    if (j > k) { /* Do we have at least one digit? */
                        /* Decode the entity. */
                        char *x;
                        x = (char *) (calloc(sizeof(char),
                                             ((j - k) + 1)));
                        memcpy(x, (const char *) &input[k], j - k);
                        *d++ = (unsigned char) strtol(x, NULL, 10);
                        free(x);
                        count++;

                        /* Skip over the semicolon if it's there. */
                        if ((j < input_len) && (input[j] == ';')) {
                            i = j + 1;
                        } else {
                            i = j;
                        }
                        continue;
                    } else {
                        goto HTML_ENT_OUT;
                    }
                }
            } else {
                /* Text entity. */
                k = j;
                while ((j < input_len) && (isalnum(input[j]))) {
                    j++;
                }
                if (j > k) { /* Do we have at least one digit? */
                    char *x;
                    x = (char *) (calloc(sizeof(char),
                                         ((j - k) + 1)));
                    memcpy(x, (const char *) &input[k], j - k);


                    const char *entity = getNamedEntity(x);
		            if(entity){
                       size_t len = strlen(entity);
		                memcpy(d, entity, len);
		                d += len;
                    }else{
                        copy = j - k + 1;
                        free(x);
                        goto HTML_ENT_OUT;
                    }
                    free(x);

                    count++;

                    /* Skip over the semicolon if it's there. */
                    if ((j < input_len) && (input[j] == ';')) {
                        i = j + 1;
                    } else {
                        i = j;
                    }

                    continue;
                }
            }
        }

        HTML_ENT_OUT:

        for (z = 0; ((z < copy) && (count < input_len)); z++) {
            *d++ = input[i++];
            count++;
        }
    }

    *d = '\0';

    return count;
}

int url_decode_uni(unsigned char *input, uint64_t input_len) {
    unsigned char *d = input;
    int64_t i, count, fact;
    int Code, hmap = -1;

    if (unlikely(input == NULL)) return -1;

    i = count = 0;
    while (i < input_len) {
        if (input[i] == '%') {
            if ((i + 1 < input_len) &&
                ((input[i + 1] == 'u') || (input[i + 1] == 'U'))) {
                /* Character is a percent sign. */
                /* IIS-specific %u encoding. */
                if (i + 5 < input_len) {
                    /* We have at least 4 data bytes. */
                    if ((VALID_HEX(input[i + 2])) &&
                        (VALID_HEX(input[i + 3])) &&
                        (VALID_HEX(input[i + 4])) &&
                        (VALID_HEX(input[i + 5]))) {
                        Code = 0;
                        fact = 1;

                        if (hmap != -1) {
                            *d = hmap;
                        } else {
                            /* We first make use of the lower byte here,
                             * ignoring the higher byte. */
                            *d = x2c(&input[i + 4]);

                            /* Full width ASCII (ff01 - ff5e)
                             * needs 0x20 added */
                            if ((*d > 0x00) && (*d < 0x5f)
                                && ((input[i + 2] == 'f')
                                    || (input[i + 2] == 'F'))
                                && ((input[i + 3] == 'f')
                                    || (input[i + 3] == 'F'))) {
                                (*d) += 0x20;
                            }
                        }
                        d++;
                        count++;
                        i += 6;
                    } else {
                        /* Invalid data, skip %u. */
                        *d++ = input[i++];
                        *d++ = input[i++];
                        count += 2;
                    }
                } else {
                    /* Not enough bytes (4 data bytes), skip %u. */
                    *d++ = input[i++];
                    *d++ = input[i++];
                    count += 2;
                }
            } else {
                /* Standard URL encoding. */
                /* Are there enough bytes available? */
                if (i + 2 < input_len) {
                    /* Yes. */

                    /* Decode a %xx combo only if it is valid.
                     */
                    char c1 = input[i + 1];
                    char c2 = input[i + 2];

                    if (VALID_HEX(c1) && VALID_HEX(c2)) {
                        *d++ = x2c(&input[i + 1]);
                        count++;
                        i += 3;
                    } else {
                        /* Not a valid encoding, skip this % */
                        *d++ = input[i++];
                        count++;
                    }
                } else {
                    /* Not enough bytes available, skip this % */
                    *d++ = input[i++];
                    count++;
                }
            }
        } else {
            /* Character is not a percent sign. */
            if (input[i] == '+') {
                *d++ = ' ';
            } else {
                *d++ = input[i];
            }

            count++;
            i++;
        }
    }

    *d = '\0';

    return count;
}


int cmd_line(char *value, uint64_t value_len) {
    int count = 0;
    int space = 0;

    char * ret = value;
    for (uint64_t i = 0; i < value_len; i++) {
        char a = value[i];
        switch (a) {
            /* remove some characters */
            case '"':
            case '\'':
            case '\\':
            case '^':
                break;

                /* replace some characters to space (only one) */
            case ' ':
            case ',':
            case ';':
            case '\t':
            case '\r':
            case '\n':
                if (space == 0) {
                    *ret++ = ' ';
                    count++;
                    space++;
                }
                break;

                /* remove space before / or ( */
            case '/':
            case '(':
                if (space) {
                    ret--;
                    count--;
                }
                space = 0;
                *ret++ = a;
                count++;
                break;

                /* copy normal characters */
            default :
                *ret++ = tolower(a);
                count++;
                space = 0;
                break;
        }
    }
    *ret = '\0';
    return count;
}


int utf8_to_unicode(const char *input,
                    uint64_t input_len, int *changed, char *data, unsigned int len) {
    unsigned int count = 0;
    char *data_orig;
    unsigned int i, j;
    unsigned int bytes_left = input_len;
    unsigned char unicode[8];
    *changed = 0;

    /* RFC3629 states that UTF-8 are encoded using sequences of 1 to 4 octets. */
    /* Max size per character should fit in 4 bytes */

    data_orig = data;

    for (i = 0; i < bytes_left;) {
        int unicode_len = 0;
        unsigned int d = 0;
        unsigned char c;
        const char *utf = (const char *) &input[i];

        c = *utf;

        /* If first byte begins with binary 0 it is single byte encoding */
        if ((c & 0x80) == 0) {
            /* single byte unicode (7 bit ASCII equivilent) has no validation */
            count++;
            if (count <= len) {
                if (c == 0 && input_len > i + 1) {
                    unsigned char z[2];
                    z[0] = *utf;
                    z[1] = *(utf + 1);
                    *data = x2c((unsigned char *) &z);
                } else {
                    *data++ = c;
                }
            }
        } else if ((c & 0xE0) == 0xC0) {
            /* If first byte begins with binary 110 it is two byte encoding*/
            /* check we have at least two bytes */
            if (bytes_left < 2) {
                /* check second byte starts with binary 10 */
                unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            } else if (((*(utf + 1)) & 0xC0) != 0x80) {
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else {
                unicode_len = 2;
                count += 6;
                if (count <= len) {
                    int length = 0;
                    /* compute character number */
                    d = ((c & 0x1F) << 6) | (*(utf + 1) & 0x3F);
                    *data++ = '%';
                    *data++ = 'u';
                    snprintf((char *) (unicode),
                             sizeof((char *) (unicode)),
                             "%x", d);
                    length = strlen((char *) (unicode));

                    switch (length) {
                        case 1:
                            *data++ = '0';
                            *data++ = '0';
                            *data++ = '0';
                            break;
                        case 2:
                            *data++ = '0';
                            *data++ = '0';
                            break;
                        case 3:
                            *data++ = '0';
                            break;
                        case 4:
                        case 5:
                            break;
                    }

                    for (j = 0; j < length; j++) {
                        *data++ = unicode[j];
                    }

                    *changed = 1;
                }
            }
        } else if ((c & 0xF0) == 0xE0) {
            /* If first byte begins with binary 1110 it is three byte encoding */
            /* check we have at least three bytes */
            if (bytes_left < 3) {
                /* check second byte starts with binary 10 */
                unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            } else if (((*(utf + 1)) & 0xC0) != 0x80) {
                /* check third byte starts with binary 10 */
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else if (((*(utf + 2)) & 0xC0) != 0x80) {
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else {
                unicode_len = 3;
                count += 6;
                if (count <= len) {
                    int length = 0;
                    /* compute character number */
                    d = ((c & 0x0F) << 12)
                        | ((*(utf + 1) & 0x3F) << 6)
                        | (*(utf + 2) & 0x3F);
                    *data++ = '%';
                    *data++ = 'u';
                    snprintf((char *) (unicode),
                             sizeof((char *) (unicode)),
                             "%x", d);
                    length = strlen((char *) (unicode));

                    switch (length) {
                        case 1:
                            *data++ = '0';
                            *data++ = '0';
                            *data++ = '0';
                            break;
                        case 2:
                            *data++ = '0';
                            *data++ = '0';
                            break;
                        case 3:
                            *data++ = '0';
                            break;
                        case 4:
                        case 5:
                            break;
                    }

                    for (j = 0; j < length; j++) {
                        *data++ = unicode[j];
                    }

                    *changed = 1;
                }
            }
        } else if ((c & 0xF8) == 0xF0) {
            /* If first byte begins with binary 11110 it
             * is four byte encoding
             */
            /* restrict characters to UTF-8 range (U+0000 - U+10FFFF) */
            if (c >= 0xF5) {
                *data++ = c;
            }
            /* check we have at least four bytes */
            if (bytes_left < 4) {
                /* check second byte starts with binary 10 */
                unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            } else if (((*(utf + 1)) & 0xC0) != 0x80) {
                /* check third byte starts with binary 10 */
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else if (((*(utf + 2)) & 0xC0) != 0x80) {
                /* check forth byte starts with binary 10 */
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else if (((*(utf + 3)) & 0xC0) != 0x80) {
                unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            } else {
                unicode_len = 4;
                count += 7;
                if (count <= len) {
                    int length = 0;
                    /* compute character number */
                    d = ((c & 0x07) << 18)
                        | ((*(utf + 1) & 0x3F) << 12)
                        | ((*(utf + 2) & 0x3F) << 6)
                        | (*(utf + 3) & 0x3F);
                    *data++ = '%';
                    *data++ = 'u';
                    snprintf((char *) (unicode),
                             sizeof((char *) (unicode)),
                             "%x", d);
                    length = strlen((char *) (unicode));

                    switch (length) {
                        case 1:
                            *data++ = '0';
                            *data++ = '0';
                            *data++ = '0';
                            break;
                        case 2:
                            *data++ = '0';
                            *data++ = '0';
                            break;
                        case 3:
                            *data++ = '0';
                            break;
                        case 4:
                        case 5:
                            break;
                    }

                    for (j = 0; j < length; j++) {
                        *data++ = unicode[j];
                    }

                    *changed = 1;
                }
            }
        } else {
            /* any other first byte is invalid (RFC 3629) */
            count++;
            if (count <= len)
                *data++ = c;
        }

        /* invalid UTF-8 character number range (RFC 3629) */
        if ((d >= 0xD800) && (d <= 0xDFFF)) {
            count++;
            if (count <= len)
                *data++ = c;
        }

        /* check for overlong */
        if ((unicode_len == 4) && (d < 0x010000)) {
            /* four byte could be represented with less bytes */
            count++;
            if (count <= len)
                *data++ = c;
        } else if ((unicode_len == 3) && (d < 0x0800)) {
            /* three byte could be represented with less bytes */
            count++;
            if (count <= len)
                *data++ = c;
        } else if ((unicode_len == 2) && (d < 0x80)) {
            /* two byte could be represented with less bytes */
            count++;
            if (count <= len)
                *data++ = c;
        }

        if (unicode_len > 0) {
            i += unicode_len;
        } else {
            i++;
        }
    }

    *data = '\0';

    return count;
}


int escape_seq_decode(unsigned char *input, int input_len) {
    unsigned char *d = input;
    int i, count;

    i = count = 0;
    while (i < input_len) {
        if ((input[i] == '\\') && (i + 1 < input_len)) {
            int c = -1;

            switch (input[i + 1]) {
                case 'a' :
                    c = '\a';
                    break;
                case 'b' :
                    c = '\b';
                    break;
                case 'f' :
                    c = '\f';
                    break;
                case 'n' :
                    c = '\n';
                    break;
                case 'r' :
                    c = '\r';
                    break;
                case 't' :
                    c = '\t';
                    break;
                case 'v' :
                    c = '\v';
                    break;
                case '\\' :
                    c = '\\';
                    break;
                case '?' :
                    c = '?';
                    break;
                case '\'' :
                    c = '\'';
                    break;
                case '"' :
                    c = '"';
                    break;
            }

            if (c != -1) i += 2;

            /* Hexadecimal or octal? */
            if (c == -1) {
                if ((input[i + 1] == 'x') || (input[i + 1] == 'X')) {
                    /* Hexadecimal. */
                    if ((i + 3 < input_len) && (isxdigit(input[i + 2]))
                        && (isxdigit(input[i + 3]))) {
                        /* Two digits. */
                        c = x2c(&input[i + 2]);
                        i += 4;
                    } else {
                        /* Invalid encoding, do nothing. */
                    }
                } else {
                    if (ISODIGIT(input[i + 1])) { /* Octal. */
                        char buf[4];
                        int j = 0;

                        while ((i + 1 + j < input_len) && (j < 3)) {
                            buf[j] = input[i + 1 + j];
                            j++;
                            if (!ISODIGIT(input[i + 1 + j])) break;
                        }
                        buf[j] = '\0';

                        if (j > 0) {
                            c = strtol(buf, NULL, 8);
                            i += 1 + j;
                        }
                    }
                }
            }

            if (c == -1) {
                /* Didn't recognise encoding, copy raw bytes. */
                *d++ = input[i + 1];
                count++;
                i += 2;
            } else {
                /* Converted the encoding. */
                *d++ = c;
                count++;
            }
        } else {
            /* Input character not a backslash, copy it. */
            *d++ = input[i++];
            count++;
        }
    }

    *d = '\0';

    return count;
}


int uri_decode(const char *input, unsigned int input_len, int *changed, char *rval, unsigned int len) {
    char *d;
    unsigned int i;
    int count = 0;

    *changed = 0;

    d = rval;

    /* ENH Only encode the characters that really need to be encoded. */

    for (i = 0; i < input_len; i++) {
        unsigned char c = input[i];

        if (c == ' ') {
            *d++ = '+';
            *changed = 1;
            count++;
        } else {
            if ((c == 42) || ((c >= 48) && (c <= 57))
                || ((c >= 65) && (c <= 90))
                || ((c >= 97) && (c <= 122))) {
                *d++ = c;
                count++;
            } else {
                *d++ = '%';
                count++;
                c2x(c, (unsigned char *) d);
                d += 2;
                count++;
                count++;
                *changed = 1;
            }
        }
    }

    *d = '\0';

    return count;
}


uint32_t remove_comments(unsigned char *input, uint32_t input_len) {
    uint32_t i, j, incomment;

    i = j = incomment = 0;
    while (i < input_len) {
        if (incomment == 0) {
            if ((input[i] == '/') && (i + 1 < input_len)
                && (input[i + 1] == '*')) {
                incomment = 1;
                i += 2;
            } else if ((input[i] == '<') && (i + 1 < input_len)
                       && (input[i + 1] == '!') && (i + 2 < input_len)
                       && (input[i + 2] == '-') && (i + 3 < input_len)
                       && (input[i + 3] == '-')) {
                incomment = 1;
                i += 4;
            } else if ((input[i] == '-') && (i + 1 < input_len)
                       && (input[i + 1] == '-')) {
                input[i] = ' ';
                break;
            } else if (input[i] == '#') {
                input[i] = ' ';
                break;
            } else {
                input[j] = input[i];
                i++;
                j++;
            }
        } else {
            if ((input[i] == '*') && (i + 1 < input_len)
                && (input[i + 1] == '/')) {
                incomment = 0;
                i += 2;
                input[j] = input[i];
                i++;
                j++;
            } else if ((input[i] == '-') && (i + 1 < input_len)
                       && (input[i + 1] == '-') && (i + 2 < input_len)
                       && (input[i + 2] == '>')) {
                incomment = 0;
                i += 3;
                input[j] = input[i];
                i++;
                j++;
            } else {
                i++;
            }
        }
    }

    if (incomment) {
        input[j++] = ' ';
    }

    return j;
}


uint32_t replace_comments(char *input, size_t len) {
    uint32_t i, j, incomment;

    i = j = incomment = 0;
    while (i < len) {
        if (incomment == 0) {
            if ((input[i] == '/') && (i + 1 < len)
                && (input[i + 1] == '*')) {
                incomment = 1;
                i += 2;
            } else {
                input[j] = input[i];
                i++;
                j++;
            }
        } else {
            if ((input[i] == '*') && (i + 1 < len)
                && (input[i + 1] == '/')) {
                incomment = 0;
                i += 2;
                input[j] = ' ';
                j++;
            } else {
                i++;
            }
        }
    }

    if (incomment) {
        input[j++] = ' ';
    }
    return j;
}

int hex_decode(unsigned char *data, int len) {
    unsigned char *d = data;
    int i, count = 0;

    if ((data == NULL) || (len == 0)) {
        return 0;
    }

    for (i = 0; i <= len - 2; i += 2) {
        *d++ = x2c(&data[i]);
        count++;
    }
    *d = '\0';

    return count;
}
