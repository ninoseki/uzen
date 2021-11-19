/*
Language: YARA
Description: YARA is the pattern matching swiss knife
Website: https://github.com/virustotal/yara
*/

import { HLJSApi, LanguageDetail } from "highlight.js";

export default function (hljs: HLJSApi): LanguageDetail {
  return {
    name: "YARA",
    aliases: ["yara", "yar"],
    case_insensitive: false,
    keywords: {
      built_in:
        "all and any ascii at base64 base64wide condition contains entrypoint false filesize for fullword global import in include int16 int16be int32 int32be int8 int8be matches meta nocase not of or private rule strings them true uint16 uint16be uint32 uint32be uint8 uint8be wide xor",
      literal: "true false",
    },
    contains: [
      hljs.C_LINE_COMMENT_MODE,
      hljs.QUOTE_STRING_MODE,
      // HEX string,
      {
        className: "string",
        begin: "=\\s*{",
        end: "}",
        excludeBegin: true,
        excludeEnd: true,
      },
      // Regexp string
      {
        className: "string",
        begin: "\\/.*?[^\\\\]/(i|c|x|t|s|m|p|w|n|J|U|d|b|e|q|x)*",
      },
      // HEX number,
      {
        className: "number",
        begin: "\\b0x[a-fA-F0-9]+\\b",
      },
      // Decimal number,
      {
        className: "number",
        begin: "\\b[0-9]+(MB|KB)?\\b",
      },
      // string identifier
      {
        className: "symbol",
        begin: "(\\$|\\#|\\@)[a-zA-Z0-9_]+",
      },
    ],
  };
}
