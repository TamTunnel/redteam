// Built-in rule: XML external entity (XXE) — stdlib/lxml XML parsers that
// resolve external entities by default.
// Python: xml.etree.ElementTree.parse, lxml.etree.parse, xml.dom.minidom.parse
// matched by strict dotted path (defusedxml.* does not match).
// JS/TS: xml2js / libxmljs parse calls (best effort — these libraries'
// entity handling varies by option; verify external entities are disabled).
// Known false negative: `import xml.etree.ElementTree as ET; ET.parse()`
// (aliased import) is not matched. Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

registry.register(
  defineRule({
    id: "sec-xxe",
    severity: "medium",
    languages: ["javascript", "typescript", "python"],
    queries: {
      javascript: `
        (call_expression
          function: (member_expression
            object: (identifier) @o (#match? @o "^(xml2js|libxmljs)$")
            property: (property_identifier) @p (#match? @p "^(parseString|parseXml|parse)$"))) @node
      `,
      typescript: `
        (call_expression
          function: (member_expression
            object: (identifier) @o (#match? @o "^(xml2js|libxmljs)$")
            property: (property_identifier) @p (#match? @p "^(parseString|parseXml|parse)$"))) @node
      `,
      // NOTE: in tree-sitter queries, fields must appear in the grammar's
      // declaration order — for python `attribute` that is object:, attribute:.
      python: `
        (call
          function: (attribute
            object: (attribute
              object: (attribute
                object: (identifier) @x (#eq? @x "xml")
                attribute: (identifier) @e (#eq? @e "etree"))
              attribute: (identifier) @c (#eq? @c "ElementTree"))
            attribute: (identifier) @m (#eq? @m "parse"))) @node
        (call
          function: (attribute
            object: (attribute
              object: (identifier) @l (#eq? @l "lxml")
              attribute: (identifier) @e (#eq? @e "etree"))
            attribute: (identifier) @m (#eq? @m "parse"))) @node
        (call
          function: (attribute
            object: (attribute
              object: (attribute
                object: (identifier) @x (#eq? @x "xml")
                attribute: (identifier) @d (#eq? @d "dom"))
              attribute: (identifier) @md (#eq? @md "minidom"))
            attribute: (identifier) @m (#eq? @m "parse"))) @node
      `,
    },
    message:
      "Possible XXE: this XML parser resolves external entities by default — a malicious document can read local files or probe the network",
    remediation:
      "Use defusedxml (defusedxml.ElementTree / defusedxml.minidom) in Python, or a parser configured with external-entity resolution disabled.",
  }),
);
