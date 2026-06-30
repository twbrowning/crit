; id: os-dynamic-exec-xecute
; name: Dynamic code execution via XECUTE
; message: XECUTE runs its argument as ObjectScript code; if any part is attacker-influenced this is code injection.
; severity: warning
; languages: objectscript
; cwe: CWE-95
; references: https://docs.intersystems.com/iris/csp/docbook/DocBook.UI.Page.cls?KEY=RCOS_cxecute
;
; Raw tree-sitter query rule (.scm). The capture named @match marks the finding.
(command_xecute) @match
