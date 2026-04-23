; JavaScript tag query for sg_repomap
; Captures definitions (@name.definition.*) and references (@name.reference.*).
; Predicates like #not-eq? are intentionally omitted — tree-sitter's C API
; requires the caller to evaluate predicates, which adds complexity we do
; not need. Instead, noise names (constructor, require, Symbol, ...) are
; filtered in C++ after extraction.

; ---- definitions ----------------------------------------------------------

(function_declaration
  name: (identifier) @name.definition.function)

(generator_function_declaration
  name: (identifier) @name.definition.function)

(class_declaration
  name: (_) @name.definition.class)

(method_definition
  name: (property_identifier) @name.definition.method)

(lexical_declaration
  (variable_declarator
    name: (identifier) @name.definition.function
    value: [(arrow_function) (function_expression)]))

(variable_declaration
  (variable_declarator
    name: (identifier) @name.definition.function
    value: [(arrow_function) (function_expression)]))

(assignment_expression
  left: [
    (identifier) @name.definition.function
    (member_expression
      property: (property_identifier) @name.definition.function)
  ]
  right: [(arrow_function) (function_expression)])

(pair
  key: (property_identifier) @name.definition.function
  value: [(arrow_function) (function_expression)])

; ---- references -----------------------------------------------------------

(call_expression
  function: (identifier) @name.reference.call)

(call_expression
  function: (member_expression
    property: (property_identifier) @name.reference.call))

(new_expression
  constructor: (identifier) @name.reference.class)

(new_expression
  constructor: (member_expression
    property: (property_identifier) @name.reference.class))
