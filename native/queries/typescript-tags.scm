; TypeScript tag query for sg_repomap
; Captures definitions (@name.definition.*) and references (@name.reference.*).
; No predicates — see javascript-tags.scm for rationale.

; ---- definitions ----------------------------------------------------------

(function_declaration
  name: (identifier) @name.definition.function)

(function_signature
  name: (identifier) @name.definition.function)

(generator_function_declaration
  name: (identifier) @name.definition.function)

(class_declaration
  name: (type_identifier) @name.definition.class)

(abstract_class_declaration
  name: (type_identifier) @name.definition.class)

(interface_declaration
  name: (type_identifier) @name.definition.interface)

(type_alias_declaration
  name: (type_identifier) @name.definition.type)

(enum_declaration
  name: (identifier) @name.definition.enum)

(module
  name: (identifier) @name.definition.module)

(method_definition
  name: (property_identifier) @name.definition.method)

(method_signature
  name: (property_identifier) @name.definition.method)

(abstract_method_signature
  name: (property_identifier) @name.definition.method)

(lexical_declaration
  (variable_declarator
    name: (identifier) @name.definition.function
    value: [(arrow_function) (function_expression)]))

(variable_declaration
  (variable_declarator
    name: (identifier) @name.definition.function
    value: [(arrow_function) (function_expression)]))

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

(type_annotation
  (type_identifier) @name.reference.type)

(type_annotation
  (generic_type
    name: (type_identifier) @name.reference.type))
