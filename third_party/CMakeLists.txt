# Vendored third-party libraries for the repomap module.
#
# We build tree-sitter core and grammars as static C libs so they link
# into sg_repomap without requiring system packages. Keep warnings off
# for vendored code — we don't maintain it.

set(TREE_SITTER_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/tree-sitter")
set(TREE_SITTER_TS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/tree-sitter-typescript")
set(TREE_SITTER_JS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/tree-sitter-javascript")
set(DOCTEST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/doctest")

# --- tree-sitter core ---------------------------------------------------
# Compile each .c separately (matches upstream's non-amalgamated layout).
# Exclude lib.c because it #includes every other .c and would double-compile.
set(TS_CORE_SRCS
  "${TREE_SITTER_ROOT}/lib/src/alloc.c"
  "${TREE_SITTER_ROOT}/lib/src/get_changed_ranges.c"
  "${TREE_SITTER_ROOT}/lib/src/language.c"
  "${TREE_SITTER_ROOT}/lib/src/lexer.c"
  "${TREE_SITTER_ROOT}/lib/src/node.c"
  "${TREE_SITTER_ROOT}/lib/src/parser.c"
  "${TREE_SITTER_ROOT}/lib/src/point.c"
  "${TREE_SITTER_ROOT}/lib/src/query.c"
  "${TREE_SITTER_ROOT}/lib/src/stack.c"
  "${TREE_SITTER_ROOT}/lib/src/subtree.c"
  "${TREE_SITTER_ROOT}/lib/src/tree_cursor.c"
  "${TREE_SITTER_ROOT}/lib/src/tree.c"
  "${TREE_SITTER_ROOT}/lib/src/wasm_store.c"
)

add_library(tree_sitter STATIC ${TS_CORE_SRCS})
target_include_directories(tree_sitter
  PUBLIC  "${TREE_SITTER_ROOT}/lib/include"
  PRIVATE "${TREE_SITTER_ROOT}/lib/src")
set_target_properties(tree_sitter PROPERTIES
  C_STANDARD 11
  POSITION_INDEPENDENT_CODE ON)
target_compile_options(tree_sitter PRIVATE -w)

# --- tree-sitter-typescript (TS only; TSX is a separate target, not built) ---
add_library(tree_sitter_typescript STATIC
  "${TREE_SITTER_TS_ROOT}/typescript/src/parser.c"
  "${TREE_SITTER_TS_ROOT}/typescript/src/scanner.c")
target_include_directories(tree_sitter_typescript
  PRIVATE "${TREE_SITTER_TS_ROOT}/typescript/src"
  PUBLIC  "${TREE_SITTER_TS_ROOT}/common")
set_target_properties(tree_sitter_typescript PROPERTIES
  C_STANDARD 11
  POSITION_INDEPENDENT_CODE ON)
target_compile_options(tree_sitter_typescript PRIVATE -w)

# --- tree-sitter-javascript ---------------------------------------------
add_library(tree_sitter_javascript STATIC
  "${TREE_SITTER_JS_ROOT}/src/parser.c"
  "${TREE_SITTER_JS_ROOT}/src/scanner.c")
target_include_directories(tree_sitter_javascript
  PRIVATE "${TREE_SITTER_JS_ROOT}/src")
set_target_properties(tree_sitter_javascript PROPERTIES
  C_STANDARD 11
  POSITION_INDEPENDENT_CODE ON)
target_compile_options(tree_sitter_javascript PRIVATE -w)

# --- doctest (header-only) ----------------------------------------------
add_library(doctest INTERFACE)
target_include_directories(doctest INTERFACE "${DOCTEST_ROOT}/doctest")
