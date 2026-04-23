set(SG_COMMON_SOURCES
  src/native/catalog_rule_compiler.cpp
  src/native/client_runtime.cpp
  src/native/policy_catalog.cpp
  src/native/policy_bridge.cpp
  src/native/json_extract.cpp
  src/native/policy_post_tool_use.cpp
  src/native/policy_pre_compact.cpp
  src/native/policy_pre_tool_use.cpp
  src/native/policy_read_compress.cpp
  src/native/policy_permission_request.cpp
  src/native/policy_stats.cpp
  src/native/policy_state.cpp
  src/native/policy_read_guard.cpp
  src/native/policy_secrets.cpp
  src/native/rule_audit.cpp
  src/native/rule_engine.cpp
  src/native/policy_session_end.cpp
  src/native/policy_session_start.cpp
  src/native/policy_stop.cpp
  src/native/policy_subagent_start.cpp
  src/native/policy_subagent_stop.cpp
  src/native/policy_tool_error.cpp
  src/native/process.cpp
  src/native/protocol.cpp
  src/native/systemd_notify.cpp
  src/native/transport.cpp
)

add_library(sg_common STATIC ${SG_COMMON_SOURCES})
target_include_directories(sg_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(sg_common PRIVATE -Wall -Wextra -Wpedantic)

add_executable(sgd src/daemon/main.cpp)
target_link_libraries(sgd PRIVATE sg_common)

add_executable(sg-hook-pre-tool-use src/clients/pre_tool_use_main.cpp)
target_link_libraries(sg-hook-pre-tool-use PRIVATE sg_common)

add_executable(sg-hook-post-tool-use src/clients/post_tool_use_main.cpp)
target_link_libraries(sg-hook-post-tool-use PRIVATE sg_common)

add_executable(sg-hook-permission-request src/clients/permission_request_main.cpp)
target_link_libraries(sg-hook-permission-request PRIVATE sg_common)

add_executable(sg-hook-read-guard src/clients/read_guard_main.cpp)
target_link_libraries(sg-hook-read-guard PRIVATE sg_common)

add_executable(sg-hook-read-compress src/clients/read_compress_main.cpp)
target_link_libraries(sg-hook-read-compress PRIVATE sg_common)

add_executable(sg-hook-stop src/clients/stop_main.cpp)
target_link_libraries(sg-hook-stop PRIVATE sg_common)

add_executable(sg-hook-session-start src/clients/session_start_main.cpp)
target_link_libraries(sg-hook-session-start PRIVATE sg_common)

add_executable(sg-hook-session-end src/clients/session_end_main.cpp)
target_link_libraries(sg-hook-session-end PRIVATE sg_common)

add_executable(sg-hook-pre-compact src/clients/pre_compact_main.cpp)
target_link_libraries(sg-hook-pre-compact PRIVATE sg_common)

add_executable(sg-hook-subagent-start src/clients/subagent_start_main.cpp)
target_link_libraries(sg-hook-subagent-start PRIVATE sg_common)

add_executable(sg-hook-subagent-stop src/clients/subagent_stop_main.cpp)
target_link_libraries(sg-hook-subagent-stop PRIVATE sg_common)

add_executable(sg-hook-tool-error src/clients/tool_error_main.cpp)
target_link_libraries(sg-hook-tool-error PRIVATE sg_common)

add_executable(asg-cli src/tools/asg_cli_main.cpp)
target_link_libraries(asg-cli PRIVATE sg_common)
add_executable(asg-statusline src/tools/asg_statusline_main.cpp)
target_link_libraries(asg-statusline PRIVATE sg_common)

add_executable(asg-install src/tools/asg_install_main.cpp)
target_link_libraries(asg-install PRIVATE sg_common)
target_compile_definitions(asg-install PRIVATE SG_SOURCE_ROOT="${CMAKE_SOURCE_DIR}")
if(SG_BUILD_REPOMAP)
  target_compile_definitions(asg-install PRIVATE SG_HAS_REPOMAP=1)
endif()

add_executable(asg-uninstall src/tools/asg_uninstall_main.cpp)
target_link_libraries(asg-uninstall PRIVATE sg_common)

# --- repomap module (Phase 0: stub only) --------------------------------
# sg_repomap is a separate static lib so tree-sitter does not leak into
# sg_common / safety-critical code. The daemon does not link it yet; that
# happens in Phase 5 when session-start wires up the render query.
if(SG_BUILD_REPOMAP)
  # Embed tag queries (.scm) into a generated C++ header so the daemon has
  # zero runtime lookup for them. file(READ) + file(WRITE) with a raw string
  # delimiter is safer than configure_file(@ONLY) because the queries use
  # @name.* captures that could collide with @VAR@ substitution.
  set(SG_REPOMAP_EMBED_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated/sg/repomap_queries_embed.hpp")
  file(READ "${CMAKE_CURRENT_SOURCE_DIR}/queries/typescript-tags.scm" SG_REPOMAP_TS_QUERY)
  file(READ "${CMAKE_CURRENT_SOURCE_DIR}/queries/javascript-tags.scm" SG_REPOMAP_JS_QUERY)
  file(WRITE "${SG_REPOMAP_EMBED_HEADER}"
"// Auto-generated from native/queries/*.scm — do not edit by hand.\n"
"#pragma once\n"
"namespace sg::repomap::embedded {\n"
"inline constexpr char kTypeScriptTagsQuery[] = R\"SGRMQUERY(${SG_REPOMAP_TS_QUERY})SGRMQUERY\";\n"
"inline constexpr char kJavaScriptTagsQuery[] = R\"SGRMQUERY(${SG_REPOMAP_JS_QUERY})SGRMQUERY\";\n"
"}  // namespace sg::repomap::embedded\n")

  add_library(sg_repomap STATIC
    src/native/repomap_parser.cpp
    src/native/repomap_index.cpp
    src/native/repomap_format.cpp
    src/native/repomap_store.cpp
    src/native/repomap_service.cpp
    src/native/policy_repomap.cpp)
  target_include_directories(sg_repomap
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
  target_compile_options(sg_repomap PRIVATE -Wall -Wextra -Wpedantic)
  # sg_repomap publicly depends on sg_common for JSON helpers used by
  # policy_repomap; private deps on tree-sitter + grammars stay hidden.
  target_link_libraries(sg_repomap
    PUBLIC  sg_common
    PRIVATE tree_sitter tree_sitter_typescript tree_sitter_javascript)

  # Daemon links the repomap library so it can route Hook::kRepomapRender.
  target_link_libraries(sgd PRIVATE sg_repomap)
  target_compile_definitions(sgd PRIVATE SG_HAS_REPOMAP=1)

  add_executable(asg-repomap src/tools/asg_repomap_main.cpp)
  target_link_libraries(asg-repomap PRIVATE sg_repomap)

  install(TARGETS asg-repomap RUNTIME DESTINATION bin)
endif()

install(TARGETS sgd sg-hook-pre-tool-use sg-hook-post-tool-use
                sg-hook-permission-request sg-hook-read-guard
                sg-hook-read-compress sg-hook-stop sg-hook-session-start
                sg-hook-session-end sg-hook-pre-compact
                sg-hook-subagent-start sg-hook-subagent-stop
                sg-hook-tool-error asg-cli asg-statusline asg-install asg-uninstall
                RUNTIME DESTINATION bin)
