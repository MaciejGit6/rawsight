# Runs rawsight once and compares its output against an expected file.
#   -DBIN=<rawsight> -DARGS="<args>" -DEXPECTED=<file> -DEXPECT_RC=<n>
# Set RAWSIGHT_UPDATE_EXPECTED=1 in the environment to rewrite the expected
# file from the current output instead of comparing.

separate_arguments(arg_list UNIX_COMMAND "${ARGS}")
execute_process(
    COMMAND ${BIN} ${arg_list}
    OUTPUT_VARIABLE out
    ERROR_VARIABLE  err
    RESULT_VARIABLE rc
)

# stderr is appended so sanitizer reports or unexpected errors show up as a diff
set(actual "${out}${err}")
# usage text prints argv[0], keep expected files independent of the build dir
string(REPLACE "${BIN}" "rawsight" actual "${actual}")
string(ASCII 27 ESC)
string(REGEX REPLACE "${ESC}\\[[0-9;]*m" "" actual "${actual}")

if(DEFINED ENV{RAWSIGHT_UPDATE_EXPECTED})
    file(WRITE "${EXPECTED}" "${actual}")
    message(STATUS "updated ${EXPECTED}")
    return()
endif()

file(READ "${EXPECTED}" expected)
if(NOT actual STREQUAL expected)
    message(FATAL_ERROR "output mismatch for: rawsight ${ARGS}\n"
                        "--- expected ---\n${expected}\n"
                        "--- actual ---\n${actual}")
endif()

if(NOT rc EQUAL EXPECT_RC)
    message(FATAL_ERROR "rawsight ${ARGS}: exit code ${rc}, expected ${EXPECT_RC}")
endif()
