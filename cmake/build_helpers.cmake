#
# Pico Keys SDK build helper functions
#

function(picokeys_apply_strict_flags)
    set(options)
    set(oneValueArgs FILTER_REGEX)
    set(multiValueArgs SOURCES)
    cmake_parse_arguments(PKAS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT PKAS_SOURCES)
        return()
    endif()

    set(PICOKEYS_STRICT_FLAGS
        -pipe
        -funsigned-char
        -fstrict-aliasing
        -fdiagnostics-color=auto
        -Wextra
        -Wchar-subscripts
        -Wundef
        -Wshadow
        -Wcast-align
        -Wwrite-strings
        -Wunused
        -Wuninitialized
        -Wpointer-arith
        -Wredundant-decls
        -Winline
        -Wformat
        -Wformat-security
        -Wswitch-enum
        -Winit-self
        -Wmissing-include-dirs
        -Wempty-body
        -Wmissing-prototypes
        -Wstrict-prototypes
        -Wold-style-definition
        -Wbad-function-cast
        -Wnested-externs
        -Wmissing-declarations
        -Werror
    )

    foreach(src IN LISTS PKAS_SOURCES)
        if(PKAS_FILTER_REGEX)
            if(NOT src MATCHES "${PKAS_FILTER_REGEX}")
                continue()
            endif()
        endif()
        set_property(SOURCE "${src}" APPEND PROPERTY COMPILE_OPTIONS ${PICOKEYS_STRICT_FLAGS})
    endforeach()
endfunction()
