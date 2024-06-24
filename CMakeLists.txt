set(COMPONENT_SRCDIRS
    "src"
)

set(COMPONENT_ADD_INCLUDEDIRS
    "src"
)

set(COMPONENT_REQUIRES
    "arduino-esp32"
)

register_component()

target_compile_options(${COMPONENT_TARGET} PRIVATE -fno-rtti)

if(CONFIG_ASYNC_TCP_SSL_ENABLED)
    target_compile_options(${COMPONENT_TARGET} PRIVATE -DASYNC_TCP_SSL_ENABLED)
endif()
