file(GLOB LXMPROXY_SRCS "src/*.cpp")

include(${CMAKE_CURRENT_LIST_DIR}/spangap_requires.cmake)
# Conditional sources: esp-idf/conditional/<name>/ is compiled only when <name>
# is staged (none — the settings pane is generated from straddle.yaml, and the
# client half of the protocol lives in the lxmf straddle).
idf_component_register(
    SRCS ${LXMPROXY_SRCS} ${SPANGAP_CONDITIONAL_SRCS}
    INCLUDE_DIRS "include" ${SPANGAP_CONDITIONAL_INCLUDE_DIRS}
    REQUIRES
        ${SPANGAP_REQUIRES}
        json
)
