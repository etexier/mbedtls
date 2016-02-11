include_directories(${PROJECT_SOURCE_DIR}/programs/hash)

add_executable(hello hello.c apps_utils.c rkl_inject.c rkl_tr34.c rkl_db.c rkl_tls.c)
target_link_libraries(hello mbedtls)

add_executable(generic_sum generic_sum.c)
target_link_libraries(generic_sum mbedtls)

install(TARGETS hello generic_sum
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
