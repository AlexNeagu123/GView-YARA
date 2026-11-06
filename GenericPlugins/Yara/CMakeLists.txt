include(generic_plugin)
create_generic_plugin(Yara)

find_package(nlohmann_json REQUIRED)
target_link_libraries(Yara PRIVATE nlohmann_json::nlohmann_json)
