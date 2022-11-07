project(aggsigtest)

find_package(cdt)

add_contract( aggsigtest aggsigtest aggsigtest.cpp )
target_include_directories( aggsigtest PUBLIC ${CMAKE_SOURCE_DIR}/../include )
target_ricardian_directory( aggsigtest ${CMAKE_SOURCE_DIR}/../ricardian )