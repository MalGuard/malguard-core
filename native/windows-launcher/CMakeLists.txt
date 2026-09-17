cmake_minimum_required(VERSION 3.20)
project(MalGuardLauncher LANGUAGES CXX)

add_executable(MalGuard WIN32 MalGuardLauncher.cpp)
target_compile_features(MalGuard PRIVATE cxx_std_17)
target_compile_definitions(MalGuard PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(MalGuard PRIVATE shell32)
