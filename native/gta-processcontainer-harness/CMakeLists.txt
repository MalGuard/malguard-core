cmake_minimum_required(VERSION 3.20)
project(MalGuardGtaContextHarness LANGUAGES CXX)

add_executable(MalGuardGtaContextHarness MalGuardGtaContextHarness.cpp)
target_compile_features(MalGuardGtaContextHarness PRIVATE cxx_std_17)
target_compile_definitions(MalGuardGtaContextHarness PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX WINVER=0x0A00 _WIN32_WINNT=0x0A00)

if(MSVC)
  set_property(TARGET MalGuardGtaContextHarness PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  target_compile_options(MalGuardGtaContextHarness PRIVATE /W4 /WX /guard:cf /sdl)
  target_link_options(MalGuardGtaContextHarness PRIVATE /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /guard:cf)
endif()
