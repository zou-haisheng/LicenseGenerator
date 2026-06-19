cmake_minimum_required(VERSION 3.15)

# 1. 必须在 project() 之前！告诉清单模式：我们要静态编译它！
set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "")
set(VCPKG_HOST_TRIPLET "x64-windows-static" CACHE STRING "")

project(LicenseGenerator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 2. 寻找 OpenSSL (清单模式会自动在后台下载并链接)
find_package(OpenSSL REQUIRED)

# 3. 强制 MSVC 编译器使用 /MT 静态运行时
if(MSVC)
    set(CompilerFlags CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE)
    foreach(CompilerFlag ${CompilerFlags})
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()
endif()

add_executable(LicenseGenerator main.cpp)
target_link_libraries(LicenseGenerator PRIVATE 
    OpenSSL::Crypto
    ws2_32
    crypt32
)