cmake_minimum_required(VERSION 3.15)

project(LicenseGenerator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

file(GLOB SOURCES "*.cpp")

add_executable(LicenseGenerator ${SOURCES})
target_include_directories(LicenseGenerator PRIVATE ${OPENSSL_INSSL_INCLUDE_DIR})
target_link_libraries(LicenseGenerator PRIVATE
    OpenSSL::Crypto
    OpenSSL::SSL
)