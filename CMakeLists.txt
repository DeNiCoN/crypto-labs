project (lab1)

cmake_minimum_required(VERSION 3.22.2)

file(GLOB lab1_SRC
  "src/*.h"
  "src/*.c"
  )

add_executable(lab1
  ${lab1_SRC}
  )

find_package(OpenSSL)
target_link_libraries(lab1
  OpenSSL::SSL
  )
