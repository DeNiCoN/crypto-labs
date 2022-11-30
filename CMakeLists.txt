project (lab1)

cmake_minimum_required(VERSION 3.22.2)

add_library(shared
  "src/shared.c"
  )

find_package(OpenSSL)
target_link_libraries(shared
  OpenSSL::SSL
  )

add_executable(des_encrypt
  "src/des_encrypt.c"
  )

target_link_libraries(des_encrypt
  shared
  )


add_executable(des_decrypt
  "src/des_decrypt.c"
  )

target_link_libraries(des_decrypt
  shared
  )

add_executable(aes_encrypt
  "src/aes_encrypt.c"
  )

target_link_libraries(aes_encrypt
  shared
  )

add_executable(aes_decrypt
  "src/aes_decrypt.c"
  )

target_link_libraries(aes_decrypt
  shared
  )
