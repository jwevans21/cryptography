add_executable(tests 
    SHA1.cc SHA2.cc)
target_link_libraries(tests gtest_main jwevans_crypto)
gtest_add_tests(TARGET  tests)