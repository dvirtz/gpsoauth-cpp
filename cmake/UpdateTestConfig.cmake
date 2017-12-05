file(READ test/config.yml TEST_CONFIG)
string(REPLACE "email:" "email: $ENV{GE_TEST}" TEST_CONFIG "${TEST_CONFIG}")
string(REPLACE "password:" "password: $ENV{GP_TEST}" TEST_CONFIG "${TEST_CONFIG}")
file(WRITE test/config.yml ${TEST_CONFIG})