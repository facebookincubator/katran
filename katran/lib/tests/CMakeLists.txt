# find libraries
find_library(CHHELPERS chhelpers)
find_path(CHHELPERS_INCLUDE_DIR chhelpers)
include(KatranTest)

katran_add_test(TARGET iphelpers-tests
  SOURCES
  IpHelpersTest.cpp
  DEPENDS
  iphelpers
  ${GTEST}
  ${PTHREAD}
  "Folly::folly"
)

katran_add_test(TARGET chhelpers-tests
  SOURCES
  CHHelpersTest.cpp
  DEPENDS
  katranlb
  ${GTEST}
  ${PTHREAD}
)

katran_add_test(TARGET libkatran-tests
  SOURCES
  KatranLbTest.cpp
  DEPENDS
  katranlb
  ${GTEST}
  ${PTHREAD}
  "Folly::folly"
)

katran_add_test(TARGET vip-tests
  SOURCES
  VipTest.cpp
  DEPENDS
  katranlb
  ${GTEST}
  ${PTHREAD}
  "Folly::folly"
)
