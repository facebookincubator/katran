katran_add_test(TARGET iphelpers-tests
  SOURCES
  IpHelpersTest.cpp
  DEPENDS
  iphelpers
)

katran_add_test(TARGET chhelpers-tests
  SOURCES
  CHHelpersTest.cpp
  DEPENDS
  katranlb
)

katran_add_test(TARGET libkatran-tests
  SOURCES
  KatranLbTest.cpp
  DEPENDS
  katranlb
)

katran_add_test(TARGET vip-tests
  SOURCES
  VipTest.cpp
  DEPENDS
  katranlb
)

katran_add_test(TARGET eventpipe-callback-test
  SOURCES
  EventPipeCallbackTest.cpp
  DEPENDS
  katranlb
)

katran_add_test(TARGET monitoring-service-core-test
  SOURCES
  MonitoringServiceCoreTest.cpp
  DEPENDS
  katranlb
)

katran_add_test(TARGET pcap-writer-test
  SOURCES
  PcapWriterTest.cpp
  DEPENDS
  katranlb
)
