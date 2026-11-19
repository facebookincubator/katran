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

katran_add_test(TARGET machelpers-tests
  SOURCES
  MacHelpersTest.cpp
  DEPENDS
  mac_helpers
)

katran_add_test(TARGET netlink-tests
  SOURCES
  NetlinkTest.cpp
  DEPENDS
  bpfadapter
)

katran_add_test(TARGET pipewriter-tests
  SOURCES
  PipeWriterTest.cpp
  DEPENDS
  pcapwriter
)

katran_add_test(TARGET murmurhash3-test
  SOURCES
  MurmurHash3Test.cpp
  DEPENDS
  murmur3
)

katran_add_test(TARGET datawriter-tests
  SOURCES
  DataWriterTest.cpp
  DEPENDS
  pcapwriter
)

katran_add_test(TARGET pcapmsg-tests
  SOURCES
  PcapMsgTest.cpp
  DEPENDS
  pcapwriter
)

katran_add_test(TARGET katransimulatorutils-tests
  SOURCES
  KatranSimulatorUtilsTest.cpp
  DEPENDS
  katransimulator
)

katran_add_test(TARGET maglevbase-tests
  SOURCES
  MaglevBaseTest.cpp
  DEPENDS
  chhelpers
)

katran_add_test(TARGET monitoringstructs-tests
  SOURCES
  MonitoringStructsTest.cpp
  DEPENDS
  pcapwriter
)

katran_add_test(TARGET maglevhash-tests
  SOURCES
  MaglevHashTest.cpp
  DEPENDS
  chhelpers
)

katran_add_test(TARGET katran-event-reader-tests
  SOURCES
  KatranEventReaderTest.cpp
  DEPENDS
  katranlb
)
