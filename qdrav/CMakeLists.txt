build_lib(
  LIBNAME qdrav
  SOURCE_FILES
    helper/qdrav-helper.cc
    model/qdrav-dpd.cc
    model/qdrav-id-cache.cc
    model/qdrav-neighbor.cc
    model/qdrav-packet.cc
    model/qdrav-routing-protocol.cc
    model/qdrav-rqueue.cc
    model/qdrav-rtable.cc
    model/qdrav-qtable.cc
    model/qdrav-route-quality-table.cc
  HEADER_FILES
    helper/qdrav-helper.h
    model/qdrav-dpd.h
    model/qdrav-id-cache.h
    model/qdrav-neighbor.h
    model/qdrav-packet.h
    model/qdrav-routing-protocol.h
    model/qdrav-rqueue.h
    model/qdrav-rtable.h
    model/qdrav-qtable.h
    model/qdrav-route-quality-table.h
  LIBRARIES_TO_LINK ${libinternet}
                    ${libwifi}
  TEST_SOURCES
    
)
