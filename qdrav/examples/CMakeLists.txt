build_lib_example(
  NAME arprl
  SOURCE_FILES arprl.cc
  LIBRARIES_TO_LINK
    ${libwifi}
    ${libinternet}
    ${libarprl}
    ${libinternet-apps}
)
