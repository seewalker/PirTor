struct directory_request_t {
  /**
   * These fields specify which directory we're contacting.  Routerstatus,
   * if present, overrides the other fields.
   *
   * @{ */
  tor_addr_port_t or_addr_port;
  tor_addr_port_t dir_addr_port;
  char digest[DIGEST_LEN];

  const routerstatus_t *routerstatus;
  /** @} */
  /** One of DIR_PURPOSE_* other than DIR_PURPOSE_SERVER. Describes what
   * kind of operation we'll be doing (upload/download), and of what kind
   * of document. */
  uint8_t dir_purpose;
  /** One of ROUTER_PURPOSE_*; used for uploads and downloads of routerinfo
   * and extrainfo docs.  */
  uint8_t router_purpose;
  /** Enum: determines whether to anonymize, and whether to use dirport or
   * orport. */
  dir_indirection_t indirection;
  /** Alias to the variable part of the URL for this request */
  const char *resource;
  /** Alias to the payload to upload (if any) */
  const char *payload;
  /** Number of bytes to upload from payload</b> */
  size_t payload_len;
  /** Value to send in an if-modified-since header, or 0 for none. */
  time_t if_modified_since;
  /** Hidden-service-specific information */
  const rend_data_t *rend_query;
  /** Extra headers to append to the request */
  config_line_t *additional_headers;
  /** */
  /** Used internally to directory.c: gets informed when the attempt to
   * connect to the directory succeeds or fails, if that attempt bears on the
   * directory's usability as a directory guard. */
  circuit_guard_state_t *guard_state;

  // NOW THE PART THAT I ADD.
};
