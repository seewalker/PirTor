
// This is run before the directory cache is listening.
int prepare_db_tor( ) {
  smartlist_t *nodes = smartlist_new();
  smartlist_add_all(nodes, nodelist_get_list());
  char *dname = "/tmp/pirtorXXXXXX";
  int i=0;
  or_options_t opt = get_options();
  SMARTLIST_FOREACH_BEGIN(nodes, node_t *, node) {
    const char *msg = NULL;
    routerinfo_t *ent = node->ri;
    char description[NODE_DESC_BUF_LEN];
    uint32_t r;
    if (!ent)
      continue;
    r = dirserv_router_get_status(ent, &msg, LOG_INFO);
    router_get_description(description, ent);
    serialize_node(i,node);
    ++i;
  } SMARTLIST_FOREACH_END(node);
  smartlist_free(nodes);
}


// Listen to what client says the params should be and accept or reject.
int negotiate_pir_server( ) {
    or_options_t options = get_options();
    // This can add a textual reason for rejecting if PIR algos or params are not compatible.
    write_http_status_line( );
}

// What to say about self as directory server.
int publish_server_stats( ) {

}
