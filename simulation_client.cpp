#include "pir_client.cpp"
#include "simulation_common.cpp"

int pir_request(string dbts,char *decoded_buf,size_t *sep_idxs) {
    char negotiate_outbuf[NEGOTIATE_LEN],negotiate_inbuf[NEGOTIATE_LEN];
    send_t *send = simulation_send;
    recv_t *recv = simulation_recv;
    int n_decoded_bytes,*req_idxs;
    negotiate_response_t *resp = new negotiate_response_t;
    negotiate_request_t *req = new negotiate_request_t;
    request_profile_t *prof = new request_profile_t;
    init_req(req,tordir,prof);
    pirdb_t dbt = parse_dbt(dbts);
    if (! pir_client_negotiate(send,recv,req,resp,prof)) {
        return -1;
    }
    req_idxs = (int*) malloc(sizeof(int) * resp->N_req); 
    if (random_selection(req_idxs,resp->N_db,resp->N_req) < 0) {
        return -1;
    }
    cout << "Client finished negotiation and selection." << endl;
    sep_idxs = (size_t*) malloc(sizeof(size_t) * resp->N_req);
    if (resp->opts.algo == PIR_XPIR) {
        n_decoded_bytes = xpir_request(req_idxs,req,resp,send,recv,decoded_buf,sep_idxs,prof);
    }
    log_request_profile(prof,&(resp->opts));
    free(req_idxs);
    return n_decoded_bytes;
}

int main(int argc,char **argv) {
    string command;
    int sock,ret,n_bytes,i,n_decoded_bytes;
    size_t *sep_idxs;
    struct sockaddr_in addr;
    char buf[INDEFINITE_SIZE],*decoded_buf;
    std::set<string> pir_commands = {"pir microdesc","pir desc","pir dirserv"},full_commands = {"full microdesc","full desc","full dirserv"},commands;
    set_union(pir_commands.begin(),pir_commands.end(),
              full_commands.begin(),full_commands.end(),
              inserter(commands,commands.begin()));
    X509 *cert;
    EVP_PKEY *key;
    BIO *certbio,*outbio; 
    if (SSL_library_init() < 0) {
        cerr << "couldn't init ssl\n" << endl;
    }
    SSL_load_error_strings();
    certbio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout,BIO_NOCLOSE);
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    const SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    sock = socket(AF_INET,SOCK_STREAM,0);
    if (sock < 0) {
        cerr << "failed to make socket" << endl;
        return EXIT_FAILURE;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(sock,(struct sockaddr *)&addr,sizeof(struct sockaddr_in)) < 0) {
       cerr << "Failed to connect" << endl;
        return EXIT_FAILURE;
    }
    ssl = SSL_new(ctx);
    if (! ssl) {
        cerr << "SSL_new failed" << endl;
        return EXIT_FAILURE;
    }
    SSL_set_fd(ssl,sock);
    ret = SSL_connect(ssl);
    if (ret == 1) {
        cert = SSL_get_peer_certificate(ssl);
        if (cert != NULL) {

        }
        else {
            cerr << "server did not give certificate" << endl;
        }
    }
    else {
        cerr << "SSL connect failed. " << SSL_get_error(ssl,ret) << endl;
        return EXIT_FAILURE;
    }
    while (1) {
        cout << "Give a command {full,pir} {microdesc,desc,dirserv}" << endl;
        getline(cin,command);
        if (commands.find(command) == commands.end()) {
            cerr << "Command not understood" << endl;
            continue;
        }
        strcpy(cmd_buf,command.c_str());
        vector<string> cmdparts;
        ::split(command,' ',cmdparts); 
        SSL_write(ssl,cmd_buf,CMD_LEN);
        if (pir_commands.find(command) != pir_commands.end()) {
            n_decoded_bytes = pir_request(cmdparts[1],decoded_buf,sep_idxs);
        }
        else {
            n_bytes = simulation_recv(buf,INDEFINITE_SIZE);
            if (n_bytes > 0) {
                cout << "Downloaded " << n_bytes << endl;
                cout << "First line: ";
                for(i=0;buf[i] != '\n';++i) {
                    putchar(buf[i]);
                }
                cout << endl;
            }
        }
    }
    SSL_shutdown(ssl);
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    free(decoded_buf);
    free(sep_idxs);
    return EXIT_SUCCESS;
}
