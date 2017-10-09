#include <cstdlib>
#include <set>
#include "pir_server.cpp"
#include "simulation_common.cpp"

const char *rsa_cert = "/home/aseewald/server.crt";
const char *rsa_key = "/home/aseewald/server.key";
const char *rsa_ca_cert = "/home/aseewald/ca.crt";

int cleanup(int err,SSL_CTX *ctx,int sock) {
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup(); 
    return err;
}

int pir_respond(string dbts) {
    pirdb_t dbt = parse_dbt(dbts);
}

int readfile(char *buf,FILE *f) {
    int len;
    return len;
}

string get_fname(pirdb_t dbt) {
    string fname;
    if (dbt == DESC) {
         fname = "cached-descriptors";
    }
    else if (dbt == MICRODESC) {
        fname = "cached-microdesc";
    }
    else if (dbt == CONSENSUS_MICRODESC) {
        fname = "cached-microdesc-consensus";
    }
    return fname;
}

int full_upload(string dbts) {
    pirdb_t dbt = parse_dbt(dbts);
    char *buf;
    long len,n;
    pir_opts junk;
    string fname = get_fname(dbt);
    FILE *f = fopen(fname.c_str(),"r");
    if (f == NULL) {
        cerr << "File " << fname << " requested but does not exist." << endl;
        exit(EXIT_FAILURE);
    }
    fseek(f,0,SEEK_END);
    len = ftell(f);
    fseek(f,0,SEEK_SET);
    if (buf = (char*) malloc(len)) {
        fread(buf,sizeof(char),len,f);
    } 
    else {
        cerr << "Failed to read file" << endl;
        return -1;
    }
    fclose(f);
    if (len > 0) {
        n = simulation_send(buf,-1);
        if (n > 0) {
            cout << "wrote " << n << "bytes to client" << endl;
            return 0;
        }
        else {
            cout << "failed to write" << endl;
            return -1;
        }
    }
    else {
        cerr << "File is empty" << endl;
        return -1;
    }
}


// ./simulation_server <n>
int main(int argc,char **argv) {
    send_t *send;
    recv_t *recv;
    int sock,client,ret;
    response_profile_t *prof = new response_profile_t;
    negotiate_response_t *resp = new negotiate_response_t;
    negotiate_request_t *req = new negotiate_request_t;
    db_src src;
    src.meaning = MEANING_FILENAME;
    src.n = argc < 2 ? 1 : std::stoi(argv[1]);
    init_paths(tordir);
    init_resp(resp,tordir,prof);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    struct sockaddr_in srv_addr,client_addr;
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(PORT);
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    sock = socket(AF_INET,SOCK_STREAM,0);
    unsigned int len;

    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        cerr << "Unable to create SSL ctx" << endl;
        return cleanup(1,ctx,sock);
    }
    if (SSL_CTX_use_certificate_file(ctx,rsa_cert,SSL_FILETYPE_PEM) <= 0) {
        cerr << "Failed to get certificate" << endl;
        return EXIT_FAILURE;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx,rsa_key,SSL_FILETYPE_PEM) <= 0) {
        cerr << "Failed to get private key" << endl;
        return EXIT_FAILURE;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        cerr << "key and certificate do not match" << endl;
        return EXIT_FAILURE;
    }
    if (sock < 0) {
        cerr << "Unable to make socket" << endl;
        return cleanup(2,ctx,sock);
    }
    if (::bind(sock,(struct sockaddr*) &srv_addr, sizeof(srv_addr)) < 0) {
        cerr << "Unable to bind socket to addr" << endl;
        return cleanup(3,ctx,sock);
    }
    if (listen(sock,1) < 0) {
        cerr << "Unable to listen" << endl;
        return cleanup(4,ctx,sock);
    }
    cout << "Waiting for client" << endl;
    client = accept(sock,(struct sockaddr*)&client_addr,&len);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl,client); 
    if ((ret = SSL_accept(ssl)) != 1) {
        cerr << "Handshake error " << SSL_get_error(ssl,ret) << endl;
        return EXIT_FAILURE;
    }
    while (1) {
        // read a command.
        cout << "Waiting for a command..." << endl;
        SSL_read(ssl,cmd_buf,CMD_LEN);
        string cmd(cmd_buf);
        vector<string> cmdparts;
        ::split(cmd,' ',cmdparts); 
        if (cmdparts[0] == "full" || cmdparts[0] == "f") {
            full_upload(cmdparts[1]);
        }
        else if (cmdparts[0] == "pir" || cmdparts[0] == "p") {
            prof = new response_profile_t;
            send = &simulation_send;
            recv = &simulation_recv;
            string fn = get_fname(req->dbt).c_str();
            src.s = (char*) malloc(fn.size() + 1);
            strcpy(src.s,fn.c_str());
            pir_server_negotiate(send,recv,resp,req,src,prof);
            if (resp->opts.algo == PIR_XPIR) {
                xpir_respond(req,resp,send,recv,prof);
            }
            log_response_profile(prof,&(resp->opts));
            free(src.s);
        }
        else {
            cout << "Didn't understand command " << cmd << " continuing" << endl;
        }
    }
    SSL_free(ssl);
    close(client);
    return cleanup(0,ctx,sock); 
}
