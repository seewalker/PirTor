#ifndef PIR_SERVER
#define PIR_SERVER
#include "pir_common.cpp"
#include <math.h>
#include <map>
#include <algorithm>
#include <stdarg.h>
#ifdef DEBUG
#include "pir_client.cpp"
#else
const bool CHATTY = true;
#endif

// where external programs being called live.
char *pir_program_path;
// where database exists.
char *pir_db_path;

long max_item_size(const char *dbdir) {
    string d = dbdir,fname;
    FILE *f;
    DIR *dir;
    struct dirent *ent;
    long len,max_bytes=0; //takes away the counting of "." and "..".
    if ((dir = opendir(dbdir)) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name,".") == 0 || strcmp(ent->d_name,"..") == 0) {
                continue;
            }
            fname = d + "/" + ent->d_name;
            f = fopen(fname.c_str(),"rb");
            if (f == NULL) {
                fclose(f); continue;
            }
            fseek(f,0,SEEK_END);
            len = ftell(f);
            if (len < 0) {
                fclose(f); continue;
            }
            max_bytes = std::max(max_bytes,len); 
            fclose(f);
        }
    }
    closedir(dir);
    return max_bytes;
}

int init_paths(const char *tordir) {
    string config_fname(tordir);
    int i;
    config_fname += "/config.yaml";
    YAML::Node config = YAML::LoadFile(config_fname)["paths"];
    string prp = config["programs"].as<string>(),dbp = config["db"].as<string>();
    pir_program_path = (char*) malloc(prp.size());
    // more memory than necessary, because I'll be concatenating a bit later.
    pir_db_path = (char*) malloc(dbp.size() + 12);
    strcpy(pir_program_path,prp.c_str());
    strcpy(pir_db_path,dbp.c_str());
    cout << "Parsed paths from configuration successfully." << endl;
}


// The tor files which I end up changing should be #ifdef PIRTOR gaurded around including this stuff.
extern "C" int mkdb_from_file(pirdb_t dbt,const char *fname,const char *db_path,int n) {
    int ret;
    char cmd[256];
    if (n != 1) {
        cout << " " << endl;
    }
    if (dbt == MICRODESC) {
        sprintf(cmd,"python %s/parse_microdesc.py %s %s --n_copies %d",pir_program_path,fname,db_path,n);
    }
    else if (dbt == DESC) {
        sprintf(cmd,"python %s/parse_desc.py %s %s --n_copies %d",pir_program_path,fname,db_path,n);
    }
    else if (dbt == CONSENSUS_MICRODESC) {
        sprintf(cmd,"python %s/parse_consensus.py %s %s --n_copies %d",pir_program_path,fname,db_path,n);
    }
    cout << "Making database with command: " << cmd << endl;
    ret = std::system(cmd);
    return ret;
}

extern "C" int mkdb(pirdb_t dbt,const char *db_path,db_src src) {
    int n,ret=-1,fd;
    va_list ap;
    char *db_str,*tmp_name = "pirdbXXX";
    FILE *f;
    if (src.meaning == MEANING_FILENAME) {
        ret = mkdb_from_file(dbt,src.s,db_path,src.n);
    }
    else if (src.meaning == MEANING_DATA) {
        fd = mkostemp(tmp_name,O_CREAT);
        f = fdopen(fd,"w");
        fputs(src.s,f);
        ret = mkdb_from_file(dbt,tmp_name,db_path,src.n);
        fclose(f);
    }
    else {
        ret = -1;
    }
    return ret;
}

// overwrites server.
int pir_opts_intersect(pir_opts &client,pir_opts &server) {
    // this max,argmax distinction will fix the selection of best.
    int i,j,max_algo=-1,argmax_algo=-1,max_crypto=-1,argmax_crypto,priority;
    for (i=0;i<N_PIR_ALGOS;++i) {
        priority = client.algos[i];
        if (priority > max_algo && server.algos[i] > 0) {
            max_algo = priority;
            argmax_algo = i;
        }
    }
    if (max_algo >= 0) {
        cout << "best algo found and is " << (pir_algo) argmax_algo << endl; 
    }
    else {
        server.agreed = 0;
        strcat(server.disagree_reason,"No intersection of algorithms\t");
        return -1;
    }
    server.algo = (pir_algo) argmax_algo;
    if (server.algo == PIR_XPIR) {
        xpir_policy policy = client.policy.x_policy;
        // agree on crypto method.
        for(i=0;i<N_XPIR_CRYPTO;++i) {
            priority = client.crypto_priorities.xmeth[i];
            if (priority > max_crypto && server.crypto_priorities.xmeth[i] > 0) {
                max_crypto = priority;
                argmax_crypto = i;
            }
        }
        xpir_policy x_pol = client.policy.x_policy;
        xpir_opts client_up = client.upper_opts.xpir,server_up=server.upper_opts.xpir,client_lo=client.lower_opts.xpir,server_lo=server.lower_opts.xpir;
        if (client_up.alpha < server_lo.alpha) {
            strcat(server.disagree_reason,"Client requires higher alpha.\t");
        }
        else if (client_lo.alpha > server_up.alpha) {
            strcat(server.disagree_reason,"Client requires lower alpha.\t");
        }
        else {
            if (x_pol.alpha == INTERSECT_MAX) {
                server.lower_opts.xpir.alpha = std::min(client_up.alpha,server_up.alpha);
            }
            else {
                server.lower_opts.xpir.alpha = std::max(client_lo.alpha,server_lo.alpha); 
            }
        }
        // setting d or failing.
        if (client_up.d < server_lo.d) {
            strcat(server.disagree_reason,"Client requires higher d.\t");
        }
        else if (client_lo.d > server_up.d) {
            strcat(server.disagree_reason,"Client requires lower d.\t");
        }
        else {
            if (x_pol.d == INTERSECT_MAX) {
                server.lower_opts.xpir.d = std::min(client_up.d,server_up.d);
            }
            else {
                server.lower_opts.xpir.d = std::max(client_lo.d,server_lo.d); 
            }
        }
        for (i=1;i<MAX_REC_LVL;++i) {
            if (i > server.lower_opts.xpir.d) {
                server.lower_opts.xpir.n[i] = 0;
            }
            else {
                if (x_pol.d == INTERSECT_MAX) {
                    server.lower_opts.xpir.n[i] = std::min(client_up.n[i],server_up.n[i]); 
                } 
                else {
                    server.lower_opts.xpir.n[i] = std::max(client_lo.n[i],server_lo.n[i]);
                }
            }
        }
        lwe_policy l_policy;
        lwe_args l_client_up,l_server_up,l_client_lo,l_server_lo;
        server.crypto.xmeth = (xpir_crypto_method) argmax_crypto;
        switch (server.crypto.xmeth) {
            case XPIR_LWE :
                l_policy = *x_pol.lp;
                l_client_up = client_up.l_args;
                l_server_up = server_up.l_args;
                l_client_lo = client_lo.l_args;
                l_server_lo = server_lo.l_args;
                if (l_client_up.security_bits < l_server_lo.security_bits) {
                    strcat(server.disagree_reason,"Client requires fewer security bits.\t");
                }
                else if (l_client_lo.security_bits > l_server_up.security_bits) {
                    strcat(server.disagree_reason,"Client requires more security bits.\t");
                }
                else { 
                    if (l_policy.security_bits == INTERSECT_MAX) {
                        server.lower_opts.xpir.l_args.security_bits = std::min(l_client_up.security_bits,l_server_up.security_bits); 
                    }
                    else {
                        server.lower_opts.xpir.l_args.security_bits = std::max(l_client_lo.security_bits,l_server_lo.security_bits); 
                    }
                }
                if (l_client_up.poly_degree < l_server_lo.poly_degree) {
                    strcat(server.disagree_reason,"Client requires lower poly degree.\t");
                }
                else if (l_client_lo.poly_degree > l_server_up.poly_degree) {
                    strcat(server.disagree_reason,"Client requires greater poly degree.\t");
                }
                else { 
                    if (l_policy.poly_degree == INTERSECT_MAX) {
                        server.lower_opts.xpir.l_args.poly_degree = std::min(l_client_up.poly_degree,l_server_up.poly_degree); 
                    }
                    else {
                        server.lower_opts.xpir.l_args.poly_degree = std::max(l_client_lo.poly_degree,l_server_lo.poly_degree); 
                    }
                }
                if (l_client_up.poly_coeff_bits < l_server_lo.poly_coeff_bits) {
                    strcat(server.disagree_reason,"Client requires lower aggregated modulus bitsize.\t");
                }
                else if (l_client_lo.poly_coeff_bits > l_server_up.poly_coeff_bits) {
                    strcat(server.disagree_reason,"Client requires greater aggregated modulus bitsize.\t");
                }
                else { 
                    if (l_policy.poly_coeff_bits == INTERSECT_MAX) {
                        server.lower_opts.xpir.l_args.poly_coeff_bits = std::min(l_client_up.poly_coeff_bits,l_server_up.poly_coeff_bits); 
                    }
                    else {
                        server.lower_opts.xpir.l_args.poly_coeff_bits = std::max(l_client_lo.poly_coeff_bits,l_server_lo.poly_coeff_bits); 
                    }
                }
                break;
            case XPIR_PAILIER :
                break;
            default:
                break;
        }
    }
    else if (server.algo == PIR_AG) {
        // agree on crypto method.
        for(i=0;i<N_AG_CRYPTO;++i) {
            for(j=0;j<N_AG_CRYPTO;++j) {
                priority = client.crypto_priorities.ameth[i];
                if (priority > max_crypto && server.crypto_priorities.ameth[i] > 0) {
                    max_crypto = priority; 
                    argmax_crypto = i;
                }
            }
        }
        client.crypto.ameth = (ag_crypto_method) argmax_crypto;
    }
    // Server overwrites lower_opts and points agreed_opts to lower_opts, now that its meaning is the consensus and not 
    server.agreed_opts = server.agreed ? &server.lower_opts : NULL;
    return 0;
}

int get_db_n(pirdb_t dbt,const char *d) {
    DIR *dir;
    struct dirent *ent;
    int i=-2; //takes away the counting of "." and "..".
    if ((dir = opendir(d)) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            ++i;
        }
    }
    closedir(dir);
    return i;
}

extern "C" int pir_server_negotiate(send_t send,recv_t recv,negotiate_response_t *resp,negotiate_request_t *req,db_src src,response_profile_t *prof) {
    char recvbuf[NEGOTIATE_LEN],*resp_buf;
    int junk,n,nreq_overlap,nreq_sufficient,agreed=1;
    size_t resp_buf_len;
    char dbdir[256];
    // currently halting here.
    recv(recvbuf,-1);
    agreed &= deserialize_pir_request(req,recvbuf);
    // intersect according to client's policy subject to server's constraints, setting disagree reason accordingly if disagreeing.
    pir_opts_intersect(req->opts,resp->opts);
    strcpy(dbdir,pir_db_path);
    if (req->dbt == DESC) {
        strcat(dbdir,"/desc");
    }
    else if (req->dbt == MICRODESC) {
        strcat(dbdir,"/microdesc");
    }
    // make the database.
    if (! file_exists(pir_db_path)) {
        resp->N_db = mkdb(req->dbt,dbdir,src);
    }
    else {
        n = get_db_n(req->dbt,dbdir);
        resp->N_db = n <= 0 ? mkdb(req->dbt,dbdir,src) : n;
    }
    nreq_overlap = req->N_req_lo <= resp->N_req_hi;
    nreq_sufficient = req->N_req_lo <= resp->N_db;
    if (nreq_overlap && nreq_sufficient) {
        resp->N_req = std::min(resp->N_req_hi,req->N_req_hi);
    }
    else {
        agreed = 0;
        if (nreq_overlap) {
            strcat(resp->opts.disagree_reason,"No overlap between nreq bounds\t");
        }
        if (nreq_sufficient) {
            strcat(resp->opts.disagree_reason,"nreq less than number of entries in db\t");
        }
    }
    resp->opts.agreed = agreed;
    resp->max_item_size = max_item_size(dbdir);
    serialize_pir_response(resp,&resp_buf,&resp_buf_len,0);
    send(resp_buf,-1);
}

// LWE parameter string is of form "LWE:<security_bits>:<poly_degree>:<aggregatedModulusBitsize>"
/*
Error codes:
    E_RANGE : 
*/

int not_all_found(set<int> found,int n) {
    int i;
    for(i=0;i<n;++i) {
       if (found.find(n-1-i) == found.end()) {
            return 1;
       }
    }
    return 0;
}

// a relational-style tsv file.
extern "C" void log_response_profile(const response_profile_t *prof,const pir_opts *opts) {
    FILE *f = fopen(prof->fname,"a"); 
    ostringstream oss;
    flock(fileno(f),LOCK_EX);
    log_line(oss,"total",prof->total,opts);
    log_line(oss,"db_load",prof->db_load,opts);
    log_line(oss,"query_recv",prof->query_recv,opts);
    log_line(oss,"response_send",prof->response_send,opts);
    log_line(oss,"generate_reply",prof->generate_reply,opts);
    log_line(oss,"mkdb",prof->mkdb,opts);
    fclose(f);
}

extern "C" int xpir_respond(negotiate_request_t *req,negotiate_response_t *resp,send_t send,recv_t recv,response_profile_t *prof) {
    clock_t t0,t1;
    size_t query_chars=0,qbsize,n_bytes;
    int i,j,n_replies;
    char *response_buf,*pop_buf;
    char dbdir[128],buf[128];
    vector<vector<char*>> query_bufs(resp->N_req);
    vector<char*> response_bufs;
    PIRParameters params;
    PIRReplyGenerator *r_generator;
    imported_database *idb;

    t0 = clock(); //get time at beginning of function.
    strcpy(dbdir,pir_db_path);
    // trailing "/" here actually necessary for xpir database to work.
    if (req->dbt == DESC) {
        strcat(dbdir,"/desc/");
    }
    else if (req->dbt == MICRODESC) {
        strcat(dbdir,"/microdesc/");
    }
    // set cryptographic params
    params.alpha = resp->opts.lower_opts.xpir.alpha;
    params.d = resp->opts.lower_opts.xpir.d;
    format_xpir_crypto(buf,resp->opts.lower_opts.xpir);
    params.crypto_params = buf;
    params.n[0] = (int) ceil((double) resp->N_db / (double) params.alpha);
    for(i=1;i<MAX_REC_LVL;++i) {
       params.n[i] = resp->opts.lower_opts.xpir.n[i];
    }
    HomomorphicCrypto *crypto = HomomorphicCryptoFactory::getCryptoMethod(params.crypto_params);
    crypto->setandgetAbsBitPerCiphertext(params.n[0]);
    t1 = clock();
    // initialize database.
    DBDirectoryProcessor db(dbdir);
    prof->db_load = clock() - t1;
    for (i=0;i<resp->N_req;++i) {
        try {
            query_bufs[i] = consume_concat(recv);
        }
        catch (const std::runtime_error &e) {
            cerr << e.what() << endl;
            return -1;
        }
        if (CHATTY) { cout << "Got all queries for i = " << i << endl;}
        if (i > 0) {
            if (query_bufs[i].size() != query_bufs[i-1].size()) {
                cerr << "WARNING: query_bufs size not matching" << endl;
            }
        }
    }
    i = 0;
    r_generator = new PIRReplyGenerator(params,*crypto,&db);
    idb = r_generator->importData(0,db.getmaxFileBytesize());
    for (auto query_buf : query_bufs) {
        delete r_generator; 
        r_generator = new PIRReplyGenerator(params,*crypto,&db);
        r_generator->freeQueries();
        for (auto q : query_buf) {
            r_generator->pushQuery(q);
        }
        t1 = clock();
        r_generator->generateReply(idb);
        n_replies = 0;
        prof->generate_reply += clock() - t1;
        if (CHATTY) { cout << "generated " << n_replies << " replies for response " << i << endl; }
        while (r_generator->popReply(&pop_buf)) {
            response_bufs.push_back(pop_buf);
            ++n_replies;
        }
        if (n_replies != r_generator->getnbRepliesGenerated()) {
            cerr << "WARNING, unexpected reply count" << endl;
        }
        response_buf = concat_batch(response_bufs,&n_bytes);
        t1 = clock();
        send(response_buf,n_bytes);
        prof->response_send += clock() - t1;
        if (CHATTY) { cout << "server sent replies for query " << i << endl; }
        for (auto &b : response_bufs) {
            free(b);
        }
        for (auto &q : query_buf) {
            free(q);
        }
        response_bufs.clear();
        ++i;
    }
    prof->total = clock() - t0;
    return 0;
}

extern "C" int ag_respond( ) {

}
#endif
