#ifndef PIR_COMMON
#define PIR_COMMON
#include <iostream>
#include <string>
#include <set>
#include <iterator>
#include <sys/file.h>
#include "pir_common.h"
#include "pir_compress.h"
#include "yaml-cpp/yaml.h"
#include "or.h"
#include "libpir.hpp"

// header_bytes is maximum size of small formatted header used in pir queries.
#define HEADER_BYTES 24
#define MAX_ROUTER_BYTES 4096
#define DEFAULT_DBDIR "~/.tor/pirdb"

using namespace std;

// issue : the new meaning of n should end up being multiplied by number of elements in database.

// UTILITIES
bool file_exists(const char *fname) {
    std::ifstream infile(fname);
    return infile.good();
}



void split(const std::string &s, char delim, vector<string> &result) {
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        result.push_back(item);
    }
}

template <typename T>
int serialize_array(ostringstream &oss,T *arr,size_t n) {
    size_t i;
    if (n == 0) {
        oss << endl;
        return -1;
    }
    for(i=0;i<(n-1);++i) {
        oss << arr[i] << ",";
    }
    oss << arr[n-1] << endl;
    return 0;
}

int deserialize_array(istringstream &iss,int *arr) {
    size_t n=0;
    string line;
    vector<string> parts;
    getline(iss,line);
    ::split(line,',',parts);
    for (auto part : parts) {
        arr[n] = std::stoi(part);
        ++n;
    }
    return n;
}
void serialize_xpir_params(const char *which,ostringstream &oss,xpir_opts xopts,pir_opts opts) {
    oss << "BEGIN " << which << endl;
    oss << xopts.alpha << endl;
    oss << xopts.d << endl;
    serialize_array(oss,xopts.n,MAX_REC_LVL);
    oss << xopts.crypto_method << endl;
    oss << xopts.l_args.security_bits << endl;
    oss << xopts.l_args.poly_degree << endl;
    oss << xopts.l_args.poly_coeff_bits << endl;
    oss << xopts.p_args.security_bits << endl;
    oss << xopts.p_args.bitKeySize << endl;
    oss << xopts.p_args.ciphSize << endl;
    oss << "END " << which << endl;
}

void serialize_ag_params(const char *which,ostringstream &oss,ag_opts,pir_opts) {

}

// can't use boost struct serialize because this needs to be called from c functions as well, and I don't want to worry about boost version mismatches on client and server.
void serialize_xpir(ostringstream &oss,pir_opts opts) {
    oss << "BEGIN XPIR" << endl;
    serialize_xpir_params("lower",oss,opts.lower_opts.xpir,opts);
    serialize_xpir_params("upper",oss,opts.upper_opts.xpir,opts);
    // xmeth is currently the problem.
    serialize_array(oss,opts.crypto_priorities.xmeth,N_XPIR_CRYPTO);
    oss << opts.crypto.xmeth << endl;
    oss << "END XPIR" << endl;
}

void serialize_ag(ostringstream &oss,pir_opts opts) {
    oss << "BEGIN AG" << endl;
    serialize_ag_params("lower",oss,opts.lower_opts.ag,opts);
    serialize_ag_params("upper",oss,opts.upper_opts.ag,opts);
    serialize_array(oss,opts.crypto_priorities.ameth,N_AG_CRYPTO);
    oss << opts.crypto.ameth << endl;
    oss << "END AG" << endl;
}

// next thing to do.
int serialize_policy(ostringstream &oss,Policy policy,pir_opts opts) {
    // serialize xpir plicy.
    oss << "BEGIN POLICY" << endl;
    if (policy.x_policy.lp != NULL) {
        oss << "XPIR_LWE " << policy.x_policy.lp->security_bits << " " << policy.x_policy.lp->poly_degree << " " << policy.x_policy.lp->poly_coeff_bits << endl;
    }
    if (policy.x_policy.pp != NULL) {
        oss << "XPIR_PAILIER " << policy.x_policy.pp->security_bits << " " << policy.x_policy.pp->bitKeySize << " " << policy.x_policy.pp->ciphSize << endl;
    }
    // when doing ag, put it here.
    oss << "END POLICY" << endl;
}

// precondition : buf and repr exist in scope.
// postcondition : repr has good serialization, or return with failure.
#define compression_check(s) {\
     if (chunked_inflate(buf,repr,&repr_len) != Z_OK) {\
        repr = (char*) malloc(strlen(buf));\
        strcpy(repr,buf); \
        \
    } \
    else { \
        if (strstr(buf,s) == NULL) { \
            cerr << "Couldn't treat as compressed text, and still malformed" << endl;\
            return 1; \
        } \
        repr = (char*) malloc(strlen(buf));\
        strcpy(repr,buf); \
    } \
}

void log_params(ostringstream &oss,const pir_opts *opts) {

}

void log_line(ostringstream &oss,const char *desc,clock_t dt,const pir_opts *opts) {
    log_params(oss,opts);
    oss << desc << "\t" << dt << endl;
}

extern "C" int serialize_pir_opts(pir_opts opts,char **opt_buf,size_t *optbuf_len,int will_compress) {
    size_t oss_size;
    ostringstream oss;
    string oss_str;

    oss << opts.algo << endl;
    serialize_array(oss,opts.algos,N_PIR_ALGOS);
    serialize_policy(oss,opts.policy,opts);
    oss << opts.agreed << endl;
    oss << opts.disagree_reason << endl;
    if (opts.algo == PIR_XPIR) {
       serialize_xpir(oss,opts); 
    }
    else if (opts.algo == PIR_AG) {
       serialize_ag(oss,opts);
    }
    // more algos would be added here.
    else if (opts.algo == UNBOUND) {
        serialize_xpir(oss,opts);
        serialize_ag(oss,opts);
    // and here.
    }
    oss_str = oss.str();
    oss_size = oss_str.size();
    if (will_compress) {
        if (chunked_deflate(oss_str.c_str(),*opt_buf,optbuf_len,Z_DEFAULT_COMPRESSION) != Z_OK) { 
            cerr << "Failed to compress, so just putting uncompressed version in buffer"; 
            *opt_buf = (char*) malloc(oss_size);
            *optbuf_len = oss_size;
            strcpy(*opt_buf,oss_str.c_str());
        }
        else { 
        } 
    } 
    else {
        // this is officially not transfering over.
        *opt_buf = (char*) malloc(oss_size);
        strcpy(*opt_buf,oss_str.c_str()); 
        *optbuf_len = oss_size;
    }
    return 0;
//    compression_continuation(will_compress);
}


extern "C" int serialize_pir_response(negotiate_response_t *resp,char **outbuf,size_t *outbuf_len,short will_compress) {
    size_t optbuf_len,oss_size;
    char *opt_buf;
    // need to pass pointer to pointer because will malloc string.
    serialize_pir_opts(resp->opts,&opt_buf,&optbuf_len,0);
    ostringstream oss;
    oss << "PIR RESPONSE" << endl;
    oss << opt_buf << endl;
    oss << resp->N_db << endl;
    oss << resp->max_item_size << endl;
    oss << resp->N_req << endl;
    string oss_str = oss.str();
    oss_size = oss_str.size();
    if (will_compress) { 
        if (chunked_deflate(oss_str.c_str(),*outbuf,outbuf_len,Z_DEFAULT_COMPRESSION) != Z_OK) { 
            cerr << "Failed to compress, so just putting uncompressed version in buffer"; 
            *outbuf = (char*) malloc(oss_size);
            *outbuf_len = oss_size;
            strcpy(*outbuf,oss_str.c_str());
            return 0;
        } 
        else { 
            return 0;
        } 
    } 
    else { 
        *outbuf = (char*) malloc(oss_size);
        *outbuf_len = oss_size;
        strcpy(*outbuf,oss_str.c_str()); 
        return 0; 
    } 
}

// return code is whether or not did compression and it worked successfully.
extern "C" int serialize_pir_request(negotiate_request_t *req,char **outbuf,size_t *outbuf_len,short will_compress) {
    size_t optbuf_len;
    char *opt_buf;
    serialize_pir_opts(req->opts,&opt_buf,&optbuf_len,0);
    ostringstream oss;
    oss << "PIR REQUEST" << endl;
    oss << opt_buf << endl;
    oss << req->dbt << endl;
    oss << req->N_req_lo << endl;
    oss << req->N_req_hi << endl;
    string oss_str = oss.str();
    if (will_compress) { 
        if (chunked_deflate(oss_str.c_str(),*outbuf,outbuf_len,Z_DEFAULT_COMPRESSION) != Z_OK) { 
            cerr << "Failed to compress, so just putting uncompressed version in buffer"; 
            *outbuf = (char*) malloc(oss_str.size());
            strcpy(*outbuf,oss_str.c_str());
            return 0;
        } 
        else { 
            cout << "serialize_pir_request succeeded at compressing." << endl;
            return 0;
        } 
    } 
    else { 
        *outbuf = (char*) malloc(oss_str.size());
        strcpy(*outbuf,oss_str.c_str()); 
        return 0; 
    } 
    //compression_continuation(will_compress);
}


int deserialize_xpir_params(const char *which,istringstream &iss,pir_opts *opts) {
    string line;
    string wh(which);
    getline(iss,line);
    xpir_opts *xo = wh == "lower" ? &(opts->lower_opts.xpir) : &(opts->upper_opts.xpir);
    if (line != "BEGIN " + wh) {
        return 0; 
    }
    #define handle_err(err) { \
        cerr << err << endl; \
        return 0; \
    }
    try {
        getline(iss,line);
        xo->alpha = std::stoi(line);
        if (xo->alpha <= 0) {
            throw new std::domain_error("alpha should be >= 1");
        }
    }
    catch (std::domain_error &error) {
        handle_err(error.what());
    }
    catch (...) {
        const char *err = "Failed to parse alpha";
        handle_err(err);
    }
    try {
        getline(iss,line);
        xo->d = std::stoi(line);
        if (xo->d <= 0) {
            throw new std::domain_error("alpha should be >=1");
        }
    }
    catch (std::domain_error &error) {
        handle_err(error.what());
    }
    catch (...) {
        const char *err = "";
        handle_err(err);
    }
    deserialize_array(iss,xo->n); 
    try {
        getline(iss,line);
        xo->crypto_method = (xpir_crypto_method) std::stoi(line);
    }
    catch (...) {
        const char *err = "";
        handle_err(err);
    }
    try {
        getline(iss,line);
        xo->l_args.security_bits = std::stoi(line);
    }
    catch (...) {
        const char *err = "";
        handle_err(err);
    }
    try {
        getline(iss,line);
        xo->l_args.poly_degree = std::stoi(line);
    }
    catch (...) {
        const char *err = "";
        handle_err(err);
    }
    try {
        getline(iss,line);
        xo->l_args.poly_coeff_bits = std::stoi(line);
    }
    catch (...) {
        const char *err = "";
        handle_err(err);
    }
    try {
        getline(iss,line);
        xo->p_args.security_bits = std::stoi(line);
    }
    catch (...) {
        const char *err = "";
        handle_err(err);
    }
    try {
        getline(iss,line);
        xo->p_args.bitKeySize = std::stoi(line);
    }
    catch (...) {
        const char *err = "";
        handle_err(err);
    }
    try {
        getline(iss,line);
        xo->p_args.ciphSize = std::stoi(line);
    }
    catch (...) {
        const char *err = "";
        handle_err(err);
    }
    getline(iss,line);
    if (line != "END " + wh) {
        return 0; 
    }
    return 1;
}

//these two is what I need to do next.
int deserialize_xpir(istringstream &iss,pir_opts *opts) {
    string line;
    getline(iss,line);
    if (line != "BEGIN XPIR") {
        return 0;
    }
    if ( ! deserialize_xpir_params("lower",iss,opts)) {
        return 0;
    }
    if ( ! deserialize_xpir_params("upper",iss,opts)) {
        return 0;
    }
    deserialize_array(iss,opts->crypto_priorities.xmeth);
    getline(iss,line);
    opts->crypto.xmeth = (xpir_crypto_method) std::stoi(line);
    getline(iss,line);
    if (line != "END XPIR") {
        return 0;
    }
    return 1;
}

int deserialize_ag_params(const char *which,istringstream &iss,pir_opts *opts) {
    return 1;
}

int deserialize_ag(istringstream &iss,pir_opts *opts) {
    ag_opts lower,upper;
    string line;
    getline(iss,line);
    if (line != "BEGIN AG") {
        return 0;
    }
    if (! deserialize_ag_params("lower",iss,opts)) {
        return 0;
    }
    if (! deserialize_ag_params("upper",iss,opts)) {
        return 0;
    }
    deserialize_array(iss,opts->crypto_priorities.ameth);
    try {
        getline(iss,line);
        opts->crypto.ameth = (ag_crypto_method) std::stoi(line);
    }
    catch (...) {
        cerr << "Failed to parse ameth" << endl;
        return 0;
    }
    getline(iss,line);
    if (line != "END AG") {
        return 0;
    }
    return 1;
}

int deserialize_policy(istringstream &iss,pir_opts *opts) {
    string line;
    vector<string> parts;
    getline(iss,line);
    if (line != "BEGIN POLICY") {
        return 0;
    }
    getline(iss,line);
    while (line != "END POLICY") {
        ::split(line,' ',parts);
        if (line.find("XPIR_LWE") != std::string::npos) {
            if (opts->policy.x_policy.lp == NULL) {
                opts->policy.x_policy.lp = new lwe_policy;
            }
            opts->policy.x_policy.lp->security_bits = (intersect_t) std::stoi(parts[1]);
            opts->policy.x_policy.lp->poly_degree = (intersect_t) std::stoi(parts[2]);
            opts->policy.x_policy.lp->poly_coeff_bits = (intersect_t)  std::stoi(parts[3]);
        }
        else if (line.find("XPIR_PAILIER") != std::string::npos) {
            if (opts->policy.x_policy.pp == NULL) {
                opts->policy.x_policy.pp = new pailier_policy;
            }
            opts->policy.x_policy.pp->security_bits = (intersect_t) std::stoi(parts[1]);
            opts->policy.x_policy.pp->bitKeySize = (intersect_t) std::stoi(parts[2]);
            opts->policy.x_policy.pp->ciphSize = (intersect_t) std::stoi(parts[3]);
            
        }
        getline(iss,line);
    }
    return 1;
}

//returning 1 means success.
int deserialize_pir_opts(pir_opts *opts,istringstream &iss) {
    int ok = 1;
    string line;
    getline(iss,line);
    #define opt_catch_body(err) {\
        ok = 0;\
        strcat(opts->disagree_reason,err);\
        cerr << err;\
    }
    try {
        opts->algo = (pir_algo) stoi(line);
    }
    catch (...) {
        const char *err = "Failed to deserialize algo\n";
        opt_catch_body(err);
    }
    try {
        deserialize_array(iss,opts->algos);
    }
    catch (...) {
        const char *err = "Failed to deserialize algos";
        opt_catch_body(err);
    }
    deserialize_policy(iss,opts); 
    getline(iss,line);
    try {
        opts->agreed = stoi(line);
    }
    catch (...) {
        const char *err = "Failed to parse agreed";
        opt_catch_body(err);
    }
    getline(iss,line);
    try {
        strcpy(opts->disagree_reason,line.c_str());
    }
    catch (...) {
        const char *err = "Failed to parse disagree_reason\n";
        opt_catch_body(err);
    }
    if (opts->algo == PIR_XPIR) {
        const char *err = "Failed to parse xpir\n";
        if (!  deserialize_xpir(iss,opts)) {
            opt_catch_body(err);
        }
    }
    else if (opts->algo == PIR_AG) {
        const char *err = "Failed to parse ag\n";
        if ( ! deserialize_ag(iss,opts)) {
            opt_catch_body(err);
        }
    }
    else if (opts->algo == UNBOUND) {
        const char *err_x = "Failed to parse xpir\n";
        const char *err_a = "Failed to parse ag\n";
        if (! deserialize_xpir(iss,opts)) {
            opt_catch_body(err_x);
        }
        if (! deserialize_ag(iss,opts)) {
            opt_catch_body(err_a);
        }
    }
    else {
        const char *err = "malformed algo\n";
        opt_catch_body(err);
    }
    return ok;
}

extern "C" int deserialize_pir_request(negotiate_request_t *req,char *buf) {
    size_t repr_len;
    char *repr;
    string line;
    compression_check("PIR REQUEST");
    istringstream iss(repr);
    getline(iss,line);
    if (line != "PIR REQUEST") {
        cerr << "Malformed negotiate_request_t" << endl;
        return 0;
    }
    if (deserialize_pir_opts(&req->opts,iss) < 0) {
        cerr << "Failed to deserialize pir opts" << endl;
        return 0;
    }
    // here I'm getting a blank line.
    do {
        getline(iss,line);
    } while (line.size() == 0);
    try {
        req->dbt = (pirdb_t) std::stoi(line);
    }
    catch (...) {
        cerr << "Failed to parse dbt" << endl;
        return 0;
    }
    try {
        getline(iss,line);
        req->N_req_lo = std::stoi(line);
    }
    catch (...) {
        cerr << "Failed to parse N_req_lo" << endl;
        return 0;
    }
    try {
        getline(iss,line);
        req->N_req_hi = std::stoi(line);
    }
    catch (...) {
        cerr << "Failed to parse N_req_hi" << endl;
        return 0;
    }
    return 1;
}

extern "C" int deserialize_pir_response(negotiate_response_t *resp,char *buf) {
    size_t repr_len;
    char *repr;
    int ok;
    string line;
    istringstream iss(buf);
    compression_check("PIR RESPONSE");
    getline(iss,line);
    #define response_catch_body(err) {\
        ok = 0;\
        strcat(resp->opts.disagree_reason,err);\
        cerr << err;\
    }
    if (line != "PIR RESPONSE") {
        const char *err = "Malformed negotiation response\n";
        response_catch_body(err);
    }
    ok = deserialize_pir_opts(&resp->opts,iss);
    if (! ok) {
        cerr << "deserialize_pir_opts returned not okay, returning" << endl;
        return ok;
    };
    try {
        do {
            getline(iss,line);
        } while (line.size() == 0);
        resp->N_db = std::stoi(line);
    } 
    catch (...){
        const char *err = "Failed to parse N\n";
        response_catch_body(err);
    }
    try {
        getline(iss,line);
        resp->max_item_size = std::stoi(line);
    }
    catch (...){
        const char *err = "Failed to parse max_item_size\n";
        response_catch_body(err);
    }
    try {
        getline(iss,line);
        resp->N_req = std::stoi(line);
    }
    catch (...){
        const char *err = "Failed to parse N_req\n";
        response_catch_body(err);
    }
    return ok;
}

extern "C" int aggressive_serialize_node( ) {
    // use boost serialize to serialize the whole struct.
}


// initializing opts from config file.
int init_opts(pir_opts *opts,YAML::Node defaults,const char *tordir) {
    int i;
    YAML::Node lower,upper,meths,pol;
    lower = defaults["xpir"]["lower"];
    upper = defaults["xpir"]["upper"];
    meths = defaults["xpir"]["methods"];
    pol = defaults["xpir"]["policy"]; 
    opts->algos[PIR_XPIR] = defaults["algos"]["xpir"].as<int>();
    opts->algos[PIR_AG] = defaults["algos"]["ag"].as<int>();
    opts->algo = UNBOUND; //not yet negotiated.
    opts->agreed = 0;
    opts->lower_opts.xpir.alpha = lower["alpha"].as<int>();
    opts->upper_opts.xpir.alpha = upper["alpha"].as<int>();
    opts->lower_opts.xpir.d = lower["d"].as<int>();
    opts->upper_opts.xpir.d = upper["d"].as<int>();
    for (i=0;i<MAX_REC_LVL;++i) {
        opts->lower_opts.xpir.n[i] = lower["n"][i].as<int>();
        opts->upper_opts.xpir.n[i] = upper["n"][i].as<int>();
    }
    opts->lower_opts.xpir.l_args.security_bits = lower["lwe"]["security_bits"].as<int>();
    opts->lower_opts.xpir.l_args.poly_degree = lower["lwe"]["poly_degree"].as<int>();
    opts->lower_opts.xpir.l_args.poly_coeff_bits = lower["lwe"]["poly_coeff_bits"].as<int>();
    opts->upper_opts.xpir.l_args.security_bits = upper["lwe"]["security_bits"].as<int>();
    opts->upper_opts.xpir.l_args.poly_degree = upper["lwe"]["poly_degree"].as<int>();
    opts->upper_opts.xpir.l_args.poly_coeff_bits = upper["lwe"]["poly_coeff_bits"].as<int>();
    //
    opts->lower_opts.xpir.p_args.security_bits = lower["pailier"]["security_bits"].as<int>();
    opts->lower_opts.xpir.p_args.bitKeySize = lower["pailier"]["bitKeySize"].as<int>();
    opts->lower_opts.xpir.p_args.ciphSize = lower["pailier"]["ciphSize"].as<int>();
    opts->upper_opts.xpir.p_args.security_bits = upper["pailier"]["security_bits"].as<int>();
    opts->upper_opts.xpir.p_args.bitKeySize = upper["pailier"]["bitKeySize"].as<int>();
    opts->upper_opts.xpir.p_args.ciphSize = upper["pailier"]["ciphSize"].as<int>();
    string meth;
    int priority,xmeth;
    for(i=0;i<N_XPIR_CRYPTO;++i) {
        opts->crypto_priorities.xmeth[i] = -1;
    }
    for(i=0;i<N_AG_CRYPTO;++i) {
        opts->crypto_priorities.ameth[i] = -1;
    }
    for (auto it = meths.begin();it != meths.end(); ++it) {
        meth = it->first.as<std::string>(); 
        priority = it->second.as<int>();
        if ((xmeth = str2xmeth(meth.c_str())) >= 0) {
            opts->crypto_priorities.xmeth[xmeth] = priority; 
        }
    }
    // set policy here.
    opts->policy.x_policy.alpha = (intersect_t) pol["alpha"].as<int>();
    opts->policy.x_policy.d = (intersect_t) pol["d"].as<int>();
    opts->policy.x_policy.n = (intersect_t) pol["n"].as<int>();
    if (opts->policy.x_policy.lp == NULL) {
        opts->policy.x_policy.lp = new lwe_policy;
    }
    opts->policy.x_policy.lp->security_bits = (intersect_t) pol["lwe"]["security_bits"].as<int>();
    opts->policy.x_policy.lp->poly_degree = (intersect_t) pol["lwe"]["poly_degree"].as<int>();
    opts->policy.x_policy.lp->poly_coeff_bits = (intersect_t) pol["lwe"]["poly_coeff_bits"].as<int>();
}

extern "C" int init_req(negotiate_request_t *req,const char *tordir,request_profile_t *prof) {
    string config_fname(tordir),fname;
    config_fname += "/config.yaml";
    try {
        YAML::Node root = YAML::LoadFile(config_fname);
        YAML::Node defaults = root["client"];
        init_opts(&req->opts,defaults,tordir);
        req->N_req_lo = defaults["n_req_lo"].as<int>();
        req->N_req_hi = defaults["n_req_hi"].as<int>();
        fname = root["request_log"].as<string>();
        prof->fname = (char*) malloc(fname.size() + 1);
        strcpy(prof->fname,fname.c_str());
    }
    catch (...) {
        cerr << "Failed to initialize request from configuration" << endl; 
        return 0;
    }
    prof->total = 0;
    prof->generate_query = 0;
    prof->query_send = 0;
    prof->response_recv = 0;
    prof->extract = 0;
    return 1;
}

extern "C" int init_resp(negotiate_response_t *resp,const char *tordir,response_profile_t *prof) {
    string config_fname(tordir),fname;
    config_fname += "/config.yaml";
    try {
        YAML::Node root = YAML::LoadFile(config_fname);
        YAML::Node defaults = root["server"];
        init_opts(&resp->opts,defaults,tordir);
        resp->N_req_hi = defaults["n_req_hi"].as<int>();
        fname = root["response_log"].as<string>();
        prof->fname = (char*) malloc(fname.size() + 1);
        strcpy(prof->fname,fname.c_str());
    }
    catch (...) {
        cerr << "Failed to initialize response from configuration" << endl;
        return 0;
    }
    prof->mkdb = 0;
    prof->total = 0;
    prof->db_load = 0;
    prof->query_recv = 0;
    prof->response_send = 0;
    prof->generate_reply = 0;
    return 1;
}

int random_selection(int *req_idxs,int N,int n_req) {
    int i,v;
    std::set<int> done;
    if (n_req > N) {
        cerr << "Requested more than exist, stopping" << endl;
        return -1;
    }
    for(i=0;i<n_req;++i) {
        do {
            v = rand() % N; 
        } while(done.find(v) != done.end());
        req_idxs[i] = v;
        done.insert(v);
    }
    return 0;
}

void log_duration(const char *descr,clock_t t) {
    FILE *timing = fopen("timing.csv","a");
    const char *timing_fmt = "%s,%f\n";
    char timing_buf[64];
    sprintf(timing_buf,timing_fmt,descr,t/(double) CLOCKS_PER_SEC); 
    flock(fileno(timing),LOCK_EX);
    fputs(timing_buf,timing);
    fclose(timing);
}

vector<char*> consume_concat(recv_t recv) {
    size_t n_bytes,header_len,n_read_1,accum=0,tmp_minus_header,len,n_read_2;
    char tmp[SSL_BLOCKSIZE],header[128],*body,*element;
    vector<char*> msgs;
    n_read_1 = recv(tmp,-1);
    if (n_read_1 < 0) {
        throw std::runtime_error("consume_concat: did not perform first recv successfully"); 
    }
    header_len = strlen(tmp);
    sscanf(tmp,"%zd",&n_bytes);
    body = (char*) malloc(n_bytes);
    tmp_minus_header = n_read_1 - (header_len+1);
    memcpy(body,tmp+header_len+1,tmp_minus_header);
    if (n_bytes > tmp_minus_header)  { //need to read more messages.
        n_read_2 = recv(body+tmp_minus_header,n_bytes - tmp_minus_header); 
        if (n_read_2 < 0) {
            throw std::runtime_error("consume_concat: did not perform second recv successfully"); 
        }
        if (tmp_minus_header + n_read_2 != n_bytes) {
            throw std::runtime_error("consume_concat: data recieved doesn't match number of bytes mentioned in header.");
        }
    }
    while (accum < n_bytes) {
        len = strlen(body + accum);
        element = (char*) malloc(len+1);
        strcpy(element,body + accum);
        msgs.push_back(element);
        accum += len + 1;
    }
    return msgs;
}

int deconcat_batch(vector<char*> &msgs,const char *concat_buf,size_t n_bytes) {
    size_t tmpsize = 8192;
    char *tmp = (char*) malloc(tmpsize);
    size_t len,accum=0;
    do {
        len = strlen(concat_buf + accum);
        if (len > tmpsize) {
            tmpsize *= 2;
            tmp = (char*) realloc(tmp,tmpsize);
        }
        strcpy(tmp,concat_buf + accum);
        accum += len + 1;
        msgs.push_back(tmp);
    } while(accum < n_bytes);
}

// This concatenated message can be read by first doing a recv to get the header followed by an exact-length recv to get the appropriate number of bytes.
char* concat_batch(vector<char*> msgs,size_t *concat_buf_size) {
    size_t n_bytes=0,header_len,cursor=0,msg_len;
    char header[32];
    char *concat_buf;
    for (auto msg : msgs) {
        // plus 1 for allowing null-terminated byte.
        n_bytes += strlen(msg) + 1;
    }
    // header expresses number of bytes, starting after the first null-terminated byte.
    sprintf(header,"%zd",n_bytes);
    header_len = strlen(header) + 1;
    concat_buf = (char*) malloc(header_len + n_bytes);
    memcpy(concat_buf,header,header_len);
    cursor += header_len;
    for (auto msg : msgs) {
        msg_len = strlen(msg) + 1;
        memcpy(concat_buf + cursor,msg,msg_len); 
        cursor += msg_len;
    }
    *concat_buf_size = cursor; 
    return concat_buf;
}

#endif
