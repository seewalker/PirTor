// XPIR request and response lengths are not straightforward to anticipate, so I don't use deterministic functions for buffer sizing.
// Also spending messages trying to communicate lengths of buffers seems wasteful, so for now just consider maximum possible sizes and tune them appropriately.
#include <string.h>
#define NEGOTIATE_LEN 1 << 14
#define MAX_REQUEST_LEN 256
#define MAX_RESPONSE_LEN 1 << 18
#define MAX_DECODED_LEN 1 << 12
#define SSL_BLOCKSIZE 8192
const char *tordir = "/home/aseewald/.tor";

enum intersect_t {
    INTERSECT_MIN,
    INTERSECT_MAX
};

enum pirdb_t {
    DESC,
    MICRODESC,
    CONSENSUS_MICRODESC,
    DIRSERV
};

// if adding an algorithm, should change this number.
#define N_PIR_ALGOS 2
enum pir_algo {
    PIR_XPIR,
    PIR_AG,
    UNBOUND // for when 
};

#define N_XPIR_CRYPTO 2
enum xpir_crypto_method {
    XPIR_LWE,
    XPIR_PAILIER,
};

enum ag_crypto_method {
    N_AG_CRYPTO
};

struct lwe_policy {
    intersect_t security_bits;
    intersect_t poly_degree;
    intersect_t poly_coeff_bits;
};

struct lwe_policy lwe_default = {INTERSECT_MAX,INTERSECT_MIN,INTERSECT_MAX};

struct lwe_args {
    unsigned int security_bits;
    unsigned int poly_degree;
    unsigned int poly_coeff_bits;
};

// what goes here?
struct pailier_policy {
    intersect_t security_bits;
    intersect_t bitKeySize;
    intersect_t ciphSize;
};

struct pailier_policy pailier_default = { };

struct pailier_args {
    unsigned int security_bits;
    unsigned int bitKeySize;
    unsigned int ciphSize;
};

struct xpir_policy {
    // shared among all xpir types.
    intersect_t alpha;
    intersect_t d;
    intersect_t n;

    // make them pointers so they can point to NULL.
    lwe_policy *lp;
    pailier_policy *pp;
};

union ag_policy {

};

// rather than hard-coding this, how can I get this value from PIRParameters.hpp
#define MAX_REC_LVL 10
struct xpir_opts {
    int alpha;
    int d;
    int n[MAX_REC_LVL];
    xpir_crypto_method crypto_method;
    // lower bounds on arg values.
    struct {
        lwe_args l_args;
        pailier_args p_args; 
    };
};

// XPIR library sets "params = <string>" where string is generated from xpir_opts here.
int format_xpir_crypto(char *buf,xpir_opts opts) {
    if (opts.crypto_method == XPIR_LWE) {
        sprintf(buf,"LWE:%i:%i:%i",opts.l_args.security_bits,opts.l_args.poly_degree,opts.l_args.poly_coeff_bits);
    }
    else if (opts.crypto_method == XPIR_PAILIER) {
        sprintf(buf,"Paillier:%i:%i:%i",opts.p_args.security_bits,opts.p_args.bitKeySize,opts.p_args.ciphSize);
    }
}

// non-negative if matched, negative upon error.
int str2xmeth(const char *x) {
    if (strcmp(x,"pailier") == 0) {
        return XPIR_PAILIER;
    }
    else if (strcmp(x,"lwe") == 0) {
        return XPIR_LWE;
    }
    else {
        return -1;
    }
}

// non-negative if matched, negative upon error.
int str2ameth(const char *x) {

}

struct ag_opts {

};

struct Policy {
    xpir_policy x_policy;
    ag_policy a_policy;
};

typedef struct crypto_opts {
    xpir_opts xpir;
    ag_opts ag;
};

struct pir_opts { 
   // the algorithm is an index into this array.
   // the stored value is a priority.
   int algos[N_PIR_ALGOS];
   pir_algo algo; // taken from algos after negotiation
   int agreed; // 1 for agreed upon, 0 for not agreed upon.
   char disagree_reason[1024];
    // All of these are structs instead of unions because at some points in the protocol, it's not yet decided which all will
    // be used.
    crypto_opts lower_opts;
    crypto_opts upper_opts;
    crypto_opts *agreed_opts;
    
    struct {
        int xmeth[N_XPIR_CRYPTO];
        int ameth[N_AG_CRYPTO];
    } crypto_priorities;
    // when negotiated, just one.
    union {
        xpir_crypto_method xmeth;
        ag_crypto_method ameth;
    } crypto;
    Policy policy;
};

struct negotiate_request_t { 
    pir_opts opts;
    pirdb_t dbt;
    size_t N_req_lo;
    size_t N_req_hi;
};

struct negotiate_response_t {
    pir_opts opts;
    size_t N_db;
    size_t N_req_hi;
    size_t N_req; // server decides within range [hi,lo]
    size_t max_item_size; // clientside_maxFileBytesize in example.
};

enum meaning_t {
    MEANING_FILENAME,
    MEANING_DATA
};

struct db_src {
    char *s;
    meaning_t meaning;
    int n;
};

struct request_profile_t {
    char *fname;
    clock_t total;
    clock_t generate_query;
    clock_t query_send;
    clock_t response_recv;
    clock_t extract;
};

struct response_profile_t {
    char *fname;
    clock_t mkdb;
    clock_t total;
    clock_t db_load;
    clock_t query_recv;
    clock_t response_send;
    clock_t generate_reply;
};

typedef long recv_t(char*,long);
typedef long send_t(const char*,long);
