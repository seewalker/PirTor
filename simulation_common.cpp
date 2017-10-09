#define CMD_LEN 64
#define PORT 5064
#define INDEFINITE_SIZE 100000
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctime>

char cmd_buf[CMD_LEN];
SSL *ssl;

int exists_null(const char *buf,int n) {
    int i,exists=0;
    for(i=0;i<n;++i) {
        exists |= buf[i] == '\0';
    }
    return exists;
}

int null_within(const char *buf,size_t len) {
    size_t i;
    for(i=0;i<len;++i) {
        if (buf[i] == '\0') {
            return 1;
        }
    }
    return 0;
}
long simulation_recv(char *buf,long len) {
    int n;
    size_t accum=0;
    while (1) {
        n = SSL_read(ssl,buf + accum,SSL_BLOCKSIZE);
        if (n <= 0) {
            cerr << "SSL read error" << endl;
            return -1;
        }
        accum += n; 
        if (len < 0) {
            if (null_within(buf,accum+1)) {
                break;
            }
        }
        else {
            if (accum >= len || n < SSL_BLOCKSIZE) {
                break;
            }
        }
    }
    return accum;
}

long simulation_send(const char *buf,long len) {
    size_t n_bytes = len < 0 ? strlen(buf) : len;
    if (buf[n_bytes] != '\0') {
        cerr << "Error : attempted to send non-null-terminated message with simulation_send" << endl;
        return -1;
    }
    // include the null-terminating byte, so that simulation_recv can know when to stop.
    return SSL_write(ssl,buf,n_bytes);
}

pirdb_t parse_dbt(string dbts) {
    if (dbts == "micro" || dbts == "microdesc") {
        return MICRODESC;
    }
    else if (dbts == "desc") {
        return DESC;
    }
    else if (dbts == "dirserv") {
        return DIRSERV;
    }
    else if (dbts == "consensus-microdesc") {
        return CONSENSUS_MICRODESC;
    }
    else { 
        cerr << "argv[1] should be micro|node|dirserv" << endl;
        exit(EXIT_FAILURE);
    }
}
