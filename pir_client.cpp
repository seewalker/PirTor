#ifndef PIR_CLIENT
#define PIR_CLIENT
#include <stdarg.h>
#include "pir_common.cpp"

const bool CHATTY = true;

// 
extern "C" int pir_client_negotiate(send_t send,recv_t recv,negotiate_request_t *req,negotiate_response_t *resp,request_profile_t *prof) {
    char recvbuf[NEGOTIATE_LEN],*reqbuf;
    int n_incoming;
    size_t reqbuf_len;
    serialize_pir_request(req,&reqbuf,&reqbuf_len,0);
    if (send(reqbuf,-1) <= 0) {
        cerr << "failed to send serialization" << endl;
        return 1; 
    }
    n_incoming = recv(recvbuf,-1);
    if (n_incoming > 0) {
        if (deserialize_pir_response(resp,recvbuf)) {
            cout << "Successfully deserialized response" << endl; 
            if (resp->opts.agreed) {
                return 1;
            }
            else {
                cout << "Response not agreed. reason is:" << endl << resp->opts.disagree_reason << endl;
                return 0;
            }
        }
        else {
            return 0;
        }
    }
    else {

    }
}



extern "C" int ag_request(int *req_idxs,int n_reqs,pir_opts opts) {

}

// a relational-style tsv file.
extern "C" void log_request_profile(const request_profile_t *prof,const pir_opts *opts) {
    FILE *f = fopen(prof->fname,"a"); 
    ostringstream oss;
    flock(fileno(f),LOCK_EX);
    log_line(oss,"total",prof->total,opts);
    log_line(oss,"generate_query",prof->generate_query,opts);
    log_line(oss,"query_send",prof->query_send,opts);
    log_line(oss,"response_recv",prof->response_recv,opts);
    log_line(oss,"extract",prof->extract,opts);
    fclose(f);
}


// i think n_replies doesn't have the right value here... 
size_t decode(vector<char*> response_bufs,char *decoded_buf,PIRReplyExtraction *r_extractor,negotiate_response_t *resp,size_t n_bytes) {
    char *tmp;
    size_t blocksize,n_replies=response_bufs.size();
    int i;     
    for (i=0;i<n_replies;++i) {
        r_extractor->pushEncryptedReply(response_bufs[i]);
    }
    r_extractor->extractReply(resp->max_item_size);
    blocksize = r_extractor->getPlaintextReplyBytesize();
    while (r_extractor->popPlaintextResult(&tmp)) {
        memcpy(decoded_buf + n_bytes,tmp,blocksize);
        n_bytes += blocksize;
        // this is actually the free that's causing a problem. disable it for now...
        //free(tmp);
   }
   if (CHATTY) { cout << "Done decoding" << endl; }
   return n_bytes;
}

extern "C" int xpir_request(int *req_idxs,negotiate_request_t *req,negotiate_response_t *resp,send_t send,recv_t recv,char *decoded_buf,size_t *sep_idxs,request_profile_t *prof) {
   clock_t t0,t1;
   size_t response_chars=0,n_req_bytes;
   int i,n_bytes,n_replies,j,qs,req_idx;
   char buf[128],response[512],response_buf[1024],send_buf[1024];
   char *query_element,*req_buf=NULL;
   vector<char*> query_elements,response_bufs;
   PIRParameters params;
   PIRReplyExtraction *r_extractor;
   
   t0 = clock(); //get timer for beginning of function.
   // set up cryptographic parameters.
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
   PIRQueryGenerator q_gen(params,*crypto);
   decoded_buf = (char*) malloc(sizeof(char) * resp->N_req * MAX_DECODED_LEN);
   for (i=0;i<resp->N_req;++i) {
       t1 = clock();
       q_gen.generateQuery(req_idxs[i]);
       prof->generate_query += clock() - t1;
       j = 0;
       while (q_gen.popQuery(&query_element)) {
           query_elements.push_back(query_element);
       }
       req_buf = concat_batch(query_elements,&n_req_bytes);
       for (auto &query_element : query_elements) {
           free(query_element);
       }
       send(req_buf,n_req_bytes);
       query_elements.clear();
   }
   if (CHATTY) { cout << "Client sent " << resp->N_req << " queries" << endl; }
   n_bytes = 0;
   for (req_idx=0;req_idx<resp->N_req;++req_idx) {
      t1 = clock();
      try {
          response_bufs = consume_concat(recv);
      }
      catch (const std::runtime_error &e) {
            cerr << e.what() << endl;
            return -1;
      }
      prof->response_recv += clock() - t1;
      t1 = clock();
      r_extractor = new PIRReplyExtraction(params,*crypto);
      n_bytes = decode(response_bufs,decoded_buf,r_extractor,resp,n_bytes);
      sep_idxs[req_idx] = n_bytes;
      prof->extract = clock() - t1;
   }
   if (CHATTY) { cout << "Client got " << resp->N_req << " responses" << endl; }
   decoded_buf[n_bytes] = '\0';
   prof->total = clock() - t0;
   return n_bytes;
}
#endif
