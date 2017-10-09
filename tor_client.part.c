// Stuff that goes in /etc/torrc
//   CLIENT_PIR_ALGO=
//   CLIENT_PIR_CONFIG=
//   SERVER_PIR_ALGOS=  // comma separated list of algos.
//   SERVER_PIR_CONFIG=



// precondition : option for doing pir is set.
int negotiate_pir_client(dir_connection_t *conn,directory_request_t *req) {
    or_options_t options = get_options();
    pir_opts popt;
    if (options->pir_algo == "XPIR") {
        popt.algo = PIR_XPIR;
    }
    else if (options->pir_algo == "AG") {
        popt.algo = PIR_AG;
    }
    add_pir_headers(req,popt);
}

// 

// Things that don't need to change:
// directory_initiate_request
// I don't think I'll need to modify directory_request_t, I can just add headers with custom keys and values.

// Things that do need to change:
//   directory_get_from_dirserver need to do what I code here.
//   how to get these later?
void add_pir_headers(directory_request_t *req,pir_options_t popt) {
    if (popt.algo == PIR_XPIR) {
        xpir_opts opts = popt.algo_opts;
        directory_request_add_header(&req->additional_headers,"d",itoa(opts.d));
        directory_request_add_header(&req->additional_headers,"alpha",itoa(opts.alpha));
        directory_request_add_header(&req->additional_headers,"n",itoa(opts.n));
        if (opts.crypto_method == XPIR_LWE) {
            directory_request_add_header(&req->additional_headers,"LWE_bits",itoa(opts.l_args.security_bits));
        }
    }
    else if (popt.algo == PIR_AG) {

    }
}
