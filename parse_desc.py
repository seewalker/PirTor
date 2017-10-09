'''
Returns number of database entries made.

python parse_microdesc.py <fname> <pirdb>
    where <fname> is path to file containing the data being turned into the database.
          <pirdb> is the directory where the records will be saved, ready to be processed by a DBDirectoryProcessor.
'''
import argparse
import sys
import zlib
import os
import subprocess
import re
from parse import parse
from parse_common import *

def is_or_address(x):
    ipv4_re = "\d+.\d+.\d+.\d+"
    ipv6_re = "\[.*\]"
    address_re = "({}|{})".format(ipv4_re,ipv6_re)
    return is_wrap(x,"or-address {}:\d+".format(address_re))
def is_onion_key_crosscert(x):
    return x == "onion-key-crosscert\n"
def is_eventdns(x):
    return is_wrap(x,"eventdns [01]")
def is_hs_dir(x):
    return is_wrap(x,"hidden-service-dir( \d+)*")
def is_ntor_crosscert(x):
    return is_wrap(x,"ntor-onion-key-crosscert [01]")
def is_published(x):
    return is_wrap(x,"published \d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d")
def is_bandwidth(x):
    r = floating_re
    return is_wrap(x,"bandwidth {} {} {}".format(r,r,r))
def is_protocols(x):
    return is_wrap(x,"protocols Link (\d+ )+Circuit \d+")
def is_signing_key(x):
    return is_wrap(x,"signing-key")
def is_router(x):
    return is_wrap(x,"router \w+ .+ \d+ \d+ \d+")
def is_router_signature(x):
    return is_wrap(x,"router-signature")
def is_uptime(x):
    return is_wrap(x,"hibernating {}".format(floating_re))
def is_extrainfo(x):
    return is_wrap(x,"extra-info-digest \S+")
def is_exit_policy(x):
    return is_wrap(x,"(accept|reject)")
def is_exit6_policy(x):
    return is_wrap(x,"ipv6-policy (accept|reject)")

def parse_consume(lines,done):
    lines,found = at_most_once(lines,f,"identity-ed25519")
    if found:
        lines = parse_pem(lines,f,["ED25519 CERT"])
        done["opt"]["identity-ed25519"] = True
        return lines,done
    lines,found = at_most_once(lines,f,"master-key-ed25519")
    if found:
        done["opt"]["master-key-ed25519"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_bandwidth)
    if found:
        done["opt"]["bandwidth"] = True
        return lines,done
    lines,found = at_most_once(lines,f,"platform")
    if found:
        done["opt"]["platform"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_published)
    if found:
        done["req"]["published"] = True
        return lines,done
    lines,found = at_most_once(lines,f,"fingerprint")
    if found:
        done["opt"]["fingerprint"] = True
        return lines,done
    lines,found = at_most_once(lines,f,"hibernating")
    if found:
        done["opt"]["hibernating"] = True
        return lines,done
    lines,found = at_most_once(lines,f,"uptime")
    if found:
        done["opt"]["uptime"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_onion_key)
    if found:
        lines = parse_pem(lines,f,["RSA PUBLIC KEY"])
        done["req"]["onion-key"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_onion_key_crosscert)
    if found:
        lines = parse_pem(lines,f,["CROSSCERT"])
        done["opt"]["onion-key-crosscert"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_ntor_onion_key)
    if found:
        done["opt"]["ntor-onion-key"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_ntor_crosscert)
    if found:
        lines = parse_pem(lines,f,["ED25519 CERT"])
        done["opt"]["ntor-crosscert"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_signing_key) 
    if found:
        lines = parse_pem(lines,f,["RSA PUBLIC KEY"])
        done["req"]["signing-key"] = True
        return lines,done
    lines,found = many_lambda(lines,f,is_exit_policy)
    if found:
        done["opt"]["exit_policy"] = True
        return lines,done
    lines,found = many_lambda(lines,f,is_exit6_policy)
    if found:
        done["opt"]["exit6_policy"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_router_25519signature)
    if found:
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_router_signature)
    if found:
        return parse_pem(lines,f,["SIGNATURE"]),done
    lines,found = at_most_once(lines,f,"contact")
    if found:
        done["contact"] = True
        return lines,done
    lines,found = at_most_once(lines,f,"family")
    if found:
        done["opt"]["family"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_eventdns)
    if found:
        done["opt"]["eventdns"] = True
        return lines,done
    lines,found = at_most_once(lines,f,"caches-extra-info")
    if found:
        done["opt"]["caches-extra-info"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_extrainfo)
    if found:
        done["opt"]["extrainfo"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_hs_dir)
    if found:
        done["opt"]["hsdir"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_protocols)
    if found:
        done["opt"]["protocols"] = True
        return lines,done
    lines,found = at_most_once(lines,f,"allow-single-hop-exits")
    if found:
        done["opt"]["allow-single-hop-exits"] = True
        return lines,done
    lines,found = many_lambda(lines,f,is_or_address)
    if found:
        return lines,done
    lines,found = at_most_once(lines,f,"tunnelled-dir-server")
    if found:
        done["opt"]["tunnelled-dir-server"] = True 
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_proto)
    if found:
        done["opt"]["proto"] = True
        return lines,done
    print("Found nothing, popping current line which is:")
    print(f.readline())
    raise ValueError

def is_record_start(f):
    return (len(peek_line(f)) == 0 or is_router(peek_line(f)) or is_comment(f))
def validate_desc(f):
    comment_consume(f)
    lines = once_lambda([],f,is_router)
    # list of things which must be there eventually.
    done = {'req' : {"published" : False,"signing-key": False,"onion-key":False},'opt' : {}}
    try:
        while not is_record_start(f):
            lines,done = parse_consume(lines,done)
    except:
        print("Rare error, continuing")
        while not is_record_start(f):
            f.readline() 
        raise ValueError
    if all(done['req'].values()):
        return lines
    else:
        print("Not all necessary entries exist, missing are:")
        for k,v in done['req'].items():
            if not v:
                print(k) 
        raise ValueError

def write_desc(in_f,out_dir,n=1,strict=False):
    i = 0
    if not os.path.exists(out_dir):
        subprocess.call(["mkdir","-p",out_dir])
    while len(peek_line(f)) > 0:
        try:
            lines = validate_desc(in_f)
            count = write_lines(lambda x:os.path.join(out_dir,"test" + str(x)),lines,i,n)
            i += count
        except:
            print("Failed to parse entry=",i)
            if strict:
                sys.exit(-1)
    return i

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("in_file",help="file containing tor microdescriptors",type=str) 
    parser.add_argument("out_dir",help="directory which will become XPIR database directory",type=str)
    parser.add_argument("--n_copies",default=1,help="number of copies of each entry to make (should be 1 unless experimentally profiling)",type=int)
    args = parser.parse_args()
    f = open(args.in_file,'r')
    ret = write_desc(f,args.out_dir,n=args.n_copies)
    print("Processed ",ret," descriptors")
    sys.exit()
