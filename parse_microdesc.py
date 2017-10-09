'''
Returns number of database entries made.

python parse_microdesc.py <fname> <pirdb>
    where <fname> is path to file containing the data being turned into the database.
          <pirdb> is the directory where the records will be saved, ready to be processed by a DBDirectoryProcessor.
'''
import sys
import zlib
import os
import re
import argparse
import subprocess
from parse import parse
from parse_common import *

def is_or_address(x):
    ipv4_re = "\d+.\d+.\d+.\d+"
    ipv6_re = "\[.*\]"
    address_re = "({}|{})".format(ipv4_re,ipv6_re)
    return is_wrap(x,"a {}:\d+".format(address_re))

def is_exit_policy(x):
    return is_wrap(x,"p (accept|reject) (\d|-|,)+")

def is_exit6_policy(x):
    return is_wrap(x,"p6 (accept|reject) (\d|-|,)+")

def is_id(x,kts=["ed25519","rsa1024"]):
    kt_s = "|".join(kts)
    return is_wrap(x,"id ({}) \S+\n".format(kt_s))

def is_proto(x):
    return is_wrap(x,"pr \w+")

def parse_consume(lines,done):
    lines,found = at_most_once_lambda(lines,f,is_ntor_onion_key)
    if found:
        done["req"]["ntor-onion-key"] = True
        return lines,done
    lines,found = at_most_once(lines,f,"family")
    if found:
        done["req"]["family"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_proto)
    if found:
        done["req"]["proto"] = True
        return lines,done
    lines,found = many_lambda(lines,f,is_or_address)
    if found:
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_exit_policy)
    if found:
        done["req"]["exit_policy"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_exit6_policy)
    if found:
        done["opt"]["exit6_policy"] = True
        return lines,done
    lines,found = at_most_once_lambda(lines,f,is_id)
    if found:
        done["opt"]["id"] = True 
        return lines,done
    print("Found nothing, popping current line which is:")
    print(f.readline())
    raise ValueError

def is_record_start(f):
    return (len(peek_line(f)) == 0 or is_onion_key(peek_line(f)) or is_comment(f))
def validate_desc(f):
    done = {'req' : {"onion-key":False},'opt' : {}}
    comment_consume(f)
    lines = once_lambda([],f,is_onion_key)
    lines = parse_pem(lines,f,["RSA PUBLIC KEY"])
    done["req"]["onion-key"] = True
    # list of things which must be there eventually.
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

def write_microdesc(in_f,out_dir,n=1,strict=False):
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
    ret = write_microdesc(f,args.out_dir,n=args.n_copies)
    print("Processed ",ret," microdescriptors")
    sys.exit(ret)
