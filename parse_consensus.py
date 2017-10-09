'''
Returns number of database entries made.

python parse_microdesc.py <fname> <pirdb>
    where <fname> is path to file containing the data being turned into the database.
          <pirdb> is the directory where the records will be saved, ready to be processed by a DBDirectoryProcessor.
'''
import re
from parse import parse
import sys
import yaml
import os

# format ~/.tor/pirdb/{dirsource-microdesc}/test{1,2..}
dbdir = yaml.load(open('config.yml','r'))

def read_meta(f):
    meta = dict()
    meta['network-status-version'] = parse("network-status-version {} {}",f.readline())
    meta['vote-status'] = parse("vote-status {}",f.readline())
    meta['consensus-method'] = parse("consensus-method {}",f.readline())
    meta['valid-after'] = parse( )
    meta['shared-rand-current-value'] = parse( ) 
    return meta


def read_dirsources(f):
    i = 0
    while 'dir-source' in peek_line(f):
        src,contact,digest = f.readline(),f.readline(),f.readline()
        # write to files suitable for DirectoryHanlder
        with open(os.path.join(dbdir,'dirsource'+meta['network-status-version'],'test'+str(i))) as of:
            of.write(src+contact+digest)
        ++i

def is_router_entry(f):
    parse('r {} peek_line(f)',peek_line(f))
    return
def read_routers(f):
    i = 0
    while is_router_entry(f):
        a,b,c,d,e = f.readline(),f.readline(),f.readline(),f.readline(),f.readline()
        with open(os.path.join(dbdir,'routers'+meta['network-status-version'],'test'+str(i)),'w') as of:
            of.write(a+b+c+d+e)
        ++i

def parse_microdesec_consensus(filename):
    with open(filename,r) as f:
        meta = read_meta(f) 
        if meta['network-status-version'] == ('3','microdesc'):
            directory = read_dirsources(f)
            routers = read_routers(f)
        assert(f.readline() == 'directory-footer')
        meta['bandwidth-weights'] = parse( ) 
        directory_keys = read_keys(f)
        yaml.dump(meta,open(dbdir))

if __name__ == "__main__":
    sys.exit( )
