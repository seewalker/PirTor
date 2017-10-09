import re

def peek_line(f):
    pos = f.tell()
    line = f.readline()
    f.seek(pos)
    return line

def at_most_once(lines,f,s):
    found = s in peek_line(f)
    if found:
        lines.append(f.readline())
    return lines,found

def at_most_once_lambda(lines,f,pred):
    found = pred(peek_line(f))
    if found:
        lines.append(f.readline())
    return lines,found

def once(lines,f,s):
    x = f.readline()
    if s in x:
        lines.append(x)
    else:
        print(s + " line missing")
        raise ValueError
    return lines

def once_lambda(lines,f,pred):
    x = f.readline()
    if pred(x):
        lines.append(x)
        return lines
    else:
        raise ValueError 

def many(lines,f,s):
    while s in peek_line(f):
        lines.append(f.readline())
    return lines

def many_lambda(lines,f,pred):
    i = 0
    while pred(peek_line(f)):
        lines.append(f.readline())
        i += 1
    return lines,i>0
def parse_pem(lines,f,key_ts):
    begin = f.readline()
    if ("BEGIN" not in begin) or not any([key_t in begin for key_t in key_ts]):
        raise ValueError
    lines.append(begin)
    while not re.match("[-]+END",peek_line(f)):
        lines.append(f.readline())
    end = f.readline()
    lines.append(end)
    return lines

def parse_signature(f):
    begin = f.readline()
    if "BEGIN SIGNATURE" not in begin:
        raise ValueError
    lines.append(begin)
    while "END SIGNATURE" not in peek_line(f):
        lines.append(f.readline())
    end = f.readline()
    lines.append(end)
    return lines

floating_re = "[+-]?([0-9]*[.])?[0-9]+"

def is_wrap(x,fmt):
    return re.match(fmt,x) is not None
def is_family(x):
    return is_wrap(x,"family (.*,)*")
def is_proto(x):
    return is_wrap(x,"proto \w+")
def is_router_25519signature(x):
    return is_wrap(x,"router-sig-ed25519 \S+\n")
def is_onion_key(x):
    return x == "onion-key\n"
def is_ntor_onion_key(x):
    return is_wrap(x,"^ntor-onion-key \S+")

COMMENT_CHAR = "@"

def is_comment(f):
    return peek_line(f)[0] == COMMENT_CHAR

def comment_consume(f):
    while is_comment(f):
        f.readline()

def write_lines(ofname,lines,count,n=1,compress=False):
    '''
    n is number of times to repeat. The reason to care about n != 1 is when profiling artificial larger datasets.
    '''
    n_success = 0
    for i in range(n):
        try:
            with open(ofname(count+n_success),'w') as of:
                if compress:
                    s = lines.join("\n")
                    data = zlib.compress(s.encode())
                    of.write(data)
                else:
                    of.writelines(lines)
            n_success += 1
        except:
            print("Error in writelines")
    return n_success
