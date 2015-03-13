#! /usr/bin/env python
"""
Transform a password into a Hashcat compatible mask/topology 
(http://hashcat.net/wiki/doku.php?id=mask_attack)
and check against the top 100 insecure topologies based on KoreLogic's 
PathWell data (http://blog.korelogic.com/blog/2014/04/04/pathwell_topologies/)

***WARNING*** 
  This does not check password length or check for 
  common or already compromised (pre-hashed) passwords 
***WARNING*** 

# By Stephen Genusa October 2014
# http://development.genusa.com

"""

import os
import sys

def transform_pwd_to_topo(the_password):
    '''Transform a password into as Hashcat mask/PathWell topology'''
    lower = 'abcdefghijklmnopqrstuvwxyz'
    upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    numeric = '0123456789'
    special =" !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
    pwd_pattern = ""
    for cur_char in the_password:
        if cur_char in lower:
            pwd_pattern += '?l'
        elif cur_char in upper:
            pwd_pattern += '?u'
        elif cur_char in numeric:
            pwd_pattern += '?d'
        elif cur_char in special:
            pwd_pattern += '?s'
        # Hashcat built-in charsetsmask types have been exhausted and 
        # the current character is something else so create a custom 
        # charset place holder
        else:
            pwd_pattern += '?1'
    return pwd_pattern


def is_pwd_topo_insecure(the_pwd_topo):
    '''Check to see if the password appears in the KoreLogic top 100 insecure topologies'''
    data_path = os.path.join(os.getcwd(), 'insecure_topos.txt')
    if not os.path.exists(data_path):
        raise Exception("Topo data file not found. Halting.")
    topo_patterns = open(data_path, 'r').read().splitlines()
    if the_pwd_topo in topo_patterns:
        return topo_patterns.index(the_pwd_topo)+1
    else:
        return 0



def check_password(the_pwd):
    '''Report on a given password's security based on the KoreLogic PathWell data'''
    pwd_topo = transform_pwd_to_topo(the_pwd)
    print 
    print "The password transformation for", '"' + the_pwd + '"', "is", pwd_topo
    topo_rank = is_pwd_topo_insecure(pwd_topo)
    if topo_rank:
        print "The password", the_pwd, "uses an insecure PathWell password topology ranked", '#' + str(topo_rank)
    else:
        print "The password", the_pwd, "uses a secure topology"


def main():
    if len(sys.argv) == 2:
        check_password(sys.argv[1])
    else:
        print "Requires one parameter: the password to test. E.G. Denver82"

if __name__ == "__main__":
    main()