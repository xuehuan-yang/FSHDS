# 1hds Pixel+ and Pixel++: Compact and Efficient Forward-Secure Multi-Signatures for PoS Blockchain Consensus
# git@github.com:ucbrise/jedi-protocol-go.git
# Hash function H
# H:{0,1}* X G0 ->Zp
# temp = H.hashToZr('AXD3rsm5JZ')

# H function
# x = group.random(G1)
# temp = H.hashToZr('AXD3rsm5JZ', e(g,x))

# import necessary libraries
import random
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import time
import numpy as np
from charm.toolbox.hash_module import Hash

import random
import string

# define the main class for the protool
class MJ18(ABEncMultiAuth):
    def __init__(self, groupObj, verbose=False):
        ABEncMultiAuth.__init__(self)
        global group, ahnipe, H, one, two,  signmsg1, signmsg2

        group = groupObj
        H = Hash(group)
        t1 = group.random(ZR)
        one = t1 / t1 # Element type with value 1
        two = one * 2 # Element type with value 2
        signmsg1 = "sign message 1"
        signmsg2 = "sign message 2"


    # Setup Function for the HDS protocol
    def setup_hds(self):
        start = time.time()

        g = group.random(G1)
        h = func_random_G1_array(l + 1)
        tau = group.random(ZR)
        g1 = g ** tau
        h0tau = h[0] ** tau

        pp = {'g': g, 'g1': g1, 'h': h, 'l' : l}
        msk = {'h0tau': h0tau}

        end = time.time()
        rt = end - start
        return pp, msk, rt

    # Key Derivation function for the HDS Protocol
    def keyderive_hds(self, msk, pp, p):
        start = time.time()
        p_idx = func_non_star_idx(p)

        r = func_random_Zp_arr(len(p_idx))
        b = func_b(pp, r)
        atemp = func_a(pp, p, p_idx, r)
        a = atemp * msk['h0tau']

        skp = {'a': a, 'b': b, 'p': p, 'I': p_idx}
        end = time.time()
        rt = end - start
        return skp, rt

    def keyderive_delegate_hds(self, skp, pp,  pprime):
        start = time.time()
        pprime_idx = func_non_star_idx(pprime)
        diff = list(set(pprime_idx) - set(skp['I']))  # Finding the array difference

        r = func_random_Zp_arr(len(pprime_idx))
        bprime = func_bprime(skp, pp, r, diff)
        atemp = func_a(pp, pprime, pprime_idx, r)
        aprime = atemp * skp['a']
        skpprime = {'a': aprime, 'b': bprime, 'p': pprime, "I": pprime_idx}

        end = time.time()
        rt = end - start
        return skpprime, rt

    def sign_hds(self, skp, pp, pstar, signmsg):
        start = time.time()
        m = signmsg
        skppstar, rt = ahnipe.keyderive_delegate_hds(skp, pp, pstar)

        s = group.random(ZR)
        x = pp['h'][0] ** s
        t = H.hashToZr(m, pair(pp['g'], x))
        y = func_y(skppstar, s, t)
        z = skppstar['a'] ** (s + t)

        sigma = {'x': x, 'y': y, 'z': z, 'pstar': pstar}
        end = time.time()
        rt = end - start
        return sigma, rt

    def verify_hds(self, pp, sigma, pstar, signmsg):
        start = time.time()

        t = H.hashToZr(signmsg, pair(pp['g'], sigma['x']))
        res_left = pair(sigma['z'], pp['g'])
        print("res_left:  ", res_left)

        pstar_ind = func_non_star_idx(pstar)
        pstar_remove_star = func_remove_star(pstar)
        h_match = func_h_match(pp,pstar_ind )

        res1 = one
        for i in range(len(pstar_ind)):
            temp = sigma['y'][i] ** H.hashToZr(pstar_remove_star[i])
            res1 = res1 * temp

        res2 = one
        for i in range(len(pstar_ind)):
            temp = pair(sigma['y'][i], h_match[i])
            res2 = res2 * temp

        res3 = (pp['h'][0] ** t) * sigma['x']
        res_right = pair(pp['g1'], res1 * res3) * res2
        print("res_right: ", res_right)

        res = 0
        if (res_left == res_right):
            res = 1
        else:
            res = 0

        end = time.time()
        rt = end - start
        return res, rt

# Generate a list of strings and '*' with random choice
def gen_str_star(l, str_len, pstarnum):
    result = []
    for _ in range(l):
        if random.choice([True, False]):  # Randomly decide whether to generate a string or '*'
            random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=str_len))
            result.append(random_string)
        else:
            result.append('*')
    return result

# Generate a list of strings and a specified number of '*'
def gen_str_star_number(l, str_len, pstarnum):
    # Create the initial list with pstarnum asterisks
    result = ['*'] * pstarnum

    # Calculate the number of random strings needed
    num_random_strings = l - pstarnum

    # Generate random strings and add to the list
    for _ in range(num_random_strings):
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=str_len))
        result.append(random_string)

    # Shuffle the list to mix asterisks and random strings
    random.shuffle(result)

    return result


# Replace '*' with random strings based on a given probability
def replace_star(lst, length=3, probability=0.5):
    result = []
    for item in lst:
        if item == '*' and random.random() < probability:
            random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
            result.append(random_string)
        else:
            result.append(item)
    return result

# Replace '*' with random strings, ensuring a specific number of '*' remain
def replace_star_num(lst, length=50, starnum=0):
    star_indices = [i for i, item in enumerate(lst) if item == '*']
    replace_indices = random.sample(star_indices, min(starnum, len(star_indices)))

    result = lst[:]  # Make a copy of lst to modify

    for i in replace_indices:
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        result[i] = random_string

    return result

def replace_star_num_prime(lst, length=50, starnum=0):
    star_indices = [i for i, item in enumerate(lst) if item == '*']
    replace_indices = random.sample(star_indices, min(starnum, len(star_indices)))

    result = lst[:]  # Make a copy of lst to modify

    for i in replace_indices:
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        result[i] = random_string

    return result



def replace_star_num_prime(lst, length=50, starnum= 0):
    star_indices = [i for i, item in enumerate(lst) if item == '*']
    replace_indices = random.sample(star_indices,
                                    min(len(lst) - starnum, len(star_indices)))  # Randomly select up to 30 indices to replace
    result = []
    star_count = 0

    for i, item in enumerate(lst):
        if i in replace_indices:
            random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
            result.append(random_string)
            star_count += 1
        else:
            result.append(item)
    return result



def func_non_star_idx(lst):
    idx = []
    for i, item in enumerate(lst):
        if item != '*':
            idx.append(i + 1)
    return idx

def func_remove_star(lst):
    idx = []
    for i, item in enumerate(lst):
        if item != '*':
            idx.append(lst[i])
    return idx
def func_non_one_value(lst):
    idx = []
    for i, item in enumerate(lst):
        if item != one:
            idx.append(lst[i])
    return idx

def func_b(pp, r):
    return [pp['g'] ** x for x in r]

def func_bprime(skp, pp, r, diff):
    b_ori_exp = func_bexpand(skp, skp['I'])

    for i in range(len(diff)):
        b_ori_exp[diff[i] - 1] = two
    b_exp = func_non_one_value(b_ori_exp)
    bprime = []
    for i in range(len(r)):
        if (b_exp[i] != two):
            bprime.append(b_exp[i] * (pp['g'] ** r[i]))
        else:
            bprime.append((pp['g'] ** r[i]))
    return bprime
def fx_func(pp, str_ind, str_val):
    temp1 = pp['g1'] ** H.hashToZr(str_val)
    temp2 = temp1 * pp['h'][str_ind + 1]
    return temp2

def func_a(pp, p, p_idx, r):
    res0 = group.random(G1)
    res = res0
    for n in range(len(p_idx)):
        str_ind = p_idx[n] - 1
        str_val = p[p_idx[n] - 1]
        temp1 = fx_func(pp, str_ind, str_val)
        temp2 = temp1 ** r[n]
        res = res * temp2
    res = res / res0
    return res

def func_bexpand(skp, Iprime):
    res = [one] * l
    for i in range(1, l + 1):
        if i in Iprime:
            res[i-1] = skp['b'][Iprime.index(i)]
    return res

def func_random_G1_array(l):
    return [group.random(G1) for _ in range(l)]


def func_random_Zp_arr(l):
    return [group.random(ZR) for _ in range(l)]

# Generates a list of elements by exponentiating pp['g'] with elements of r
def func_b(mpk, r):
    return [mpk['g'] ** x for x in r]

def func_y(skppstar, s, t):
    array = []
    for i in range(len(skppstar["I"])):
        temp = skppstar['b'][i] ** (s + t)
        array.append(temp)
    return array

def func_h_match(pp, pstar_ind):
    h_ori = pp["h"]
    h_match = []
    for i in range(len(pstar_ind)):
        h_match.append(h_ori[pstar_ind[i]])
    return h_match

def generate_random_str(length):
    random_str = ''
    base_str = 'helloworlddfafj23i4jri3jirj23idaf2485644f5551jeri23jeri23ji23'
    for i in range(length):
        random_str += base_str[random.randint(0, length - 1)]
    return random_str

def func_count_star(lst):
    return lst.count('*')

def policy_generate_debug():
    # p >= pprime > = pstar
    p = ['a', 'b', '*', '*', '*', '*', '*', '*', '*', 'c']
    pprime = ['a', 'b', '*', '*', 'D', '*', '*', '*', '*', 'c']
    pstar = ['a', 'b', '*', '*', 'D', 'E', '*', '*', '*', 'c']
    return p, pprime, pstar

def policy_generate_random():
    p = gen_str_star(10, l)  # p means random string
    pprime = replace_star(p) # pprime means delegatable pattern
    pstar = replace_star(pprime) # pstar means policy pattern
    return p, pprime, pstar


def main():
    global groupObj
    global ahnipe
    global l
    global str_len
    groupObj = PairingGroup('SS512')
    ahnipe = MJ18(groupObj)
    l =50
    str_len = 50

    # str_raspberrypi = ''
    str_raspberrypi = 'raspberry'
    scenario = 1
    if scenario == 1:
        pnum, pprimenum, pstarnum= 50, 30, np.arange(20, -1, -5)
        varlen = pstarnum
        output_txt = './'+ str_raspberrypi+'2hds1.txt'
    elif scenario == 2:
        pnum, pprimenum, pstarnum= np.arange(50, 25, -5) , 30, 20
        varlen = pnum
        output_txt = './'+ str_raspberrypi+'2hds2.txt'
    elif scenario == 3:
        pnum, pprimenum, pstarnum= 40, np.arange(30,5,-5), 10
        varlen = pprimenum
        output_txt = './'+ str_raspberrypi+'2hds3.txt'

    with open(output_txt, 'w+', encoding='utf-8') as f:
        f.write(
            "p  pprime  pstar  Seq SetupAveTime       KeyDerAveTime      KeyDeriveDeAveTime SignAvetime        VerifyAveTime" + '\n')

        for i in range(len(varlen)):
            seq = 3 # number of runs and calculate the average running time  default 3 times
            sttol, kdtot, kddtot, signtot, vertot = 0.0, 0.0, 0.0, 0.0, 0.0
            for j in range(seq):
                if scenario == 1:
                    pnum_, pprimenum_, pstarnum_ = 50, 30, varlen[i]
                elif scenario == 2:
                    pnum_, pprimenum_, pstarnum_ = varlen[i], 30, 20
                elif scenario == 3:
                    pnum_, pprimenum_, pstarnum_ = 40, varlen[i], 10

                p = gen_str_star_number(l, str_len, pnum_)  # p means random string
                pnum_verify = func_count_star(p)

                pprime = replace_star_num(p, str_len, pnum_ - pprimenum_)
                pprimenum_verify = func_count_star(pprime)

                pstar = replace_star_num(pprime, str_len, pprimenum_- pstarnum_)
                pstarnum_verify = func_count_star(pstar)

                pp, msk, setupt = ahnipe.setup_hds()
                skp, keydert = ahnipe.keyderive_hds(msk, pp, p)
                skpprime, keyderdelt = ahnipe.keyderive_delegate_hds(skp, pp,  pprime)
                sigma, signt = ahnipe.sign_hds(skp, pp, pstar, signmsg1)
                verify_result, verifyt = ahnipe.verify_hds(pp, sigma, pstar, signmsg1)
                if (verify_result == 1):
                    print("skp signature verification success!!!!\n")
                else:
                    print("skp waring !!!!!\n")
                sigmaprime, signt = ahnipe.sign_hds(skpprime, pp, pstar, signmsg2)
                verify_result2, verifyt2 = ahnipe.verify_hds(pp, sigmaprime, pstar, signmsg2)
                if (verify_result2 == 1):
                    print("skpprime signature verification success!!!!\n")
                else:
                    print("skpprime waring !!!!!\n")
                sttol, kdtot, kddtot, signtot, vertot = sttol + setupt, kdtot + keydert, kddtot + keyderdelt, signtot + signt, vertot + verifyt

            outp = str(pnum_).zfill(2)
            outpprime = str(pprimenum_).zfill(2)
            outpstar = str(pstarnum_).zfill(2)
            out0 = str(seq).zfill(2)
            out1 = str(format(sttol / float(seq), '.16f'))
            out2 = str(format(kdtot / float(seq), '.16f'))
            out3 = str(format(kddtot / float(seq), '.16f'))
            out4 = str(format(signtot / float(seq), '.16f'))
            out5 = str(format(vertot / float(seq), '.16f'))
            f.write(outp+ ' '+ outpprime +' '+ outpstar + ' ' + out0 + '  ' + out1 + ' ' + out2 + ' ' + out3 + ' ' + out4 + ' ' + out5)
            f.write('\n')


if __name__ == "__main__":
    main()
