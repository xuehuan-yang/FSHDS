# 1hds Pixel+ and Pixel++: Compact and Efficient Forward-Secure Multi-Signatures for PoS Blockchain Consensus
# git@github.com:ucbrise/jedi-protocol-go.git
# Hash function H
# H:{0,1}* X G0 ->Zp
# temp = H.hashToZr('AXD3rsm5JZ')

# H function
# x = group.random(G1)
# temp = H.hashToZr('AXD3rsm5JZ', e(g,x))

import random
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import time
import numpy as np
from charm.toolbox.hash_module import Hash
import sys

# sys.path.append('../../')
# from common.msp import *

import random
import string

global groupObj
global ahnipe
groupObj = PairingGroup('SS512')

class MJ18(ABEncMultiAuth):
    def __init__(self, groupObj, verbose=False):
        ABEncMultiAuth.__init__(self)
        global group, ahnipe, H, one, two,  l

        group = groupObj
        H = Hash(group)
        t1 = group.random(ZR)
        one = t1 / t1 # element type
        two = one * 2 # element type
        # signmsg1 = "sign message 1"
        # signmsg2 = "sign message 2"
        l = 10

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

    def keyderive_hds(self, msk, pp, p):
        start = time.time()
        p_idx = func_non_star_idx(p)

        r = func_random_Zp_arr(len(p_idx))
        b = func_b(pp, r)
        atemp = func_a(pp, p, p_idx, r)
        # a = atemp * msk['h0tau']
        a = atemp

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
        ahnipe = MJ18(groupObj)
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

        # res3 = (pp['h'][0] ** t) * sigma['x']
        # res_right = pair(pp['g1'], res1 * res3) * res2
        res_right = pair(pp['g1'], res1) * res2
        print("res_right: ", res_right)

        res = 0
        if (res_left == res_right):
            res = 1
        else:
            res = 0

        end = time.time()
        rt = end - start
        return res, rt


def gen_str_star(length, l):
    result = []
    for _ in range(l):
        if random.choice([True, False]):  # Randomly decide whether to generate a string or '*'
            random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
            result.append(random_string)
        else:
            result.append('*')
    return result


def replace_star(lst, length=3, probability=0.5):
    result = []
    for item in lst:
        if item == '*' and random.random() < probability:
            random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
            result.append(random_string)
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
