# 2WIBE (Wicked Identity Based Encryption)
# Generalized Key Delegation for Hierarchical Identity-Based Encryption
# https://eprint.iacr.org/2007/221.pdf
# Hash function H
# H:{0,1}* X G0 ->Zp
# temp = H.hashToZr('AXD3rsm5JZ')
# f(x) = g1** H.hashToZr('AXD3rsm5JZ')


# H function
# x = group.random(G1)
# temp = H.hashToZr('AXD3rsm5JZ', e(g,x))

import random
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import time
import numpy as np
from charm.toolbox.hash_module import Hash

import random
import string

class MJ18(ABEncMultiAuth):
    def __init__(self, groupObj, verbose=False):
        ABEncMultiAuth.__init__(self)
        global group, H, one, two, signmsg

        group = groupObj
        H = Hash(group)
        t1 = group.random(ZR)
        one = t1 / t1 # element type
        two = one * 2 # element type
        signmsg = "sign message "


    def setup_wibe(self):
        start = time.time()

        g = group.random(G1)
        hL = func_random_G1_array(L + 1)
        alpha = group.random(ZR)
        g1 = g ** alpha
        h0alpha = hL[0] ** alpha

        mpk = {'g': g, 'g1': g1, 'hL': hL}
        msk = {'h0alpha': h0alpha}

        end = time.time()
        rt = end - start
        return mpk, msk, rt

    def keyderive_wibe(self, msk, mpk, p):
        start = time.time()
        p_idx = func_non_star_idx(p)
        I = func_Iindex(p, p_idx, mpk)  # I means idx

        r = func_random_Zp_arr(len(I))
        b = func_b(mpk, r)
        a_part1 = func_a_part1(mpk, p, p_idx, r)
        a_part2 = func_a_part2(mpk, p, p_idx, r)
        a = msk['h0alpha'] * a_part1 * a_part2

        skp = {'a': a, 'b': b, 'p': p, 'I': I}
        end = time.time()
        rt = end - start

        return skp, rt

    def akeyderive_delegate_wibe(self, skp, mpk, pprime):
        start = time.time()
        pprime_idx = func_non_star_idx(pprime)
        Iprime = func_Iindex(pprime, pprime_idx, mpk)  # I means idx
        diff = list(set(Iprime) - set(skp['I']))  # Finding the array difference

        r = func_random_Zp_arr(len(Iprime))
        bprime = func_bprime(skp, mpk, r, diff)

        aprime_part1 = func_a_part1(mpk, pprime, pprime_idx, r)
        aprime_part2 = func_a_part2(mpk, pprime, pprime_idx, r)
        aprime = skp['a'] * aprime_part1 * aprime_part2

        skpprime = {'a': aprime, 'b': bprime, 'p': pprime, 'I': Iprime}
        end = time.time()
        rt = end - start
        return skpprime, rt

    def encry_wibe(self, mpk, pstar, t, randomGT):
        start = time.time()
        m = randomGT
        print("m_enc:     ", m)
        C0 = mpk['g'] ** t
        CL = func_CL(mpk, pstar, t)
        Cm = (pair(mpk['g1'], mpk['hL'][0]) ** t) * m
        C = {"C0": C0, "CL": CL, "Cm": Cm}
        end = time.time()
        rt = end - start
        return C, rt

    def sign_wibe(self,mpk,skp, pstar, randomGT, t):
        start = time.time()
        rm = group.random(ZR)
        signm = signmsg

        C, encryt = ahnipe.encry_wibe(mpk, pstar, t, randomGT)
        tempHash = mpk["g1"] ** (H.hashToZr(signm) * rm)
        siga = skp['a'] * tempHash

        bm = mpk['g'] ** rm
        CM = mpk['g1'] ** (H.hashToZr(signm) * t)
        Csignm = {'C': C, 'CM' : CM}

        signskp = {'a': siga, 'b': skp['b'], 'p': skp['p'], 'I': skp['I'], 'bm':bm}
        sigma = {'signskp': signskp, 'Csignm': Csignm}

        end = time.time()
        rt = end -start
        return sigma, randomGT, rt

    def verify_wibe(self, mpk, pstar, sigma, randomGT):
        start = time.time()

        m3_cal, decry2t = ahnipe.decry_wibe(mpk, sigma['signskp'], sigma['Csignm']['C'])

        temp = pair(sigma['Csignm']['CM'], sigma['signskp']['bm'])
        res_cal = m3_cal * temp
        res = 0
        if (randomGT == res_cal):
            res = 1
        else:
            res= 0
        end = time.time()
        rt = end - start
        return res, rt

    def decry_wibe(self, mpk, skp, C):
        start = time.time()
        m_top = func_m_top(mpk, skp, C)
        m_bottom = pair(C['C0'], skp['a'])
        m_cal = C['Cm'] * m_top / m_bottom
        end = time.time()
        rt = end - start
        return m_cal, rt


def gen_str_star(length, L):
    result = []
    for _ in range(L):
        if random.choice([True, False]):  # Randomly decide whether to generate a string or '*'
            random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
            result.append(random_string)
        else:
            result.append('*')
    return result

def gen_str_star_number(L, str_len, pstarnum):
    # Create the initial list with pstarnum asterisks
    result = ['*'] * pstarnum

    # Calculate the number of random strings needed
    num_random_strings = L - pstarnum

    # Generate random strings and add to the list
    for _ in range(num_random_strings):
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=str_len))
        result.append(random_string)

    # Shuffle the list to mix asterisks and random strings
    random.shuffle(result)

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

def replace_star_num(lst, length=50, starnum=0):
    star_indices = [i for i, item in enumerate(lst) if item == '*']
    replace_indices = random.sample(star_indices, min(starnum, len(star_indices)))

    result = lst[:]  # Make a copy of lst to modify

    for i in replace_indices:
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        result[i] = random_string

    return result

def func_non_star_idx(lst):
    idx = []
    for i, item in enumerate(lst):
        if item != '*':
            idx.append(i + 1)
    return idx


def func_Iindex(p, p_idx, mpk):
    p_len = len(p)
    redundancy = list(range(p_len + 1, L + 1))
    I = p_idx + redundancy
    return I


def non_star_value(lst):
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
def func_b(mpk, r):
    return [mpk['g'] ** x for x in r]

def func_bprime(skp, mpk, r, diff):
    b_ori_exp = func_bexpand(skp, skp['I'])

    for i in range(len(diff)):
        b_ori_exp[diff[i]-1] = two
    b_exp = func_non_one_value(b_ori_exp)

    bprime = []
    for i in range(len(r)):
        if (b_exp[i] != two):
            # print("b_exp[i] not two:", b_exp[i])
            bprime.append(b_exp[i] * (mpk['g'] ** r[i]))
        else:
            # print("b_exp[i]==two:", b_exp[i])
            bprime.append((mpk['g'] ** r[i]))
    return bprime


def fx_func(mpk, str_ind, str_val):
    temp1 = mpk['g1'] ** H.hashToZr(str_val)
    temp2 = temp1 * mpk['hL'][str_ind + 1]
    return temp2


def func_a_part1(mpk,p, p_idx, r):
    res0 = group.random(G1)
    res = res0
    for n in range(len(p_idx)):
        str_ind = p_idx[n] - 1
        str_val = p[p_idx[n] - 1]
        temp1 = fx_func(mpk, str_ind, str_val)
        temp2 = temp1 ** r[n]
        res = res * temp2
    res = res / res0
    return res


def func_a_part2(mpk, p, p_idx, r):
    res = one
    for i in range(len(p) + 1, L + 1):
        i_vir = i - len(p) + len(p_idx) - 1
        res = res * (mpk['hL'][i] ** r[i_vir])
    return res


def func_ri_expand(mpk, riprime, p_ind):
    res = [one] * L
    for i in range(1, L + 1):
        if i in p_ind:
            res[i - 1] = riprime[p_ind.index(i)]
    return res


def func_bexpand(skp, Iprime):
    res = [one] * L
    for i in range(1, L + 1):
        if i in Iprime:
            res[i-1] = skp['b'][Iprime.index(i)]
    return res

def func_bexpand_delegate(mpk, skp, Iprime):
    temp = func_bexpand(skp, skp['I'])
    biexpand = temp
    difference = list(set(Iprime) - set(skp['I']))     # Finding the array difference
    for i in range(len(difference)):
        biexpand[difference[i]-1] = two
    return biexpand


def func_biprime(mpk, riprime_exp, biexpand):
    biprime = []
    for i in range(L):
        if (riprime_exp[i] == one):
            biprime.append(one)
        else:
            biprime.append(biexpand[i] * (mpk['g'] ** riprime_exp[i]))
    return biprime


def func_aprime_part1(mpk, skp, pprime, riprime):
    pprime_idx = func_non_star_idx(pprime)
    pprime_val = non_star_value(pprime)

    temp = one
    for n in range(len(pprime_idx)):
        temp1 = fx_func(mpk, pprime_idx[n], pprime_val[n])
        temp = temp * (temp1 ** riprime[n])
    aprime = skp['a'] * temp
    return aprime


def func_CL(mpk, pstar, t):
    CL = []
    for i in range(L):
        if i < len(pstar):
            CL.append(fx_func(mpk, i, pstar[i]) ** t)
        if i >= len(pstar):
            CL.append(mpk['hL'][i + 1] ** t)
    return CL


def func_m_top(mpk, skp, C):
    res = one
    biexpand = func_bexpand(skp, skp['I'])
    for i in range(len(biexpand)):
        if biexpand[i] != one:
            res = res * pair(biexpand[i], C['CL'][i])
    res = res
    return res

def func_m_top_prime(mpk, skp, C):
    res = one
    biexpand = func_bexpand(skp, skp['I'])
    for i in range(len(biexpand)):
        if biexpand[i] != one:
            res = res * pair(biexpand[i], C['CL'][i])
    res = res
    return res

def func_random_G1_array(L):
    return [group.random(G1) for _ in range(L)]


def func_random_Zp_arr(L):
    return [group.random(ZR) for _ in range(L)]


def yl_func(L, blstar, s, t):
    array = []
    for i in range(L):
        temp = blstar[i] ** (s + t)
        array.append(temp)
    return array


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
    p = gen_str_star(10, L)  # p means random string
    pprime = replace_star(p) # pprime means delegatable pattern
    pstar = replace_star(pprime) # pstar means policy pattern
    return p, pprime, pstar

def main():
    global groupObj
    global ahnipe
    global L
    global str_len
    groupObj = PairingGroup('SS512')
    ahnipe = MJ18(groupObj)
    L =50
    str_len = 50

    # str_raspberrypi = ''
    str_raspberrypi = 'raspberry'
    scenario = 3
    if scenario == 1:
        pnum, pprimenum, pstarnum= 50, 30, np.arange(20, -1, -5)
        varlen = pstarnum
        output_txt = './'+ str_raspberrypi+'2wibe1.txt'
    elif scenario == 2:
        pnum, pprimenum, pstarnum= np.arange(50, 25, -5) , 30, 20
        varlen = pnum
        output_txt = './'+ str_raspberrypi+'2wibe2.txt'
    elif scenario == 3:
        pnum, pprimenum, pstarnum= 40, np.arange(30,5,-5), 10
        varlen = pprimenum
        output_txt = './'+ str_raspberrypi+'2wibe3.txt'

    L_array = np.arange(15, 30, 5)  # maximum number of attibute string

    with open(output_txt, 'w+', encoding='utf-8') as f:
        f.write(
            "p  pprime  pstar  Seq SetupAveTime       KeyDerAveTime      KeyDeriveDeAveTime EncryAvetime        DecryAveTime" + '\n')

        for i in range(len(varlen)):
            seq = 3 # number of runs default 3 times
            sttol, kdtot, kddtot, encrytot, decrytot = 0.0, 0.0, 0.0, 0.0, 0.0
            for j in range(seq):
                if scenario == 1:
                    pnum_, pprimenum_, pstarnum_ = 50, 30, varlen[i]
                elif scenario == 2:
                    pnum_, pprimenum_, pstarnum_ = varlen[i], 30, 20
                elif scenario == 3:
                    pnum_, pprimenum_, pstarnum_ = 40, varlen[i], 10

                p = gen_str_star_number(L, str_len, pnum_)  # p means random string
                pnum_verify = func_count_star(p)

                pprime = replace_star_num(p, str_len, pnum_ - pprimenum_)
                pprimenum_verify = func_count_star(pprime)

                pstar = replace_star_num(pprime, str_len, pprimenum_- pstarnum_)
                pstarnum_verify = func_count_star(pstar)

                mpk, msk, setupt = ahnipe.setup_wibe()
                skp, keydert = ahnipe.keyderive_wibe(msk, mpk, p)
                skpprime, keyderdelt = ahnipe.akeyderive_delegate_wibe(skp, mpk, pprime)
                t = group.random(ZR)
                randomGT = group.random(GT)
                C, encryt = ahnipe.encry_wibe(mpk, pstar, t, randomGT)
                m_cal, decryt = ahnipe.decry_wibe(mpk, skp, C)
                mprime_cal, decry2t = ahnipe.decry_wibe(mpk, skpprime, C)

                print("m_cal:     ", m_cal)
                print("mprime_cal:", mprime_cal)

                sigma, randomGT, signt = ahnipe.sign_wibe(mpk,skp, pstar, randomGT, t)
                verify_result, verifyt = ahnipe.verify_wibe(mpk, pstar, sigma, randomGT)
                if (verify_result == 1):
                    print("signature verification success!!!!\n")
                else:
                    print("waring !!!!!\n")

                sttol, kdtot, kddtot, encrytot, decrytot = sttol + setupt, kdtot + keydert, kddtot + keyderdelt, encrytot + encryt, decrytot + decryt

            outp = str(pnum_).zfill(2)
            outpprime = str(pprimenum_).zfill(2)
            outpstar = str(pstarnum_).zfill(2)
            out0 = str(seq).zfill(2)
            out1 = str(format(sttol / float(seq), '.16f'))
            out2 = str(format(kdtot / float(seq), '.16f'))
            out3 = str(format(kddtot / float(seq), '.16f'))
            out4 = str(format(encrytot / float(seq), '.16f'))
            out5 = str(format(decrytot / float(seq), '.16f'))
            f.write(
                outp + ' ' + outpprime + ' ' + outpstar + ' ' + out0 + '  ' + out1 + ' ' + out2 + ' ' + out3 + ' ' + out4 + ' ' + out5)
            f.write('\n')


if __name__ == "__main__":
    main()
