# Hash function H
# H:{0,1}* X G0 ->Zp
# temp = H.hashToZr('AXD3rsm5JZ')
# x = group.random(G1)
# temp = H.hashToZr('AXD3rsm5JZ', e(g,x))

import sys

# sys.path.append("/Users/zhenfei/Documents/GitHub/bls_sigs_ref/python-impl")
sys.path.append("/home/yangxh/alphabet/charm/avcharm/src/fshds/4fshds/pixel-python")
import copy
from mhds import *  # mhds = modify 1hds.py  treat as the blackbox to import functions

from param import default_param  # this step takes longer times
from keygen import setup_pixel, keygen_pixel
from keyupdate import sk_update

def setup_fshds():
    pk_pixel, msk_pixel, prng, t1 = setup_pixel()
    pp, msk, t2 = ahnipe.setup_hds()
    return pp, msk,pk_pixel, msk_pixel, prng, t1+t2

def keyderive_fshds(msk, pp, p, pk_pixel, msk_pixel, prng):
    skp, t1 = ahnipe.keyderive_hds(msk, pp, p)
    sk, t2 = keygen_pixel(pk_pixel, msk_pixel, prng)
    return sk, skp, t1+t2

def keyderive_delegate_fshds(skp, pp, pprime):
    skpprime, keyderdelt = ahnipe.keyderive_delegate_hds(skp, pp, pprime)
    return skpprime, keyderdelt

def keyupdate_fshds(sk):
    start = time.time()
    sk2 = sk_update(copy.deepcopy(sk), default_param, 8, b"")
    end = time.time()
    t = end - start
    print("key update time: ", t)
    return sk2, t

def sign_fshds(skp, pp, pstar, signmsg1):
    sigma, signt = ahnipe.sign_hds(skp, pp, pstar, signmsg1)
    return sigma, signt

def verify_fshds(pp, sigma, pstar, signmsg1):
    verify_result, verifyt = ahnipe.verify_hds(pp, sigma, pstar, signmsg1)
    return verify_result, verifyt

def verify_fshds_prime(pp, sigma, pstar, signmsg1):
    verify_result, verifyt = ahnipe.verify_hds(pp, sigma, pstar, signmsg1)
    return verify_result, verifyt

def main():
    global groupObj
    global ahnipe
    global signmsg1
    global signmsg2
    groupObj = PairingGroup('SS512')
    ahnipe = MJ18(groupObj)
    signmsg1 = "sign message 1"
    signmsg2 = "sign message 2"

    l_array = np.arange(10, 20, 5)  # maximum number of attibute string

    output_txt = './4fshds.txt'

    with open(output_txt, 'w+', encoding='utf-8') as f:
        f.write(
            "Seq SetupAveTime       KeyDerAveTime      KeyDeriveDeAveTime KeyUpdateAveTime  SignAvetime        VerifyAveTime" + '\n')

        for i in range(len(l_array)):
            seq = 1
            sttol, kdtot, kddtot, kutot, signtot, vertot = 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
            for j in range(seq):
                global l
                l = l_array[i]

                p, pprime, pstar = policy_generate_debug()   # p >= pprime > = pstar good for debug
                # p, pprime, pstar = policy_generate_random()   # p >= pprime > = pstar  good for test with random strings

                pp, msk,pk_pixel, msk_pixel, prng, setupt = setup_fshds()
                sk, skp, keydert = keyderive_fshds(msk, pp, p, pk_pixel, msk_pixel, prng)
                skpprime, keyderdelt = keyderive_delegate_fshds(skp, pp,  pprime)
                sk_update, keyupdatet = keyupdate_fshds(sk)
                sigma, signt = sign_fshds(skp, pp, pstar, signmsg1)
                verify_result, verifyt = verify_fshds(pp, sigma, pstar, signmsg1)


                # sigmaprime, signt = verify_fshds_prime(skpprime, pp, pstar, signmsg2)
                # verify_result2, verifyt2 = verify_fshds(pp, sigmaprime, pstar, signmsg2)


                # pp, msk, setupt = ahnipe.setup_hds()
                # skp, keydert = ahnipe.keyderive_hds(msk, pp, p)
                # skpprime, keyderdelt = ahnipe.keyderive_delegate_hds(skp, pp,  pprime)
                # sigma, signt = ahnipe.sign_hds(skp, pp, pstar, signmsg1)
                # verify_result, verifyt = ahnipe.verify_hds(pp, sigma, pstar, signmsg1)
                if (verify_result == 1):
                    print("skp signature verification success!!!!\n")
                else:
                    print("skp waring !!!!!\n")
                # sigmaprime, signt = ahnipe.sign_hds(skpprime, pp, pstar, signmsg2)
                # verify_result2, verifyt2 = ahnipe.verify_hds(pp, sigmaprime, pstar, signmsg2)
                if (verify_result2 == 1):
                    print("skpprime signature verification success!!!!\n")
                else:
                    print("skpprime waring !!!!!\n")
                sttol, kdtot, kddtot, kutot, signtot, vertot = sttol + setupt, kdtot + keydert, kddtot + keyderdelt, kutot+keyupdatet, signtot + signt, vertot + verifyt
                print("calculate time !!!")

            out0 = str(l).zfill(2)
            out1 = str(format(sttol / float(seq), '.16f'))
            out2 = str(format(kdtot / float(seq), '.16f'))
            out3 = str(format(kddtot / float(seq), '.16f'))
            out4 = str(format(kutot / float(seq), '.16f'))
            out5 = str(format(signtot / float(seq), '.16f'))
            out6 = str(format(vertot / float(seq), '.16f'))
            f.write(out0 + '  ' + out1 + ' ' + out2 + ' ' + out3 + ' ' + out4 + ' ' + out5 + ' ' + out6 )
            f.write('\n')
            print("save time done !!!")


if __name__ == "__main__":
    main()
