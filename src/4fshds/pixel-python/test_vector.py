# This is a python implementation of Pixel Signature scheme
# This code generates test vectors for the scheme, that is used to
# cross compare with rust's test vectors, to ensure the correctness
# of the implementation.

# This code is of low quality, and should not be used for any purpose
# other than testing and debugging.

# change this path to they python bls code
import sys
# sys.path.append("/Users/zhenfei/Documents/GitHub/bls_sigs_ref/python-impl")
sys.path.append("/home/yangxh/alphabet/charm/avcharm/src/fshds/4fshds/pixel-python")

import filecmp
import copy
import shutil

from param import default_param
from keyupdate import sk_update
from keygen import key_gen, serialize_sk, print_sk
from serdesZ import serialize
from sig import sign_present, serialize_sig, print_sig

# The following function generates the test vectors.
# The test vectors are stored in a subfolder "test_vector"
# They are stored in both plain mode (human readable): this mode does NOT
# match Rust's output; and in binary mode (serialized as per the spec)
# the binary mode match the output from Rust.
def test_vector():

    seed = b"this is a very long seed for pixel tests"
    msg = b"this is the message we want pixel to sign";

    print("Initialization")
    pk, sk = key_gen(seed)
    sig = sign_present(sk, 1, default_param, msg)

    sk_back_up = copy.deepcopy(sk)

    # output pk to a binary file
    pk_buf = b"\0" + serialize(pk, True)
    f = open("test_vector/pk_bin.txt", "wb")
    f.write(pk_buf)
    f.close()
    shutil.copy2("test_vector/pk_bin.txt", "../test_vector/test_vector/pk_bin.txt")
    assert filecmp.cmp("test_vector/pk_bin.txt", "../test_vector/test_vector/pk_bin.txt")

    # output sk to a human readable file
    fname = "test_vector/sk_plain_01.txt"
    t = sys.stdout
    sys.stdout = open(fname, 'w')
    print_sk(sk)
    sys.stdout = t

    # output sk to a binary file
    sk_buf = serialize_sk(sk)
    f = open("test_vector/sk_bin_01.txt", "wb")
    f.write(sk_buf)
    f.close()
    shutil.copy2("test_vector/sk_bin_01.txt", "../test_vector/test_vector/sk_bin_01.txt")
    assert filecmp.cmp("test_vector/sk_bin_01.txt", "../test_vector/test_vector/sk_bin_01.txt")

    # output sig to a human readable file
    fname = "test_vector/sig_plain_01.txt"
    t = sys.stdout
    sys.stdout = open(fname, 'w')
    print_sig(sig)
    sys.stdout = t

    # output sig to a binary file
    sig_buf = serialize_sig(sig)
    f = open("test_vector/sig_bin_01.txt", "wb")
    f.write(sig_buf)
    f.close()
    shutil.copy2("test_vector/sig_bin_01.txt", "../test_vector/test_vector/sig_bin_01.txt")
    assert filecmp.cmp("test_vector/sig_bin_01.txt", "../test_vector/test_vector/sig_bin_01.txt")

    # update the secret key sequentially, and make sure the
    # updated key matched rust's outputs.
    for i in range(2,8):
        print("updating to time %d"%i)

        # updated sk and signatures
        sk2 = sk_update(copy.deepcopy(sk), default_param, i, b"")
        sig = sign_present(sk2, i, default_param, msg)

        # output sk to a human readable file
        fname = "test_vector/sk_plain_%02d.txt"%i
        t = sys.stdout
        sys.stdout = open(fname, 'w')
        print_sk(sk2)
        sys.stdout = t

        # output sk to a binary file
        sk_buf = serialize_sk(sk2)
        fname = "test_vector/sk_bin_%02d.txt"%i
        f = open(fname, "wb")
        f.write(sk_buf)
        f.close()

        # compare with rust's output
        fname2 = "../test_vector/test_vector/sk_bin_%02d.txt"%i
        shutil.copy2(fname, fname2)
        assert filecmp.cmp(fname, fname2)

        # output sig to a human readable file
        fname = "test_vector/sig_plain_%02d.txt"%i
        t = sys.stdout
        sys.stdout = open(fname, 'w')
        print_sig(sig)
        sys.stdout = t

        # output sig to a binary file
        fname = "test_vector/sig_bin_%02d.txt"%i
        fname2 = "../test_vector/test_vector/sig_bin_%02d.txt"%i
        sig_buf = serialize_sig(sig)
        f = open(fname, "wb")
        f.write(sig_buf)
        f.close()
        shutil.copy2(fname, fname2)
        assert filecmp.cmp(fname, fname2)

        sk = copy.deepcopy(sk2)

    sk = copy.deepcopy(sk_back_up)
    for i in range(2,4):

        cur_time = sk[1][0][0]
        tar_time = cur_time+i
        print("updating from time %d to time %d"%(cur_time, tar_time))

        # updated sk and signatures
        sk2 = sk_update(copy.deepcopy(sk), default_param, tar_time, b"")
        sig = sign_present(sk2, tar_time, default_param, msg)

        # output sk to a human readable file
        fname = "test_vector/sk_plain_ff_%04d_%04d.txt"%(cur_time,tar_time)
        t = sys.stdout
        sys.stdout = open(fname, 'w')
        print_sk(sk2)
        sys.stdout = t

        # output sk to a binary file
        sk_buf = serialize_sk(sk2)
        fname = "test_vector/sk_bin_ff_%04d_%04d.txt"%(cur_time,tar_time)
        f = open(fname, "wb")
        f.write(sk_buf)
        f.close()

        # compare with rust's output
        fname2 = "../test_vector/test_vector/sk_bin_ff_%04d_%04d.txt"%(cur_time,tar_time)
        shutil.copy2(fname, fname2)
        assert filecmp.cmp(fname, fname2)

        # output sig to a human readable file
        fname = "test_vector/sig_plain_ff_%04d_%04d.txt"%(cur_time,tar_time)
        t = sys.stdout
        sys.stdout = open(fname, 'w')
        print_sig(sig)
        sys.stdout = t

        # output sig to a binary file
        fname = "test_vector/sig_bin_ff_%04d_%04d.txt"%(cur_time,tar_time)
        fname2 = "../test_vector/test_vector/sig_bin_ff_%04d_%04d.txt"%(cur_time,tar_time)
        sig_buf = serialize_sig(sig)
        f = open(fname, "wb")
        f.write(sig_buf)
        f.close()
        shutil.copy2(fname, fname2)
        assert filecmp.cmp(fname, fname2)

        print("sk = copy.deepcopy(sk2) before !!!!!")
        sk = copy.deepcopy(sk2)
        print("sk = copy.deepcopy(sk2) after !!!!!")

    print("test_vector:  done !!!!")

if __name__ == "__main__":
    def main():
        test_vector()
    main()
