#!/usr/bin/python
#
# pure Python implementation of optimized simplified SWU map to BLS12-381 G1

from consts import p
from curve_ops import clear_h, eval_iso, from_jacobian, point_add
from fields import Fq, sgn0
from hash_to_field import Hp
from util import get_cmdline_options, print_g1_hex, print_tv_hash

# distinguished non-square in Fp for SWU map
xi_1 = Fq(p, 11)
sqrt_mxi_1_cubed = (- xi_1 ** 3) ** ((p + 1) // 4)

# 11-isogenous curve parameters
EllP_a = Fq(p, 0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d)
EllP_b = Fq(p, 0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0)

###
## Simplified SWU map for Ell1'
###
# map an element of Fp to the curve Ell1', 11-isogenous to Ell1
def osswu_help(t):
    assert isinstance(t, Fq)

    # first, compute X0(t), detecting and handling exceptional case
    num_den_common = xi_1 ** 2 * t ** 4 + xi_1 * t ** 2
    x0_num = EllP_b * (num_den_common + 1)
    x0_den = -EllP_a * num_den_common
    x0_den = EllP_a * xi_1 if x0_den == 0 else x0_den

    # g(X0(t))
    gx0_den = pow(x0_den, 3)
    gx0_num = EllP_b * gx0_den
    gx0_num += EllP_a * x0_num * pow(x0_den, 2)
    gx0_num += pow(x0_num, 3)

    # try taking sqrt of g(X0(t))
    # this uses the trick for combining division and sqrt from Section 5 of
    # Bernstein, Duif, Lange, Schwabe, and Yang, "High-speed high-security signatures."
    # J Crypt Eng 2(2):77--89, Sept. 2012. http://ed25519.cr.yp.to/ed25519-20110926.pdf
    tmp1 = gx0_num * gx0_den            # u v
    tmp2 = tmp1 * pow(gx0_den, 2)       # u v^3
    sqrt_candidate = tmp1 * pow(tmp2, (p - 3) // 4)

    # did we find it?
    if sqrt_candidate ** 2 * gx0_den == gx0_num:
        # found sqrt(g(X0(t))). Force sign of y to equal sign of t
        (x_num, y) = (x0_num, sqrt_candidate)

    else:
        x1_num = xi_1 * t ** 2 * x0_num
        y1 = sqrt_candidate * t ** 3 * sqrt_mxi_1_cubed
        (x_num, y) = (x1_num, y1)

    # set sign of y equal to sign of t
    y = sgn0(y) * sgn0(t) * y
    assert sgn0(y) == sgn0(t)
    return (x_num * x0_den, y * pow(x0_den, 3), x0_den)

###
## 11-isogeny from Ell1' to Ell1
###
# map coefficients
xnum = ( Fq(p, 0x11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7),
         Fq(p, 0x17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb),
         Fq(p, 0xd54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0),
         Fq(p, 0x1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861),
         Fq(p, 0xe99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9),
         Fq(p, 0x1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983),
         Fq(p, 0xd6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84),
         Fq(p, 0x17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e),
         Fq(p, 0x80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317),
         Fq(p, 0x169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e),
         Fq(p, 0x10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b),
         Fq(p, 0x6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229) )
xden = ( Fq(p, 0x8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c),
         Fq(p, 0x12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff),
         Fq(p, 0xb2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19),
         Fq(p, 0x3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8),
         Fq(p, 0x13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e),
         Fq(p, 0xe7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5),
         Fq(p, 0x772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a),
         Fq(p, 0x14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e),
         Fq(p, 0xa10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641),
         Fq(p, 0x95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a),
         Fq(p, 0x1) )
ynum = ( Fq(p, 0x90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33),
         Fq(p, 0x134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696),
         Fq(p, 0xcc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6),
         Fq(p, 0x1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb),
         Fq(p, 0x8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb),
         Fq(p, 0x16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0),
         Fq(p, 0x4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2),
         Fq(p, 0x987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29),
         Fq(p, 0x9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587),
         Fq(p, 0xe1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30),
         Fq(p, 0x19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132),
         Fq(p, 0x18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e),
         Fq(p, 0xb182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8),
         Fq(p, 0x245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133),
         Fq(p, 0x5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b),
         Fq(p, 0x15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604) )
yden = ( Fq(p, 0x16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1),
         Fq(p, 0x1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d),
         Fq(p, 0x58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2),
         Fq(p, 0x16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416),
         Fq(p, 0xbe0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d),
         Fq(p, 0x8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac),
         Fq(p, 0x166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c),
         Fq(p, 0x16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9),
         Fq(p, 0x1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a),
         Fq(p, 0x167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55),
         Fq(p, 0x4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8),
         Fq(p, 0xaccbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092),
         Fq(p, 0xad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc),
         Fq(p, 0x2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7),
         Fq(p, 0xe0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f),
         Fq(p, 0x1) )
# compute 11-isogeny map from Ell1' to Ell1
def iso11(P):
    return eval_iso(P, (xnum, xden, ynum, yden))

def opt_swu_map(t, t2=None):
    Pp = osswu_help(t)
    if t2 is not None:
        Pp2 = osswu_help(t2)
        Pp = point_add(Pp, Pp2)
    P = iso11(Pp)
    return clear_h(P)

def map2curve_osswu(alpha, dst=None):
    return opt_swu_map( *( Fq(p, *hh) for hh in Hp(alpha, 2, dst) ) )

if __name__ == "__main__":
    import sys

    def run_tests():
        import random
        for _ in range(0, 128):
            t1 = Fq(p, random.getrandbits(380))
            t2 = Fq(p, random.getrandbits(380))
            # test helpers individually
            for t in (t1, t2):
                P = osswu_help(t)
                Pp = from_jacobian(P)
                assert Pp[0] ** 3 + EllP_a * Pp[0] + EllP_b == Pp[1] ** 2
                P = iso11(P)
                Pp = from_jacobian(P)
                assert Pp[0] ** 3 + 4 == Pp[1] ** 2
                P = clear_h(P)
                Pp = from_jacobian(P)
                assert Pp[0] ** 3 + 4 == Pp[1] ** 2
            # now test end-to-end
            P = from_jacobian(opt_swu_map(t1, t2))
            assert P[0] ** 3 + 4 == P[1] ** 2
            sys.stdout.write('')
            sys.stdout.flush()
        sys.stdout.write("\n")

    def main():
        opts = get_cmdline_options()
        if opts.run_tests:
            run_tests()
        else:
            for hash_in in opts.test_inputs:
                print_tv_hash(hash_in, b'\x01', map2curve_osswu, print_g1_hex, False, opts)

    main()
