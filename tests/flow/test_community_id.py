"""Community ID v1 against the reference vectors from corelight/pycommunityid tests."""

import pytest

from sih26145.flow.community_id import community_id

VECTORS = [
    # proto, src, dst, sport/type, dport/code, seed0, seed1
    ("TCP", "128.232.110.120", "66.35.250.204", 34855, 80, "1:LQU9qZlK+B5F3KDmev6m5PMibrg=", "1:3V71V58M3Ksw/yuFALMcW0LAHvc="),
    ("TCP", "66.35.250.204", "128.232.110.120", 80, 34855, "1:LQU9qZlK+B5F3KDmev6m5PMibrg=", "1:3V71V58M3Ksw/yuFALMcW0LAHvc="),
    ("TCP", "10.0.0.1", "10.0.0.2", 10, 11569, "1:SXBGMX1lBOwhhoDrZynfROxnhnM=", "1:HmBRGR+fUyXF4t8WEtal7Y0gEAo="),
    ("UDP", "192.168.1.52", "8.8.8.8", 54585, 53, "1:d/FP5EW3wiY1vCndhwleRRKHowQ=", "1:Q9We8WO3piVF8yEQBNJF4uiSVrI="),
    ("UDP", "8.8.8.8", "192.168.1.52", 53, 54585, "1:d/FP5EW3wiY1vCndhwleRRKHowQ=", "1:Q9We8WO3piVF8yEQBNJF4uiSVrI="),
    ("ICMP", "192.168.0.89", "192.168.0.1", 8, 0, "1:X0snYXpgwiv9TZtqg64sgzUn6Dk=", "1:03g6IloqVBdcZlPyX8r0hgoE7kA="),
    ("ICMP", "192.168.0.1", "192.168.0.89", 0, 8, "1:X0snYXpgwiv9TZtqg64sgzUn6Dk=", "1:03g6IloqVBdcZlPyX8r0hgoE7kA="),
    ("ICMP", "192.168.0.89", "192.168.0.1", 20, 1, "1:tz/fHIDUHs19NkixVVoOZywde+I=", "1:Ie3wmFyxiEyikbsbcO03d2nh+PM="),
    ("ICMPv6", "fe80::200:86ff:fe05:80da", "fe80::260:97ff:fe07:69ea", 135, 0, "1:dGHyGvjMfljg6Bppwm3bg0LO8TY=", "1:kHa1FhMYIT6Ym2Vm2AOtoOARDzY="),
    ("ICMPv6", "3ffe:507:0:1:200:86ff:fe05:80da", "3ffe:507:0:1:260:97ff:fe07:69ea", 3, 0, "1:/OGBt9BN1ofenrmSPWYicpij2Vc=", "1:Ij4ZxnC87/MXzhOjvH2vHu7LRmE="),
]


@pytest.mark.parametrize("proto,src,dst,sp,dp,seed0,seed1", VECTORS)
def test_reference_vectors(proto, src, dst, sp, dp, seed0, seed1):
    assert community_id(proto, src, dst, sp, dp) == seed0
    assert community_id(proto, src, dst, sp, dp, seed=1) == seed1
