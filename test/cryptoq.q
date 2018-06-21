\l src/cryptoq_binary.q
\l src/cryptoq.q

.tst.desc["SHA"]{
  should["Generate SHA256"]{
    .cryptoq.sha256["Generate sha256"] mustmatch 0x1531CD20161E70EB3873A4C868F99F1D507A45515ED03486CB07BA1988CA15E2;
    .cryptoq.sha256["$tpest-(t%["] mustmatch 0x0CEE49B90A178A956081AB4DB76F468BA92EC3365DA71D724F27A8CE464C4C21;
     };
  should["Generate SHA512"]{
    .cryptoq.sha512["abc"] mustmatch 0xDDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F ;
    res:0x8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909;
    .cryptoq.sha512["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] mustmatch res;
    };
  should["Generate SHA224"]{
    .cryptoq.sha224["abc"] mustmatch 0x23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7;
    .cryptoq.sha224["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] mustmatch 0x75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525;
    };
  should["Generate SHA384"]{
    .cryptoq.sha384["abc"] mustmatch 0xCB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7;
    res:0x09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039;
    .cryptoq.sha384["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] mustmatch res;
    }; 
  };

.tst.desc["HMAC"]{
  should["Generate HMAC-MD5"]{
    .cryptoq.hmac_md5["key";"Generate sha256"] mustmatch 0x4f720c984da94949a783c255217d226f;
    .cryptoq.hmac_md5["key";"$tpest-(t%["] mustmatch 0xa03c57b59377fa0e6982ca4b392d2032;
    };
  should["Generate HMAC-SHA256"]{
    .cryptoq.hmac_sha256["key";"Generate sha256"] mustmatch 0x07c476de05d9fbf91b4831b5d9373aa576d614679052c4e84daf5e72a8ee47d6;
    .cryptoq.hmac_sha256["key";"$tpest-(t%["] mustmatch 0x029874f50b8d22e5e06b3f4c01b4021083fd3148e5dcd7a30e8742344fe5b5bc;
    };
  should["Generate HMAC-SHA512"]{
    res:0x077c35bc6dedaa99113fcfc580e08ebc3d7e12852ef813d7a88172d9278b6cfc791e5595915109efd8816631e0ff8004f37de2da260ff63e180654b0b2b1eed0;
    .cryptoq.hmac_sha512["key";"Generate sha512"] mustmatch res;
    res:0xaf5fa09d9c1049b23580c443466f8d2989a8cceecfdbc6802e62ed352be48d82239e61de9e04da1db4be2832b9fec492ac10c278c91a5e2e60a146cf0b914dcc;
    .cryptoq.hmac_sha512["key";"$tpest-(t%["] mustmatch res;
    };
  };
