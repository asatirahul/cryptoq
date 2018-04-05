\l src/cryptoq_binary.q
\l src/cryptoq.q

.tst.desc["SHA256"]{
  should["Generate SHA256"]{
    .cryptoq.sha256["Generate sha256"] mustmatch 0x1531CD20161E70EB3873A4C868F99F1D507A45515ED03486CB07BA1988CA15E2;
    .cryptoq.sha256["$tpest-(t%["] mustmatch 0x0CEE49B90A178A956081AB4DB76F468BA92EC3365DA71D724F27A8CE464C4C21;
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
  };
