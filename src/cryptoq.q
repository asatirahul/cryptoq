\d .cryptoq
/ ==================================
/      Public API
/ ==================================

/ base 64 encode
/ @param (String)
b64_encode:{
  (.Q.b6 2 sv/: 6 cut (raze 0b vs/: x),(2*c)#0b),#[c:(0;2;1)count[x] mod 3;"="]
 };

/ base 64 decode
/ @param (String)
b64_decode:{
  d:(neg sum "="=x)_"c"$2 sv/:8 cut raze -6#/:0b vs/: .Q.b6?x;
  $[(10h =type d)&(1=count d);first d ;d]
 };

/ base 64 encode for any data structure. First it converts data to json and then encodes it.
/ @param (All)
b64_json_encode:{ b64_encode .j.j x};

/ base 64 decode. It expects json string inside encoded string
b64_json_decode:{
   d:.j.k b64_decode x;
   $[(10h =type d)&(1=count d);first d ;d]
 };

/ =================
/ HASH FUNCTIONS
/ ==================

/ Returns SHA256 Hash of Msg
/ @param Msg [String]
/ @return Hexadecimal
sha256:{[Msg] sha256_start[Msg;256]};

/ Returns SHA512 Hash of Msg 
/ @param Msg [String]
/ @return Hexadecimal
sha512:{[Msg] sha512_start [Msg;512]};

/ Returns SHA384 Hash of Msg
/ @param Msg [String]
/ @return Hexadecimal
sha384:{[Msg] sha512_start[Msg;384]};

/ Returns SHA224 Hash of Msg 
/ @param Msg [String]
/ @return Hexadecimal
sha224:{[Msg] sha256_start[Msg;224]};

/ HMAC function
/ @param Key (String) Key for hmac
/ @param Msg (String) Msg to hash
/ @param HashFunc (function) Hash funtion to use. Should accept string and return hex value
/ @param BlockSize (integer) Blocksize in bits
/ @return hexadecimal hmac value
hmac:{[Key; Msg; HashFunc; BlockSize]
  kp: raze 0b vs/:"x"$(Key;HashFunc Key)BlockSize<8*count Key:Key,();  /key_padded value will be stored in this
  if[BlockSize>c:count kp; kp: kp,(BlockSize- c)#0b];
  key_pads: kp<>/:BlockSize#/:(00110110b;01011100b); / 0x36,0x5c
  h1: HashFunc "c"$'2 sv/: 8 cut key_pads[0],raze 0b vs/:"x"$Msg,();
  HashFunc "c"$'2 sv/: 8 cut raze key_pads[1],0b vs/:h1
  };

/ HMAC MD5
hmac_md5:{[Key;Msg] hmac[Key;Msg;md5;512]};

/ HMAC SHA256
hmac_sha256:{[Key;Msg] hmac[Key;Msg;sha256;512]};

/ HMAC SHA512
hmac_sha512:{[Key;Msg] hmac[Key;Msg;sha512;1024]};

/ converts input msg to String
/ @param Msg (Hex|Char|String)
format:{[Msg]
  if[-4h = type Msg; :enlist "c"$Msg]; / hex atom -> string
  if[4h = type Msg; :"c"$Msg];  / hex list -> string
  if[10h = type Msg; :Msg]; / string
  if[-10h = type Msg; :enlist Msg]; / char -> String
 };

/ enlist Input if it is an atom else return Input
/ @param Data (any) Any Input type
/ @return (List)
maybe_enlist_data:{[Data] (Data;enlist Data)0>type Data};


/ ===============================================
/    SHA Algo Common Functions and Data Structure
/ ===============================================
/ H and K constants in binary
H:()!();K:()!();
H[224]:.cryptoq_binary.hex_to_bin@'(0xc1059ed8;0x367cd507;0x3070dd17;0xf70e5939;0xffc00b31;0x68581511;0x64f98fa7;0xbefa4fa4);
H[256]:.cryptoq_binary.hex_to_bin@'(0x6a09e667;0xbb67ae85;0x3c6ef372;0xa54ff53a;0x510e527f;0x9b05688c;0x1f83d9ab;0x5be0cd19);
H[384]:.cryptoq_binary.hex_to_bin@'(0xcbbb9d5dc1059ed8;0x629a292a367cd507;0x9159015a3070dd17;0x152fecd8f70e5939;0x67332667ffc00b31;0x8eb44a8768581511;0xdb0c2e0d64f98fa7;0x47b5481dbefa4fa4);
H[512]:.cryptoq_binary.hex_to_bin@'(0x6a09e667f3bcc908;0xbb67ae8584caa73b;0x3c6ef372fe94f82b;0xa54ff53a5f1d36f1;0x510e527fade682d1;0x9b05688c2b3e6c1f;0x1f83d9abfb41bd6b;0x5be0cd19137e2179);

K[256]:.cryptoq_binary.hex_to_bin@'(0x428a2f98; 0x71374491; 0xb5c0fbcf; 0xe9b5dba5; 0x3956c25b; 0x59f111f1; 0x923f82a4; 0xab1c5ed5; 0xd807aa98; 0x12835b01; 0x243185be; 0x550c7dc3; 0x72be5d74; 0x80deb1fe; 0x9bdc06a7; 0xc19bf174; 0xe49b69c1; 0xefbe4786; 0x0fc19dc6; 0x240ca1cc; 0x2de92c6f; 0x4a7484aa; 0x5cb0a9dc; 0x76f988da; 0x983e5152; 0xa831c66d; 0xb00327c8; 0xbf597fc7; 0xc6e00bf3; 0xd5a79147; 0x06ca6351; 0x14292967; 0x27b70a85; 0x2e1b2138; 0x4d2c6dfc; 0x53380d13; 0x650a7354; 0x766a0abb; 0x81c2c92e; 0x92722c85; 0xa2bfe8a1; 0xa81a664b; 0xc24b8b70; 0xc76c51a3; 0xd192e819; 0xd6990624; 0xf40e3585; 0x106aa070; 0x19a4c116; 0x1e376c08; 0x2748774c; 0x34b0bcb5; 0x391c0cb3; 0x4ed8aa4a; 0x5b9cca4f; 0x682e6ff3; 0x748f82ee; 0x78a5636f; 0x84c87814; 0x8cc70208; 0x90befffa; 0xa4506ceb; 0xbef9a3f7; 0xc67178f2);

K[512]:.cryptoq_binary.hex_to_bin@'(0x428a2f98d728ae22; 0x7137449123ef65cd; 0xb5c0fbcfec4d3b2f; 0xe9b5dba58189dbbc; 0x3956c25bf348b538; 0x59f111f1b605d019; 0x923f82a4af194f9b; 0xab1c5ed5da6d8118; 0xd807aa98a3030242; 0x12835b0145706fbe;
        0x243185be4ee4b28c; 0x550c7dc3d5ffb4e2; 0x72be5d74f27b896f; 0x80deb1fe3b1696b1; 0x9bdc06a725c71235; 0xc19bf174cf692694; 0xe49b69c19ef14ad2; 0xefbe4786384f25e3; 0x0fc19dc68b8cd5b5; 0x240ca1cc77ac9c65;
        0x2de92c6f592b0275; 0x4a7484aa6ea6e483; 0x5cb0a9dcbd41fbd4; 0x76f988da831153b5; 0x983e5152ee66dfab; 0xa831c66d2db43210; 0xb00327c898fb213f; 0xbf597fc7beef0ee4; 0xc6e00bf33da88fc2; 0xd5a79147930aa725;
        0x06ca6351e003826f; 0x142929670a0e6e70; 0x27b70a8546d22ffc; 0x2e1b21385c26c926; 0x4d2c6dfc5ac42aed; 0x53380d139d95b3df; 0x650a73548baf63de; 0x766a0abb3c77b2a8; 0x81c2c92e47edaee6; 0x92722c851482353b;
        0xa2bfe8a14cf10364; 0xa81a664bbc423001; 0xc24b8b70d0f89791; 0xc76c51a30654be30; 0xd192e819d6ef5218; 0xd69906245565a910; 0xf40e35855771202a; 0x106aa07032bbd1b8; 0x19a4c116b8d2d0c8; 0x1e376c085141ab53;
        0x2748774cdf8eeb99; 0x34b0bcb5e19b48a8; 0x391c0cb3c5c95a63; 0x4ed8aa4ae3418acb; 0x5b9cca4f7763e373; 0x682e6ff3d6b2b8a3; 0x748f82ee5defb2fc; 0x78a5636f43172f60; 0x84c87814a1f0ab72; 0x8cc702081a6439ec;
        0x90befffa23631e28; 0xa4506cebde82bde9; 0xbef9a3f7b2c67915; 0xc67178f2e372532b; 0xca273eceea26619c; 0xd186b8c721c0c207; 0xeada7dd6cde0eb1e; 0xf57d4f7fee6ed178; 0x06f067aa72176fba; 0x0a637dc5a2c898a6;
        0x113f9804bef90dae; 0x1b710b35131c471b; 0x28db77f523047d84; 0x32caab7b40c72493; 0x3c9ebe0a15c9bebc; 0x431d67c49c100d4c; 0x4cc5d4becb3e42b6; 0x597f299cfc657e2a; 0x5fcb6fab3ad6faec; 0x6c44198c4a475817);

/ Functions
rrotate:.cryptoq_binary.rrotate;
rshift:.cryptoq_binary.rshift;
sch:{(x&y) <> z& not x};
smaj:{(x&y)<>(x&z)<>y&z};
 
/ ==================================
/      SHA256 Algo
/ ==================================

/ SHA 256 Functions
ssig1:{(<>) over rrotate[x;]each 2 13 22};
ssig2:{(<>) over rrotate[x;]each 6 11 25};
ssig3:{rrotate[x;7] <> rrotate[x;18] <> rshift[x;3]};
ssig4:{rrotate[x;17] <> rrotate[x;19] <> rshift[x;10]};
ssig3_4:{a: x rrotate\ 7,10; a <> (a[1] rrotate\ 1,1) <> x rshift\ 3,7 };
/ pad message
sha_message_padding:{[Bin] raze Bin,1b,#[512-mod[65+c;512];0b], .cryptoq_binary.int_to_bin_length[c:count Bin;64] };

/ returns words for block
sha_block_words_old:{[Block]
  W:32 cut Block;
  first ({m:x 0;i: x 1; (m,enlist (.cryptoq_binary.bin_modulo/)(ssig4[m i-2];m[i-7];ssig3[m i-15];m i-16) ;i+1)}/)[48;(W;16)]
 };

sha_block_words:{[Block]
 W:32 cut Block;
 first ({m:x 0;i: x 1; (m,enlist .cryptoq_binary.bin_modulo_list (ssig4[m i-2];m[i-7];ssig3[m i-15];m i-16) ;i+1)}/)[48;(W;16)]
 };

sha_compression:{[Block;hc]
  Words: sha_block_words Block;
  i:0;nhc:hc;
  while[i<64;nhc:sha_cal_hvals[Words;nhc;i];i:i+1];
  .cryptoq_binary.bin_modulo'[hc;nhc]
 };

/ calculate new H constants for sha256 block
sha_cal_hvals:{[Words;hc;i]
   a:hc 0;b:hc 1;c:hc 2 ;d:hc 3;e:hc 4;f:hc 5;g:hc 6;h:hc 7;
   t1:(.cryptoq_binary.bin_modulo/)(h;ssig2[e];sch[e;f;g];K[256;i];Words[i]);
   t2:.cryptoq_binary.bin_modulo[ssig1[a];smaj[a;b;c]];
   h:g; g:f; f:e; e:.cryptoq_binary.bin_modulo[d;t1]; d:c; c:b; b:a; a:.cryptoq_binary.bin_modulo[t1;t2];
   (a;b;c;d;e;f;g;h)
 };

/ sha 256 starting function
/ @param Msg (String) Message to hash
/ @param ShaNum (Integer) Sha Algo- 256|224
sha256_start:{[Msg;ShaNum]
  Bin: .cryptoq_binary.string_to_bin Msg;
  MsgPadded: sha_message_padding Bin;
  nblocks: count [MsgPadded] div 512;
  i:0; hc:H ShaNum;
  ind : til 512;
  while[i<nblocks; hc:sha_compression[MsgPadded (512*i)+ind;hc];i:i+1];
  .cryptoq_binary.bin_to_hex (,/)$[ShaNum=224;-1_hc;hc]
 };
/ =============

/ ==================================
/      SHA512 Algo
/ ==================================

/ SHA 512 Constants
H_512: (0x6a09e667f3bcc908; 0xbb67ae8584caa73b; 0x3c6ef372fe94f82b; 0xa54ff53a5f1d36f1; 0x510e527fade682d1; 0x9b05688c2b3e6c1f; 0x1f83d9abfb41bd6b; 0x5be0cd19137e2179);
K_512: (0x428a2f98d728ae22; 0x7137449123ef65cd; 0xb5c0fbcfec4d3b2f; 0xe9b5dba58189dbbc; 0x3956c25bf348b538; 0x59f111f1b605d019; 0x923f82a4af194f9b; 0xab1c5ed5da6d8118; 0xd807aa98a3030242; 0x12835b0145706fbe; 
        0x243185be4ee4b28c; 0x550c7dc3d5ffb4e2; 0x72be5d74f27b896f; 0x80deb1fe3b1696b1; 0x9bdc06a725c71235; 0xc19bf174cf692694; 0xe49b69c19ef14ad2; 0xefbe4786384f25e3; 0x0fc19dc68b8cd5b5; 0x240ca1cc77ac9c65; 
        0x2de92c6f592b0275; 0x4a7484aa6ea6e483; 0x5cb0a9dcbd41fbd4; 0x76f988da831153b5; 0x983e5152ee66dfab; 0xa831c66d2db43210; 0xb00327c898fb213f; 0xbf597fc7beef0ee4; 0xc6e00bf33da88fc2; 0xd5a79147930aa725; 
        0x06ca6351e003826f; 0x142929670a0e6e70; 0x27b70a8546d22ffc; 0x2e1b21385c26c926; 0x4d2c6dfc5ac42aed; 0x53380d139d95b3df; 0x650a73548baf63de; 0x766a0abb3c77b2a8; 0x81c2c92e47edaee6; 0x92722c851482353b; 
        0xa2bfe8a14cf10364; 0xa81a664bbc423001; 0xc24b8b70d0f89791; 0xc76c51a30654be30; 0xd192e819d6ef5218; 0xd69906245565a910; 0xf40e35855771202a; 0x106aa07032bbd1b8; 0x19a4c116b8d2d0c8; 0x1e376c085141ab53; 
        0x2748774cdf8eeb99; 0x34b0bcb5e19b48a8; 0x391c0cb3c5c95a63; 0x4ed8aa4ae3418acb; 0x5b9cca4f7763e373; 0x682e6ff3d6b2b8a3; 0x748f82ee5defb2fc; 0x78a5636f43172f60; 0x84c87814a1f0ab72; 0x8cc702081a6439ec; 
        0x90befffa23631e28; 0xa4506cebde82bde9; 0xbef9a3f7b2c67915; 0xc67178f2e372532b; 0xca273eceea26619c; 0xd186b8c721c0c207; 0xeada7dd6cde0eb1e; 0xf57d4f7fee6ed178; 0x06f067aa72176fba; 0x0a637dc5a2c898a6; 
        0x113f9804bef90dae; 0x1b710b35131c471b; 0x28db77f523047d84; 0x32caab7b40c72493; 0x3c9ebe0a15c9bebc; 0x431d67c49c100d4c; 0x4cc5d4becb3e42b6; 0x597f299cfc657e2a; 0x5fcb6fab3ad6faec; 0x6c44198c4a475817);

/ sch and smaj is same as SHA256
s512_sum1:{(<>) over rrotate[x;]each 28 34 39};
s512_sum2:{(<>) over rrotate[x;]each 14 18 41};
s512_sig1:{rrotate[x;1] <> rrotate[x;8] <> rshift[x;7]};
s512_sig2:{rrotate[x;19] <> rrotate[x;61] <> rshift[x;6]};

/ pad message
sha512_message_padding:{[Bin] raze Bin,1b,#[1024-mod[129+c;1024];0b], .cryptoq_binary.int_to_bin_length[c:count Bin;128] };

/ sha 512 starting function
/ @param Msg (String) Message to hash
/ @param ShaNum (Integer) Sha Algo- 256|384
sha512_start:{[Msg;ShaNum]
  Bin: .cryptoq_binary.string_to_bin Msg;
  MsgPadded: sha512_message_padding Bin;
  nblocks: count [MsgPadded] div 1024;
  i:0; hc:H ShaNum;
  ind : til 1024;
  while[i<nblocks; hc:sha512_compression[MsgPadded (1024*i)+ind;hc];i:i+1];
  .cryptoq_binary.bin_to_hex (,/)$[384=ShaNum;-2_hc;hc]
 };

sha512_block_words:{[Block]
 W:64 cut Block;
 first ({m:x 0;i:x 1; (m,enlist .cryptoq_binary.bin_modulo_64_list (s512_sig2[m i-2];m[i-7];s512_sig1[m i-15];m i-16) ;i+1)}/)[64;(W;16)]
 };

sha512_compression:{[Block;hc]
  Words: sha512_block_words Block;
  i:0;nhc:hc;
  while[i<80;nhc:sha512_cal_hvals[Words;nhc;i];i:i+1];
  .cryptoq_binary.bin_modulo_64'[hc;nhc]
 };

/ calculate new H constants for sha256 block
sha512_cal_hvals:{[Words;hc;i]
   a:hc 0;b:hc 1;c:hc 2 ;d:hc 3;e:hc 4;f:hc 5;g:hc 6;h:hc 7;
   t1:(.cryptoq_binary.bin_modulo_64/)(h;s512_sum2[e];sch[e;f;g];K[512;i];Words[i]);
   t2:.cryptoq_binary.bin_modulo_64[s512_sum1[a];smaj[a;b;c]];
   h:g; g:f; f:e; e:.cryptoq_binary.bin_modulo_64[d;t1]; d:c; c:b; b:a; a:.cryptoq_binary.bin_modulo_64[t1;t2];
   (a;b;c;d;e;f;g;h)
 };

/ =============
\d .
