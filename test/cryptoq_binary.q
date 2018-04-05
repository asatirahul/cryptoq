\l src/cryptoq_binary.q

.tst.desc["Binary Rotation"]{
  before{
    `Bin mock 1011b; / 13
  };
  should["Correctly Rotate Binary"]{
    .cryptoq_binary.rrotate[Bin;1] mustmatch 1101b;
    .cryptoq_binary.rrotate[Bin;6] mustmatch 1110b;
    .cryptoq_binary.lrotate[Bin;7] mustmatch 1101b;
    };
  should["Correctly Shift Binary"]{
    .cryptoq_binary.rshift[Bin;1] mustmatch 0101b;
    .cryptoq_binary.rshift[Bin;10] mustmatch 0000b;
    .cryptoq_binary.lshift[Bin;1] mustmatch 0110b;
    .cryptoq_binary.rshift[Bin;10] mustmatch 0000b;
  };

 };

.tst.desc["Modulo Addition"]{
   before{
     `Bin1 mock .cryptoq_binary.int_to_bin 2000000000;
     `Bin2 mock .cryptoq_binary.int_to_bin 3000000000;
     `Res mock -32#.cryptoq_binary.int_to_bin 705032704;
   };
   should["Correctly Modulo 2^32 addition"]{
     .cryptoq_binary.bin_modulo[Bin1;Bin2] mustmatch Res;
     };
  };
