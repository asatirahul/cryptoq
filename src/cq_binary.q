\d .cq_binary

hex: "0123456789abcdef";
string_to_bin:{[Str] hex_to_bin  "x"$Str};
hex_to_bin:{(,/)0b vs/:x};
bin_to_hexstr:{hex 2 sv/: 4 cut x};
bin_to_hextype:{raze last each 0x0 vs/: 2 sv/: 8 cut x};
int_to_bin:{0b vs x};

/ 2^32 modulo addition
modulo:{m:4294967296; s:sum[2 sv/:(x;y)]; if[s>=m;s:s mod m];-32#0b vs s};

/ checks if input is of type binary or hexadecimal
/ @param Data (Bin|Hex) binary or hex input
/ @return (Bool) return 1b is input is binary or hex
/ @throws  NOT_BIN_HEX_TYPE If input is not binary or hexadecimal
is_bin_hex:{[Data] $[abs[type Data] in 1 4h;1b;'NOT_BIN_HEX_TYPE]};

/ rotate binary left by n positions
/ @param Bin (Binary | Hex) Binary number
/ @ param n (int) position to shift
/ @return (Binary|Hex) Rotated Binary
lrotate:{[Bin;n] .cq_binary.is_bin_hex Bin; n rotate  maybe_enlist_data Bin };

/ rotate binary left by n positions
/ @param Bin (Binary | Hex) Binary number
/ @ param n (int) position to shift
/ @return (Binary|Hex) Rotated Binary
rrotate:{[Bin;n] .cq_binary.is_bin_hex Bin;neg[n] rotate maybe_enlist_data  Bin };

/ left shift binary by n positions
/ @param Bin (Binary | Hex) Binary number
/ @ param n (int) position to shift
/ @return (Binary|Hex) Shifted Data
lshift:{[Bin;n] @[lrotate[Bin;n];c-1+til min n,c:count Bin;:;(0b;0x00)4h= abs type Bin]}

/ right shift binary by n positions
/ @param Bin (Binary | Hex) Binary number
/ @ param n (int) position to shift
/ @return (Binary|Hex) Shifted  Data
rshift:{[Bin;n] @[rrotate[Bin;n];til min n,count Bin;:;(0b;0x00)4h= abs type Bin]};

/ enlist Input if it is an atom else return Input
/ @param Data (any) Any Input type
/ @return (List)
maybe_enlist_data:{[Data] (Data;enlist Data)0>type Data};

\d .
