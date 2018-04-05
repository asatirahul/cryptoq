\d .cryptoq_binary

hex: "0123456789abcdef";
htb:"0123456789abcdef"!-4#'0b vs/: hex?hex;

/ Hex To Binary
hex_to_bin:{raze htb raze  string x};

/ String to Binary
string_to_bin:{hex_to_bin "x"$ x};

/  Binary to hex string
bin_to_hexstr:{htb?4 cut (mod[8-count[x] mod 8;8]#0b),x};

/ Binary To Hexadecimal
bin_to_hex:{$[1=count d:"X"$/: 2 cut bin_to_hexstr x;first d;d]};

/ Integer to Binary
int_to_bin:{0b vs x};

/ 2^32 modulo of binaries using int  addition
int_modulo:{m:4294967296; s:sum[2 sv/:(x;y)]; if[s>=m;s:s mod m];-32#0b vs s};

/ 2^32 modulo binary addition
bin_modulo:{-32#0b vs sum 2 sv/:(x;y)};

/ checks if input is of type binary or hexadecimal
/ @param Data (Bin|Hex) binary or hex input
/ @return (Bool) return 1b is input is binary or hex
/ @throws  NOT_BIN_HEX_TYPE If input is not binary or hexadecimal
is_bin_hex:{[Data] $[abs[type Data] in 1 4h;1b;'NOT_BIN_HEX_TYPE]};

/ rotate binary left by n positions
/ @param Bin (Binary | Hex) Binary number
/ @ param n (int) position to shift
/ @return (Binary|Hex) Rotated Binary
lrotate:{[Bin;n] is_bin_hex Bin; n rotate  maybe_enlist_data Bin };

/ rotate binary left by n positions
/ @param Bin (Binary | Hex) Binary number
/ @ param n (int) position to shift
/ @return (Binary|Hex) Rotated Binary
rrotate:{[Bin;n] is_bin_hex Bin;neg[n] rotate maybe_enlist_data  Bin };

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
