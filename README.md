# GMCalc

gmcalc is a glibc malloc calculator that allows to found the relations between 
the malloc sizes, the chunk sizes and the bins.

It allowes to answer questions like the following:
- What bins can be used after freeing a chunk created with `malloc(78)`?

```
$ gmcalc s2b -m 78
chunk: 0x60 bins: fastbin[5] small[5](bins[6])
```
Ok, so I will look in the fastbin 5 with my favorite debugger.

- How many bytes do I need to allocate with malloc to create a chunk of 0x80 bytes?
```
$ gmcalc c2m 0x80
chunk: 128 0x80 malloc: 105-120 0x69-0x78
```
Nice, I need to call `malloc(105)` to create a chunk of 0x80 bytes. Pwn is coming... ;)


## Installation

From pypi:
```
pip3 install gmcalc
```

From repo:
```
git clone ...
cd gmcalc/
pip install .
```

## Usage


### Environment parameters

The glibc bins and aligments varies in function of the glibc version, program
architecture and bits, therefore you can specify the following arguments to
perform calculations in your desired environment.

In each command you can specify:
- `-b/--bits` -> The programs bits: 32 or 64.
- `-g/--glibc` -> The glibc 2 minor version.
- `-n/--no-x86` -> If the architecture is x86 or another.

The bits of the program determine the minimum chunk size (because of the size 
of `size_t` type), which also influences bins and their sizes ranges.

Moreover, since glibc version 2.26, the chunks in programs with x86 
architecture are always aligned with 16 bytes, regardless of the bits. Due to 
this, if architecture is x86 is taken into account.


### Malloc to Chunk

The command `m2c` (malloc to chunk), allows to calculate the size of the
chunk allocated for a malloc of given size.

Calculate chunk size of `malloc(0)` (64 bits):
```
$ gmcalc m2c 0
malloc: 0 0x0 chunk: 32 0x20
```

Calculate chunk size of `malloc(16)` in 32 bits:
```
$ gmcalc m2c -b 32 16
malloc: 16 0x10 chunk: 24 0x18
```

### Chunk to Malloc

The command `c2m` (chunk to malloc) indicates the range of size range you can
pass to malloc in order to produce a chunk of the given size.

Calculate malloc range for a chunk size of 0x20 bytes (64 bits):
```
$ gmcalc c2m 0x20
chunk: 32 0x20 malloc: 0-24 0x0-0x18
```

Calculate malloc range for a chunk size of 0x20 bytes in 32 bits:
```
$ gmcalc c2m -b 32 0x20
chunk: 32 0x20 malloc: 21-28 0x15-0x1c
```

### Bin to Size

The command `b2s` (Bin to Size) indicates the chunk sizes that can be found
in the given bin.

Size of the fastbin 5:
```
$ gmcalc b2s f5
bin: fast[5] chunk: 0x60 malloc: 0x49-0x58
```

The way to specify a bin is using a prefix and a index in one of the following ways:
- `<prefix><index>` -> `small1`
- `<prefix>[<index>]` -> `small[1]`
- `<prefix>:<index>` -> `small:1`

There is an special case, the unsorted bin, which doesn't require an index.

The prefixes are the following:
- small -> s, small. E.g: small1, s1.
- large bins -> l, large. E.g: l1, large1.
- unsorted bin -> u, unsorted. E.g: u, unsorted.
- double bins (the attribute bins of malloc_state) -> b, bin, bins. E.g: b1, bin1, bins1.
- fast bins -> f, fast. E.g: f1, fast1.
- tcaches -> t, tcache. E.g: t1, tcache1.


### Size to Bin

The command `s2b` (Size to Bin) indicates the bins where a chunk of a given
size can be inserted. Any chunk range can be inserted in the unsorted bin, so
this is not shown.

Note: Tcache bin is only shown if glibc version is 2.26 or older.

Bins for a chunk of 0x60 bytes (glibc 19):
```
$ gmcalc s2b 0x60
chunk: 0x60 bins: fastbin[5] small[5](bins[6])
```

Bins for a chunk of 0x60 in glibc 26:
```
$ gmcalc s2b 0x60 -g 26
chunk: 0x60 bins: tcache[5] fastbin[5] small[5](bins[6])
```

Bins for a chunk allocated with `malloc(1337)`:
```
$ gmcalc s2b 1337 -m 
chunk: 0x550 bins: large[5](bins[69])
```

