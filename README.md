# HeapCalc




## Usage


### Malloc to Chunk

Calculate chunk size (64 bits):
```
heapcalc m2c 0
malloc: 0 0x0 chunk: 32 0x20
```

Calculate chunk size for 32 bits:
```
heapcalc m2c -b 32 16
malloc: 16 0x10 chunk: 24 0x18
```


### Chunk to Malloc

Calculate malloc range for a chunk size of 0x20 bytes (64 bits):
```
heapcalc c2m 0x20
chunk: 32 0x20 malloc: 0-24 0x0-0x18
```

Calculate malloc range for a chunk size of 0x20 bytes in 32 bits:
```
heapcalc c2m -b 32 0x20
chunk: 32 0x20 malloc: 21-28 0x15-0x1c
```
