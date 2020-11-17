
X86 = "x86"
COUNT_TCACHES = 64
COUNT_FASTBINS = 10


class HeapConfig:

    def __init__(self, bits, arch, libc_version):
        self.bits = bits
        self.arch = arch
        self.libc_version = libc_version

        if bits == 64:
            self.align = 16
            self.small_bins_count = 62
        else:
            if arch == X86 and libc_version >= 26:
                self.align = 16
                self.small_bins_count = 63
            else:
                self.align = 8
                self.small_bins_count = 62

        self.min_chunk_size = bits//2

        self.large_bins_count = 126 - self.small_bins_count - 1
        self.start_large_index = self.small_bins_count + 2

        self.tcaches_count = COUNT_TCACHES
        self.fastbins_count = COUNT_FASTBINS
        self.double_bins_count = 126
