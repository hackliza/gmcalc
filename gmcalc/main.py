import argparse
import sys
from typing import Any, Iterator, Optional
import logging
from functools import partial
from .heap_config import HeapConfig, X86
from .large_bins import calc_large_bin_size, calc_large_bin_index

logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Calculate the real size of a chunk allocated with malloc",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    cmd_parsers = parser.add_subparsers()
    cmd_parsers.required = True
    cmd_parsers.dest = 'command'

    m2c_parser = cmd_parsers.add_parser(
        "m2c",
        help="Malloc size to Chunk size",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    m2c_parser.add_argument(
        "size",
        help="Chunk size.",
        nargs="*",
    )

    m2c_parser.add_argument(
        "-n", "--no-x86",
        help="Architecture is not x86.",
        action="store_true",
    )

    m2c_parser.add_argument(
        "-b", "--bits",
        choices=[32, 64],
        type=int,
        default=64,
        help="Program bits."
    )

    m2c_parser.add_argument(
        "-g", "--glibc",
        metavar="VERSION",
        type=glibc_version,
        default=19,
        help="Version of the glibc 2. e.g: 19, 2.19"
    )

    m2c_parser.add_argument(
        "-v",
        help="Verbosity",
        action="count",
        default=0
    )

    c2m_parser = cmd_parsers.add_parser(
        "c2m",
        help="Chunk size to Malloc size range",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    c2m_parser.add_argument(
        "size",
        help="Size of the chunk to calculate",
        nargs="*",
    )

    c2m_parser.add_argument(
        "-n", "--no-x86",
        help="Indicates that architecture is not x86",
        action="store_true",
    )

    c2m_parser.add_argument(
        "-b", "--bits",
        choices=[32, 64],
        type=int,
        default=64,
        help="Bits of the program."
    )

    c2m_parser.add_argument(
        "-g", "--glibc",
        metavar="VERSION",
        type=glibc_version,
        default=19,
        help="Version of the glibc 2. e.g: 19, 2.19"
    )

    c2m_parser.add_argument(
        "-v",
        help="Verbosity",
        action="count",
        default=0
    )

    b2s_parser = cmd_parsers.add_parser(
        "b2s",
        help="Gets the chunks size of a given bin",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    b2s_parser.add_argument(
        "bin",
        help="Bin to get the size or size range",
        nargs="*",
    )

    b2s_parser.add_argument(
        "-n", "--no-x86",
        help="Indicates that architecture is not x86",
        action="store_true",
    )

    b2s_parser.add_argument(
        "-b", "--bits",
        choices=[32, 64],
        type=int,
        default=64,
        help="Bits of the program."
    )

    b2s_parser.add_argument(
        "-g", "--glibc",
        metavar="VERSION",
        type=glibc_version,
        default=19,
        help="Version of the glibc 2. e.g: 19, 2.19"
    )

    b2s_parser.add_argument(
        "-m", "--malloc",
        action="store_true",
        help="Display malloc size instead of chunk size.",
        dest="use_malloc_size",
    )

    b2s_parser.add_argument(
        "-v",
        help="Verbosity",
        action="count",
        default=0
    )

    s2b_parser = cmd_parsers.add_parser(
        "s2b",
        help="Indicates what bin corresponds to a chunk size.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    s2b_parser.add_argument(
        "size",
        help="Size of the chunk.",
        nargs="*",
    )

    s2b_parser.add_argument(
        "-n", "--no-x86",
        help="Indicates that architecture is not x86",
        action="store_true",
    )

    s2b_parser.add_argument(
        "-b", "--bits",
        choices=[32, 64],
        type=int,
        default=64,
        help="Bits of the program."
    )

    s2b_parser.add_argument(
        "-g", "--glibc",
        metavar="VERSION",
        type=glibc_version,
        default=19,
        help="Version of the glibc 2. e.g: 19, 2.19"
    )

    s2b_parser.add_argument(
        "-m", "--malloc",
        action="store_true",
        help="Display malloc size instead of chunk size.",
        dest="use_malloc_size",
    )

    s2b_parser.add_argument(
        "-v",
        help="Verbosity",
        action="count",
        default=0
    )

    args = parser.parse_args()

    try:
        if args.format.startswith("d"):
            args.format = "dec"
        elif args.format.startswith("h"):
            args.format = "hex"
    except AttributeError:
        pass

    if args.no_x86:
        args.arch = "other"
    else:
        args.arch = X86

    return args


def glibc_version(v: str):
    versions = v.split(".")

    if len(versions) == 1:
        return int(versions[0])

    return int(versions[1])


def dec_or_hex_int(v: str):
    try:
        if v.startswith("0x"):
            return int(v, 16)

        return int(v)
    except ValueError:
        raise ValueError("'%s' is not decimal or hex" % v)


def main():
    args = parse_args()
    init_log(args.v)

    config = HeapConfig(
        bits=args.bits,
        arch=args.arch,
        libc_version=args.glibc
    )

    logger.info("glibc version: 2.%s", config.libc_version)
    logger.info("bits: %s", config.bits)
    logger.info("arch: %s", config.arch)
    logger.info("align: %s", config.align)
    logger.info("min chunk size: %s", config.min_chunk_size)
    logger.info("small bins count: %s", config.small_bins_count)
    logger.info("large bins count: %s", config.large_bins_count)
    logger.info("fast bins count: %s", config.fastbins_count)
    logger.info("tcaches count: %s", config.tcaches_count)

    if args.command == "c2m":
        targets = args.size
        command_func = partial(
            chunk_2_malloc_size,
            config=config,
        )
    elif args.command == "m2c":
        targets = args.size
        command_func = partial(
            malloc_2_chunk_size,
            config=config,
        )
    elif args.command == "b2s":
        targets = args.bin
        command_func = partial(
            bin_2_chunk_size,
            config=config,
            use_malloc_size=args.use_malloc_size,
        )
    elif args.command == "s2b":
        targets = args.size
        command_func = partial(
            size_2_bins,
            config=config,
            use_malloc_size=args.use_malloc_size,
        )
    else:
        raise NotImplementedError("Unknonw command '%s'" % args.command)

    for target in read_text_targets(targets):
        command_func(target)


def bin_2_chunk_size(
        bin_id: str,
        config: HeapConfig,
        use_malloc_size: bool
):
    try:
        bin_type, bin_index = parse_bin_id(bin_id, config)
    except ValueError as ex:
        logger.warning(ex)
        return

    if bin_type in ["tcache", "small", "fast"]:
        min_size = config.min_chunk_size
        bin_min_size = min_size + config.align * (bin_index - 1)
        bin_max_size = bin_min_size
        bin_name = "%s[%d]" % (bin_type, bin_index)

        if bin_type == "small":
            bin_name += "(bins[%d])" % (bin_index + 1)

    elif bin_type == "large":
        bin_min_size, bin_max_size = calc_large_bin_size(bin_index, config)
        bin_name = "large[%d](bins[%d])" % (
            bin_index, bin_index + config.start_large_index - 1)

    elif bin_type == "unsorted":
        bin_name = "unsorted(bins[1])"
        bin_min_size = config.min_chunk_size
        bin_max_size = -1
    else:
        raise NotImplementedError("Unreachable code: bin type '%s'" % bin_type)

    if bin_min_size == -1:
        malloc_min_size = bin_min_size = "??"
    else:
        malloc_min_size, _ = calc_malloc_size(bin_min_size, config)
        malloc_min_size = "0x%x" % malloc_min_size
        bin_min_size = "0x%x" % bin_min_size

    if bin_max_size == -1:
        malloc_max_size = bin_max_size = "??"
    else:
        _, malloc_max_size = calc_malloc_size(bin_max_size, config)
        malloc_max_size = "0x%x" % malloc_max_size
        bin_max_size = "0x%x" % bin_max_size

    if bin_min_size == bin_max_size:
        chunk_str = "chunk: %s" % bin_min_size
    else:
        chunk_str = "chunk: %s-%s" % (bin_min_size, bin_max_size)

    malloc_str = "malloc: %s-%s" % (malloc_min_size, malloc_max_size)

    print("bin: %s %s %s" % (bin_name, chunk_str, malloc_str))


def parse_bin_id(
        bin_id: str,
        config: HeapConfig,
) -> (str, int):
    bin_id = bin_id.lower()

    if bin_id == "u" or bin_id == "unsorted":
        return "unsorted", 0

    bins_desc = [
        {
            "name": "small",
            "prefix": ["small", "s"],
            "count": config.small_bins_count,
        },
        {
            "name": "large",
            "prefix": ["large", "l"],
            "count": config.large_bins_count,
        },
        {
            "name": "fast",
            "prefix": ["fastbin", "fast", "f"],
            "count": config.fastbins_count,
        },
        {
            "name": "tcache",
            "prefix": ["tcache", "t"],
            "count": config.tcaches_count,
        },
        {
            "name": "bin",
            "prefix": ["bins", "bin", "b"],
            "count": config.double_bins_count,
        }
    ]

    try:
        for bin_desc in bins_desc:
            for prefix in bin_desc["prefix"]:
                if bin_id.startswith(prefix):
                    bin_index = bin_id[len(prefix):]

                    # to allow formats like large[4] or small:1
                    bin_index = bin_index.lstrip(":[").rstrip("]")

                    bin_index = _parse_bin_index(
                        bin_index,
                        bin_desc["count"]
                    )
                    if bin_desc["name"] != "bin":
                        return bin_desc["name"], bin_index

                    if bin_index == 1:
                        return "unsorted", 0
                    elif bin_index < config.start_large_index:
                        return "small", bin_index - 1
                    else:
                        return "large", bin_index - \
                            config.start_large_index + 1

    except ValueError as ex:
        raise ValueError("Invalid bin '%s': %s" % (bin_id, ex))

    raise ValueError("Unknown bin '%s'" % bin_id)


def _parse_bin_index(bin_index: str, max_index: int):
    bin_index = dec_or_hex_int(bin_index)
    if bin_index < 1 or bin_index > max_index:
        raise ValueError("Index must be in range 1-%d" % (max_index))

    return bin_index


def chunk_2_malloc_size(
        chunk_size: int,
        config: HeapConfig,
):
    try:
        chunk_size = dec_or_hex_int(chunk_size)
        (min_size, max_size) = calc_malloc_size(
            chunk_size,
            config=config,
        )
    except ValueError as ex:
        logger.warning(ex)
        return

    print(
        "chunk: %d 0x%x malloc: %d-%d 0x%x-0x%x" % (
            chunk_size, chunk_size, min_size, max_size, min_size, max_size
        )
    )


def calc_malloc_size(
        chunk_size: int,
        config: HeapConfig,
) -> (int, int):
    chunk_size = remove_chunk_size_flags(chunk_size)
    check_chunk_size(chunk_size, config)

    max_size = chunk_size - (config.bits//8)
    min_size = max_size - (config.align - 1)

    if min_size < 10:
        min_size = 0

    return min_size, max_size


def check_chunk_size(chunk_size: int, config: HeapConfig):
    if chunk_size < config.min_chunk_size:
        raise ValueError(
            "Size 0x%x is too small for %d bits. Min is 0x%x." % (
                chunk_size, config.bits, config.min_chunk_size
            )
        )

    if chunk_size % config.align != 0:
        raise ValueError(
            "Invalid chunk size 0x%x: Not aligned with %d" % (
                chunk_size, config.align
            )
        )


def remove_chunk_size_flags(chunk_size: int) -> int:
    return chunk_size & ~0x7


def malloc_2_chunk_size(
        malloc_size: int,
        config: HeapConfig,
):
    try:
        malloc_size = dec_or_hex_int(malloc_size)
    except ValueError as ex:
        logger.warning(ex)
        return

    chunk_size = calc_chunk_size(
        malloc_size,
        config=config,
    )

    print(
        "malloc: %d 0x%x chunk: %d 0x%x" % (
            malloc_size, malloc_size, chunk_size, chunk_size
        )
    )


def calc_chunk_size(
        malloc_size: int,
        config: HeapConfig,
) -> int:

    if config.bits == 64:
        x = -9
    else:
        if config.align == 16:
            x = 3
        else:
            x = -5

    chunk_size = ((malloc_size+x)//config.align) * \
        config.align + config.min_chunk_size

    return max(chunk_size, config.min_chunk_size)


def size_2_bins(size: int, config: HeapConfig, use_malloc_size: bool):
    try:
        size = dec_or_hex_int(size)

        if use_malloc_size:
            chunk_size = calc_chunk_size(size, config)
        else:
            chunk_size = remove_chunk_size_flags(size)

        check_chunk_size(chunk_size, config)

    except ValueError as ex:
        logger.warning(ex)
        return

    small_index = (chunk_size - config.min_chunk_size) // config.align + 1
    bins = []
    if is_size_in_tcache(chunk_size, config):
        bins.append("tcache[%d]" % small_index)

    if is_size_in_fastbin(chunk_size, config):
        bins.append("fastbin[%d]" % small_index)

    if is_size_in_small_bin(chunk_size, config):
        bins.append("small[%d](bins[%d])" % (small_index, small_index + 1))

    else:
        bins_index = calc_large_bin_index(chunk_size, config)
        bins.append("large[%d](bins[%d])" % (
            bins_index - config.start_large_index, bins_index))

    if chunk_size >= 0x20000:
        bins.append("mmap")

    print("chunk: 0x%x bins: %s" % (chunk_size, " ".join(bins)))


def is_size_in_fastbin(size: int, config: HeapConfig) -> bool:
    max_size = config.min_chunk_size + config.align * 9
    return config.min_chunk_size <= size <= max_size


def is_size_in_tcache(size: int, config: HeapConfig) -> bool:
    if config.libc_version < 26:
        return False

    max_size = config.min_chunk_size + config.align * 63
    return config.min_chunk_size <= size <= max_size


def is_size_in_small_bin(size: int, config: HeapConfig) -> bool:
    max_size = config.min_chunk_size + \
        config.align * (config.small_bins_count - 1)
    return config.min_chunk_size <= size <= max_size


def init_log(verbosity=0, log_file=None):

    if verbosity == 1:
        level = logging.INFO
    elif verbosity > 1:
        level = logging.DEBUG
    else:
        level = logging.WARN

    logging.basicConfig(
        level=level,
        filename=log_file,
        format="%(levelname)s:%(name)s:%(message)s"
    )


def read_text_targets(targets: Any) -> Iterator[str]:
    yield from read_text_lines(read_targets(targets))


def read_targets(targets: Optional[Any]) -> Iterator[str]:
    """Function to process the program ouput that allows to read an array
    of strings or lines of a file in a standard way. In case nothing is
    provided, input will be taken from stdin.
    """
    if not targets:
        yield from sys.stdin

    for target in targets:
        try:
            with open(target) as fi:
                yield from fi
        except FileNotFoundError:
            yield target


def read_text_lines(fd: Iterator[str]) -> Iterator[str]:
    """To read lines from a file and skip empty lines or those commented
    (starting by #)
    """
    for line in fd:
        line = line.strip()
        if line == "":
            continue
        if line.startswith("#"):
            continue

        yield line


if __name__ == '__main__':
    main()
