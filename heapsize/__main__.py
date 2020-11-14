import argparse
import sys
from typing import Any, Iterator, Optional
import logging
from functools import partial

logger = logging.getLogger(__name__)

COUNT_TCACHES = 64
COUNT_FASTBINS = 10
COUNT_SMALL_BINS_32 = 63
COUNT_SMALL_BINS_64 = 62
COUNT_LARGE_BINS_32 = 63
COUNT_LARGE_BINS_64 = 64
COUNT_DOUBLE_BINS = 127


def parse_args():
    parser = argparse.ArgumentParser(
        description="Calculate the real size of a chunk allocated with malloc"
    )
    cmd_parsers = parser.add_subparsers()
    cmd_parsers.required = True
    cmd_parsers.dest = 'command'

    m2c_parser = cmd_parsers.add_parser(
        "m2c",
        help="Converts malloc size into a chunk size"
    )

    m2c_parser.add_argument(
        "size",
        help="Size of the chunk to calculate",
        nargs="*",
    )

    m2c_parser.add_argument(
        "-f", "--format",
        help="Output format string.",
        choices=["d", "dec", "h", "hex", "hexa"],
        default="h"
    )

    m2c_parser.add_argument(
        "-a", "--arch",
        choices=[32, 64],
        type=int,
        default=64,
        help="Architecture of the program."
    )

    m2c_parser.add_argument(
        "-v",
        help="Verbosity",
        action="count",
        default=0
    )

    c2m_parser = cmd_parsers.add_parser(
        "c2m",
        help="Converts chunk size into the malloc size range"
    )

    c2m_parser.add_argument(
        "size",
        help="Size of the chunk to calculate",
        nargs="*",
    )

    c2m_parser.add_argument(
        "-f", "--format",
        help="Output format string.",
        choices=["d", "dec", "h", "hex", "hexa"],
        default="h"
    )

    c2m_parser.add_argument(
        "-a", "--arch",
        choices=[32, 64],
        type=int,
        default=64,
        help="Architecture of the program."
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
    )

    b2s_parser.add_argument(
        "bin",
        help="Bin to get the size or size range",
        nargs="*",
    )

    b2s_parser.add_argument(
        "-a", "--arch",
        choices=[32, 64],
        type=int,
        default=64,
        help="Architecture of the program."
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
        help="Indicates what bin corresponds to a chunk size."
    )

    s2b_parser.add_argument(
        "size",
        help="Size of the chunk.",
        nargs="*",
    )

    s2b_parser.add_argument(
        "-a", "--arch",
        choices=[32, 64],
        type=int,
        default=64,
        help="Architecture of the program."
    )

    args = parser.parse_args()

    try:
        if args.format.startswith("d"):
            args.format = "dec"
        elif args.format.startswith("h"):
            args.format = "hex"
    except AttributeError:
        pass

    return args


def dec_or_hex_int(v: str):
    try:
        if v.startswith("0x"):
            return int(v, 16)

        return int(v)
    except ValueError:
        raise ValueError("'%s' is not decimal or hex")


def main():
    args = parse_args()
    init_log(args.v)
    arch = args.arch

    if args.command == "c2m":
        targets = args.size
        command_func = partial(
            chunk_2_malloc_size,
            arch=arch,
            print_format=args.format
        )
    elif args.command == "m2c":
        targets = args.size
        command_func = partial(
            malloc_2_chunk_size,
            arch=arch,
            print_format=args.format
        )
    elif args.command == "b2s":
        targets = args.bin
        command_func = partial(
            bin_2_chunk_size,
            arch=arch,
            use_malloc_size=args.use_malloc_size,
        )
    else:
        raise NotImplementedError("Unknonw command '%s'" % args.command)

    for target in read_text_targets(targets):
        command_func(target)


def bin_2_chunk_size(bin_id: str, arch: int, use_malloc_size: bool):
    try:
        bin_type, bin_index = parse_bin_id(bin_id, arch)
    except ValueError as ex:
        logger.warning(ex)
        return

    if bin_type in ["tcache", "small", "fast"]:
        min_size = arch // 2
        bin_min_size = min_size + 0x10 * (bin_index - 1)
        bin_max_size = bin_min_size

    elif bin_type == "large":
        if bin_index < 34:
            min_size = 0x400
            bin_min_size = min_size + 0x40 * (bin_index - 1)
            bin_max_size = bin_min_size + 0x30

        elif bin_index == 34:
            bin_min_size = 0xc40
            bin_max_size = 0xdf0
        elif bin_index < 49:
            min_size = 0xe00
            bin_min_size = min_size + 0x200 * (bin_index - 35)
            bin_max_size = bin_min_size + 0x1f0
        elif bin_index < 57:
            min_size = 0x2a00
            bin_min_size = min_size + 0x1000 * (bin_index - 49)
            bin_max_size = bin_min_size + 0xff0
        elif bin_index == 57:
            bin_min_size = 0xaa00
            bin_max_size = bin_min_size + 0x6000 - 0x10
        else:
            min_size = 0x10a00
            bin_min_size = min_size + 0x8000 * (bin_index - 58)
            bin_max_size = bin_min_size + 0x7ff0

    elif bin_type == "unsorted":
        print("%s 0x400-???" % (bin_id))
        return
    else:
        raise NotImplementedError("Unreachable code: bin type '%s'" % bin_type)

    if use_malloc_size:
        min_min_size, min_max_size = calc_malloc_size(bin_min_size, arch)
        max_min_size, max_max_size = calc_malloc_size(bin_max_size, arch)

        bin_min_size = min_min_size
        bin_max_size = max_max_size

    if bin_min_size == bin_max_size:
        print("%s 0x%x" % (bin_id, bin_min_size))
    else:
        print("%s 0x%x-0x%x" % (bin_id, bin_min_size, bin_max_size))


def parse_bin_id(bin_id: str, arch: int) -> (str, int):
    if bin_id == "u":
        return "unsorted", 0

    try:
        if bin_id.startswith("s"):
            bin_type = "small"
            bin_index = bin_id[1:]
            if arch == 64:
                max_index = COUNT_SMALL_BINS_64
            else:
                max_index = COUNT_SMALL_BINS_32

            bin_index = _parse_bin_index(bin_id[1:], max_index)
            return bin_type, bin_index

        elif bin_id.startswith("l"):
            bin_type = "large"
            if arch == 64:
                max_index = COUNT_LARGE_BINS_64
            else:
                max_index = COUNT_LARGE_BINS_32

            bin_index = _parse_bin_index(bin_id[1:], max_index)
            return bin_type, bin_index

        elif bin_id.startswith("b"):
            bin_type = ""
            bin_index = _parse_bin_index(bin_id[1:], COUNT_DOUBLE_BINS)

            if arch == 64:
                start_large_index = 64
            else:
                start_large_index = 65

            if bin_index == 1:
                return "unsorted", 0
            elif bin_index < start_large_index:
                return "small", bin_index - 1
            else:
                return "large", bin_index - start_large_index + 1

        elif bin_id.startswith("f"):
            bin_type = "fast"
            bin_index = _parse_bin_index(bin_id[1:], COUNT_FASTBINS)
            return bin_type, bin_index

        elif bin_id.startswith("t"):
            bin_type = "tcache"
            bin_index = _parse_bin_index(bin_id[1:], COUNT_TCACHES)
            return bin_type, bin_index

    except ValueError:
        raise ValueError("Invalid bin '%s'" % bin_id)

    raise ValueError("Unknown bin '%s'" % bin_id)


def _parse_bin_index(bin_index: str, max_index: int):
    bin_index = int(bin_index)
    if bin_index < 1 or bin_index > max_index:
        raise ValueError()

    return bin_index


def chunk_2_malloc_size(chunk_size: int, arch: int, print_format: str):
    try:
        chunk_size = dec_or_hex_int(chunk_size)
        (min_size, max_size) = calc_malloc_size(chunk_size, arch=arch)
    except ValueError as ex:
        logger.warning(ex)
        return

    if print_format.startswith("h"):
        format_str = "0x%x 0x%x-0x%x"
    else:
        format_str = "%d %d-%d"
    print(format_str % (chunk_size, min_size, max_size))


def calc_malloc_size(chunk_size: int, arch: int) -> (int, int):
    size_mul = arch//32
    min_size = 0x10 * size_mul

    if chunk_size < min_size:
        raise ValueError(
            "Invalid chunk size 0x%x for arch %d: Too small" % (
                chunk_size, arch
            )
        )

    chunk_size = remove_chunk_size_flags(chunk_size)

    max_size = chunk_size - (4 * size_mul)
    min_size = max_size - 15

    if min_size < 10:
        min_size = 0

    return min_size, max_size


def remove_chunk_size_flags(chunk_size: int) -> int:
    return chunk_size & ~0x7


def malloc_2_chunk_size(malloc_size: int, arch: int, print_format: str):
    try:
        malloc_size = dec_or_hex_int(malloc_size)
    except ValueError as ex:
        logger.warning(ex)
        return

    chunk_size = calc_chunk_size(malloc_size, arch=arch)

    if print_format.startswith("h"):
        format_str = "0x%x 0x%x"
    else:
        format_str = "%d %d"
    print(format_str % (malloc_size, chunk_size))


def calc_chunk_size(malloc_size: int, arch: int = 64) -> int:

    if arch == 64:
        x = -9
        min_size = 0x20
    else:
        x = 3
        min_size = 0x10

    chunk_size = ((malloc_size+x)//16)*16+min_size

    return max(chunk_size, min_size)


def size_2_bins(chunk_size: int, arch: int):
    size_mul = arch//32
    min_size = 0x10 * size_mul

    if chunk_size < min_size:
        raise ValueError(
            "Invalid chunk size 0x%x for arch %d: Too small" % (
                chunk_size, arch
            )
        )

    chunk_size = remove_chunk_size_flags(chunk_size)

    bins_indexes = []
    small_index = (chunk_size - min_size)//0x10

    if is_size_in_tcache(chunk_size, arch):
        bins_indexes.append("tcache %d" % small_index)

    pass


def is_size_in_fastbin(size: int, arch: int) -> bool:
    min_size = arch//2
    max_size = min_size + 0x10 * 9
    return min_size <= size <= max_size


def is_size_in_tcache(size: int, arch: int) -> bool:
    min_size = arch//2
    max_size = min_size + 0x10 * 63
    return min_size <= size <= max_size


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
