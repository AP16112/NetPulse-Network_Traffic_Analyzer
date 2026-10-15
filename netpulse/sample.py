"""Create a repeatable, offline PCAP fixture: python -m netpulse.sample."""
import argparse
import random
from scapy.all import PcapWriter
from .capture import demo_packets


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic traffic; sends no packets.")
    parser.add_argument("output", nargs="?", default="sample.pcap")
    args = parser.parse_args()
    rng = random.Random(42)
    with PcapWriter(args.output, linktype=1, sync=True) as writer:
        for second in range(90):
            for packet in demo_packets(1_700_000_000 + second, 95 if second in (35, 70) else rng.randint(6, 16), rng):
                writer.write(packet)
    print(f"Created {args.output}. Import it using PCAP file mode.")


if __name__ == "__main__":
    main()
