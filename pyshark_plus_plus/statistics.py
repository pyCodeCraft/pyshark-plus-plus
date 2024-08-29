import re


def parse_io_statistics(stdout: str):

    # Extract the duration and interval
    duration_match = re.search(r'Duration: (\d+\.\d+) secs', stdout)
    interval_match = re.search(r'Interval: (\d+\.\d+) secs', stdout)
    duration = float(duration_match.group(1)) if duration_match else None
    interval = float(interval_match.group(1)) if interval_match else None

    # Extract the frames and bytes information
    frames = int(stdout.splitlines()[-2].split('|')[-2].strip())
    bytes_ = int(stdout.splitlines()[-2].split('|')[-3].strip())

    # Create the PCAP statistics dictionary
    pcap_statistics = {
        'duration': duration,
        'interval': interval,
        'frames': frames,
        'bytes': bytes_,
    }

    return pcap_statistics
