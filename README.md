# BytesProcesser
This class allows to efficiently convert bigger than memory pcap files to a labeled feature-per-byte dataset in parquet format
This allows for AI developers to access a dataset with a feature space of the first 1525 bytes of the ip layer as described on https://arxiv.org/pdf/2305.11039.pdf

The class uses the times and ips involved in events to extract and label the data, 
It also uses an additional time ranges list to consider when extracting data from the pcap even outside the events

Contributions are welcome, some points to work on are:
-Include support port filtering logic
-Include support for pcapng, possibly using a different parser than dpkt
-Include support for more protocols


