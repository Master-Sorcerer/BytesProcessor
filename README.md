# BytesProcessor

<img src="https://i.imgur.com/cTlLveD_d.webp?maxwidth=760&fidelity=grand" alt="BytesProcessor Logo" width="400"/>

`BytesProcessor` is a utility class designed for the efficient conversion of pcap files (even those exceeding available memory) into a labeled feature-per-byte dataset in the more compact and optimized parquet format. This eases the process for AI developers aiming to utilize a data-rich feature space.

## Key Features
- **Feature-rich Data**: Extracts the initial 1525 bytes of the IP layer, conforming to the standards detailed in this research [paper](https://arxiv.org/pdf/2305.11039.pdf).
  
- **Flexible Extraction**: The class employs time and IP information tied to events, ensuring relevant data is extracted and appropriately labeled. Furthermore, an additional time range list provides greater granularity, capturing even those data points outside predefined events.

## How to Use

To use the `BytesProcessor`, follow these steps:

1. **Set Up Attack Details**:
   Define the details of the attack you wish to process. For instance, for the CICIDS2017 dataset from a Thursday's working hours, you might set one of the details as:

   ```python
   attack_details= {
       "attacks": [
           {
               "timestamp_range": (1499343600, 1499346000),
               "attacker_ips": ["172.16.0.1"],
               "victim_ips": ["192.168.10.50"],
               "label": "Bruteforce"
           },...
       ]
   ```

2. **Specify PCAP and Output Directories**:
   Set the path to your PCAP file and the directory where you wish to store the output parquet files:

   ```python
   pcap_path = "Thursday_workingHours.pcap"
   ParquetDir = "Datasets/CICIDS2017/Thursday/parquets"
   ```

3. **Determine Processing Parameters**:
   Decide on the number of processes and the specific timestamp ranges you wish to extract:

   ```python
   num_processes = 6
   ranges_to_extract = [attack["timestamp_range"] for attack in attack_details['attacks']]
   # To extract a custom range: ranges_to_extract = [(start_timestamp, end_timestamp)]
   ```

4. **Initialize and Run Processor**:
   Now, initialize the `BytesProcessor` and begin the PCAP processing:

   ```python
   processor = BytesProcessor(pcap_path, ParquetDir, num_processes, attack_details, ranges_to_extract)
   
   import time
   start_time = time.time()
   processor.process_pcap(chunk_size=700000)
   end_time = time.time()
   elapsed_time = end_time - start_time
   print(f"Elapsed Time: {elapsed_time:.2f} seconds")
   ```

This will process the PCAP file and save the results in the specified parquet directory. The elapsed time for processing will also be printed.


## Contribution

Contributions are enthusiastically welcomed! Here are some areas we're particularly interested in:

- **Port Filtering Logic**: Enhance the utility by adding logic to filter specific ports.
  
- **Support for pcapng**: While `dpkt` is our go-to parser, we're open to integrating other parsers that can efficiently handle pcapng.
  
- **Extended Protocol Support**: Increase the versatility of `BytesProcessor` by including support for more protocols.

For detailed guidelines on contributing, please refer to the [Contribution Guide](./CONTRIBUTING.md).

## License

This project is licensed under the GNLU License.

## Contact

For questions, suggestions, or feedback, please open an issue on the GitHub repository.

---

[BytesProcessor GitHub Repository](https://github.com/Master-Sorcerer/BytesProcessor)
