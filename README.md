# BytesProcessor

<img src="https://i.imgur.com/cTlLveD_d.webp?maxwidth=760&fidelity=grand" alt="BytesProcessor Logo" width="400"/>

`BytesProcessor` is a utility class designed for the efficient conversion of large pcap files (even those exceeding available memory) into a labeled feature-per-byte dataset in the more compact and optimized parquet format. This eases the process for AI developers aiming to utilize a data-rich feature space.

## Key Features
- **Feature-rich Data**: Extracts the initial 1525 bytes of the IP layer, conforming to the standards detailed in this research [paper](https://arxiv.org/pdf/2305.11039.pdf).
  
- **Flexible Extraction**: The class intelligently employs time and IP metrics tied to events, ensuring relevant data is extracted and appropriately labeled. Furthermore, an additional time range list provides greater granularity, capturing even those data points outside predefined events.

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
