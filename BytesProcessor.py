import logging
import dpkt
from multiprocessing import get_context
import numpy as np
import pandas as pd
import functools
import sys
import os
import gc
logging.basicConfig(level=logging.INFO)

class BytesProcessor:
    """
    This class allows to efficiently convert bigger than memory pcap files to a labeled feature-per-byte dataset in parquet format.
    """
    def __init__(self,pcap_path,parquet_directory,num_processes,attack_details,ranges_to_extract,chunk_size=20000):
        """
        pcap_path: This is the path of the .pcap file, note that dpkt does not support pcapng. there are tools available for the efficient conversion

        parquet_directory: This is the directory where the files will be written, there are 2 set of chunks, "data"(Packets in given range) and "adversarial"(Packets in the range with attacker ip source).

        attack_details: a dictionary with the following structure:
        attack_details={
             "attacks": [
        {
            "timestamp_range": (start_timestamp, end_timestamp),  # Tuple of two integers representing the start and end timestamps.
            "attacker_ips": [ip1, ip2, ...],  # List of strings representing attackers IP addresses.
            "victim_ips": [ip1, ip2, ...],    # List of strings representing victims IP addresses.
            "label": "Attack_Type"            # String representing the type/label of the attack (e.g., "Bruteforce", "XSS").
        },
        ...
                        ]
        }

        num_processes: The number of processes to create when parsing the packets

        ranges_to_extract: These are the time frames from which we will save the data 

        chunk_size=the number of packets to read at once
        """
        self.pcap_path = pcap_path
        self.parquet_directory = parquet_directory
        self.attack_details = attack_details
        self.num_processes=num_processes
        self.ranges_to_extract=ranges_to_extract
        self.chunk_size=chunk_size

    def process_pcap(self, chunk_size = None):
        """Reads a pcap in chunks of chunk_size in bytes, saves the labeled files and adv forward files in the range of interest."""
        if chunk_size==None:
            chunk_size=self.chunk_size
        
        self.current_chunk = 0
        try:
            print("tryin to open pcap")
            with open(self.pcap_path, 'rb') as f:
                logging.info(f"opening: {self.pcap_path}")
                pcap_reader = dpkt.pcap.Reader(f)
                packets_chunk = []
                print("opened")

                for counter, (ts, buf) in enumerate(pcap_reader, 1):
                    
                    packets_chunk.append((ts, buf))
                    if counter % chunk_size == 0:
                        dataset_df=[]
                        logging.info(f"Read {counter} packets so far...")
                        logging.info(f"Sending Chunk To be Processed")
                        dataset_df, forward_data = self._process_chunk(packets_chunk, num_processes=self.num_processes)
                        logging.info(f"Chunk Processed")

                        if len(dataset_df) != 0:
                            self._save_chunk(dataset_df, forward_data)
                            packets_chunk = [] 
                            del dataset_df
                            del forward_data
                            gc.collect()

                        else:
                            logging.info(f"No data to save in this chunk")
                            packets_chunk = []  # Reset chunk
                        #If you are using a WSL2 and the gpu version We need to manually drop the disk-access related caches for each time we interact with the pcap
                        #os.system('sudo sh -c "echo 1 > /proc/sys/vm/drop_caches"')    

                if len(packets_chunk)!=0:
                    #Process and save the chunk if there are still some packets
                    dataset_df, forward_data = self._process_chunk(packets_chunk, num_processes=self.num_processes)
                    if len(dataset_df) != 0:
                        self._save_chunk(dataset_df, forward_data)
                        packets_chunk = [] 
                        del dataset_df
                        del forward_data
                        gc.collect()
                    logging.info(f"Done processing")

        except EOFError:
            logging.info("Reached the end of the pcap in a chunk.")
            if packets_chunk:
                #Process and save the chunk
                dataset_df, forward_data = self._process_chunk(packets_chunk, num_processes=self.num_processes)
                self._save_chunk(dataset_df, forward_data)
                del dataset_df
                del forward_data
                logging.info(f"Done processing")

        except Exception as e:
            logging.error(f"Error processing pcap file. Error: {e}")
            sys.exit(1)

    def _save_chunk(self, dataset_df, forward_data):
        """Save the extracted data into parquets."""

        logging.info("Saving labeled data in the range of interest.")
        dataset_df.to_parquet(os.path.join(self.parquet_directory, f"data_{self.current_chunk}.parquet"))
        if not forward_data.empty:
            logging.info("Saving adv file too.")
            forward_data.to_parquet(os.path.join(self.parquet_directory, f"adversarial_{self.current_chunk}.parquet"))
            print(forward_data.head(5))
        self.current_chunk +=1

    def _process_chunk(self, packets_chunk, num_processes):
        """
        Parses the dpkt objects and checks if the packets read are of interest
        Returns a ready to save dataframe in case they are
        """

        labeled_data=[]
        forward_data=[]
        sub_chunks = self._split_into_sub_chunks(packets_chunk, num_processes)

        #Divide the parsing of data in various processes
        with get_context("spawn").Pool(num_processes) as pool:
                #Python has a ctrl c bug with the use of pools
                print("wait untill the multiprocessing is done before hitting ctrl+c")
                parsed_sub_chunks = pool.map(self._parse_packets_sub_chunk, sub_chunks)
                print("done, you can interrupt if needed")


        parsed_chunk =pd.DataFrame([packet for sub_chunk in parsed_sub_chunks for packet in sub_chunk])
        del parsed_sub_chunks
        gc.collect()
        logging.info("Parsed Packets")

        #Extract only packets of interest avoid processing bytes outside ranges given
        range_chunk = self._extract_ranges(parsed_chunk,self.ranges_to_extract)
        del parsed_chunk
        gc.collect()
        

        if not range_chunk.empty:
            logging.info("Further processing packets of interest")
            print(range_chunk.head(5))
            range_chunk = range_chunk.reset_index(drop=True)
            labeled_data, forward_data = self._obtain_data(range_chunk)
        del range_chunk

        gc.collect()
        return labeled_data, forward_data
    
    def _obtain_data(self, range_chunk):
        """
        Takes the dataframe of packets that are in the range of interest and returns a ready to save dataframe
        It formats and labels the data from the packets of interest.
        """

        #Obtain labeled data
        labeled_data, combined_forward_mask=self.label_attack_data(range_chunk.drop('payload', axis=1), self.attack_details)
        assert not labeled_data.isna().any().any(), "nans detected in labeled data" 
        logging.info("Labeled data")
        
        #Create the list of arrays from the payloads
        target_length = 1525  # or any other desired target length 
        array_list = [np.frombuffer(payload, dtype=np.uint8) for payload in range_chunk['payload']]

        del range_chunk
        gc.collect()

       #Create the payload dataframe from the list of arrays
        payload_df = pd.DataFrame(self._pad_and_stack_arrays(array_list, target_length))
        assert not payload_df.isna().any().any(), "nans detected in bytesdf" 
        
       #Create column names for the payload matrix
        new_columns = [f"byte({i})" for i in range(1525)]
        payload_df.columns=new_columns
        
       #Concantenate the payload bytes with the rest of df
        labeled_data=pd.concat([(labeled_data),payload_df], axis=1)
        logging.info("Processed payloads")
        del payload_df
        gc.collect()

        assert not labeled_data.isna().any().any(), "nans after concatenating" 

        return labeled_data, labeled_data[combined_forward_mask]
    
    def _split_into_sub_chunks(self, packets_chunk, num_processes):
        """Split the packets_chunk into num_processes sub-chunks."""

        avg_len = len(packets_chunk) // num_processes
        sub_chunks = [packets_chunk[i:i+avg_len] for i in range(0, len(packets_chunk), avg_len)]

        #Add any remaining packets to last subchunk
        if len(packets_chunk) % num_processes != 0:
             sub_chunks[-1].extend(packets_chunk[avg_len * num_processes:])
        return sub_chunks

    def _parse_packets_sub_chunk(self, packets_sub_chunk):
        """Parses a sub-chunk of packets."""
        return self._parse_packets_chunk(packets_sub_chunk)
        
    def _parse_packets_chunk(self, packets_chunk):
        """
        Uses dpkt to extract the features for the labeling, as well as the ip bytes.
        Receives a list of dpkt objects and returns a list dictionaries containing the data
        """
        # Extract relevant fields from packets
        parsed_packets_chunk = []  

        for ts, buf in packets_chunk:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue  # Not an IP packet
                ip=eth.data
                src_ip = dpkt.utils.inet_to_str(ip.src)
                dst_ip = dpkt.utils.inet_to_str(ip.dst)
                timestamp = ts  #
                if isinstance(ip.data, dpkt.tcp.TCP):
                    protocol = "6"
                    tcp = ip.data
                    src_port = tcp.sport
                    dst_port = tcp.dport
                elif isinstance(ip.data, dpkt.udp.UDP):
                    protocol = "17"
                    udp = ip.data
                    src_port = udp.sport
                    dst_port = udp.dport
                else:
                    continue  # Not a TCP or UDP packet

                parsed_packets_chunk.append({
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "payload": self._process_payload(ip),
                    "label": "benign"
                })
            except Exception as e:
                print("ERROR PROCESSING A PACKET")
                print(e)
        del packets_chunk
        gc.collect()
        return parsed_packets_chunk

    def _process_payload(self, ip):
        """
        Removes bias from the bytes
        Takes a dpkt ip object and returns the bytes without bias
        """
        ip.src = ip.dst = b'\x00\x00\x00\x00'
        if isinstance(ip.data, dpkt.tcp.TCP):
            ip.data.sport = ip.data.dport = 0
        elif isinstance(ip.data, dpkt.udp.UDP):
            ip.data.sport = ip.data.dport = 0
        return bytes(ip)

    def _pad_and_stack_arrays(self,array_list, target_length):
        """
        Pads, stacks and normalize the payloads.
        Takes a list of arrays representing the payloads and returns a matrix of normalized bytes
        """

        # Allocate a matrix of zeros
        stacked_array = np.zeros((len(array_list), target_length), dtype=np.uint8)

        # Fill them with padded values
        for i, array in enumerate(array_list):
            stacked_array[i, :(len(array[:target_length]))] = array[:target_length]

        # Normalize
        stacked_array=stacked_array/np.float32(255)
        
        return stacked_array

    def label_attack_data(self, attack_data, attack_details):
        """
        Labels the attack data dataframe based on IPs and timestamps.
        Also creates an adversarial forward mask to extract the forward adversarial packets.
        """
        forward_packets_masks = []
        masks = []
        new_labels = attack_data['label'].copy()

        for attack in attack_details["attacks"]:
            timestamp_mask = attack_data['timestamp'].between(*attack["timestamp_range"])

            # If both attacker and victim IPs are given, filter bidirectionally
            if "attacker_ips" in attack and "victim_ips" in attack:
                ip_mask = ((attack_data['src_ip'].isin(attack["attacker_ips"]) & 
                            attack_data['dst_ip'].isin(attack["victim_ips"])) | 
                        (attack_data['dst_ip'].isin(attack["attacker_ips"]) & 
                            attack_data['src_ip'].isin(attack["victim_ips"])))
                
            # If only attacker IPs are given, consider all packets having the attacker IP as the source
            elif "attacker_ips" in attack:
                ip_mask = attack_data['src_ip'].isin(attack["attacker_ips"])

            # If only victim IPs are given, consider all packets having the victim IP as the destination
            elif "victim_ips" in attack:
                ip_mask = attack_data['dst_ip'].isin(attack["victim_ips"])
            else:
                continue

            # Mask for adversarial forward packets
            forward_mask = timestamp_mask & attack_data['src_ip'].isin(attack["attacker_ips"])
            forward_packets_masks.append(forward_mask)

            # Final mask with IP and timerange conditions
            final_mask = timestamp_mask & ip_mask
            masks.append(final_mask)

        # Use these masks to update new_labels
        for mask, attack in zip(masks, attack_details["attacks"]):
            new_labels[mask] = attack["label"]
            assert not new_labels.isna().any(), "nans detected"   

        # Combine forward masks
        combined_forward_mask = functools.reduce(lambda x, y: x | y, forward_packets_masks)
        
        # update the label, extract adv forward packets
        new_labels_reset = new_labels.reset_index(drop=True)
        attack_data['label'] = new_labels_reset.values  # Ensures values are assigned irrespective of index alignment

        return attack_data, combined_forward_mask

    def _extract_ranges(self, df, ranges_to_extract):
        """
        Extract packets on the range given from the chunk dataframe
        Returns a dataframe containing only packets on the given ranges
        """
        range_masks = []
        df['timestamp'] = df['timestamp'].astype(float)
        #Extract the ranges on the list passed
        for extracted_range in ranges_to_extract:
            start_time, end_time =[float(t) for t in extracted_range]
            current_range_mask = df['timestamp'].between(start_time, end_time)
            range_masks.append(current_range_mask)

        combined_range_mask = functools.reduce(lambda x, y: x | y, range_masks)
        range_df = df[combined_range_mask]
        return range_df


if __name__=='__main__':
     
    #These are thursday cicids2017 working hours attack details
    attack_details= {   
    "attacks": [
        {
            "timestamp_range": (1499343600, 1499346000),
            "attacker_ips": ["172.16.0.1"],
            "victim_ips": ["192.168.10.50"],
            "label": "Bruteforce"
        },
        {
            "timestamp_range": (1499346900, 1499348100),
            "attacker_ips": ["172.16.0.1"],
            "victim_ips": ["192.168.10.50"],
            "label": "XSS"
        },
        {
            "timestamp_range": (1499348400, 1499348520),
            "attacker_ips": ["172.16.0.1"],
            "victim_ips": ["192.168.10.50"],
            "label": "SQLi"
        },
        {
            "timestamp_range": (1499361540, 1499361660),
            "attacker_ips": ["205.174.165.73"],
            "victim_ips": ["192.168.10.8"],
            "label": "Infiltration"
        },
        {
            "timestamp_range": (1499362380, 1499362500),
            "attacker_ips": ["205.174.165.73"],
            "victim_ips": ["192.168.10.8"],
            "label": "Infiltration"
        },
        {
            "timestamp_range": (1499363580, 1499364000),
            "attacker_ips": ["205.174.165.73"],
            "victim_ips": ["192.168.10.25"],
            "label": "Infiltration"
        },
        {
            "timestamp_range": (1499364240, 1499366700),
            "attacker_ips": ["192.168.10.8", "205.174.165.73"],
            "victim_ips": ["192.168.10.8"],
            "label": "Infiltration"
        }
        ]
        }
    
    pcap_path= "Thursday_workingHours.pcap"
    ParquetDir="Datasets/CICIDS2017/Thursday/parquets"
    num_processes=6
    #If you want you can extract the same ranges of the attack, or the totality of pcap or a custom range
    ranges_to_extract = [attack["timestamp_range"] for attack in attack_details['attacks']]
    #ranges_to_extract = [(1499343600,1499366700)]

    processor=BytesProcessor(pcap_path,ParquetDir,num_processes,attack_details,ranges_to_extract)
    import time
    start_time = time.time()
    processor.process_pcap(chunk_size=700000)  
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Elapsed Time: {elapsed_time:.2f} seconds")