#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>
#include <queue>

#define MAX_PACKET_LEN 65535
#define MAX_CONNECTIONS 10000

struct connection {
	uint32_t saddr; // source IP address
	uint16_t sport; // source port
	uint32_t daddr; // destination IP address
	uint16_t dport; // destination port
	int packets_in; // number of incoming packets
	int packets_out; // number of outgoing packets
	long long int start_time; // connection start time
};

struct hashmap {
	int size;
	struct connection *connections;
};

// hash function
int hash_func(struct connection *conn, int size) {
	int hash_val = ((conn->saddr ^ conn->sport) + (conn->daddr ^ conn->dport))
			% size;
	return hash_val;
}

// insert a new connection into the hash map
void hashmap_insert(struct hashmap *map, struct connection *conn) {
	int hash_val = hash_func(conn, map->size);
	while (map->connections[hash_val].saddr != 0
			&& map->connections[hash_val].sport != 0
			&& map->connections[hash_val].daddr != 0
			&& map->connections[hash_val].dport != 0) {
		hash_val = (hash_val + 1) % map->size;
	}
	map->connections[hash_val] = *conn;
}

// find a connection in the hash map
struct connection* hashmap_find(struct hashmap *map, uint32_t saddr,
		uint16_t sport, uint32_t daddr, uint16_t dport) {
	struct connection *conn = NULL;
	int hash_val = ((saddr ^ sport) + (daddr ^ dport)) % map->size;
	while (map->connections[hash_val].saddr != 0
			&& map->connections[hash_val].sport != 0
			&& map->connections[hash_val].daddr != 0
			&& map->connections[hash_val].dport != 0) {
		if (map->connections[hash_val].saddr == saddr
				&& map->connections[hash_val].sport == sport
				&& map->connections[hash_val].daddr == daddr
				&& map->connections[hash_val].dport == dport) {
			conn = &map->connections[hash_val];
			break;
		}
		hash_val = (hash_val + 1) % map->size;
	}
	return conn;
}

// Structure to store packet information
struct packet_info {
	u_char src_mac[6];
	u_char dst_mac[6];
	u_char src_ip[4];
	u_char dst_ip[4];
	u_short src_port;
	u_short dst_port;
	char *host;
	char *user_agent;
	uint http_request;
	time_t start_time;
	u_int8_t protocol;
};

unsigned int packets_counter;

// Queue to store packet information
std::queue<struct connection*> packet_queue;

// Mutex for queue synchronization
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

// Condition variable for queue synchronization
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

// Flag to indicate if the capture thread should stop
int capture_thread_stop = 0;

// Pcap connection handle
pcap_t *handle;

// Handle SIGINT signal function
void handle_sigint(int dummy) {
	printf("\nStopping program...\n");
	capture_thread_stop = 1;
}

// Callback function for libpcap to process packets
void process_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet) {

	struct hashmap *map = (struct hashmap*) args;

	struct iphdr *ip_header = (struct iphdr*) (packet
			+ sizeof(struct ether_header));
	struct tcphdr *tcp_header = (struct tcphdr*) (packet
			+ sizeof(struct ether_header) + (ip_header->ihl * 4));
	uint32_t saddr = ntohl(ip_header->saddr);
	uint16_t sport = ntohs(tcp_header->source);
	uint32_t daddr = ntohl(ip_header->daddr);
	uint16_t dport = ntohs(tcp_header->dest);
	long long int current_time = time(0);
	const char *http_payload;
	int ip_header_size = sizeof(struct ip);
	int tcp_header_size;

	// check if the packet is a TCP packet
	if (ip_header->protocol != IPPROTO_TCP) {
		return;
	}

	// check if the packet is a SYN packet (i.e., a new connection)
	if (tcp_header->syn == 1 && tcp_header->ack == 0) {
		struct connection conn = { .saddr = saddr, .sport = sport, .daddr =
				daddr, .dport = dport, .packets_in = 0, .packets_out = 0,
				.start_time = current_time };
		hashmap_insert(map, &conn);
	}

	// find the connection in the hash map
	struct connection *conn = hashmap_find(map, saddr, sport, daddr, dport);
	if (conn == NULL) {
		return;
	}

	// count the packet
	if (saddr == conn->saddr && sport == conn->sport) {
		conn->packets_out++;
	} else {
		conn->packets_in++;
	}

//	if (conn->dport == 80 || conn->sport == 80) {
//		// Get TCP header
//		tcp_header = (struct tcphdr*) (packet + ethernet_header_size
//				+ ip_header_size);
//		tcp_header_size = tcp_header->th_off * 4;
//
//		// Get HTTP payload
//		http_payload = (char*) (packet + ethernet_header_size + ip_header_len
//				+ tcp_header_size);
//
//	}

	// check if the connection is closed
	if (tcp_header->fin == 1) {
		printf(
				"Connection %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u closed after %d seconds, %d packets in, %d packets out\n",
				(conn->saddr >> 24) & 0xff, (conn->saddr >> 16) & 0xff,
				(conn->saddr >> 8) & 0xff, conn->saddr & 0xff, conn->sport,
				(conn->daddr >> 24) & 0xff, (conn->daddr >> 16) & 0xff,
				(conn->daddr >> 8) & 0xff, conn->daddr & 0xff, conn->dport,
				(int) (current_time - conn->start_time), conn->packets_in,
				conn->packets_out);

		// remove the connection from the hash map
		conn->saddr = 0;
		conn->sport = 0;
		conn->daddr = 0;
		conn->dport = 0;
		conn->packets_in = 0;
		conn->packets_out = 0;
		conn->start_time = 0;
	}

	// Lock the queue mutex
	pthread_mutex_lock(&queue_mutex);
	// Add the packet information to the queue
	packet_queue.push(conn);

	// Signal the writing thread that there is data in the queue
	pthread_cond_signal(&queue_cond);

	// Unlock the queue mutex
	pthread_mutex_unlock(&queue_mutex);

	if (capture_thread_stop) {
		pcap_breakloop(handle);
	}
}

// Capture thread function to read packets from the interface or pcap file
void* capture_thread_func(void *arg) {
	char *device = (char*) arg;
	char error_buffer[PCAP_ERRBUF_SIZE];

	// initialize the hash map
	struct hashmap connections_map = { .size = MAX_CONNECTIONS, .connections =
			(struct connection*) malloc(
					sizeof(struct connection) * MAX_CONNECTIONS) };

	if (connections_map.connections == NULL) {
		perror("Failed to allocate memory for connections array");
		return NULL;
	}
	memset(connections_map.connections, 0,
			sizeof(struct connection) * connections_map.size);

	// Open the device or pcap file for capturing
	if (strstr(device, ".pcap")) {
		handle = pcap_open_offline(device, error_buffer);
	} else {
		handle = pcap_open_live(device, MAX_PACKET_LEN, 1, 1000, error_buffer);
	}
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", device, error_buffer);
		return NULL;
	}

	// Start capturing packets
	pcap_loop(handle, -1, process_packet, (u_char*) &connections_map);

	// Close the handle
	pcap_close(handle);
	// cleanup
	free(connections_map.connections);

	return NULL;
}

// Writing thread function to write extracted data to the text file
void* writing_thread_func(void *arg) {
	char *filename = (char*) arg;
	FILE *fp;

	// Open the text file for writing
	fp = fopen(filename, "w");
	if (fp == NULL) {
		fprintf(stderr, "Couldn't open file %s for writing\n", filename);
		return NULL;
	}

	while (1) {
		// Lock the queue mutex
		pthread_mutex_lock(&queue_mutex);
		// Wait for the queue to have data
		while (packet_queue.empty() && !capture_thread_stop) {
			pthread_cond_wait(&queue_cond, &queue_mutex);
		}

		// If the capture thread has stopped and the queue is empty, break the loop
		if (capture_thread_stop && packet_queue.empty()) {
			break;
		}

		// Get the packet information from the front of the queue
		struct connection *conn = packet_queue.front();
		packet_queue.pop();

		// Unlock the queue mutex
		pthread_mutex_unlock(&queue_mutex);
		// Write the packet information to the text file
		fprintf(fp,
				"Connection %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u closed after %d seconds, %d packets in, %d packets out\n",
				(conn->saddr >> 24) & 0xff, (conn->saddr >> 16) & 0xff,
				(conn->saddr >> 8) & 0xff, conn->saddr & 0xff, conn->sport,
				(conn->daddr >> 24) & 0xff, (conn->daddr >> 16) & 0xff,
				(conn->daddr >> 8) & 0xff, conn->daddr & 0xff, conn->dport,
				(int) (time(0) - conn->start_time), conn->packets_in,
				conn->packets_out);
		fprintf(fp, "\n");
	}

	// Close the text file
	fclose(fp);

	return NULL;
}

int main(int argc, char *argv[]) {

	signal(SIGINT, handle_sigint);

// Check the number of arguments
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <interface or pcap file> <output file>\n",
				argv[0]);
		return 1;
	}

	printf("##### Sniffer program started!! #####\n");

	char *filename = argv[1];
	char *output_file = argv[2];

// Initialize the queue mutex and condition variable
	pthread_mutex_init(&queue_mutex, NULL);
	pthread_cond_init(&queue_cond, NULL);

// Start the capture thread
	pthread_t capture_thread;
	if (pthread_create(&capture_thread, NULL, capture_thread_func, filename)) {
		fprintf(stderr, "Error creating capture thread\n");
		return 1;
	}

// Start the writing thread
	pthread_t writing_thread;
	if (pthread_create(&writing_thread, NULL, writing_thread_func,
			output_file)) {
		fprintf(stderr, "Error creating writing thread\n");
		return 1;
	}

// Wait for the capture thread to finish
	if (pthread_join(capture_thread, NULL)) {
		fprintf(stderr, "Error waiting for capture thread\n");
		return 1;
	}

// Set the capture thread stop flag
	capture_thread_stop = 1;

//// Signal the queue condition variable
	pthread_cond_signal(&queue_cond);

// Wait for the writing thread to finish
	if (pthread_join(writing_thread, NULL)) {
		fprintf(stderr, "Error waiting for writing thread\n");
		return 1;
	}

// Destroy the queue mutex and condition variable
	pthread_mutex_destroy(&queue_mutex);
	pthread_cond_destroy(&queue_cond);

	printf("##### Sniffer program finished!! #####\n");

	return 0;
}

