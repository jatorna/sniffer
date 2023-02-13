#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <queue>

#define MAX_PACKET_LEN 65535

// Structure to store packet information
struct packet_info {
	u_char src_mac[6];
	u_char dst_mac[6];
	u_char src_ip[4];
	u_char dst_ip[4];
	u_short src_port;
	u_short dst_port;
	char host[100];
	char user_agent[100];
	char http_request[100];
	time_t start_time;
	u_int8_t protocol;
};

unsigned int packets_counter;

// Queue to store packet information
std::queue<struct packet_info> packet_queue;

// Mutex for queue synchronization
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

// Condition variable for queue synchronization
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

// Flag to indicate if the capture thread should stop
int capture_thread_stop = 0;

pcap_t *handle;

void print_stats() {
	printf("Num total packets tracked: %u\n", packets_counter);
}

void handle_sigint(int dummy) {
	printf("\nStopping program...\n");
	capture_thread_stop = 1;
}

// Callback function for libpcap to process packets
void process_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet) {
	struct packet_info info;

	// Extract MAC addresses of source and destination
	memcpy(info.src_mac, packet, 6);
	memcpy(info.dst_mac, packet + 6, 6);

	// Extract IP addresses of source and destination
	memcpy(info.src_ip, packet + 26, 4);
	memcpy(info.dst_ip, packet + 30, 4);

	// Extract source and destination ports for TCP and UDP packets
	if (packet[23] == IPPROTO_TCP) { // TCP packet
		memcpy(&info.src_port, packet + 34, 2);
		memcpy(&info.dst_port, packet + 36, 2);
		info.protocol = IPPROTO_TCP;

		// Extract Host and User-Agent strings for HTTP packets
		if (info.src_port == 80 || info.dst_port == 80) {
			// TODO: Extract Host and User-Agent strings
		}
	} else if (packet[23] == IPPROTO_UDP) { // UDP packet
		memcpy(&info.src_port, packet + 34, 2);
		memcpy(&info.dst_port, packet + 36, 2);
		info.protocol = IPPROTO_UDP;
	}

	// Lock the queue mutex
	pthread_mutex_lock(&queue_mutex);

	// Add the packet information to the queue
//	info.start_time = time(NULL);
	packets_counter++;
	packet_queue.push(info);

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
	pcap_loop(handle, -1, process_packet, NULL);

// Close the handle
	pcap_close(handle);

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
		struct packet_info info = packet_queue.front();
		packet_queue.pop();

// Unlock the queue mutex
		pthread_mutex_unlock(&queue_mutex);

// Write the packet information to the text file
		fprintf(fp, "Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				info.src_mac[0], info.src_mac[1], info.src_mac[2],
				info.src_mac[3], info.src_mac[4], info.src_mac[5]);
		fprintf(fp, "Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				info.dst_mac[0], info.dst_mac[1], info.dst_mac[2],
				info.dst_mac[3], info.dst_mac[4], info.dst_mac[5]);
		fprintf(fp, "Source IP: %d.%d.%d.%d\n", info.src_ip[0], info.src_ip[1],
				info.src_ip[2], info.src_ip[3]);
		fprintf(fp, "Destination IP: %d.%d.%d.%d\n", info.dst_ip[0],
				info.dst_ip[1], info.dst_ip[2], info.dst_ip[3]);
		if (info.protocol == IPPROTO_TCP || info.protocol == IPPROTO_UDP) {
			fprintf(fp, "Source Port: %d\n", info.src_port);
			fprintf(fp, "Destination Port: %d\n", info.dst_port);
		}
		if (info.protocol == IPPROTO_TCP && strlen(info.http_request) > 0) {
			fprintf(fp, "HTTP Request: %s\n", info.http_request);
			fprintf(fp, "Host: %s\n", info.host);
			fprintf(fp, "User Agent: %s\n", info.user_agent);
		}
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
//	pthread_cond_signal(&queue_cond);

// Wait for the writing thread to finish
	if (pthread_join(writing_thread, NULL)) {
		fprintf(stderr, "Error waiting for writing thread\n");
		return 1;
	}

// Destroy the queue mutex and condition variable
	pthread_mutex_destroy(&queue_mutex);
	pthread_cond_destroy(&queue_cond);

	print_stats();
	printf("##### Sniffer program finished!! #####\n");


	return 0;
}

