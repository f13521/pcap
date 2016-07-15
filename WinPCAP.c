#define HAVE_REMOTE
#include "pcap.h"
#include "remote-ext.h"
#include "libnet-headers.h"
#include <WinSock.h>

#pragma comment (lib, "wpcap.lib")

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture
		// 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	int i; 

	libnet_ethernet_hdr *ethernet;
	libnet_ipv4_hdr *ip;
	libnet_tcp_hdr *tcp;

	ethernet = (libnet_ethernet_hdr *)(pkt_data);
	ip = (libnet_ipv4_hdr *)(pkt_data + ETHER_SIZE);
	tcp = (libnet_tcp_hdr *)(pkt_data + ETHER_SIZE + IP_HEADER_LEN);

	/*
	* unused variables
	*/
	(VOID)(param);
	(VOID)(pkt_data);


	if (ip->ip_p == 6)
	{

		printf(" eth S_MAC : ");
		for (i = 0; i < ETHER_ADDR_LEN; i++)
			printf("%02x:", ethernet->ether_shost[i]);

		printf(" eth D_MAC : ");
		for (i = 0; i < ETHER_ADDR_LEN; i++)
			printf("%02x:", ethernet->ether_dhost[i]);
		printf("\n");
		
		printf(" IP S_IP : %s , IP D_IP : %s\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));

		printf(" TCP S_PORT : %d , TCP D_PORT : %d\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));

		printf("--------------------------------------------------------------- \n");
	}
}