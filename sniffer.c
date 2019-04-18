#include "daemon.h"

char	*find_device(char *str)
{
	pcap_if_t   *alldevs, *list;
	char        errbuff[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&alldevs, errbuff) != 0)
	{
		printf("pcap_findalldevs failed: %s\n", errbuff);
		exit(EXIT_FAILURE);
	}
	list = alldevs;
	if (str)
	{
		while (list)
		{
			if (!strcmp(str, list->name))
				break;
			list = list->next;
		}
		if (list)
			return (list->name);
		else
		{
			list = alldevs;
			printf("Device not found: %s\nTry these devices: ",  str);
			while (list)
			{
				printf("%s ", list->name);
				list = list->next;
			}
			printf("\n");
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		while (list)
		{
			if (!strcmp(list->name, "eth0"))
				break;
			list = list->next;
		}
		if (list)
			return (list->name);
		else
			return (alldevs->name);
	}
}


static void callback(uint8_t* user, const struct pcap_pkthdr *hdr, const uint8_t* bytes)
{
	t_nod				*pack;
	struct iphdr		*ip_header;
	struct sockaddr_in	source;

	(void)(user);
	ip_header = (struct iphdr*)(bytes + sizeof(struct ethhdr));
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip_header->saddr;

	if (!(pack = (t_nod*)malloc(sizeof(t_nod))))
	{
		syslog(LOG_ERR, "Error malloc");
		exit(EXIT_FAILURE);
	}
	pack->left = NULL;
	pack->right = NULL;
	strncpy(pack->ip_adrr, inet_ntoa(source.sin_addr), 16);
	pack->count = 1;
	add_tree(pack, &root_nod);
}

bool	list_devs(void)
{
	pcap_if_t	*currdev;

	/* get a list of capture devices, and free that list */
	if (pcap_findalldevs(&alldevs, errbuff))
	{
		syslog(LOG_ERR, "pcap_findalldevs failed: %s", errbuff);
		exit(EXIT_FAILURE);
	}
	currdev = alldevs;
	while (currdev)
	{
		if (!strcmp(currdev->name, config))
			return (true);
		currdev = currdev->next;
	}
	return (false);
}

void	*sniffer()
{
	struct bpf_program	filterprog;
	if (list_devs() == false)
	{
		syslog(LOG_ERR, "Error iface");
		exit(EXIT_FAILURE);
	}
	/* returns the device identifier */
	if (!(pcap = pcap_open_live(config, MAX_LEN_BUFF, 1, 100, errbuff)))
	{
		syslog(LOG_ERR, "Error calling pcap_open_live(): %s", errbuff);
		exit(EXIT_FAILURE);
	}
	/* compile the filter expression (FILTER: ip, tcp, arp) */
	if (pcap_compile(pcap, &filterprog, FILTER, 0, PCAP_NETMASK_UNKNOWN) == -1)
	{
		syslog(LOG_ERR, "Error calling pcap_compile(): %s", pcap_geterr(pcap));
		exit(EXIT_FAILURE);
	}
	/* set the filter */
	if (pcap_setfilter(pcap, &filterprog) == -1)
	{
		syslog(LOG_ERR, "Error pcap_setfilter(); %s", pcap_geterr(pcap));
		exit(EXIT_FAILURE);
	}
	/* loop for callback function and get packets*/
	pcap_loop(pcap, PCAP_ERROR, callback, NULL);
	syslog(LOG_INFO, "pcap_loop returned");
	exit(EXIT_FAILURE);
}

void	fork_process()
{
	pcap = NULL;
	root_nod = NULL;
	/* start daemon */
	daemonize();
	/* create new process for sniffing */
	if (pthread_create(&tid, NULL, sniffer, 0))
	{
		syslog(LOG_ERR, "Error create thread");
		exit(EXIT_FAILURE);
	}
	/* listening command of cli */
	connect_cli();
}