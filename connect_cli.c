#include "daemon.h"

static void	command_select(char *readbuf)
{
	pcap_close(pcap);
	pcap = NULL;
	dell_tree(root_nod);
	root_nod = NULL;
	bzero(config, ft_strlen(config));
	strcpy(config, readbuf + 6);
	/* stop pthread sniffing */
	if (pthread_cancel(tid))
	{
		syslog(LOG_ERR, "Can not cancel thread");
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}
	/* create a thread for sniffing */
	if (pthread_create(&tid, NULL, sniffer, 0))
	{
		syslog(LOG_ERR, "Can not create thread");
		pcap_freealldevs(alldevs);
		exit(EXIT_FAILURE);
	}
}

static void	command_show(const int sock, char *readbuf)
{
	t_nod	*lst;
	char	*nbr = NULL;
	int		count = 0;

	if (!strcmp(readbuf + 4, config))
	{
		count_pack(&count, root_nod);
		nbr = ft_itoa(count);
		send(sock, nbr, strlen(nbr), 0);
		ft_strdel(&nbr);
		return ;
	}
	lst = search_intree(readbuf + 4, root_nod);
	if (lst)
	{
		nbr = ft_itoa(lst->count);
		send(sock, nbr, strlen(nbr), 0);
		ft_strdel(&nbr);
	}
	else
		send(sock, "ip not found", 13, 0);
}

int		command_cli(const int sock)
{
	t_nod		*lst;
	char		*nbr = NULL;
	char		readbuf[MAX_CONECT_BUFF];
	int			len;

	len = (int)recv(sock,readbuf, MAX_CONECT_BUFF, 0);
	readbuf[len] = '\0';
	if (!strcmp(readbuf, "stop"))
		exit(EXIT_SUCCESS);
	else if (!strcmp(readbuf, "stat"))
	{
		printf("STAT\n");
		tree_traversal(root_nod, sock);
		return (1);
	}
	else if (!strncmp(readbuf, "show", 4))
	{
		printf("SHOW\n");
		command_show(sock, readbuf);
		return (1);
	}
	else if (!strncmp(readbuf, "select", 6)) {
		printf("SELECT\n");
		command_select(readbuf);
	}
	return (1);
}

int		bind_passive_socket(int * sock)
{
	struct sockaddr_in	sin;
	int 				newsock, optval;
	socklen_t			optlen;

	memset(&sin.sin_zero, 0, 8);
	sin.sin_port = htons(SNIFFED_PORT);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if ((newsock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		return -1;
	optval = 1;
	optlen = sizeof(int);
	setsockopt(newsock, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);
	if (bind(newsock, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) < 0)
		return -1;
	if (listen(newsock, SOMAXCONN) < 0)
		return -1;
	*sock = newsock;
	return 0;
}

void	*connect_cli()
{
	int					proceed, master, slave, retval;
	struct sockaddr_in	client;
	socklen_t			clilen;

	if (bind_passive_socket(&master) != 0)
	{
		syslog(LOG_ERR, "bind() failed");
		exit(EXIT_FAILURE);
	}
	while (1) 
	{
		proceed = 1;
		retval = 0;
		while (proceed == 1)
		{
			clilen = sizeof(client);
			slave = accept(master, (struct sockaddr *) &client, &clilen);
			if (slave < 0)
			{
				if (errno == EINTR)
					continue;
				syslog(LOG_ERR, "accept() failed");
				proceed = 0;
				retval = -1;
			}
			else
			{
				retval = command_cli(slave); /* receive and send command from cli */
				if (retval)
					proceed = 0;
			}
			close(slave);
		}
	}
}
