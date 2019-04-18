#include "daemon.h"

void 	ft_stop(int argc, char *argv[], int sock)
{
	if (argc == 2) {
		if (getuid() != 0)
		{
			printf("Error permission denied");
			exit(EXIT_FAILURE);
		}
		send(sock, argv[1], sizeof(argv[1]), 0);
	}
	else
	{
		printf("Error count arguments");
		exit(EXIT_FAILURE);
	}
}

void 	ft_show(int argc, char *argv[], int sock) 
{
	regex_t				regex;
	char				*comand;
	char				buff[128];
	int					len;

	if (argc == 4) {
		if (!regcomp(&regex, REGEX_IP, REG_EXTENDED) &&
			!regexec(&regex, argv[2], 0, NULL, 0) &&
			!strcmp(argv[3], "count"))
		{
			comand = ft_strjoin(argv[1], argv[2]);
			send(sock, comand, strlen(comand), 0);
			if ((len = recv(sock, buff, MAX_LINE_LEN, 0)) < 0) {
				exit(EXIT_FAILURE);
			}
			printf("packets: %s\n", buff);
		}
		else {
			printf("wrong IP\n");
		}		
	}
	else
		printf("Error command show, see help.\nUsage: ./cli --help\n");
}

void 	ft_select(int argc, char *argv[], int sock) 
{
	char	*buf;

	if (argc == 4 && strcmp(argv[3], "iface"))
	{
		buf = ft_strjoin(argv[1], find_device(argv[3]));
		send(sock, buf, ft_strlen(buf), 0);
	}
	else {
		printf("Error count arguments\n");
		exit(EXIT_FAILURE);
	}
}

void 	ft_stat(int argc, char *argv[], int sock)
{
	char	buff[MAX_LINE_LEN];
	ssize_t len;
	char	**map;
	char	*dst;
	char	*leaks;

	send(sock, argv[1], sizeof(argv[1]), 0);
	dst = NULL;
	while(1)
	{
		leaks = dst;
		ft_bzero(buff, MAX_LINE_LEN);
		if ((len = recv(sock, buff, MAX_LINE_LEN, 0)) < 0)
		{
			ft_putendl_fd("Error recv", STDERR_FILENO);
			exit(EXIT_FAILURE);
		}
		if (len == 0)
			break;
		dst = dst != NULL ? ft_strjoin(dst, buff) : ft_strdup(buff);
		ft_strdel(&leaks);
	}
	if (!(map = ft_strsplit(dst, 'a')))
		return;
	ft_strdel(&dst);
	for(int i = 0; map[i]; i++)
	{
		ft_putendl(map[i]);
		ft_strdel(&(map[i]));
	}
	free(map);
}

static int	ft_conect_cli(void)
{
	int					sock;
	struct sockaddr_in	addr;

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("Error init socket\n");
		exit(EXIT_FAILURE);
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)SNIFFED_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		printf("Error connect\n");
		exit(EXIT_FAILURE);
	}
	return (sock);
}

void	ft_help()
{
	int		fd;
	int     n;
	char	buff[BUFF];

	if ((fd = open("help", O_RDONLY)) < 0)
	{
		printf("Error opening file\n");
		exit(EXIT_FAILURE);
	}
	bzero(buff, BUFF);
	while((n = read(fd, buff, BUFF)) > 0)
	{
		printf("%s", buff);
		bzero(buff, BUFF);
	}
	exit(EXIT_SUCCESS);
}

void	ft_start(int argc, char **argv)
{
	if (argc == 2 || argc == 3) 
	{
		strcpy(config, find_device(argv[2])); 
		fork_process();
	}
	else {
		printf("Error count arguments\n");
		exit(EXIT_FAILURE);
	}
}

void 	cli(int argc, char *argv[])
{
	if (!strcmp(argv[1], "start"))
		ft_start(argc, argv);
	else if (!strcmp(argv[1], "--help"))
		ft_help();
	int sock = ft_conect_cli();
	if (!strcmp(argv[1], "stat"))
		ft_stat(argc, argv, sock);
	else if (!strcmp(argv[1], "select"))
		ft_select(argc, argv, sock);
	else if (!strcmp(argv[1], "show"))
		ft_show(argc, argv, sock);
	else if (!strcmp(argv[1], "stop"))
		ft_stop(argc, argv, sock);
	else
		printf("Error commands, see help.\nUsage: ./cli --help\n");
} 

int  	main(int argc, char **argv)
{
	if (argc > 1 && argc < 5)
		cli(argc, argv);
	else
		printf("Error arguments, see help.\nUsage: ./cli --help\n");
	return 0;
}