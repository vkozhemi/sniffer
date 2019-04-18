#ifndef DAEMON_H
# define DAEMON_H

# include <syslog.h>
# include <fcntl.h>
# include <signal.h>
# include <stdbool.h>
# include <regex.h>
# include <netinet/in.h>
# include <sys/resource.h>
# include <net/if.h>
# include <sys/ioctl.h>
# include <errno.h>
# include <pthread.h>
# include <pcap.h>
# include <arpa/inet.h>
# include <sys/stat.h>
# include <stdio.h> 
# include <stdlib.h>
# include <errno.h> 
# include <sys/socket.h> 
# include <netinet/if_ether.h> 
# include <ctype.h>
# include <string.h>
# include <unistd.h>
# include <sys/types.h>
# include <sys/time.h>
# include "libftprintf/includes/libft.h"
# include "libftprintf/includes/get_next_line.h"
# include "libftprintf/includes/printf.h"

#define SNIFFED_PORT 30333
#define MAX_CONECT_BUFF 128
#define MAX_LEN_BUFF 65536
#define FILTER "ip"
#define MAX_LINE_LEN 128

# define REGEX_IP "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
# define UID 501
# define SNIFFED_PORT 30333
# define BUFF 1024

# define TRUE 1 
# define FALSE 0 
# define PORT 8888 
# define MAX 30
# define ETH_ALEN 6

# define FILTER "ip"
# define LOCKFILE "/var/run/sniffd.pid"
# define CONFIG_FILE "/etc/sniffd.conf"
# define LOG_PREFIX "/dev/sniffd.log"
# define LOCKMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)

typedef struct		s_nod
{
	struct s_nod	*left;
	struct s_nod	*right;
	char			ip_adrr[17];
	int				count;
}					t_nod;

char		config[20];
pcap_if_t   *alldevs;
char		errbuff[PCAP_ERRBUF_SIZE];
pcap_t		*pcap;
t_nod		*root_nod;
pthread_t	tid;

void	fork_process();
void	*connect_cli();
void	daemonize(void);
void	*sniffer();
char	*find_device(char *str);

/* binaty tree */
int		ipcmp(char *ip1, char *ip2);
void	add_tree(t_nod *pack, t_nod **root);
t_nod	*search_intree(char *ip, t_nod *root);
char	*strcpych(char *s1, char *s2, char c);
void	tree_traversal(t_nod *nod, int sock);
void	dell_tree(t_nod *lst);
void	count_pack(int *count, t_nod *nod);

struct ethhdr
{
	unsigned char h_dest[ETH_ALEN];
	unsigned char h_source[ETH_ALEN];
	/* packet type ID */
	uint16_t      h_proto;
} __attribute__((packed));

struct iphdr
{
#if defined(__LITTLE_ENDIAN__)
	uint8_t  ihl:4,
           version:4;
#elif defined (__BIG_ENDIAN__)
	uint8_t  version:4,
           ihl:4;
#else
#endif
	uint8_t  tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
} __attribute__((packed));

#endif
