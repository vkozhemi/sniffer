#include "daemon.h"

int		sendall(int sock, char *buf, int len, int flags)
{
	int total = 0;
	int n = 0;

	while(total < len)
	{
		n = (int)send(sock, buf + total, len - total, flags);
		if(n == -1)
			break ;
		total += n;
	}
	return (n == -1 ? -1 : total);
}

int		ipcmp(char *ip1, char *ip2)
{
	int		nbr1;
	int		nbr2;

	nbr1 = ft_atoi(ip1);
	nbr2 = ft_atoi(ip2);
	if (nbr1 == nbr2 && *ip1 && *ip2)
	{
		while (*ip1)
		{
			if (*ip1 == '.')
			{
				ip1++;
				break;
			}
			ip1++;
		}
		while (*ip2)
		{
			if (*ip2 == '.')
			{
				ip2++;
				break;
			}
			ip2++;
		}
		return (ipcmp(ip1, ip2));
	}
	return (nbr1 - nbr2);
}

void	add_tree(t_nod *pack, t_nod **root)
{
	t_nod	*nod;
	int		flag;

	if (!(*root))
		*root = pack;
	else
	{
		nod = *root;
		while (nod)
		{

			if (!(flag = ipcmp(nod->ip_adrr, pack->ip_adrr)))
			{
				nod->count += pack->count;
				free(pack);
				break;
			}
			else if (flag > 0)
			{
				if (!nod->left)
				{
					nod->left = pack;
					break;
				}
				nod = nod->left;
			}
			else
			{
				if (!nod->right)
				{
					nod->right = pack;
					break;
				}
				nod = nod->right;
			}
		}
	}
}

t_nod	*search_intree(char *ip, t_nod *root)
{
	t_nod	*nod;
	int 	flag;

	nod = root;
	while (nod)
	{
		if (!(flag = ipcmp(nod->ip_adrr, ip)))
			break ;
		if (flag > 0)
			nod = nod->left;
		else
			nod = nod->right;
	}
	return (nod);
}
char	*strcpych(char *s1, char *s2, char c)
{
	int i;

	i = -1;
	while (s2[++i])
		s1[i] = s2[i];
	s1[i++] = c;
	s1[i] = '\0';
	return (s1);
}

void	tree_traversal(t_nod *nod, int sock)
{
	char	str[17];

	if (nod)
	{
		strcpych(str, nod->ip_adrr, 'a');
		sendall(sock, str, (int)strlen(str), 0);
		tree_traversal(nod->right, sock);
		tree_traversal(nod->left, sock);
	}
}

void	dell_tree(t_nod *lst)
{
	if (lst)
	{
		dell_tree(lst->left);
		dell_tree(lst->right);
		free(lst);
	}
}

void	count_pack(int *count, t_nod *nod)
{
	if (nod)
	{
		(*count) += nod->count;
		count_pack(count, nod->left);
		count_pack(count, nod->right);
	}
}