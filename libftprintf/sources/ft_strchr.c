/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/26 15:32:54 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/04/02 18:58:11 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

char	*ft_strchr(const char *s, int c)
{
	size_t j;

	j = 0;
	while (s[j] != '\0')
	{
		if (s[j] == c)
			return ((char *)s + j);
		j++;
	}
	if (c == 0 && s[j] == '\0')
		return ((char *)s + j);
	return (NULL);
}
