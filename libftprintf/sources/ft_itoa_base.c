/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa_base.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/17 16:12:21 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/17 16:12:24 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

int			ft_len(intmax_t value, int base)
{
	intmax_t len;

	if (value <= 0)
		len = 1;
	else
		len = 0;
	while (value)
	{
		value = value / base;
		len++;
	}
	return (len);
}

intmax_t	ft_abs(intmax_t value)
{
	if (value < 0)
		value = value * (-1);
	return (value);
}

char		*ft_itoa_base(intmax_t value, int base, int size)
{
	intmax_t	nbr;
	int			len;
	char		*str;
	char		*base_string;

	nbr = ft_abs(value);
	len = ft_len(value, base);
	if (size == 0)
		base_string = "0123456789ABCDEF";
	else
		base_string = "0123456789abcdef";
	str = (char *)malloc(sizeof(char) * len + 1);
	if (str == NULL)
		return (NULL);
	str[len] = '\0';
	while (nbr)
	{
		str[--len] = base_string[nbr % base];
		nbr = nbr / base;
	}
	if (value < 0)
		str[0] = '-';
	else if (value == 0)
		str[0] = '0';
	return (str);
}
