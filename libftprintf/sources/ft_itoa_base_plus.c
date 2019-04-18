/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa_base_plus.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/17 16:13:57 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/17 16:14:01 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

intmax_t	ft_len_plus(intmax_t value, int base)
{
	intmax_t len;

	len = 0;
	while (value)
	{
		value = value / base;
		len++;
	}
	return (len);
}

intmax_t	ft_abs_plus(intmax_t value)
{
	if (value < 0)
		value = value * (-1);
	return (value);
}

char		*ft_itoa_base_plus(intmax_t value, int base, int size)
{
	intmax_t	nbr;
	int			len;
	char		*str;
	char		*base_string;

	if (value == MIN_SIZE)
		return (ft_strdup("9223372036854775808"));
	nbr = ft_abs_plus(value);
	len = ft_len_plus(value, base);
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
	if (value == 0)
		str[0] = '0';
	return (str);
}
