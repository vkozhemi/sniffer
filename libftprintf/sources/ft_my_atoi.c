/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_my_atoi.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/23 19:36:44 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/08/23 19:36:46 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

int		ft_my_atoi(const char *str, int *i)
{
	unsigned long long int	result;

	result = 0;
	while (str[*i] == ' ')
		(*i)++;
	while (str[*i] >= '0' && str[*i] <= '9')
		result = result * 10 + str[(*i)++] - '0';
	return (result);
}
