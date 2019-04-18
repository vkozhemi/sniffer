/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_percent.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/04 14:25:23 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/08/04 14:25:27 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_percent(t_s *s)
{
	s->width -= 1;
	if (s->minus && ++s->count)
	{
		write(1, "%", 1);
		if (s->width)
			while (0 < s->width-- && ++s->count)
				write(1, " ", 1);
	}
	else if (s->minus == 0 && ++s->count)
	{
		if (s->width)
		{
			while (0 < s->width-- && ++s->count)
			{
				if (s->noll)
					write(1, "0", 1);
				else
					write(1, " ", 1);
			}
		}
		write(1, "%", 1);
	}
	ft_bzero(s, sizeof(int) * 22 + sizeof(char) * 3);
}
