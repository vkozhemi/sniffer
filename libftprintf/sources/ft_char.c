/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_char.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/03 18:28:22 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/08/03 18:28:25 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_char_s_minus(char c, t_s *s)
{
	write(1, &c, 1);
	s->count++;
	s->width -= 1;
	while (s->width && ++s->count)
	{
		write(1, " ", 1);
		s->width--;
	}
	s->count += s->i;
}

void	ft_char_s_no_minus(char c, t_s *s)
{
	s->width -= 1;
	while (s->width && ++s->count)
	{
		if (s->noll)
			write(1, "0", 1);
		else
			write(1, " ", 1);
		s->width--;
	}
	write(1, &c, 1);
	s->count++;
}

void	ft_char(char c, t_s *s)
{
	if (!c)
		c = '\0';
	if (s->width)
	{
		if (s->minus)
		{
			ft_char_s_minus(c, s);
		}
		else if (s->minus == 0)
			ft_char_s_no_minus(c, s);
	}
	else
	{
		write(1, &c, 1);
		s->count++;
	}
	ft_bzero(s, sizeof(int) * 24 + sizeof(char) * 3);
}
