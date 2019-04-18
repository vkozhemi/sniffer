/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   uns_int_flag_no_minus.c                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/21 17:31:55 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/21 17:31:57 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_flag_no_minus_uns_int_0(t_s *s)
{
	if (s->noll && s->precision)
	{
		while (s->calc_width > 0 && ++s->i)
		{
			write(1, " ", 1);
			s->calc_width--;
		}
	}
}

void	ft_flag_no_minus_uns_int_1(t_s *s, uintmax_t d, char *p, int *i)
{
	while (s->calc_width > 0 && s->noll == 0 && ++s->i)
	{
		write(1, " ", 1);
		s->calc_width--;
	}
	if (s->hash && p[*i] == 'x' && d && s->flag_uns_int)
	{
		write(1, "0x", 2);
		s->i += 2;
		s->flag_uns_int--;
	}
	if (s->hash && p[*i] == 'X' && d && s->flag_uns_int)
	{
		write(1, "0X", 2);
		s->i += 2;
		s->flag_uns_int--;
	}
}

void	ft_flag_no_minus_uns_int_2(t_s *s, uintmax_t d)
{
	if (s->noll && d)
	{
		while (s->calc_width > 0 && ++s->i)
		{
			write(1, "0", 1);
			s->calc_width--;
		}
	}
}

void	ft_flag_no_minus_uns_int(t_s *s, uintmax_t d, char *p,
		int *i)
{
	s->flag_uns_int = 1;
	ft_flag_no_minus_uns_int_0(s);
	ft_flag_no_minus_uns_int_1(s, d, p, i);
	ft_flag_no_minus_uns_int_2(s, d);
	if (s->hash && d > 0 && (p[*i] == 'o' || p[*i] == 'O') && ++s->i)
		write(1, "0", 1);
	else if (s->hash && d == 0 && s->flag_precision == 1
		&& (p[*i] == 'o' || p[*i] == 'O') && ++s->i)
		write(1, "0", 1);
	else if (s->hash && d == 0 && s->noll && s->precision == 0
		&& (p[*i] == 'o' || p[*i] == 'O') && ++s->i)
		write(1, "0", 1);
	while (s->calc_precision > 0 && ++s->i)
	{
		write(1, "0", 1);
		s->calc_precision--;
	}
	if (s->precision == 0 && d == 0 && s->flag_precision)
		write(1, "", 0);
	else
		ft_putstr(s->str);
}
