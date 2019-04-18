/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   uns_int_flag_minus.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/21 17:36:34 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/21 17:36:36 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_flag_minus_uns_int_0(t_s *s, uintmax_t d, char *p, int *i)
{
	if (s->hash && d && (p[*i] == 'o' || p[*i] == 'O') && ++s->i)
		write(1, "0", 1);
	if (s->hash && p[*i] == 'x' && d)
	{
		write(1, "0x", 2);
		s->i += 2;
	}
	else if (s->hash && p[*i] == 'X' && d)
	{
		write(1, "0X", 2);
		s->i += 2;
	}
}

void	ft_flag_minus_uns_int(t_s *s, uintmax_t d, char *p, int *i)
{
	ft_flag_minus_uns_int_0(s, d, p, i);
	while (s->calc_precision > 0 && ++s->i)
	{
		write(1, "0", 1);
		s->calc_precision--;
	}
	if (s->hash && d == 0 && s->precision == 0 &&
		s->flag_precision && (p[*i] != 'X' || p[*i] != 'x') && ++s->i)
		write(1, "0", 1);
	if (s->hash && d == 0 && s->precision == 0 &&
		s->flag_precision && (p[*i] == 'X' || p[*i] == 'x') && ++s->i)
		write(1, " ", 1);
	if (s->precision == 0 && d == 0 && s->flag_precision)
		write(1, "", 0);
	else
		ft_putstr(s->str);
	while (s->calc_width > 0 && ++s->i)
	{
		write(1, " ", 1);
		s->calc_width--;
	}
}
