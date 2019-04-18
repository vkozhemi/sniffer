/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   int_flag_minus.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/21 17:36:34 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/21 17:36:36 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_flag_minus_int_0(t_s *s, intmax_t d)
{
	if (d < 0 && ++s->i)
		write(1, "-", 1);
	else if (s->plus && d >= 0 && s->flag_int && ++s->i)
		write(1, "+", 1);
	if (s->space && ++s->i)
		write(1, " ", 1);
	while (s->calc_precision > 0 && ++s->i)
	{
		ft_putchar('0');
		s->calc_precision--;
	}
}

void	ft_flag_minus_int(t_s *s, char *str, intmax_t d)
{
	if (s->space && d >= 0 && ++s->i)
		write(1, " ", 1);
	if (s->plus && d >= 0 && s->flag_int && ++s->i)
	{
		write(1, "+", 1);
		s->flag_int--;
	}
	if (s->calc_precision > 0)
		ft_flag_minus_int_0(s, d);
	if (d < 0 && s->precision == 0 && ++s->i)
		write(1, "-", 1);
	if (s->precision == 0 && d == 0 && s->flag_precision)
		write(1, "", 0);
	else
		ft_putstr(str);
	while (s->calc_width > 0 && ++s->i)
	{
		write(1, " ", 1);
		s->calc_width--;
	}
}
