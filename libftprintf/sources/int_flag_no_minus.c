/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   int_flag_no_minus.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/21 17:31:55 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/21 17:31:57 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_flag_no_minus_int_0(t_s *s, intmax_t d)
{
	if (s->calc_width == 0 && s->plus && d >= 0 && ++s->i)
		write(1, "+", 1);
	else if (d < 0 && ++s->i)
		write(1, "-", 1);
}

void	ft_flag_no_minus_int_1(t_s *s, intmax_t d)
{
	while (s->calc_width > 0 && ++s->i)
	{
		write(1, " ", 1);
		s->calc_width--;
	}
	if (s->plus && d >= 0 && ++s->i)
		write(1, "+", 1);
	else if (d < 0 && ++s->i)
		write(1, "-", 1);
}

void	ft_flag_no_minus_int_2(t_s *s, intmax_t d)
{
	while (s->calc_width && d < 0 && ++s->i)
	{
		write(1, " ", 1);
		s->calc_width--;
	}
	if (s->plus && d >= 0 && ++s->i)
		write(1, "+", 1);
	else if (d < 0 && ++s->i)
		write(1, "-", 1);
	else if (++s->i)
		write(1, " ", 1);
}

void	ft_flag_no_minus_int_3(t_s *s, intmax_t d)
{
	if (d < 0 && s->flag_int && ++s->i)
	{
		write(1, "-", 1);
		s->flag_int--;
	}
	else if (s->plus && d >= 0 && s->flag_int && ++s->i)
	{
		write(1, "+", 1);
		s->flag_int--;
	}
	write(1, "0", 1);
	s->i++;
}

void	ft_flag_no_minus_int(t_s *s, char *str, intmax_t d)
{
	if (s->space && s->noll && s->calc_width && d >= 0
		&& ++s->i)
		write(1, " ", 1);
	else if (s->space && s->plus == 0 && d > 0 && ++s->i)
		write(1, " ", 1);
	if (s->calc_width == 0)
		ft_flag_no_minus_int_0(s, d);
	while (s->calc_width > 0)
	{
		if ((d < 0 && s->noll == 0) || (s->plus && s->noll == 0))
			ft_flag_no_minus_int_1(s, d);
		else if (s->noll && s->precision)
			ft_flag_no_minus_int_2(s, d);
		else if (s->noll)
			ft_flag_no_minus_int_3(s, d);
		else if (++s->i)
			write(1, " ", 1);
		s->calc_width--;
	}
	while (0 < s->calc_precision-- && ++s->i)
		write(1, "0", 1);
	if (s->precision == 0 && d == 0 && s->flag_precision)
		write(1, "", 0);
	else
		ft_putstr(str);
}
