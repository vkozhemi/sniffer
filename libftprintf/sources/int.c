/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   int.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/21 17:43:40 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/21 17:43:43 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_plus_minus_int(intmax_t d, char **str)
{
	if (d < 0)
		*str = ft_itoa_base_plus(d, 10, 0);
	else
		*str = ft_itoa_base(d, 10, 0);
}

void	ft_find_precision_int(t_s *s, char *str)
{
	if (s->precision)
	{
		s->calc_precision = s->precision - ft_strlen(str);
		if (s->calc_precision < 0)
			s->calc_precision = 0;
	}
	else
		s->calc_precision = 0;
}

void	ft_width_int(t_s *s, char *str, intmax_t d)
{
	if (s->width)
	{
		if (s->width && d == 0 && s->precision == 0 &&
			s->flag_precision)
			s->calc_width = s->width;
		else if ((s->plus && d > 0) || (s->plus && d < 0) ||
			d < 0 || (s->plus && d == 0))
			s->calc_width = s->width - ft_strlen(str) -
			s->calc_precision - 1;
		else if (d == 0 && s->precision == 0 && s->flag_precision)
			s->calc_width = s->width;
		else if (s->space)
			s->calc_width = s->width - ft_strlen(str) -
			s->calc_precision - 1;
		else
			s->calc_width = s->width - ft_strlen(str) -
			s->calc_precision;
	}
	else
		s->calc_width = 0;
	if (s->calc_width < 0)
		s->calc_width = 0;
}

void	ft_count_int(t_s *s, char *str, intmax_t d)
{
	if (d == 0 && s->precision)
		s->count += s->i + ft_strlen(str);
	else if (d == 0 && s->precision == 0 && s->flag_precision == 0)
		s->count += s->i + ft_strlen(str);
	else if (d == 0 && s->precision == 0)
		s->count += s->i;
	else
		s->count += ft_strlen(str) + s->i;
}

void	ft_int(intmax_t d, t_s *s)
{
	char	*str;

	s->flag_int = 1;
	str = NULL;
	s->calc_precision = 0;
	ft_plus_minus_int(d, &str);
	ft_find_precision_int(s, str);
	ft_width_int(s, str, d);
	if (s->minus)
		ft_flag_minus_int(s, str, d);
	else
		ft_flag_no_minus_int(s, str, d);
	ft_count_int(s, str, d);
	ft_bzero(s, sizeof(int) * 24 + sizeof(char) * 3);
	free(str);
}
