/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   uns_int.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/23 18:00:06 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/23 18:00:11 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_choose_base(uintmax_t d, t_s *s, char **str)
{
	if (s->conversions == 'u')
		*str = ft_itoa_base_uns(d, 10, 0);
	else if (s->conversions == 'U')
		*str = ft_itoa_base_uns(d, 10, 0);
	else if (s->conversions == 'o')
		*str = ft_itoa_base_uns(d, 8, 0);
	else if (s->conversions == 'O')
		*str = ft_itoa_base_uns(d, 8, 0);
	else if (s->conversions == 'x')
		*str = ft_itoa_base_uns(d, 16, 1);
	else if (s->conversions == 'X')
		*str = ft_itoa_base_uns(d, 16, 0);
}

void	ft_find_precision_uns_int(t_s *s, uintmax_t d,
		char *p, int *i)
{
	if (s->precision)
	{
		if ((p[*i] == 'O' || p[*i] == 'o') && s->hash && d)
			s->calc_precision = s->precision - s->len - 1;
		else
			s->calc_precision = s->precision - s->len;
		if (s->calc_precision < 0)
			s->calc_precision = 0;
	}
	else
		s->calc_precision = 0;
}

void	ft_width_uns_int(t_s *s, uintmax_t d, char *p, int *i)
{
	if (s->width)
	{
		if (s->hash && d == 0 && (p[*i] == 'x' || p[*i] == 'X'))
			s->calc_width = s->width - s->len - s->calc_precision;
		else if (s->hash && (p[*i] == 'x' || p[*i] == 'X'))
			s->calc_width = s->width - s->len - s->calc_precision - 2;
		else if (s->hash && d == 0 && s->precision &&
			(p[*i] == 'o' || p[*i] == 'O'))
			s->calc_width = s->width - s->len - s->calc_precision;
		else if (s->hash && d == 0 && (p[*i] == 'o' || p[*i] == 'O'))
			s->calc_width = s->width - s->len - s->calc_precision;
		else if (s->hash && (p[*i] == 'o' || p[*i] == 'O'))
			s->calc_width = s->width - s->len - s->calc_precision - 1;
		else if (d == 0 && s->precision == 0 && s->flag_precision)
			s->calc_width = s->width;
		else if (s->width && d == 0 && s->precision == 0 &&
			s->flag_precision)
			s->calc_width = s->width;
		else
			s->calc_width = s->width - s->len - s->calc_precision;
	}
	else
		s->calc_width = 0;
	if (s->calc_width < 0)
		s->calc_width = 0;
}

void	ft_count_uns_int(t_s *s, uintmax_t d)
{
	if (d == 0 && s->precision)
		s->count += s->i + s->len;
	else if (d == 0 && s->precision == 0 && s->flag_precision == 0)
		s->count += s->i + s->len;
	else if (d == 0 && s->precision == 0)
		s->count += s->i;
	else
		s->count += s->i + s->len;
}

void	ft_uns_int(uintmax_t d, t_s *s, char *p, int *i)
{
	char *str;

	str = NULL;
	s->calc_precision = 0;
	ft_choose_base(d, s, &str);
	s->len = ft_strlen(str);
	s->str = str;
	ft_find_precision_uns_int(s, d, p, i);
	ft_width_uns_int(s, d, p, i);
	if (s->minus)
		ft_flag_minus_uns_int(s, d, p, i);
	else
		ft_flag_no_minus_uns_int(s, d, p, i);
	ft_count_uns_int(s, d);
	ft_bzero(s, sizeof(int) * 24 + sizeof(char) * 2 + sizeof(char*));
	free(str);
}
