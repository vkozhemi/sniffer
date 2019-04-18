/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_pointer.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/03 19:22:27 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/08/03 19:22:30 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_pointer_precision(t_s *s, unsigned long int d)
{
	if (d == 0)
		s->calc_precision = s->precision;
	else
		s->calc_precision = s->precision - s->len_p;
	if (s->calc_precision < 0)
		s->calc_precision = 0;
}

void	ft_pointer_width(t_s *s, unsigned long int d)
{
	if (s->width && s->precision == 0 && d == 0 && s->flag_precision)
		s->calc_width = s->width - s->calc_precision - 1 - s->len_p;
	else if (s->width && s->precision && s->flag_precision && d == 0)
		s->calc_width = s->width - s->calc_precision - 1 - s->len_p;
	else
		s->calc_width = s->width - s->calc_precision - 2 - s->len_p;
}

void	ft_pointer_minus(t_s *s, char *str, unsigned long int d)
{
	ft_putstr("0x");
	while (s->calc_precision > 0 && ++s->count)
	{
		write(1, "0", 1);
		s->calc_precision--;
	}
	if (s->flag_precision == 0 && d == 0)
		write(1, "0", 1);
	if (d)
		ft_putstr(str);
	while (s->calc_width > 0 && ++s->count)
	{
		write(1, " ", 1);
		s->calc_width--;
	}
	if (d == 0 && s->precision == 0 && s->flag_precision == 0)
		s->count += 2 + s->len_p;
	else if (d == 0)
		s->count += 1 + s->len_p;
	else
		s->count += 2 + s->len_p;
}

void	ft_pointer_no_minus(t_s *s, char *str, unsigned long int d)
{
	if (s->noll == 0)
		while (s->calc_width-- > 0 && ++s->count)
			write(1, " ", 1);
	ft_putstr("0x");
	if (s->noll)
		while (s->calc_width-- > 0 && ++s->count)
			write(1, "0", 1);
	if (s->precision == 0 && d == 0 && s->flag_precision == 0)
		write(1, "0", 1);
	while (s->calc_precision-- > 0 && ++s->count)
		write(1, "0", 1);
	if (d)
		ft_putstr(str);
	if (d == 0 && s->precision == 0 && s->flag_precision == 0)
		s->count += 2 + s->len_p;
	else if (d == 0)
		s->count += 1 + s->len_p;
	else
		s->count += 2 + s->len_p;
}

void	ft_pointer(va_list ap, t_s *s)
{
	int					i;
	char				*str;
	unsigned long int	d;

	i = 0;
	d = va_arg(ap, unsigned long int);
	str = ft_itoa_base(d, 16, 1);
	s->len_p = ft_strlen(str);
	if (s->precision)
		ft_pointer_precision(s, d);
	else
		s->calc_precision = 0;
	if (s->width)
		ft_pointer_width(s, d);
	else
		s->calc_width = 0;
	if (s->calc_width < 0)
		s->calc_width = 0;
	if (s->minus)
		ft_pointer_minus(s, str, d);
	else if (s->minus == 0)
		ft_pointer_no_minus(s, str, d);
	ft_bzero(s, sizeof(int) * 24 + sizeof(char) * 3);
	free(str);
}
