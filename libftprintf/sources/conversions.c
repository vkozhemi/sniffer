/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   conversions.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/24 17:04:40 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/24 17:04:43 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_c(va_list ap, t_s *s, wchar_t value)
{
	char c;

	if (s->modifier == 'l')
	{
		value = va_arg(ap, wchar_t);
		ft_wchar_c(value, s);
	}
	else
	{
		c = va_arg(ap, int);
		ft_char(c, s);
	}
}

void	ft_s(va_list ap, t_s *s)
{
	if (s->modifier == 'l')
		ft_wchar_s(ap, s);
	else
		ft_str(ap, s);
}

void	ft_d_i_d(char *p, int *i, va_list ap, t_s *s)
{
	if (s->modifier == 'l' || p[*i] == 'D')
		ft_int(va_arg(ap, long int), s);
	else if (s->modifier == 'L')
		ft_int(va_arg(ap, long long int), s);
	else if (s->modifier == 'h')
		ft_int((short)va_arg(ap, int), s);
	else if (s->modifier == 'H')
		ft_int((char)va_arg(ap, int), s);
	else if (s->modifier == 'j')
		ft_int(va_arg(ap, intmax_t), s);
	else if (s->modifier == 'z')
		ft_int(va_arg(ap, size_t), s);
	else
		ft_int(va_arg(ap, int), s);
}

void	ft_u_x_o(char *p, int *i, va_list ap, t_s *s)
{
	if (s->modifier == 'l')
		ft_uns_int(va_arg(ap, unsigned long int), s, p, i);
	else if (s->modifier == 'L')
		ft_uns_int(va_arg(ap, unsigned long long int), s, p, i);
	else if (s->modifier == 'h' && p[*i] != 'U')
		ft_uns_int((unsigned short)va_arg(ap, unsigned int), s, p, i);
	else if (s->modifier == 'H' && (p[*i] == 'O' || p[*i] == 'U'))
		ft_uns_int((unsigned int)va_arg(ap, unsigned int), s, p, i);
	else if (s->modifier == 'H')
		ft_uns_int((unsigned char)va_arg(ap, unsigned int), s, p, i);
	else if (s->modifier == 'j')
		ft_uns_int(va_arg(ap, uintmax_t), s, p, i);
	else if (s->modifier == 'z')
		ft_uns_int(va_arg(ap, size_t), s, p, i);
	else if (p[*i] == 'U' || p[*i] == 'O')
		ft_uns_int(va_arg(ap, unsigned long int), s, p, i);
	else
		ft_uns_int(va_arg(ap, unsigned int), s, p, i);
}

void	ft_conversions(char *p, int *i, va_list ap, t_s *s)
{
	wchar_t value;

	value = 0;
	ft_get_conversions(p, i, s);
	ft_get_conversions_str(p, i, s);
	if (p[*i] == 'c')
		ft_c(ap, s, value);
	else if (p[*i] == 's')
		ft_s(ap, s);
	else if (p[*i] == 'd' || p[*i] == 'i' || p[*i] == 'D')
		ft_d_i_d(p, i, ap, s);
	else if (p[*i] == 'u' || p[*i] == 'U' || p[*i] == 'o' || p[*i] == 'O'
			|| p[*i] == 'x' || p[*i] == 'X')
		ft_u_x_o(p, i, ap, s);
	else if (p[*i] == 'C')
	{
		value = va_arg(ap, wchar_t);
		ft_wchar_c(value, s);
	}
	else if (p[*i] == 'S')
		ft_wchar_s(ap, s);
	else if (p[*i] == 'p')
		ft_pointer(ap, s);
	else if (p[*i] == '%')
		ft_percent(s);
}
