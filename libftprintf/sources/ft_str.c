/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_str.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/03 18:30:41 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/08/03 18:30:43 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_str_precision(t_s *s, int *j)
{
	if (s->precision > *j)
		s->precision = *j;
	else
		*j = s->precision;
}

void	ft_str_minus(t_s *s, int j, char *str, int i)
{
	s->calc_width = s->width - j;
	if (s->calc_width < 0)
		s->calc_width = 0;
	while (str[i] && i < s->precision && ++s->count)
	{
		write(1, &str[i], 1);
		i++;
	}
	while (s->calc_width && ++s->count)
	{
		write(1, " ", 1);
		s->calc_width--;
	}
}

void	ft_str_no_minus(t_s *s, int j, char *str, int i)
{
	if (s->width)
	{
		s->calc_width = s->width - j;
		if (s->calc_width < 0)
			s->calc_width = 0;
		while (s->calc_width && ++s->count)
		{
			if (s->noll)
				write(1, "0", 1);
			else
				write(1, " ", 1);
			s->calc_width--;
		}
	}
	if (s->precision == 0 && s->flag_precision)
		write(1, "", 0);
	else if (s->precision)
		while (str[i] && i < s->precision && ++s->count)
			write(1, &str[i++], 1);
	else
	{
		ft_putstr(str);
		s->count += ft_strlen(str);
	}
}

void	ft_str(va_list ap, t_s *s)
{
	int		i;
	char	*str;
	int		j;

	i = 0;
	str = va_arg(ap, char *);
	if (!str)
		str = "(null)";
	j = ft_strlen(str);
	if (s->precision || s->flag_precision)
		ft_str_precision(s, &j);
	else
		s->precision = j;
	if (s->minus)
		ft_str_minus(s, j, str, i);
	else if (s->minus == 0)
		ft_str_no_minus(s, j, str, i);
	ft_bzero(s, sizeof(int) * 24 + sizeof(char) * 3);
}
