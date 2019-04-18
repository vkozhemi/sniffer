/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   printf.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/24 16:39:15 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/24 16:39:18 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_get_conversions_str(char *p, int *i, t_s *s)
{
	if (p[*i] == 'c')
		s->conversions = p[*i];
	else if (p[*i] == 's')
		s->conversions = p[*i];
	else if (p[*i] == 'C')
		s->conversions = p[*i];
	else if (p[*i] == 'S')
		s->conversions = p[*i];
	else if (p[*i] == '%')
		s->conversions = p[*i];
}

void	ft_get_conversions(char *p, int *i, t_s *s)
{
	if (p[*i] == 'd' || p[*i] == 'i')
		s->conversions = p[*i];
	else if (p[*i] == 'D')
		s->conversions = p[*i];
	else if (p[*i] == 'u')
		s->conversions = p[*i];
	else if (p[*i] == 'U')
		s->conversions = p[*i];
	else if (p[*i] == 'O')
		s->conversions = p[*i];
	else if (p[*i] == 'o')
		s->conversions = p[*i];
	else if (p[*i] == 'x')
		s->conversions = p[*i];
	else if (p[*i] == 'X')
		s->conversions = p[*i];
	else if (p[*i] == 'p')
		s->conversions = p[*i];
}

void	ft_check_conversions(char *p, int *i, t_s *s)
{
	if (p[*i] == 's' || p[*i] == 'S' || p[*i] == 'p' || p[*i] == 'd' ||
		p[*i] == 'D' || p[*i] == 'i' || p[*i] == 'o' || p[*i] == 'O' ||
		p[*i] == 'u' || p[*i] == 'U' || p[*i] == 'x' || p[*i] == 'X' ||
		p[*i] == 'c' || p[*i] == 'C' || p[*i] == '%')
		(*i)++;
	else
	{
		ft_char(p[*i], s);
		(*i)++;
	}
}

void	ft_call_pars(char *fmt, va_list ap, t_s *s)
{
	int		i;
	char	*p;

	i = 0;
	p = fmt;
	while (p[i])
	{
		if (p[i] == '%')
		{
			if (!p[i + 1])
				return ;
			i++;
			ft_flags(p, &i, s);
			ft_field_width(p, &i, s);
			ft_precision(p, &i, s);
			ft_size_modifier(p, &i, s);
			ft_conversions(p, &i, ap, s);
			ft_check_conversions(p, &i, s);
		}
		else if (++s->count)
		{
			write(1, &p[i], 1);
			i++;
		}
	}
}

int		ft_printf(char *fmt, ...)
{
	size_t	result;
	t_s		*s;
	va_list	ap;
	int		len;

	result = 0;
	s = (t_s*)malloc(sizeof(t_s));
	s->count = 0;
	va_start(ap, fmt);
	ft_call_pars(fmt, ap, s);
	va_end(ap);
	len = s->count;
	free(s);
	return (len);
}
