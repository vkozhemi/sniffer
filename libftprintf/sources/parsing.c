/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/24 17:52:15 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/24 17:52:18 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_flags(char *p, int *i, t_s *s)
{
	s->minus = 0;
	s->plus = 0;
	s->hash = 0;
	s->noll = 0;
	s->space = 0;
	while (p[*i] == '-' || p[*i] == '+' || p[*i] == '#'
			|| p[*i] == '0' || p[*i] == ' ')
	{
		if (p[*i] == '-')
			s->minus = 1;
		else if (p[*i] == '+')
			s->plus = 1;
		else if (p[*i] == '#')
			s->hash = 1;
		else if (p[*i] == '0')
			s->noll = 1;
		else if (p[*i] == ' ')
			s->space = 1;
		(*i)++;
	}
}

void	ft_field_width(char *p, int *i, t_s *s)
{
	s->width = 0;
	s->width = ft_atoi(p + (*i));
	while (p[*i] >= '0' && p[*i] <= '9')
		(*i)++;
}

void	ft_precision(char *p, int *i, t_s *s)
{
	s->flag_precision = 0;
	s->precision = 0;
	if (p[*i] == '.')
	{
		(*i)++;
		s->precision = ft_atoi(p + (*i));
		while (p[*i] >= '0' && p[*i] <= '9')
			(*i)++;
		s->flag_precision = 1;
	}
}

void	ft_size_modifier(char *p, int *i, t_s *s)
{
	if ((p[*i] == 'h' && p[*i + 1] == 'h') ||
			(p[*i] == 'l' && p[*i + 1] == 'l'))
	{
		if (p[*i] == 'h')
			s->modifier = 'H';
		else if (p[*i] == 'l')
			s->modifier = 'L';
		while (p[*i] == 'h' || p[*i] == 'l')
			(*i)++;
	}
	else if (p[*i] == 'h' || p[*i] == 'l' || p[*i] == 'j' || p[*i] == 'z')
	{
		s->modifier = p[*i];
		(*i)++;
	}
}
