/*
 * Copyright (c) 2007-2011, Paul Meng (mirnshi@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
 * THE POSSIBILITY OF SUCH DAMAGE.
**/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#if Linux || Darwin
#include <sys/ioctl.h>
#endif

#include <termios.h>

#include "keydef.h"
#include "readline.h"

int _readline(struct rls *rls);
int findhistory(struct rls *rls, int start);
void trimspace(char *buf);
void vprint(char *s, int len);

void set_terminal(struct termios *ts);
void reset_terminal(struct termios *ts);

char *readline(const char *prompt, struct rls *rls)
{	
	if (prompt == NULL || rls == NULL)
		return NULL;

	printf("%s", prompt);
	fflush(stdout);	
	rls->prompt = (char *)prompt;
	if (_readline(rls) == 0)
		return NULL;
	
	return rls->kbuffer;
}

int readline_tab(char** (*cb)(const char *string, const char *part), struct rls *rls)
{
	if (cb != NULL)
		rls->tab_callback = cb;
	
	return 0;
}

int loadhistory(const char *filename, struct rls *rls)
{
	FILE *fp = fopen(filename, "r");
	int len;
	
	if (fp == NULL)
		return errno;

	while (fgets(rls->kbuffer, rls->maxbuflen, fp)) {
		len = strlen(rls->kbuffer);
		if (len == 0)
			continue;
		if (rls->kbuffer[len - 1] == '\n')
			rls->kbuffer[len - 1] = '\0';
			
		if (rls->hist_curr == rls->maxhistnum) {
			memmove(rls->history[0], rls->history[1], rls->maxhistnum - 1);
			rls->hist_curr--;
		}
		strcpy(rls->history[rls->hist_curr++], rls->kbuffer);

	}
	rls->hist_total = rls->hist_curr;
	fclose(fp);
	
	return 0;
}

int savehistory(const char *filename, struct rls *rls)
{
	FILE *fp = fopen(filename, "w");
	int i;
	
	if (fp == NULL)
		return errno;
	
	for (i = 0; i < rls->hist_total; i++)
		fprintf(fp, "%s\n", rls->history[i]);
	fclose(fp);
	
	return 0;
}

struct rls * readline_init(int histnum, int buflen)
{
	struct rls *rls = NULL;
	int i;
	char *p = NULL;
	
	if (histnum < 1 || buflen < 1)
		return NULL;
		
	rls = malloc(sizeof(struct rls));
	while (rls != NULL) {
		memset(rls, 0, sizeof(struct rls));
		
		p = malloc((histnum + 2) * buflen);
		if (p == NULL)
			break;
		memset(p, 0, (histnum + 2) * buflen);
		rls->kbuffer = p;
		
		rls->history = malloc(histnum * sizeof(char *));	
		if (rls->history == NULL)
			break;
		for (i = 0; i <= histnum; i++) 
			rls->history[i] = p + buflen * i;
		
		rls->kbuffer = p + buflen * (histnum + 1);
		rls->maxbuflen = buflen;
		rls->maxhistnum = histnum;
	
		return rls;
	}
	
	if (p != NULL)
		free(p);
	
	if (rls != NULL)
		free(rls);
		
	return NULL;	
}

void readline_free(struct rls *rls)
{
	if (rls->kbuffer != NULL)
		free(rls->kbuffer);
	if (rls->history != NULL)
		free(rls->history);
	free(rls);
}

int _readline(struct rls *rls)
{
	int flags;
	struct termios termios;
	int i, j;
	int fkey;
	char *kb;
	int ihist;
	int rc;
	char **tab;
	char *p;
	
	set_terminal(&termios);
	
	memset(rls->kbuffer, 0, rls->maxbuflen);
	rls->pos = 0;
	rls->hist_curr = rls->hist_total;
	/*
	flags = fcntl(0, F_GETFL);
	fcntl(0, F_SETFL, flags);
	*/
	
	flags = 0;
	ihist = 0;
	kb = rls->kb;
	do {
		fflush(stdout);
		memset(kb, 0, sizeof(rls->kb));
		rc = read(0, kb, sizeof(rls->kb));
		if (rc <= 0) {
			usleep(1);
			continue;
		}
#if 0
		printf("\n%2.2x - %2.2x - %2.2x - %2.2x - %2.2x - %2.2x - %2.2x - %2.2x\n",
			kb[0], kb[1], kb[2], kb[3], kb[4], kb[5], kb[6], kb[6]);
		fflush(stdout);
#endif		
		if (kb[0] == ESC && kb[1] == ESC_PAD) {
			fkey = kb[2] | (kb[3] << 8);
			if (fkey == KEY_UP) {
				if (flags == 0) {
					/* set history-mode */
					flags = 1;
					ihist = rls->hist_total;
					if (rls->pos != 0)
						strcpy(rls->history[rls->maxhistnum], rls->kbuffer);
					else
						rls->history[rls->maxhistnum][0] = '\0';
				};
				if (ihist == 0)
					continue;
						
				i = findhistory(rls, 0 - ihist);
				
				if (i == -1)
					continue;
				ihist = i;
				
				while (rls->pos-- > 0)
					vprint("\b \b", 3);
				
				strcpy(rls->kbuffer, rls->history[ihist]);

				rls->pos = strlen(rls->kbuffer);
				vprint(rls->kbuffer, rls->pos);

				continue;
			}
			
			if (fkey == KEY_DOWN){
				if (flags == 0)
					continue;
				if (ihist >= rls->hist_total)
					continue;
						
				i = findhistory(rls, ihist);
				if (i == -1)
					continue;
				ihist = i;
				
				while (rls->pos-- > 0)
					vprint("\b \b", 3);
				
				strcpy(rls->kbuffer, rls->history[ihist]);

				rls->pos = strlen(rls->kbuffer);
				vprint(rls->kbuffer, rls->pos);

				continue;
			}
			if (fkey == KEY_RIGHT) {
				if (rls->pos < strlen(rls->kbuffer))
					vprint(&(rls->kbuffer[rls->pos++]), 1);
				continue;
			}
			if (fkey == KEY_LEFT) {
				if (rls->pos > 0) {
					vprint("\b", 1);
					rls->pos --;
				}
				continue;
			}
			if (fkey == KEY_HOME) {
				while (rls->pos > 0) {
					vprint("\b", 1);
					rls->pos --;
				}
				continue;
			}
			if (fkey == KEY_END) {
				while (rls->pos < strlen(rls->kbuffer)) {
					vprint(&(rls->kbuffer[rls->pos++]), 1);
				}
				continue;
			}	
			
		}
		flags = 0;
				
		/* 'enter' */
		if (kb[0] == LF) {
			trimspace(rls->kbuffer);
			rls->pos = strlen(rls->kbuffer);
			if (rls->pos == 0)
				break;
			if (rls->hist_total == rls->maxhistnum) {
				memmove(rls->history[0], rls->history[1], 
				    rls->maxbuflen * (rls->maxhistnum - 1));
				rls->hist_total--;
			}
			strcpy(rls->history[rls->hist_total++], rls->kbuffer);
			break;
		} 
		
		if (kb[0] == CTRLC) {
			rls->pos = 0;
			rls->kbuffer[0] = '\0';
			break;
		}
		
		if (kb[0] == '\t') {
			if (rls->tab_callback == NULL)
				continue;
			
			p= NULL;
			if (rls->pos != 0) {
				p = rls->kbuffer + rls->pos;
				while (p > rls->kbuffer) {
					if (*(p - 1) == ' ')
						break;
					p--;
				}
			}
			
			tab = rls->tab_callback(rls->kbuffer, p);
			if (tab == NULL)
				continue;
			
			/* only one */	
			if (*tab != NULL && *(tab + 1) == NULL) {
				
				for (i = 0; i < strlen(p); i++)
					vprint("\b \b", 3);
				i = strlen(*tab);
				vprint(*tab, i);
				if (p - rls->kbuffer + i < rls->maxbuflen) {
					strcpy(p, *tab);
					rls->pos = strlen(rls->kbuffer);
				}
				
				free(*tab);
				free(tab);
				continue;			
			}
			/* more than one */
			vprint("\n", 1);
			i = 0;
			while (*(tab + i)) {
				vprint(*(tab + i), strlen(*(tab + i)));
				vprint(" ", 1);
				free(*(tab + i));
				i++;
			}
			vprint("\n", 1);
			free(tab);
			
			vprint(rls->prompt, strlen(rls->prompt));
			vprint(rls->kbuffer, rls->pos);
			continue;
		}
		
		/* backspace */
		if ((kb[0] == BACKSP0)|| (kb[0] == BACKSP1)) {
			if (rls->pos > 0) {
				i = strlen(rls->kbuffer);
				j = rls->pos;
				while (j < i) {
					rls->kbuffer[j - 1] = rls->kbuffer[j];
					j++;
				}
				rls->kbuffer[j - 1] = '\0';
				
				rls->pos--;
				vprint("\b", 1);
				vprint(&rls->kbuffer[rls->pos], strlen(&rls->kbuffer[rls->pos]));
				vprint(" \b", 2);
				for (i = 0; i < strlen(rls->kbuffer) - rls->pos; i++)
					vprint("\b", 1);
			}
			continue;
		}
		
		/* normal key */	
		i = 0;
		while (i < rc) {
			if (isprint((int)kb[i])) {
				if (rls->pos < strlen(rls->kbuffer)) {
					j = strlen(rls->kbuffer);
					/* avoid overflow */
					if (j < rls->maxbuflen - 1) {
						while (j > rls->pos) {
							rls->kbuffer[j] = rls->kbuffer[j-1];
							j--;
						}
						
						rls->kbuffer[rls->pos] = kb[i];
						vprint(&rls->kbuffer[rls->pos], 
						    strlen(&rls->kbuffer[rls->pos]));
						for (j = 0; j < strlen(rls->kbuffer) - rls->pos - 1; j++)
							vprint("\b", 1);
					}
				} else {
					rls->kbuffer[rls->pos] = kb[i];
					vprint(&kb[i], 1);
				}
				rls->pos++;
			}
			i++;
		}
	} while (kb[0] != CTRLP);
		
	reset_terminal(&termios);
	
	return 1;
}

int findhistory(struct rls *rls, int start)
{
	int len, i;
	
	/* no pattern */
	len = strlen(rls->history[rls->maxhistnum]);
	if (len == 0) {
		if (start >= 0) {
			start++;
			return (start < rls->hist_total) ? start : -1;
		} else {
			start = 0 - start;
			start --;
			return (start > - 1) ? start : -1;
		}
	} else {
		if (start >= 0) {
			start++;
			for (i = start; i < rls->hist_total; i++)
				if (!strncmp(rls->history[rls->maxhistnum], rls->history[i], len))
					return i;
			return -1;
		} else {
			start = 0 - start;
			start --;
			for (i = start; i >= 0; i--)
				if (!strncmp(rls->history[rls->maxhistnum], rls->history[i], len))
					return i;
			return -1;
		}
	}

}

void trimspace(char *buf)
{
	char *p, *q;
	
	p = buf;
	
	if (p == NULL)
		return;
	q = p + strlen(p);
	
	while (q > p && *q == ' ')
		q--;
	*(q + 1) = '\0';
	
	while (*p == ' ')
		p++;
	q = p;
	
	while (*q != '\0')
	    *p++ = *q++;
	*p = '\0';
}

void vprint(char *s, int len)
{
	int rc;
	rc = write(1, s, len);
	if (rc != len);
}

void set_terminal(struct termios *stored_settings)
{
	struct termios new_settings;
	
	tcgetattr(0, stored_settings);
	new_settings = *stored_settings;
	new_settings.c_lflag &= ~(ICANON | ECHO | ISIG);
	new_settings.c_cc[VTIME] = 0;
	new_settings.c_cc[VMIN] = 1;

	tcsetattr(0, TCSANOW, &new_settings);
	return;
}

void reset_terminal(struct termios *stored_settings)
{
	tcsetattr(0, TCSANOW, stored_settings);
	return;
}

#ifdef MAIN
char* cmd [] ={ "happy", "hot", "how" ,"read", "red", NULL };

char **my_complete(const char *string, const char *part)
{
	char **matches;
	int i, j;
	
	matches = malloc(20 * sizeof(char *));
	if (matches == NULL)
		return NULL;

	memset(matches, 0, 20 * sizeof(char*));
	i = j = 0;
	if (part != NULL) {
		while (cmd[i] != NULL) {
			if (!strncmp(part, cmd[i], strlen(part)))
				matches[j++] = strdup(cmd[i]);
			i++;
		}
	} else {
		while (cmd[i] != NULL) {
			matches[j++] = strdup(cmd[i]);
			i++;
		}
	}

	return matches;
}

int main(int argc, char **argv)
{
	struct rls *rls;
	char *p;
	int i;
	
	rls = readline_init(5, 1024);
	readline_tab(my_complete, rls);
	while (rls) {
		p = readline("CLI> ", rls);
		if (p != NULL)
			printf("\nget %s\n", p);
		if (!strcmp(p, "h")) {
			printf("\n");
			for (i = 0; i < rls->hist_total; i++)
				printf("%d: %s\n", i + 1, rls->history[i]);
		}	
		if (strcmp(p, "quit"))
			continue;
		break;
	}
	return 1;
}
#endif
/* end of file */
