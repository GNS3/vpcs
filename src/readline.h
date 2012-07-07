/*
 * Copyright (c) 2007-2012, Paul Meng (mirnshi@gmail.com)
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

#ifndef _READLINE_H_
#define _READLINE_H_

#include <termios.h>
#include "keydef.h"

struct rls {
	char kb[16];
	char *kbuffer;	/* key buffer */
	int pos; 	/* pointer of key buffer */
	char **history;
	int hist_total; /* current pointer of the history*/
	char *prompt;
	int maxbuflen;
	int maxhistnum;
	char** (*tab_callback)(const char *string, const char *part);
};

struct rls *readline_init(int histnum, int buflen);
void readline_free(struct rls *rls);

/* print the prompt, read a command string from the terminal and return it */
char *readline(const char *prompt, struct rls *rls);

/* register tab completion callback function
 *
 * char** (*cb)(const char *string, const char *part)
 *    args:   string, the current input string
 *            part, the partial word
 *    return: an array of strings which is a list of completions
 */
int readline_tab(char** (*cb)(const char *string, const char *part), struct rls *rls);

int savehistory(const char *filename, struct rls *rls);
int loadhistory(const char *filename, struct rls *rls);

void set_terminal(struct termios *stored_settings);
void reset_terminal(struct termios *stored_settings);

void kbhit(void);

#endif
/* end of file */
