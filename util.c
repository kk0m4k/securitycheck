/*
 * 리눅스 및 유닉스 계열 시스템의 서버 보안 설정 현황을 체크하기 위한 프로그램
*/

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(HPUX)
#include <ctype.h>
#endif


#define TRUE	1
#define FALSE	0

char **strv_init();
int strv_count(char **strv);
int strv_insert(char ***pstrv, char *str, int endline);
void strv_free(char **strv);
char *strchomp(char *str);
char *strchop(char *str);
void strcata(char **pstr, char *str);
char **split(char *str, char *delim);
char **split_tok(char *str, char *tok);
char *merge(char **strv, char *delim);
char* strtrim(char* str);
int iswhitespace(int c);

int
StrLwr( char *str )
{ 
	int loop = 0; 
	while( str[loop] != '\0' ) 
	{
		str[loop] = (char) tolower( str[loop] );
		loop++;
	}
	return loop; 
}

int
logwrite(const char * logfile, const char * p_data) {
	FILE *p_FILEstream = NULL;

	p_FILEstream = fopen(logfile, "a+");
	if ( !p_FILEstream ) return FALSE;

	fwrite(p_data, 1, strlen(p_data), p_FILEstream);
	fclose(p_FILEstream);
	return TRUE;	
}

int
delete_comment( char *str )
{ 
	int loop = 0; 
	while( str[loop] != '\0' ) 
	{
		if ( str[loop] == '#') {
			str[loop] = '\0';
			break;
		}
		str[loop] = str[loop];
		loop++;
	}
	return loop; 
}


int g_cli_sockfd = -1;
pid_t pipecmd(char *arg, FILE *fp[])
{
	int fds_out[2];
	int fds_in[2];
	pid_t pid;

	pipe(fds_out);
	pipe(fds_in);
	signal(SIGCHLD,SIG_IGN);

	if ((pid = fork()) == 0)
	{
		char **argv = split(arg, " ");
		signal(SIGCHLD,SIG_IGN);
		signal(SIGTERM, SIG_DFL);
		signal(SIGINT, SIG_DFL);

		if ( g_cli_sockfd >= 0 ) close(g_cli_sockfd);
		close(fds_out[0]);
		close(STDOUT_FILENO);
		dup2(fds_out[1], STDOUT_FILENO);

		close(fds_in[1]);
		close(STDIN_FILENO);
		dup2(fds_in[0], STDIN_FILENO);
		if (execvp(argv[0], argv) < 0)
			exit(-1);
		return pid;
	}
	close(fds_out[1]);
	close(fds_in[0]);
	fp[0] = fdopen(fds_out[0], "r");
	fp[1] = fdopen(fds_in[1], "w");
	return pid;
}



void strcata(char **pstr, char *str)
{
	if (*pstr) {
		*pstr = realloc(*pstr, strlen(*pstr) + strlen(str) + 1);
		strcat(*pstr, str);
	}
	else
		*pstr = strdup(str);
}

char **strv_init()
{
	char **strv = malloc(sizeof (char *));

	*strv = NULL;
	return strv;
}

int strv_count(char **strv)
{
	char **sptr = strv;
	int count = 0;

	while (*sptr) {
		sptr++;
		count++;
	}

	return count;
}

int strv_insert(char ***pstrv, char *str, int endline)
{
	char **sptr;
	int count = strv_count(*pstrv);

	*pstrv = realloc(*pstrv, (count + 2) * sizeof (char *));
	if (!pstrv)
		return -1;
	sptr = *pstrv + count;
	*sptr = NULL;
	if (endline & 2)
		strcata(sptr, "\r\n");
	strcata(sptr, str);
	if (endline & 1)
		strcata(sptr, "\r\n");
	sptr++;
	*sptr = NULL;


	return 0;
}

void strv_free(char **strv)
{
	char **sptr = strv;

	if (sptr == NULL)
		return;
	while (*sptr) {
		free(*sptr);
		sptr++;
	}

	free(strv);
	return;
}

char *strchomp(char *str)
{
	int len = strlen(str);
	while (len > 0 && iswhitespace(str[len - 1])) {
		str[len - 1] = '\0';
		len--;
	}
	return str;
}

char *strchop(char *str)
{
	char *ptr = str;
	while (iswhitespace(*ptr))
		ptr++;
	if (ptr != str) {
		char *ptr2 = str;
		while (*ptr) {
			*ptr2 = *ptr;
			ptr++;
			ptr2++;
		}
		*ptr2 = *ptr;
	}
	return strchomp(str);
}

char **split(char *str, char *delim)
{
	char **strv = strv_init();
	char *tmp = strdup(str);
	char *ptr = tmp;
	char *dptr = strstr(ptr, delim);

	int dlen = strlen(delim);

	while (dptr)
	{
		*dptr = '\0';
		strchomp(ptr);
		strv_insert(&strv, ptr, 0);
		ptr = dptr + dlen;
		dptr = strstr(ptr, delim);
	}
	strchomp(ptr);
	strv_insert(&strv, ptr, 0);
	free(tmp);

	return strv;
}

char **split_tok(char *str, char *tok)
{
	char **strv = strv_init();
	char *tmp = strdup(str);
	char *ptr = strtok(tmp, tok);

	while (ptr)
	{
		strchomp(ptr);
		strv_insert(&strv, ptr, 0);
		ptr = strtok(NULL, tok);
	}
	free(tmp);

	return strv;
}

char *merge(char **strv, char *delim)
{
	char **sptr = strv;
	char *str = NULL;

	while (*sptr) {
		strcata(&str, *sptr);
		sptr++;
		if (*sptr)
			strcata(&str, delim);
	}

	return str;
}


char* strtrim(char* str)
{
	int i;
	while( isspace((int)*str) ) str++;

	i = strlen(str);
	for (--i;i>=0;i--) {
		if( !isspace((int)str[i]) )
			break;
		str[i] = '\0';
	}
	return str;
}

int iswhitespace(int c)
{
	if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
		return 1;

	return 0;
}

