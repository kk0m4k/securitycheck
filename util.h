/*
 * 리눅스 및 유닉스 계열 시스템의 서버 보안 설정 현황을 체크하기 위한 프로그램
*/

#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>

int StrLwr( char *str );
int logwrite(const char * logfile, const char * p_data);
pid_t pipecmd(char *arg, FILE *fp[]);
