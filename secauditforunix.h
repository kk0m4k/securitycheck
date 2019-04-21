/*
 * written by Kim, Taehoon(kimfrancesco@gmail.com)
*/

#ifndef SECAUDITFORUNIX
#define SECAUDITFORUNIX

#include "util.h"
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>


#define	TRUE	0
#define	FALSE	1
#define MAXBUF	4096

#define	SAFE	"SAFE"
#define WEAK	"WEAK"
#define	NA	"NA"



#define ROOTUID 0
#define ROOTGID 0


#define	UMASK_CMD	"umask"
#define	PATH_CMD	"env"
const char * p_pwdfile = "/etc/passwd";

#ifdef Linux
const char * p_pwdconfigfile = "/etc/login.defs";
const char * p_root_remoteloginfile = "/etc/securetty";
#define SHADOWPWFILE	"/etc/shadow"	
#define PASSWORDMINLENTH	"PASS_MIN_LEN"

#elif defined(SunOS)
const char * p_pwdconfigfile = "/etc/default/passwd";
const char * p_root_remoteloginfile = "/etc/default/login";
#define SHADOWPWFILE	"/etc/shadow"	
#define PASSWORDMINLENTH	"PASSLENGTH"

#elif defined(HPUX)
const char * p_pwdconfigfile = "/etc/default/security";
const char * p_root_remoteloginfile = "/etc/securetty";
#define SHADOWPWFILE	"/tcb/files/auth/r/root"	
#define NONTRUST_PASSWORDMINLENTH "MIN_PASSWORD_LENGTH"
#define TRUST_PASSWORDMINLENTH "u_maxlen"
#endif

#define	CATEGORY_PREFIX				"[No_%d]"
#define	CHK_ROOTUID_COMMENT			"root 계정 이외에 UID 0를 갖고 있는 계정이 있는지 조사"
#define CHK_PASSWD_MIN_LENGTH_COMMENT		"계정 패스워드 최소 길이 확인(최소 길이 8이상)"
#define	CHK_PASSWD_SHADOWING_COMMENT		"패스워드 파일 sahdowing(/etc/shadow, /tcb/...)이 활성화되어 있는지 조사"
#define	CHK_HOMEDIR_PERMISSION_COMMENT		"계정별 홈디렉터리 권한의 적절성 확인"
#define CHK_GLOBALPROFILE_PERMISSION_COMMENT	"시스템 /etc/profile 환경 설정 파일의 퍼미션 조사"
#define	CHK_ROOT_REMOTELOGIN_COMMENT		"root 계정으로 원격 쉘 접속(telnet/rlogin) 가능 조사"
#define	CHK_HISTORYFILE_PERMISSION_COMMENT	"계정별 history 파일의 퍼미션 조사"
#define CHK_ROOTUMASK_PERMISSION_COMMENT	"root 계정의 umask 설정 조사"
#define CHK_ROOT_PATHENV_COMMENT		"root 계정의 PATH 환경변수 시작이 .(현재디렉터리)되어  있는지 조사"
#define CHK_GLOBALSYSTEM_PERMISSION_COMMENT	"주요 시스템 파일의 접근 권한 조사"
#define	CHK_RSERVICEFILE_PERMISSION_COMMENT	"r 명령어(rsh,rlogin...) 설정 파일의 접근 권한 조사"
#define	CHK_RSERVICECONFIG_COMMENT		"r 명령어(rsh, rlogin...) 설정 파일에 + 지시어 존재유무 조사"
#define CHK_TCPWRAPPERCONFIG_COMMENT	 	"tcpwrapper 설정파일(hosts.allow)에 ALL 지시어 존재 유무 조사"
#define CHK_SYSLOGFILE_PERMISSION_COMMENT	"syslog.conf 파일의 접근 권한 조사 "
#define CHK_SYSTEMLOGFILE_PERMISSION_COMMENT	"시스템 로그 파일의 접근 권한 조사"
#define CHK_ROOT_CRONFILE_PERMISSION_COMMENT	"root cron 파일의 접근 권한 조사"
#define CHK_ROOT_CRONFILE_OWNER_COMMENT		"root cron 파일의 소유 계정 조사"

#define	CATEGORY_SEPARATOR				" : "

int chk_rootuid_duplication(const char * p_pwdfile);
int chk_password_length(const char *p_pwdconfigfile);
int chk_password_shadowing(void);
int chk_homedirectory_permission(void);
int chk_globalprofile_permission(void);
int chk_root_remotelogin(void);
int chk_historyfile_permission(void);
int chk_rootumask(void);
int chk_root_pathenv(void);
int chk_globalsystemfile_permission(void);
int chk_rseriveconfig(void);
int chk_tcpwrapper_config(void);
int chk_syslogfile_permission(void);
int chk_systemlogfile_permission(void);
int chk_root_cronfile_permission(void);
int chk_root_cronfile_owner(void);
int chk_rserivefile_permission(void);

extern int StrUpr( char *str );
extern int delete_comment( char *str );
extern int logwrite(const char * logfile, const char * p_data);
extern pid_t pipecmd(char *argv, FILE *fp[]);
#endif
