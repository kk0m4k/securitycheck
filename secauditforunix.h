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
#define	CHK_ROOTUID_COMMENT			"root ���� �̿ܿ� UID 0�� ���� �ִ� ������ �ִ��� ����"
#define CHK_PASSWD_MIN_LENGTH_COMMENT		"���� �н����� �ּ� ���� Ȯ��(�ּ� ���� 8�̻�)"
#define	CHK_PASSWD_SHADOWING_COMMENT		"�н����� ���� sahdowing(/etc/shadow, /tcb/...)�� Ȱ��ȭ�Ǿ� �ִ��� ����"
#define	CHK_HOMEDIR_PERMISSION_COMMENT		"������ Ȩ���͸� ������ ������ Ȯ��"
#define CHK_GLOBALPROFILE_PERMISSION_COMMENT	"�ý��� /etc/profile ȯ�� ���� ������ �۹̼� ����"
#define	CHK_ROOT_REMOTELOGIN_COMMENT		"root �������� ���� �� ����(telnet/rlogin) ���� ����"
#define	CHK_HISTORYFILE_PERMISSION_COMMENT	"������ history ������ �۹̼� ����"
#define CHK_ROOTUMASK_PERMISSION_COMMENT	"root ������ umask ���� ����"
#define CHK_ROOT_PATHENV_COMMENT		"root ������ PATH ȯ�溯�� ������ .(������͸�)�Ǿ�  �ִ��� ����"
#define CHK_GLOBALSYSTEM_PERMISSION_COMMENT	"�ֿ� �ý��� ������ ���� ���� ����"
#define	CHK_RSERVICEFILE_PERMISSION_COMMENT	"r ��ɾ�(rsh,rlogin...) ���� ������ ���� ���� ����"
#define	CHK_RSERVICECONFIG_COMMENT		"r ��ɾ�(rsh, rlogin...) ���� ���Ͽ� + ���þ� �������� ����"
#define CHK_TCPWRAPPERCONFIG_COMMENT	 	"tcpwrapper ��������(hosts.allow)�� ALL ���þ� ���� ���� ����"
#define CHK_SYSLOGFILE_PERMISSION_COMMENT	"syslog.conf ������ ���� ���� ���� "
#define CHK_SYSTEMLOGFILE_PERMISSION_COMMENT	"�ý��� �α� ������ ���� ���� ����"
#define CHK_ROOT_CRONFILE_PERMISSION_COMMENT	"root cron ������ ���� ���� ����"
#define CHK_ROOT_CRONFILE_OWNER_COMMENT		"root cron ������ ���� ���� ����"

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
