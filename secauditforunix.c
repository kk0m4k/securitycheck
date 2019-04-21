/* 
 * written by Kim, Taehoon(kimfrancesco@gmail.com)
*/

#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
 
#ifndef SECAUDITFORUNIX
#include "secauditforunix.h"
#endif

static int category_no;
static char logfile[512];

int
main(int argc, char *argv[]) {

	int b_rs = 0;	

	if ( argc < 2 ) return 0;

#ifdef DEBUG
	printf("[%s] %s\n", __FILE__, argv[1]);
#endif
	
	strncpy(logfile, argv[1], sizeof(logfile));
	b_rs = chk_rootuid_duplication(p_pwdfile);
//	b_rs = chk_password_length(p_pwdconfigfile);
	b_rs = chk_password_shadowing();
	b_rs = chk_homedirectory_permission();
	b_rs = chk_globalprofile_permission();
	b_rs = chk_root_remotelogin();
	b_rs = chk_historyfile_permission();
	b_rs = chk_rootumask();
	b_rs = chk_root_pathenv();
	b_rs = chk_globalsystemfile_permission();
	b_rs = chk_rserivefile_permission();
	b_rs = chk_rseriveconfig();
	b_rs = chk_tcpwrapper_config();
	b_rs = chk_syslogfile_permission();
	b_rs = chk_systemlogfile_permission();
	b_rs = chk_root_cronfile_permission();
	b_rs = chk_root_cronfile_owner();

	return 0;
}

int chk_rootuid_duplication(const char * p_pwdfile) {

	int i_cnt_rootuid = 0;
	FILE *p_FILEstream = NULL;
	struct passwd *u_info = NULL;
	char log_buffer[MAXBUF] = {0};
	char category_buf[16] = {0};
	char rootuserlist[256] = {0};

	p_FILEstream = fopen(p_pwdfile, "r");
	
	if ( ! p_FILEstream ) return FALSE;

	while ( ( u_info = fgetpwent(p_FILEstream)) != NULL ) {
		if ( u_info->pw_uid == ROOTUID && strcmp("root", u_info->pw_name) ) {
			i_cnt_rootuid ++;
			if ( i_cnt_rootuid == 1 ) { 
				sprintf(rootuserlist, "%s ", u_info->pw_name);
			} else  {	
				strncat(rootuserlist, u_info->pw_name, sizeof(rootuserlist)-strlen(rootuserlist));
			}
		}
#if defined(DEBUG)
		if ( u_info->pw_uid == ROOTUID && !strcmp("root", u_info->pw_name) ) {
			printf("%s 계정 UID 값이 0\n", u_info->pw_name);
		}
#endif
	}

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_ROOTUID_COMMENT, CATEGORY_SEPARATOR, i_cnt_rootuid ? "WEAK" : "SAFE");
	if ( i_cnt_rootuid ) { 
		strcat(log_buffer, rootuserlist);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);

	fclose(p_FILEstream);
	return TRUE; 
}

int chk_password_length(const char *p_pwdconfigfile) {

	int passwd_length = 0;
	FILE *p_FILEstream = NULL;	
	char buf[2048] = {0};
	char buf2[2048] = {0};
	char *token = NULL;
	char s_passwdminlength[64] = {0};
#if defined(HPUX) 
	char *separate = ":= \t";
#else
	char *separate = "= \t";
#endif
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
#if defined(HPUX)	
	char hpux_pwdconfigfile[128] = {0};	
	int hpux_trustmode = 0;
#endif

#if defined(DEBUG)
	printf("%s : ",CHK_PASSWD_MIN_LENGTH_COMMENT);
#endif
	
#if defined(HPUX) 
	if (! access("/tcb/files/auth/system/default", F_OK)	) {
		strncpy(hpux_pwdconfigfile, "/tcb/files/auth/system/default", sizeof(hpux_pwdconfigfile)-1);
		p_pwdconfigfile=&hpux_pwdconfigfile[0]; 
		hpux_trustmode = 1;
	} else {
		strncpy(hpux_pwdconfigfile, "/etc/default/security", sizeof(hpux_pwdconfigfile)-1);
	}
		p_pwdconfigfile=&hpux_pwdconfigfile[0]; 
#endif	

#if defined(HPUX)
	if ( (   hpux_trustmode && ! access("/tcb/files/auth/system/default", F_OK) ) ||
		 ( ! hpux_trustmode && ! access("/etc/default/security", F_OK) ) ) {
#endif
	p_FILEstream = fopen(p_pwdconfigfile, "r");	
	if ( !p_FILEstream ) return FALSE;

	while ( fgets(buf, 2048, p_FILEstream) != NULL ) {
#if defined(HPUX)
		if (! hpux_trustmode) delete_comment(buf);
#else
		delete_comment(buf);
#endif
		if (buf[0] == '\0') continue;

#if defined(HPUX)	
		if ( hpux_trustmode ) {

			strcpy(s_passwdminlength, TRUST_PASSWORDMINLENTH);
		} else {
			
			strcpy(s_passwdminlength, NONTRUST_PASSWORDMINLENTH);
		}
#else
		strcpy(s_passwdminlength, PASSWORDMINLENTH);
#endif
		if ( strstr(buf, s_passwdminlength) ) {
			strcpy(buf2, buf);
#if defined(DEBUG)	
			fputs(buf, stdout);
#endif
			token = strtok(buf, separate);
			while (token != NULL) {
				
				if ( token[strlen(token)-1] == '\n') token[strlen(token)-1] = '\0';
				if ( atoi(token) ) {
					passwd_length = atoi(token);
					break;
				}
				token = strtok(NULL, separate);
			} 
			break;	
		}
		memset(buf, '\0', sizeof(buf));
		memset(buf2, '\0', sizeof(buf));
	}
#if defined(HPUX)
	} else {
		passwd_length=0;
	}
#endif

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_PASSWD_MIN_LENGTH_COMMENT, CATEGORY_SEPARATOR, passwd_length < 8 ? "WEAK" : "SAFE");
	if ( passwd_length ) {
		strcat(log_buffer, buf2);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);

	fclose(p_FILEstream);
	return TRUE;	
}


int chk_password_shadowing(void) {

	int b_passwd_shadow_weak = 0;
	FILE *p_FILEstream = NULL;
	struct passwd *u_info = NULL;
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[1024]= {0};

#if defined(DEBUG)
	printf("a\n");
#endif
#if defined(DEBUG)
	printf("%s : ",CHK_PASSWD_SHADOWING_COMMENT);
#endif
    p_FILEstream = fopen(p_pwdfile, "r");

    if ( ! p_FILEstream ) return FALSE;

	while ( ( u_info = fgetpwent(p_FILEstream)) != NULL ) {
		if ( !strcmp("root", u_info->pw_name) ) {
			if (strcmp("x", u_info->pw_passwd) ) { 
				if ( access(SHADOWPWFILE,F_OK) ) {
					b_passwd_shadow_weak = 1;
					sprintf(buf, "%s:%s", u_info->pw_name, u_info->pw_passwd);
					break;
				}
			}
		}
	}

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_PASSWD_SHADOWING_COMMENT, CATEGORY_SEPARATOR, b_passwd_shadow_weak ? "WEAK" : "SAFE");

	if ( b_passwd_shadow_weak) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);

    fclose(p_FILEstream);
	return TRUE; 
}



int chk_homedirectory_permission(void) {

	FILE *p_FILEstream = NULL;
	struct passwd *u_info = NULL;
	struct stat st = {0};
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[1024]= {0};
	int b_homedir_permission_weak = 0;

    printf("d");
#if defined(DEBUG)
    printf("%s : ",CHK_HOMEDIR_PERMISSION_COMMENT);
#endif
    p_FILEstream = fopen(p_pwdfile, "r");

    if ( ! p_FILEstream ) return FALSE;

	while ( ( u_info = fgetpwent(p_FILEstream)) != NULL ) {
		if ( u_info->pw_dir != NULL ) {

		if ( stat(u_info->pw_dir, &st) == -1 ) continue;

		if ( st.st_mode & S_IWOTH )  {
			if ( ! strcmp(u_info->pw_dir, "/var/spool/uucppublic") ) continue;
			b_homedir_permission_weak = 1;
			sprintf(buf, "%s %s %o", u_info->pw_name, u_info->pw_dir, st.st_mode & 07777);
		}
		memset(&st,'\0', sizeof(struct stat) );
		}
	}

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_HOMEDIR_PERMISSION_COMMENT, CATEGORY_SEPARATOR, b_homedir_permission_weak ? "WEAK" : "SAFE");
	if ( b_homedir_permission_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);

    fclose(p_FILEstream);
    return TRUE;	
}


int chk_globalprofile_permission(void) {

	FILE *p_FILEstream = NULL;
	struct passwd *u_info = NULL;
	struct stat st = {0};
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[1024]= {0};
	int b_globalprofile_permission_weak = 0;

#if defined(DEBUG)
    printf("%s : ",CHK_GLOBALPROFILE_PERMISSION_COMMENT);
#endif

	if  ( ! access("/etc/profile",F_OK)) {
		stat("/etc/profile", &st);
		if ( st.st_mode & S_IWOTH )  {
			b_globalprofile_permission_weak = 1;
			sprintf(buf, "%s %o", "/etc/profile", st.st_mode & 07777);
		}
	}

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_GLOBALPROFILE_PERMISSION_COMMENT, CATEGORY_SEPARATOR, b_globalprofile_permission_weak ? "WEAK" : "SAFE");
	if ( b_globalprofile_permission_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);
    return TRUE;	
}


int chk_root_remotelogin(void) {

	FILE *p_FILEstream = NULL;
	char buf[2048] = {0};
	char buf2[2048] = {0};
	char *token = NULL;
	char *separate = "= \t";

	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	int b_root_remotelogin_weak = 0;

#if defined(DEBUG)
    printf("%s : ",CHK_ROOT_REMOTELOGIN_COMMENT);
#endif

	if  ( ! access(p_root_remoteloginfile,F_OK)) {

		p_FILEstream = fopen(p_root_remoteloginfile, "r");	

		if ( !p_FILEstream ) return FALSE;

#if defined(SunOS)	
	b_root_remotelogin_weak = 1;
#endif

		while ( fgets(buf, 2048, p_FILEstream) != NULL ) {
			delete_comment(buf);
			if (buf[0] == '\0') continue;
			StrLwr(buf);
#if defined(SunOS)	
			if ( strstr(buf, "console") ) {
				strcpy(buf2, buf);
	   		 	token = strtok(buf, separate);
				while (token != NULL) { 
					if ( token[strlen(token)-1] == '\n') token[strlen(token)-1] = '\0';
					if ( ! strcmp(token, "/dev/console")) {
						b_root_remotelogin_weak = 0;
						break;
					}
					token = strtok(NULL, separate);
				} 
			}
#elif defined(Linux) 
			if ( strstr(buf, "pts") ) {
				b_root_remotelogin_weak = 1;
				strcpy(buf2, buf);
				break;
			}
#endif
			memset(buf, '\0', sizeof(buf));
			memset(buf2, '\0', sizeof(buf));
		}
	} else {
		b_root_remotelogin_weak = 1;
		sprintf(buf2, "%s file not exists", p_root_remoteloginfile);
	}

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_ROOT_REMOTELOGIN_COMMENT, CATEGORY_SEPARATOR, b_root_remotelogin_weak ? "WEAK" : "SAFE");

	if ( b_root_remotelogin_weak ) {
		strcat(log_buffer, buf2);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);

	if ( p_FILEstream ) fclose(p_FILEstream);
	return TRUE;
}

int chk_historyfile_permission(void) {

	FILE *p_FILEstream = NULL;
	struct passwd *u_info = NULL;
	struct stat st = {0};
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[2048]= {0};
	char buf2[1024]= {0};
	int b_historyfile_permission_weak = 0;
	char history_path[128] = {0};

#if defined(DEBUG)
    printf("%s : ",CHK_HISTORYFILE_PERMISSION_COMMENT);
#endif
    p_FILEstream = fopen(p_pwdfile, "r");

    if ( ! p_FILEstream ) return FALSE;

	while ( ( u_info = fgetpwent(p_FILEstream)) != NULL ) {
		if ( u_info->pw_dir != NULL ) {
			sprintf(history_path, "%s/%s", u_info->pw_dir, ".bash_history");
			if  ( ! access(history_path,F_OK)) {
				stat(history_path, &st);
				if ( st.st_mode & S_IROTH || st.st_mode & S_IWOTH )  {
					b_historyfile_permission_weak = 1;
					if ( buf[0] != '\0') {
						sprintf(buf2, "%s %o",history_path, st.st_mode & 07777);
						strcat(buf, buf2);
					} else {
						sprintf(buf, "%s %o",history_path, st.st_mode & 07777);
					}
				}
				memset(&st,'\0', sizeof(struct stat));
			}

			memset(history_path,'\0', sizeof(history_path));

			sprintf(history_path, "%s/%s", u_info->pw_dir, ".sh_history");
			if  ( ! access(history_path,F_OK)) {
				stat(history_path, &st);
				if ( st.st_mode & S_IROTH || st.st_mode & S_IWOTH )  {
					b_historyfile_permission_weak = 1;
					if ( buf[0] != '\0') {
						sprintf(buf2, "%s %o",history_path, st.st_mode & 07777);
						strcat(buf, buf2);
					} else {
						sprintf(buf, "%s %o",history_path, st.st_mode & 07777);
					}
				}
				memset(&st,'\0', sizeof(struct stat));
			}
		}
		memset(history_path,'\0', sizeof(history_path));
	}

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_HISTORYFILE_PERMISSION_COMMENT, CATEGORY_SEPARATOR, b_historyfile_permission_weak ? "WEAK" : "SAFE");
	if ( b_historyfile_permission_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);

	if ( p_FILEstream ) fclose(p_FILEstream);
    return TRUE;	
}

int chk_rootumask(void) {

	FILE *fp[2];
	FILE *p_FILEstream = NULL;
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[1024]= {0};
	int b_rootumask_weak = 0;

	pipecmd(UMASK_CMD, fp);

	if( ! fp[0] ) return FALSE;
	fclose(fp[1]);

	fgets(buf, 1024, fp[0]);
	
	if ( buf[2] == '0' || buf[2] == '4' ) b_rootumask_weak = 1;

	fclose(fp[0]);

	category_no++;

	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_ROOTUMASK_PERMISSION_COMMENT, CATEGORY_SEPARATOR, b_rootumask_weak ? "WEAK" : "SAFE");
	if ( b_rootumask_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);

    return TRUE;	
}

int chk_root_pathenv(void) {

	FILE *fp[2];
	FILE *p_FILEstream = NULL;
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[1024]= {0};
	int b_root_pathenv_weak = 0;
	char *ptr = NULL;

	pipecmd(PATH_CMD, fp);

	if( ! fp[0] ) return FALSE;

	fclose(fp[1]);

	while (fgets(buf, 1024, fp[0])) {
		if ( ! strncmp(buf, "PATH=", 5) ) break;
		memset(buf, 0x0, sizeof(buf));
	}

	ptr = buf + 4;
	while ((ptr = strchr(ptr + 1, '.'))) {
		if (*(ptr-1) == '=') {
			b_root_pathenv_weak = 1;		
			break;
		}
	}

	fclose(fp[0]);

	category_no++;

	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_ROOT_PATHENV_COMMENT, CATEGORY_SEPARATOR, b_root_pathenv_weak ? "WEAK" : "SAFE");
	if ( b_root_pathenv_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);

    return TRUE;	
}


int chk_globalsystemfile_permission(void) {

	FILE *p_FILEstream = NULL;
	struct stat st = {0};	
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[2048]= {0};
	char buf2[1024]= {0};
	int b_globalsystemfile_permission_weak = 0;
	char *p_systemfile[] = {"/etc/hosts", "/etc/inetd.conf", "/etc/passwd", "/etc/hosts.allow", "/etc/shadow", NULL};
	int loop_count = 0;

	while( p_systemfile[loop_count] != NULL ) {
		if  ( ! access(p_systemfile[loop_count],F_OK)) {
			stat(p_systemfile[loop_count], &st);
			if ( st.st_mode & S_IWOTH )  {
				b_globalsystemfile_permission_weak = 1;
				if ( buf[0] != '\0') {
					sprintf(buf2, " %s %o",p_systemfile[loop_count], st.st_mode & 07777);
					strcat(buf, buf2);
				} else {
					sprintf(buf, "%s %o",p_systemfile[loop_count], st.st_mode & 07777);
				}
			}
		}
		loop_count++;	
	}

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_GLOBALSYSTEM_PERMISSION_COMMENT, CATEGORY_SEPARATOR, b_globalsystemfile_permission_weak ? "WEAK" : "SAFE");
	if ( b_globalsystemfile_permission_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);
    return TRUE;	
}

int chk_rserivefile_permission(void) {

	FILE *p_FILEstream = NULL;
	struct passwd *u_info = NULL;
	struct stat st = {0};	
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[2048]= {0};
	char buf2[1024]= {0};
	int b_rservicefile_permission_weak = 0;
	char rservicefile_path[128] = {0};

#if defined(DEBUG)
    printf("%s : ",CHK_RSERVICEFILE_PERMISSION_COMMENT);
#endif
    p_FILEstream = fopen(p_pwdfile, "r");

    if ( ! p_FILEstream ) return FALSE;

	while ( ( u_info = fgetpwent(p_FILEstream)) != NULL ) {
		if ( u_info->pw_dir != NULL ) {
			sprintf(rservicefile_path, "%s/%s", u_info->pw_dir, ".rhosts");
			if  ( ! access(rservicefile_path,F_OK)) {
				stat(rservicefile_path, &st);
				if (  st.st_mode & S_IWOTH )  {
					b_rservicefile_permission_weak = 1;
					if ( buf[0] != '\0') {
						sprintf(buf2, "%s %o",rservicefile_path, st.st_mode & 07777);
						strcat(buf, buf2);
					} else {
						sprintf(buf, "%s %o",rservicefile_path, st.st_mode & 07777);
					}
				}
				memset(&st,'\0', sizeof(struct stat));
			}
		}
		memset(rservicefile_path,'\0', sizeof(rservicefile_path));
	}

	memset(&st,'\0', sizeof(struct stat));
	sprintf(rservicefile_path, "%s", "/etc/hosts.equiv");
	if  ( ! access(rservicefile_path, F_OK)) {
		stat(rservicefile_path, &st);
		if ( st.st_mode & S_IWOTH )  {
			b_rservicefile_permission_weak = 1;
			if ( buf[0] != '\0') {
				sprintf(buf2, " %s %o",rservicefile_path, st.st_mode & 07777);
				strcat(buf, buf2);
			} else {
				sprintf(buf, "%s %o",rservicefile_path, st.st_mode & 07777);
			}
		}
	}

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_RSERVICEFILE_PERMISSION_COMMENT, CATEGORY_SEPARATOR, b_rservicefile_permission_weak ? "WEAK" : "SAFE");
	if ( b_rservicefile_permission_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);

    fclose(p_FILEstream);
    return TRUE;	
}

int chk_rseriveconfig(void) {

	FILE *p_FILEstream = NULL;
	FILE *p_FILEstream2 = NULL;
	struct passwd *u_info = NULL;
	struct stat st = {0};	
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[2048]= {0};
	char buf2[1024]= {0};
	char buf3[1024]= {0};
	int b_rserviceconfig_weak = 0;
	char rservicefile_path[128] = {0};

#if defined(DEBUG)
    printf("%s : ",CHK_RSERVICEFILE_PERMISSION_COMMENT);
#endif
    p_FILEstream = fopen(p_pwdfile, "r");

    if ( ! p_FILEstream ) return FALSE;

	while ( ( u_info = fgetpwent(p_FILEstream)) != NULL ) {
		if ( u_info->pw_dir != NULL ) {
			sprintf(rservicefile_path, "%s/%s", u_info->pw_dir, ".rhosts");
			if  ( ! access(rservicefile_path,F_OK)) {
				p_FILEstream2 = fopen(rservicefile_path, "r");	
				if ( !p_FILEstream2 ) continue;
				while ( fgets(buf, 2048, p_FILEstream2) != NULL ) {
					delete_comment(buf);
					if (buf[0] == '\0') continue;
					if ( strstr(buf, "+") ) {
						b_rserviceconfig_weak = 1;
						sprintf(buf2, "%s %s",rservicefile_path, buf);
					}
					memset(buf, '\0', sizeof(buf));
#if defined(DEBUG)	
						fputs(buf, stdout);
#endif
				}
				fclose(p_FILEstream2);
			}
		}
		memset(buf, '\0', sizeof(buf));
	}
	
	memset(&st,'\0', sizeof(struct stat));
	sprintf(rservicefile_path, "%s", "/etc/hosts.equiv");
	if  ( ! access(rservicefile_path, F_OK)) {
		p_FILEstream2 = fopen(rservicefile_path, "r");	
		if ( p_FILEstream2 ) { 
			while ( fgets(buf, 2048, p_FILEstream2) != NULL ) {
				delete_comment(buf);
				if (buf[0] == '\0') continue;
				if ( strstr(buf, "+") ) {
					b_rserviceconfig_weak = 1;
					if ( buf2[0] != '\0') {
						sprintf(buf3, " %s %s",rservicefile_path, buf);
						strcat(buf2, buf3);
					} else {
						sprintf(buf2, "%s %s",rservicefile_path, buf);
					}
				}
				memset(buf, '\0', sizeof(buf));
			}
			fclose(p_FILEstream2);
		}
	}

	memset(buf, '\0', sizeof(buf));
	strcpy(buf, buf2);

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_RSERVICECONFIG_COMMENT, CATEGORY_SEPARATOR, b_rserviceconfig_weak ? "WEAK" : "SAFE");
	if ( b_rserviceconfig_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);

	fclose(p_FILEstream);
	return TRUE;	
}

int chk_tcpwrapper_config(void) {

	FILE *p_FILEstream = NULL;
	struct passwd *u_info = NULL;
	struct stat st = {0};	
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[2048]= {0};
	char buf2[1024]= {0};
	char buf3[1024]= {0};
	int b_tcpwrapperconfig_weak = 0;
	char tcpwrapperfile_path[128] = {0};

#if defined(DEBUG)
    printf("%s : ",CHK_TCPWRAPPERCONFIG_COMMENT);
#endif


#if defined(Linux) || defined(SunOS)
	if ( (! access("/etc/hosts.allow", F_OK) &&  access("/etc/hosts.deny", F_OK)) ||
		    (access("/etc/hosts.allow", F_OK) &&  access("/etc/hosts.deny", F_OK)) ) {
		b_tcpwrapperconfig_weak = 1;
		sprintf(buf2, "%s file not exists", "/etc/hosts.deny");
#elif defined(HPUX)
	if ( ( access("/var/adm/inetd.sec", F_OK) && ! access("/etc/hosts.allow", F_OK) && access("/etc/hosts.deny", F_OK)) ||
		   (access("/var/adm/inetd.sec", F_OK) && access("/etc/hosts.allow", F_OK) && access("/etc/hosts.deny", F_OK) )) {
		b_tcpwrapperconfig_weak = 1;
		sprintf(buf2, "access control file not exists");
#endif

	} else {

		sprintf(tcpwrapperfile_path, "%s", "/etc/hosts.allow");

		if ( ! access(tcpwrapperfile_path, F_OK) ) {
			p_FILEstream = fopen(tcpwrapperfile_path, "r");	

			if ( p_FILEstream ) {
				while ( fgets(buf, 2048, p_FILEstream) != NULL ) {
					delete_comment(buf);
					if (buf[0] == '\0') continue;
					if ( strstr(buf, "ALL") ) {
						b_tcpwrapperconfig_weak = 1;
						if ( buf2[0] != '\0' ) {
							sprintf(buf3, "%s", buf);
							strcat(buf2, buf3);
						} else {
							sprintf(buf2, "%s", buf);
						}
					
					}
					memset(buf, '\0', sizeof(buf));
				}
			}
			fclose(p_FILEstream);
		}
	}	

	memset(buf, '\0', sizeof(buf));
	strcpy(buf, buf2);

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_TCPWRAPPERCONFIG_COMMENT, CATEGORY_SEPARATOR, b_tcpwrapperconfig_weak ? "WEAK" : "SAFE");
	if ( b_tcpwrapperconfig_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);
	return TRUE;
}

int chk_syslogfile_permission(void) {

	FILE *p_FILEstream = NULL;
	struct stat st = {0};	
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[2048]= {0};
	char buf2[1024]= {0};
	int b_syslogfile_permission_weak = 0;

#if defined(DEBUG)
    printf("%s : ",CHK_SYSLOGFILE_PERMISSION_COMMENT);
#endif

	if  ( ! access("/etc/syslog.conf",F_OK)) {
		stat("/etc/syslog.conf", &st);
		if ( st.st_mode & S_IWOTH )  {
			b_syslogfile_permission_weak = 1;
			if ( buf[0] != '\0') {
				sprintf(buf2, " %s %o","/etc/syslog.conf", st.st_mode & 07777);
				strcat(buf, buf2);
			} else {
				sprintf(buf, "%s %o","/etc/syslog.conf", st.st_mode & 07777);
			}
		}
	}

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_SYSLOGFILE_PERMISSION_COMMENT, CATEGORY_SEPARATOR, b_syslogfile_permission_weak ? "WEAK" : "SAFE");
	if ( b_syslogfile_permission_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);
    return TRUE;	
}

int chk_systemlogfile_permission(void) {

	struct stat st = {0};	
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[2048]= {0};
	char buf2[1024]= {0};
	int b_systemlogfile_permission_weak = 0;
	char *p_systemlogfile[] = {"/var/log/messages", "/var/log/wtmp", "/var/log/lastlog", "/var/adm/messages","/var/adm/sulog","/var/adm/wtmp","/var/adm/wtmpx", "/var/adm/lastlog", NULL};
	int loop_count = 0;

#if defined(DEBUG)
    printf("%s : ",CHK_SYSTEMLOGFILE_PERMISSION_COMMENT);
#endif

	while( p_systemlogfile[loop_count] != NULL ) {
		if  ( ! access(p_systemlogfile[loop_count],F_OK)) {
			stat(p_systemlogfile[loop_count], &st);
			if ( st.st_mode & S_IWOTH )  {
				b_systemlogfile_permission_weak = 1;
				if ( buf[0] != '\0') {
					sprintf(buf2, " %s %o",p_systemlogfile[loop_count], st.st_mode & 07777);
					strcat(buf, buf2);
				} else {
					sprintf(buf, "%s %o",p_systemlogfile[loop_count], st.st_mode & 07777);
				}
			}
		}
		loop_count++;	
	}

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_SYSTEMLOGFILE_PERMISSION_COMMENT, CATEGORY_SEPARATOR, b_systemlogfile_permission_weak ? "WEAK" : "SAFE");
	if ( b_systemlogfile_permission_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);
    return TRUE;	
}

int chk_root_cronfile_permission(void) {

	struct stat st = {0};	
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[2048]= {0};
	char buf2[1024]= {0};
	int b_root_cronfile_permission_weak = 0;
	char *p_root_cronfile[] = {"/var/spool/cron/crontabs/root", "/var/spool/cron/root",NULL};
	int loop_count = 0;

#if defined(DEBUG)
    printf("%s : ",CHK_ROOT_CRONFILE_PERMISSION_COMMENT);
#endif

	while( p_root_cronfile[loop_count] != NULL ) {
		if  ( ! access(p_root_cronfile[loop_count],F_OK)) {
			stat(p_root_cronfile[loop_count], &st);
			if ( st.st_mode & S_IWOTH )  {
				b_root_cronfile_permission_weak = 1;
				if ( buf[0] != '\0') {
					sprintf(buf2, " %s %o",p_root_cronfile[loop_count], st.st_mode & 07777);
					strcat(buf, buf2);
				} else {
					sprintf(buf, "%s %o",p_root_cronfile[loop_count], st.st_mode & 07777);
				}
			}
		}
		loop_count++;	
	}

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_ROOT_CRONFILE_PERMISSION_COMMENT, CATEGORY_SEPARATOR, b_root_cronfile_permission_weak ? "WEAK" : "SAFE");
	if ( b_root_cronfile_permission_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);
    return TRUE;	
}

int chk_root_cronfile_owner(void) {

	struct stat st = {0};	
	char category_buf[16] = {0};
	char log_buffer[MAXBUF] = {0};
	char buf[2048]= {0};
	char buf2[1024]= {0};
	int b_root_cronfile_owner_weak = 0;
	char *p_root_cronfile[] = {"/var/spool/cron/crontabs/root", "/var/spool/cron/root",NULL};
	int loop_count = 0;

#if defined(DEBUG)
    printf("%s : ",CHK_ROOT_CRONFILE_OWNER_COMMENT);
#endif

	while( p_root_cronfile[loop_count] != NULL ) {
		if  ( ! access(p_root_cronfile[loop_count],F_OK)) {
			stat(p_root_cronfile[loop_count], &st);
			if ( st.st_uid != 0 )  {
				b_root_cronfile_owner_weak = 1;
				if ( buf[0] != '\0') {
					sprintf(buf2, " %s %d",p_root_cronfile[loop_count], st.st_uid);
					strcat(buf, buf2);
				} else {
					sprintf(buf, "%s %o",p_root_cronfile[loop_count], st.st_uid);
				}
			}
		}
		loop_count++;	
	}

	category_no++;
	sprintf(category_buf, CATEGORY_PREFIX, category_no);
	sprintf(log_buffer, "%s %s %s %s\n", category_buf, CHK_ROOT_CRONFILE_OWNER_COMMENT, CATEGORY_SEPARATOR, b_root_cronfile_owner_weak ? "WEAK" : "SAFE");
	if ( b_root_cronfile_owner_weak ) {
		strcat(log_buffer, buf);
		strcat(log_buffer, "\n");
	}

	logwrite(logfile, log_buffer);
    return TRUE;	
}
