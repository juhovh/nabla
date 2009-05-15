
#ifndef COMMON_H
#define COMMON_H

#include <stdarg.h>

#define LOG_DEBUG 1
#define LOG_ERR 2
#define LOG_WARNING 3
#define LOG_INFO 4

#ifdef _DEBUG
#define D(x) x
#else
#define D(x) {}
#endif


/* parseline() rules */
enum pl_ruletype
{
	PLRT_STRING,		/* Offset points to a String (strdup()) */
	PLRT_INTEGER,		/* Offset points to a Integer (unsigned int) */
	PLRT_BOOL,		/* Offset points to a Boolean. */
	PLRT_IPV4,		/* Offset points to a IPv4 address (inet_pton(..., AF_INET)) */
	PLRT_IPV6,		/* Offset points to a IPv6 address (inet_pton(..., AF_INET6)) */
	PLRT_END		/* End of rules */
};

struct pl_rule
{
	const char		*title;
	unsigned int		type;
	unsigned int		offset;
};


typedef struct tlssocket * TLSSOCKET;


/* Common Functions */
void dologA(int level, const char *fmt, va_list ap);
void dolog(int level, const char *fmt, ...);

/* Networking functions */
void sock_printf(TLSSOCKET sock, const char *fmt, ...);
int sock_getline(TLSSOCKET sock, char *rbuf, unsigned int rbuflen, unsigned int *filled, char *ubuf, unsigned int ubuflen);
TLSSOCKET connect_client(const char *hostname, const char *service, int family, int socktype);
TLSSOCKET listen_server(const char *description, const char *hostname, const char *service, int family, int socktype);
void sock_free(TLSSOCKET sock);
#ifdef AICCU_GNUTLS
int sock_gotls(TLSSOCKET sock);
#endif

/* Parsing functions */
unsigned int countfields(char *s);
int copyfield(char *s, unsigned int n, char *buf, unsigned int buflen);
int parseline(char *line, const char *split, struct pl_rule *rules, void *data);

/* Convienience */
void MD5String(const char *sString, char *sSignature, unsigned int siglen);
int is_rfc1918(char *ipv4);


#endif
