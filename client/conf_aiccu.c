/**
 *  Nabla - Automatic IP Tunneling and Connectivity
 *  Copyright (C) 2009  Juho Vähä-Herttua
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* This file contains large parts of aiccu.c from AICCU utility
 * written by Jeroen Massar and released under 3 clause BSD
 * Copyright 2003-2005 SixXS - http://www.sixxs.net
 * http://www.sixxs.net/tools/aiccu/LICENSE
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

/* We use quite a lot of stuff from the AICCU common.c */
#include "tic/common.h"
#include "tic/tic.h"

#define AICCU_VER       "2007.01.15"
#define AICCU_CONFIG    "aiccu.conf"
#define AICCU_PID       "/var/run/aiccu.pid"

/* AICCU Configuration */
struct AICCU_conf
{
	/* Only for AICCU */
	char            *username;              /* Username */
	char            *password;              /* Password */
	char            *protocol;              /* TIC/TSP/L2TP */
	char            *server;                /* TIC/TSP etc server */
	char            *ipv6_interface;        /* IPv6 interface (tunnel interface: sit0, tun0 etc) */
	char            *tunnel_id;             /* ID of the tunnel to use */
	char            *local_ipv4_override;   /* Local IPv4 override, for behind-NAT scenario's */
	char            *setupscript;           /* Script to run after having set up the tunnel */
	char            *pidfile;               /* File to store the PID */

	/* used by other parts */
	struct TIC_conf *tic;                   /* TIC Structure */

	bool            daemonize;              /* Daemonize? */
	bool            verbose;                /* Verbosity */
	bool            running;                /* Still running? */
	bool            tunrunning;             /* Is the tundev running? */

	bool            automatic;              /* Try to be totally automatic? */
	bool            behindnat;              /* Behind a NAT */
	bool            requiretls;             /* Require TLS for TIC? */
	bool            makebeats;              /* Make heartbeats? */
	bool            noconfigure;            /* No configuration (used to only send heartbeats) */
	bool            defaultroute;           /* Configure a default route */
};

/* Config */
struct pl_rule aiccu_conf_rules[] =
{
	/* Configuration */
	{"username",		PLRT_STRING,	offsetof(struct AICCU_conf, username)},
	{"password",		PLRT_STRING,	offsetof(struct AICCU_conf, password)},
	{"protocol",		PLRT_STRING,	offsetof(struct AICCU_conf, protocol)},
	{"server",		PLRT_STRING,	offsetof(struct AICCU_conf, server)},
	{"ipv6_interface",	PLRT_STRING,	offsetof(struct AICCU_conf, ipv6_interface)},
	{"tunnel_id",		PLRT_STRING,	offsetof(struct AICCU_conf, tunnel_id)},
	{"local_ipv4_override",	PLRT_STRING,	offsetof(struct AICCU_conf, local_ipv4_override)},

	/* Post Setup script path */
	{"setupscript",		PLRT_STRING,	offsetof(struct AICCU_conf, setupscript)},

	/* Automatic */
	{"automatic",		PLRT_BOOL,	offsetof(struct AICCU_conf, automatic)},

	/* Operational options */
	{"daemonize",		PLRT_BOOL,	offsetof(struct AICCU_conf, daemonize)},
	{"verbose",		PLRT_BOOL,	offsetof(struct AICCU_conf, verbose)},
	{"behindnat",		PLRT_BOOL,	offsetof(struct AICCU_conf, behindnat)},
	{"requiretls",		PLRT_BOOL,	offsetof(struct AICCU_conf, requiretls)},
	{"noconfigure",		PLRT_BOOL,	offsetof(struct AICCU_conf, noconfigure)},
	{"makebeats",		PLRT_BOOL,	offsetof(struct AICCU_conf, makebeats)},
	{"defaultroute",	PLRT_BOOL,	offsetof(struct AICCU_conf, defaultroute)},
	{"pidfile",		PLRT_STRING,	offsetof(struct AICCU_conf, pidfile)},
	{NULL,			PLRT_END,	0},
};

bool aiccu_InitConfig(struct AICCU_conf *g_aiccu)
{
#ifdef AICCU_GNUTLS
	int ret;
#define CAFILE "ca.pem"
#endif
	/* Allocate & Initialize */
	g_aiccu = (struct AICCU_conf *)malloc(sizeof(*g_aiccu));
	if (!g_aiccu) return false;
	memset(g_aiccu, 0, sizeof(*g_aiccu));
	g_aiccu->tic = (struct TIC_conf *)malloc(sizeof(*g_aiccu->tic));
	memset(g_aiccu->tic, 0, sizeof(*g_aiccu->tic));

	/* Initialize config to defaults */
	g_aiccu->running	= true;
	g_aiccu->tunrunning	= false;
	g_aiccu->daemonize	= 0;
	g_aiccu->verbose	= false;
	g_aiccu->requiretls	= false;		/* Not mandatory yet */
	g_aiccu->noconfigure	= false;
	g_aiccu->makebeats	= true;
	g_aiccu->defaultroute	= true;
	g_aiccu->ipv6_interface	= strdup("aiccu");
	if (!g_aiccu->ipv6_interface) return false;
	g_aiccu->protocol	= strdup("tic");
	if (!g_aiccu->protocol) return false;
	g_aiccu->server		= strdup("tic.sixxs.net");
	if (!g_aiccu->server) return false;
	g_aiccu->pidfile	= strdup(AICCU_PID);
	if (!g_aiccu->pidfile) return false;

#ifdef AICCU_GNUTLS
	/* Initialize GNUTLS */
	ret = gnutls_global_init();
	if (ret != 0)
	{
		dolog(LOG_ERR, "GNUTLS failed to initialize: %s (%d)\n", gnutls_strerror(ret), ret);
		return false;
	}

	/* X509 credentials */
	ret = gnutls_certificate_allocate_credentials(&g_aiccu->tls_cred);
	if (ret != 0)
	{
		dolog(LOG_ERR, "GNUTLS failed to initialize: %s (%d)\n", gnutls_strerror(ret), ret);
		return false;
	}

	/* For the time being don't load the PEM as it is not there... */

#if 0
	/* Sets the trusted cas file */
 	ret = gnutls_certificate_set_x509_trust_file(g_aiccu->tls_cred, CAFILE, GNUTLS_X509_FMT_PEM);
	if (ret < 0)
	{
		dolog(LOG_ERR, "GNUTLS failed to initialize: %s (%d)\n", gnutls_strerror(ret), ret);
		return false;
	}
#endif

	/* Configure GNUTLS logging to happen using our own logging interface */
	gnutls_global_set_log_function(aiccu_tls_log);

#ifdef DEBUG
	/* Show some GNUTLS debugging information */
	gnutls_global_set_log_level(5);
#endif

#endif /* AICCU_GNUTLS */

	return true;
}

/* Locate where the configfile is stored */
void aiccu_LocateFile(const char *what, char *filename, unsigned int length);
void aiccu_LocateFile(const char *what, char *filename, unsigned int length)
{
	memset(filename, 0, length);
#if defined(_WIN32) || defined(_WIN64)
	/* Figure out the "C:\Windows" location */
	/* as that is where we store our configuration */
	GetWindowsDirectory(filename, length);
	strncat(filename, "\\", length);
	strncat(filename, what, length);
#else
	/* Use the default location */
	strncat(filename, "/etc/", length);
	strncat(filename, what, length);
#endif
}

/* configure this client */
bool aiccu_LoadConfig(struct AICCU_conf *g_aiccu, const char *filename)
{
	FILE			*f;
	char			buf[1000];
	char			filenames[256];
	unsigned int		line = 0;

	if (!filename)
	{
		aiccu_LocateFile(AICCU_CONFIG, filenames, sizeof(filenames));
		filename = filenames;
	}

	f = fopen(filename, "r");
	if (!f)
	{
		dolog(LOG_ERR, "Could not open config file \"%s\"\n", filename);
		return false;
	}

	while (fgets(buf, sizeof(buf), f))
	{
		line++;
		if (parseline(buf, " ", aiccu_conf_rules, g_aiccu)) continue;

		dolog(LOG_WARNING, "Unknown configuration statement on line %u of %s: \"%s\"\n", line, filename, buf);
	}
	fclose(f);

	return true;
}

/* Save the configuration */
bool aiccu_SaveConfig(struct AICCU_conf *g_aiccu, const char *filename)
{
	FILE *f;
	char filenames[512];

	if (!filename)
	{
		aiccu_LocateFile(AICCU_CONFIG, filenames, sizeof(filenames));
		filename = filenames;
	}

	f = fopen(filename, "w");
	if (!f)
	{
		dolog(LOG_ERR, "Could not open config file \"%s\" for writing\n", filename);
		return false;
	}

	fprintf(f, "# AICCU Configuration (Saved by AICCU %s)\n", AICCU_VER);
	fprintf(f, "\n");
	fprintf(f, "# Login information\n");
	fprintf(f, "username %s\n", g_aiccu->username);
	fprintf(f, "password %s\n", g_aiccu->password);
	fprintf(f, "protocol %s\n", g_aiccu->protocol);
	fprintf(f, "server %s\n", g_aiccu->server);
	fprintf(f, "\n");
	fprintf(f, "# Interface names to use\n");
	fprintf(f, "ipv6_interface %s\n", g_aiccu->ipv6_interface);
	fprintf(f, "\n");
	fprintf(f, "# The tunnel_id to use\n");
	fprintf(f, "# (only required when there are multiple tunnels in the list)\n");
	fprintf(f, "tunnel_id %s\n", g_aiccu->tunnel_id);
	fprintf(f, "\n");
	fprintf(f, "# Try to automatically login and setup the tunnel?\n");
	fprintf(f, "automatic %s\n", g_aiccu->automatic ? "true" : "false");
	fprintf(f, "\n");
	fprintf(f, "# Script to run after setting up the interfaces (default: none)\n");
	fprintf(f, "%ssetupscript %s\n", g_aiccu->setupscript ? "" : "#", g_aiccu->setupscript ? g_aiccu->setupscript : "<path>");
	fprintf(f, "\n");
	fprintf(f, "# TLS Required?\n");
	fprintf(f, "requiretls %s\n", g_aiccu->requiretls ? "true" : "false");
	fprintf(f, "\n");
	fprintf(f, "# Be verbose?\n");
	fprintf(f, "verbose %s\n", g_aiccu->verbose ? "true" : "false");
	fprintf(f, "\n");
	fprintf(f, "# Daemonize?\n");
	fprintf(f, "daemonize %s\n", g_aiccu->daemonize ? "true" : "false");
	fprintf(f, "\n");
	fprintf(f, "# Behind NAT (default: false)\n");
	fprintf(f, "# Notify the user that a NAT-kind network is detected\n");
	fprintf(f, "behindnat %s\n", g_aiccu->behindnat ? "true" : "false");
	fprintf(f, "\n");
	fprintf(f, "# PID File\n");
	fprintf(f, "pidfile %s\n", g_aiccu->pidfile);
	fprintf(f, "\n");
	fprintf(f, "# Make heartbeats (default true)\n");
	fprintf(f, "# In general you don't want to turn this off\n");
	fprintf(f, "# Of course only applies to AYIYA and heartbeat tunnels not to static ones\n");
	fprintf(f, "makebeats %s\n", g_aiccu->makebeats ? "true" : "false");
	fprintf(f, "\n");
	fprintf(f, "# Add a default route (default: true)\n");
	fprintf(f, "defaultroute %s\n", g_aiccu->defaultroute ? "true" : "false");
	fprintf(f, "\n");
	fprintf(f, "# Don't configure anything (default: false)\n");
	fprintf(f, "noconfigure %s\n", g_aiccu->noconfigure ? "true" : "false");
	fclose(f);
	return true;
}

void aiccu_FreeConfig(struct AICCU_conf *g_aiccu)
{
	if (!g_aiccu) return;

#ifdef AICCU_GNUTLS
	gnutls_certificate_free_credentials(g_aiccu->tls_cred);
	gnutls_global_deinit();
#endif

	if (g_aiccu->username)		{ free(g_aiccu->username);	g_aiccu->username	= NULL; }
	if (g_aiccu->password)		{ free(g_aiccu->password);	g_aiccu->password	= NULL; }
	if (g_aiccu->ipv6_interface)	{ free(g_aiccu->ipv6_interface);g_aiccu->ipv6_interface	= NULL; }
	if (g_aiccu->tunnel_id)		{ free(g_aiccu->tunnel_id);	g_aiccu->tunnel_id	= NULL; }
	if (g_aiccu->tic)		{ free(g_aiccu->tic);		g_aiccu->tic		= NULL; }
	if (g_aiccu->setupscript)	{ free(g_aiccu->setupscript);	g_aiccu->setupscript	= NULL; }
	if (g_aiccu->pidfile)		{ free(g_aiccu->pidfile);	g_aiccu->pidfile	= NULL; }

	free(g_aiccu);
	g_aiccu = NULL;
}

