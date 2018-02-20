/* ------------------------------------------------------------------------
   (C) 2018 by Roland Genske <roland@genske.org>

   Workaround for FRITZ!App Fon SIP via VPN

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   2018-02-09 - v0.1
   2018-02-20 - v0.2, functionally complete

   ------------------------------------------------------------------------ */

/* ------------------------------------------------------------------------
   dependencies
   ------------------------------------------------------------------------ */

#include "fapfon_proxy.h"
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <assert.h>
#include <errno.h>


/* ------------------------------------------------------------------------
   command line options
   ------------------------------------------------------------------------ */

#define DEFAULT_SIP_PORT "5060"
#define DEFAULT_LOG_LEVEL 0

options_t options;


/* ------------------------------------------------------------------------
   usage, parse command line
   ------------------------------------------------------------------------ */

static const char short_opt[] = "hp:t:u:v::l:D:V";
static struct option long_opt[] = {
   { "help",     no_argument,       0, 'h' },
   { "port",     required_argument, 0, 'p' },
   { "tcp-port", required_argument, 0, 't' },
   { "udp-port", required_argument, 0, 'u' },
   { "verbose",  optional_argument, 0, 'v' },
   { "logfile",  required_argument, 0, 'l' },
   { "dump",     required_argument, 0, 'D' },
   { "version",  no_argument,       0, 'V' },
   { NULL }
};

static void usage(void)
{
   fprintf(stderr,

      "usage: %s [options] BOX_ADDRESS[:SIP_PORT]\n"
      "SIP_PORT default: " DEFAULT_SIP_PORT "\n"
      "options:\n"
      "  -h            --help             This list\n"
      "  -p PORT       --port=PORT        Server SIP_PORT, TCP and UDP\n"
      "  -t PORT       --tcp-port=PORT    Server SIP_PORT, TCP\n"
      "  -u PORT       --udp-port=PORT    Server SIP_PORT, UDP\n"
      "  -v [level]    --verbose[=level]  Verbosity 0:ERROR 1:INFO "
                                                   "2:DETAIL 3:VERBOSE\n"
      "  -l LOGFILE    --logfile=LOGFILE  Log file or - (stdout)"
                                                 ", default: stderr\n"
      "  -D {FON|BOX}  --dump={FON|BOX}   Dump FON/BOX messages to stdout\n"
      "  -V            --version          Version information\n"

      , options.pname);

   exit(3);
}

static void parse_commandline(int argc, char *argv[])
{
   int opt, err = 0;

   options.pname = strrchr(argv[0], '/');
   if (options.pname)
      argv[0] = ++options.pname;
   else
      options.pname = argv[0];

   options.log_fp = stderr;
   options.log_level = DEFAULT_LOG_LEVEL;

   while ((opt = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1)
   {
      switch (opt)
      {
         case 'h':
            usage();

         case 'p':
         {
            int arg_l = strlen(optarg), port_l;
            if (is_port(optarg, arg_l, &port_l) && port_l == arg_l)
               options.tcp_port = options.udp_port = optarg;
            else {
               fprintf(stderr, "Invalid port '%s'\n", optarg);
               err++;
            }
            break;
         }

         case 't':
         {
            int arg_l = strlen(optarg), port_l;
            if (is_port(optarg, arg_l, &port_l) && port_l == arg_l)
               options.tcp_port = optarg;
            else {
               fprintf(stderr, "Invalid port '%s'\n", optarg);
               err++;
            }
            break;
         }

         case 'u':
         {
            int arg_l = strlen(optarg), port_l;
            if (is_port(optarg, arg_l, &port_l) && port_l == arg_l)
               options.udp_port = optarg;
            else {
               fprintf(stderr, "Invalid port '%s'\n", optarg);
               err++;
            }
            break;
         }

         case 'v':
            if (optarg)
            {
               int level;
               if (   strlen(optarg) == 1
                   && *optarg >= '0' && *optarg <= '9'
                   && (level = *optarg - '0') <= LOG_MAX_LEVEL)
               {
                  options.log_level = level;
                  break;
               }
               else {
                  level = 0;
                  while (optarg[level] == 'v')
                     level++;

                  if (optarg[level] == '\0')
                  {
                     if (level < LOG_MAX_LEVEL)
                        options.log_level = level + 1;
                     else
                        options.log_level = LOG_MAX_LEVEL;
                     break;
                  }
               }

               fprintf(stderr, "Invalid verbosity '%s'\n", optarg);
               err++;
            }
            else if (options.log_level < LOG_MAX_LEVEL)
               options.log_level++;
            break;

         case 'l':
            if (strlen(optarg) == 1 && *optarg == '-')
               options.log_fp = stdout;
            else {
               FILE *fp = freopen(optarg, "a", stderr);
               if (fp)
                  options.log_fp = fp;
               else {
                  int err_no = errno;
                  fprintf(stderr, "Failed to open log file '%s' [%d] %s\n",
                     optarg, err_no, strerror(err_no));
                  err++;
               }
            }
            break;

         case 'D':
            if (!strcasecmp("FON", optarg))
               options.log_dump |= LOG_DUMP_FON;
            else if (!strcasecmp("BOX", optarg))
               options.log_dump |= LOG_DUMP_BOX;
            else {
               fprintf(stderr, "Invalid dump mode '%s'\n", optarg);
               err++;
            }
            break;

         case 'V':
            printf("%s version %s\n", options.pname, VERSION_STRING);
            exit(2);

         default:
            err++;
      }
   }

   if (optind == argc)
   {
      fprintf(stderr, "Box address not specified\n");
      err++;
   }

   while (optind < argc)
   {
      /* parse box address */

      int arg_l = strlen(argv[optind]), addr_l;
      if (is_addr(argv[optind], arg_l, &addr_l))
      {
         int port_l;

         memcpy(options.box.addr, argv[optind], addr_l);
         options.box.addr[options.box.addr_l = addr_l] = '\0';

         if (addr_l == arg_l)
         {
            strcpy(options.box.port, DEFAULT_SIP_PORT);
            options.box.port_l = strlen(options.box.port);
            optind++;
            break;
         }

         if (   argv[optind][addr_l] == ':'
             && ++addr_l < arg_l
             && is_port(argv[optind] + addr_l, arg_l - addr_l, &port_l)
             && addr_l + port_l == arg_l)
         {
            memcpy(options.box.port, argv[optind] + addr_l, port_l);
            options.box.port[options.box.port_l = port_l] = '\0';
            optind++;
            break;
         }
      }

      fprintf(stderr, "Invalid box address '%s'\n", argv[optind]);
      err++;
      optind++;
      break;
   }

   if (optind != argc)
   {
      fprintf(stderr, "Too many arguments '%s%s'\n",
         argv[optind], argc - optind > 1 ? " ..." : "");
      err++;
   }

   if (err)
   {
      fputc('\n', stderr);
      usage();
   }

   log_printf(LOG_VERBOSE, "Box address %.*s:%.*s",
      options.box.addr_l, options.box.addr,
      options.box.port_l, options.box.port);

   if (options.tcp_port == NULL)
      options.tcp_port = DEFAULT_SIP_PORT;
   if (options.udp_port == NULL)
      options.udp_port = DEFAULT_SIP_PORT;

   log_printf(LOG_VERBOSE, "TCP: Server SIP port %s", options.tcp_port);
   log_printf(LOG_VERBOSE, "UDP: Server SIP port %s", options.udp_port);
}


/* ------------------------------------------------------------------------
   process server socket event
   ------------------------------------------------------------------------ */

void client_tcp_setup(int sfd);
void client_udp_setup(int sfd);
static int sfd_server_tcp = -1, sfd_server_udp = -1;

void on_tcp_server_event(int sfd, int sfd_event)
{
   if (sfd_event & ~SFD_EVENT_DATA)
   {
      log_printf(LOG_ERROR, "TCP server socket no longer available"
         " - shutting down");
      sfd_close(&sfd_server_udp);
      sfd_close(&sfd_server_tcp);
      exit(1);
   }

   client_tcp_setup(sfd);
}

void on_udp_server_event(int sfd, int sfd_event)
{
   if (sfd_event & ~SFD_EVENT_DATA)
   {
      log_printf(LOG_ERROR, "UDP server socket no longer available"
         " - shutting down");
      sfd_close(&sfd_server_udp);
      sfd_close(&sfd_server_tcp);
      exit(1);
   }

   client_udp_setup(sfd);
}


/* ------------------------------------------------------------------------
   process network event
   ------------------------------------------------------------------------ */

void on_client_event(int sfd, void *context, int sfd_event);

static void on_event(int sfd, void *context, int sfd_event)
{
   if (context)
      on_client_event(sfd, context, sfd_event);
   else if (sfd == sfd_server_tcp)
      on_tcp_server_event(sfd, sfd_event);
   else {
      assert(sfd == sfd_server_udp);
      on_udp_server_event(sfd, sfd_event);
   }
}


/* ------------------------------------------------------------------------
   setup server sockets
   ------------------------------------------------------------------------ */

static void server_setup(void)
{
   if (   tcp_listen(&sfd_server_tcp, NULL, 0,
                      options.tcp_port, strlen(options.tcp_port))
       && sfd_register(sfd_server_tcp, NULL, NULL)
       && udp_bind(&sfd_server_udp, NULL, 0,
                   options.udp_port, strlen(options.udp_port))
       && sfd_register(sfd_server_udp, NULL, NULL))
   {
      return;
   }

   log_printf(LOG_ERROR, "Server initialization failed");
   exit(1);
}


/* ------------------------------------------------------------------------
   main
   ------------------------------------------------------------------------ */

static volatile sig_atomic_t signal_in_progress;

static void signal_handler(int sig)
{
   const char *sig_s;

   if (signal_in_progress)
      raise(sig);
   signal_in_progress = 1;

   switch (sig)
   {
      case SIGTERM:
         sig_s = "TERM";
         break;
      case SIGINT:
         sig_s = "INT";
         break;
      case SIGQUIT:
         sig_s = "QUIT";
         break;
      case SIGHUP:
         sig_s = "HUP";
         break;
      default:
         sig_s = NULL;
         log_printf(LOG_ERROR, "Received signal %d", sig);
   }

   if (sig_s)
      log_printf(LOG_INFO, "Exit %s version %s on %s signal",
         options.pname, VERSION_STRING, sig_s);

   signal(sig, SIG_DFL);
   raise(sig);
}

static void install_signal_handler(void)
{
   struct sigaction act;

   memset(&act, 0, sizeof(act));
   act.sa_handler = signal_handler;

   sigaction(SIGTERM, &act, NULL);
   sigaction(SIGINT, &act, NULL);
   sigaction(SIGQUIT, &act, NULL);
   sigaction(SIGHUP, &act, NULL);
}

int main(int argc, char *argv[])
{
   parse_commandline(argc, argv);
   install_signal_handler();

   log_printf(LOG_INFO, "Start %s version %s",
      options.pname, VERSION_STRING);

   server_setup();
   while (sfd_wait(on_event))
      ;

   log_printf(LOG_INFO, "Exit %s version %s",
      options.pname, VERSION_STRING);
   return 0;
}


/* ------------------------------------------------------------------------
   logging
   ------------------------------------------------------------------------ */

void log_printf(enum loglevel_t level, const char *fmt, ...)
{
   va_list va;
   FILE *fp;
   struct tm tm;
   time_t tv;
   char tmp[24];

   if (level == LOG_DUMP)
      fp = stdout;
   else if (level <= options.log_level)
      fp = options.log_fp;
   else
      return;

   time (&tv);
   localtime_r(&tv, &tm);
   strftime(tmp, sizeof(tmp), "%Y%m%d %H%M%S", &tm);

   if (level == LOG_DUMP)
      fprintf(fp, "%s ", tmp + 2);
   else
      fprintf(fp, "%s V%d ", tmp + 2, level);

   va_start(va, fmt);
   vfprintf(fp, fmt, va);
   va_end(va);

   fputc('\n', fp);
   fflush(fp);
}
