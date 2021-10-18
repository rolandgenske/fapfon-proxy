/* ------------------------------------------------------------------------
   (C) 2018 by Roland Genske <roland@genske.org>

   Workaround for FRITZ!App Fon SIP via VPN

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   2018-02-09 - v0.1
   2018-02-21 - v0.2, functionally complete
   2018-12-21 - v0.3, fix UDP REGISTER not recognized
   2021-10-18 - v0.4, additional diagnostics when packet not recognized

   ------------------------------------------------------------------------ */

#if !defined(FAPFON_PROXY_H_INCLUDED)
#define FAPFON_PROXY_H_INCLUDED

/* ------------------------------------------------------------------------
   version
   ------------------------------------------------------------------------ */

#define VERSION_STRING "0.4.1018"


/* ------------------------------------------------------------------------
   dependencies
   ------------------------------------------------------------------------ */

#include <stdio.h>
#include <inttypes.h>


/* ------------------------------------------------------------------------
   address/port type
   ------------------------------------------------------------------------ */

typedef struct
{
   char addr[16], port[6];
   uint8_t addr_l, port_l;
}
addr_t;


/* ------------------------------------------------------------------------
   command line options
   ------------------------------------------------------------------------ */

enum loglevel_t
{
   LOG_ERROR   = 0,
   LOG_INFO    = 1,
   LOG_DETAIL  = 2,
   LOG_VERBOSE = 3,
   LOG_DUMP
};

#define LOG_MAX_LEVEL LOG_VERBOSE

#define LOG_DUMP_FON 1
#define LOG_DUMP_BOX 2

typedef struct
{
   char *pname;                  /* process name */
   addr_t box;                   /* Box address/port */
   const char *tcp_port;         /* SIP port, TCP */
   const char *udp_port;         /* SIP port, UDP */
   FILE *log_fp;                 /* log file descriptor */
   enum loglevel_t log_level;    /* log level */
   int log_dump;                 /* LOG_DUMP_FON and/or LOG_DUMP_BOX */
}
options_t;

extern options_t options;


/* ------------------------------------------------------------------------
   protocol buffer
   ------------------------------------------------------------------------ */

typedef struct
{
   char *p;
   uint16_t allocated, used;
}
buf_t;

void buf_cleanup(buf_t *buf);
int buf_resize(buf_t *buf, uint32_t size);


/* ------------------------------------------------------------------------
   packet assembly
   ------------------------------------------------------------------------ */

enum packet_status_t
{
   PACKET_INITIAL,
   PACKET_ERROR,
   PACKET_INCOMPLETE,
   PACKET_READY
};

typedef struct { int16_t len; } len_t;
typedef struct { int16_t offs, len; } loc_t;

typedef struct
{
   buf_t buf;
   int16_t status;

   len_t header, data;
   len_t method;

   loc_t current_line;
   loc_t via_line, via, from, to, contact, content_length;
}
packet_t;

int next_packet(packet_t *packet, const void *next_data, uint32_t next_size);


/* ------------------------------------------------------------------------
   protocol data
   ------------------------------------------------------------------------ */

typedef struct
{
   char *p;
   uint16_t i, l;
}
data_t;

int data_modify(packet_t *packet, data_t *data,
                int replace_i, int replace_l,
                const char *with, int with_l);

int addr_find(const data_t *data, int *addr_l_p);
int port_find(const data_t *data, int addr_i, int addr_l, int *port_l_p);


/* ------------------------------------------------------------------------
   network
   ------------------------------------------------------------------------ */

typedef void (*sfd_callback_t)(int sfd, void *context, int sfd_event);
typedef void (*sfd_cleanup_t)(void *context);

#define SFD_EVENT_DATA    1
#define SFD_EVENT_ERROR   2
#define SFD_EVENT_HANGUP  4

int sfd_wait(sfd_callback_t cb);
int sfd_register(int sfd, void *context, sfd_cleanup_t cleanup);

int tcp_listen(int *sfd_p, const char *addr, uint8_t addr_l,
                           const char *port, uint8_t port_l);
int udp_bind(int *sfd_p, const char *addr, uint8_t addr_l,
                         const char *port, uint8_t port_l);
void sfd_close(int *sfd_p);

int tcp_accept(int *sfd_p, int listen_sfd,
               char *peer_addr, uint8_t *peer_addr_l_p,
               char *peer_port, uint8_t *peer_port_l_p);
int tcp_connect(int *sfd_p, const char *addr, uint8_t addr_l,
                            const char *port, uint8_t port_l);
void tcp_disconnect(int *sfd_p);

int udp_connect(int *sfd_p, const char *addr, uint8_t addr_l,
                            const char *port, uint8_t port_l,
                const char *source_addr, uint8_t source_addr_l,
                const char *source_port, uint8_t source_port_l);
void udp_disconnect(int *sfd_p);

int sfd_local_addr(int sfd, char *local_addr, uint8_t *local_addr_l_p,
                            char *local_port, uint8_t *local_port_l_p);

int sfd_transmit(int sfd, const void *data_p, uint16_t data_l);
int sfd_receive(int sfd, void *data_p, uint16_t data_l);
int udp_receive(int sfd, void *data_p, uint16_t data_l,
                char *peer_addr, uint8_t *peer_addr_l_p,
                char *peer_port, uint8_t *peer_port_l_p,
                char *local_addr, uint8_t *local_addr_l_p,
                char *local_port, uint8_t *local_port_l_p);
int sfd_available(int sfd);

int is_addr(const char *p, int l, int *l_p);
void addr_ntoa(char *to, uint8_t *l_p, uint32_t addr);
int addr_aton(uint32_t *addr_p, const char *addr, uint8_t addr_l);

int is_port(const char *p, int l, int *l_p);
void port_ntoa(char *to, uint8_t *l_p, uint16_t port);
int port_aton(uint16_t *port_p, const char *port, uint8_t port_l);


/* ------------------------------------------------------------------------
   logging
   ------------------------------------------------------------------------ */

void log_printf(enum loglevel_t level, const char *fmt, ...)
   __attribute__ ((format(printf, 2, 3)));

void log_dump(enum loglevel_t level, const void *bufp, uint32_t len);

#endif /* FAPFON_PROXY_H_INCLUDED */
