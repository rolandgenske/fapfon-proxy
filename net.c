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
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <assert.h>
#include <errno.h>


/* ------------------------------------------------------------------------
   socket event management
   ------------------------------------------------------------------------ */

typedef struct poll_item
{
   struct poll_item *next;
   int sfd;
   void *context;
   sfd_cleanup_t cleanup;
}
poll_item_t;

typedef struct
{
   poll_item_t *pi;
   int sfd_event;
}
poll_item_notify_t;

static struct
{
   poll_item_t *pi;
   poll_item_notify_t *pin;
   struct pollfd *pfd;
   int allocated, used;
}
poll_list;

int sfd_wait(sfd_callback_t cb)
{
   poll_item_t *pi;
   struct pollfd *pfd;
   int i, cnt = 0;

   for (pi = poll_list.pi; pi != NULL; pi = pi->next)
   {
      assert(cnt < poll_list.used);
      pfd = poll_list.pfd + cnt++;

      pfd->fd = pi->sfd;
      pfd->events = POLLIN;
      pfd->revents = 0;
   }

   assert(cnt == poll_list.used);
   for (;;)
   {
      cnt = poll(poll_list.pfd, poll_list.used, -1);
      if (cnt > 0)
         break;

      if (cnt == -1)
      {
         int err_no = errno;
         if (err_no == EINTR)
            continue;

         log_printf(LOG_ERROR, "sfd_wait: "
            "poll [%d] %s", err_no, strerror(err_no));
         return 0;
      }
   }

   pi = poll_list.pi;
   pfd = poll_list.pfd;

   for (i = 0; i < cnt;)
   {
      assert(pi != NULL);
      assert(pi->sfd == pfd->fd);

      if (pfd->revents)
      {
         int sfd_event = 0;

         assert(!(pfd->revents & POLLNVAL));
         if (pfd->revents & POLLIN)
            sfd_event |= SFD_EVENT_DATA;
         if (pfd->revents & POLLERR)
            sfd_event |= SFD_EVENT_ERROR;
         if (pfd->revents & POLLHUP)
            sfd_event |= SFD_EVENT_HANGUP;

         poll_list.pin[i].pi = pi;
         poll_list.pin[i].sfd_event = sfd_event;
         i++;
      }

      pi = pi->next;
      pfd++;
   }

   for (i = 0; i < cnt; i++)
   {
      cb(poll_list.pin[i].pi->sfd,
         poll_list.pin[i].pi->context,
         poll_list.pin[i].sfd_event);
   }

   return 1;
}

#define SFD_REGISTER_INCREMENT 24

int sfd_register(int sfd, void *context, sfd_cleanup_t cleanup)
{
   poll_item_t *pi;

   if (sfd == -1)
      return 0;

   if (poll_list.used + 1 > poll_list.allocated)
   {
      poll_item_notify_t *pin;
      struct pollfd *pfd;
      int allocate = (  (poll_list.used + SFD_REGISTER_INCREMENT)
                      / SFD_REGISTER_INCREMENT) * SFD_REGISTER_INCREMENT;

      pin = realloc(poll_list.pin,
                    allocate * sizeof(poll_item_notify_t));
      if (pin == NULL)
      {
         log_printf(LOG_ERROR, "sfd_register:"
            " Memory allocation failed (%u bytes)",
            (unsigned int)(allocate * sizeof(poll_item_notify_t)));
         return 0;
      }

      pfd = realloc(poll_list.pfd,
                    allocate * sizeof(struct pollfd));
      if (pfd == NULL)
      {
         log_printf(LOG_ERROR, "sfd_register:"
            " Memory allocation failed (%u bytes)",
            (unsigned int)(allocate * sizeof(struct pollfd)));
         free(pin);
         return 0;
      }

      poll_list.pin = pin;
      poll_list.pfd = pfd;
      poll_list.allocated = allocate;
   }

   pi = malloc(sizeof(poll_item_t));
   if (pi == NULL)
   {
      log_printf(LOG_ERROR, "sfd_register:"
         " Memory allocation failed (%u bytes)",
         (unsigned int)sizeof(poll_item_t));
      return 0;
   }

   pi->next = poll_list.pi;
   pi->sfd = sfd;
   pi->context = context;
   pi->cleanup = cleanup;
   poll_list.pi = pi;

   poll_list.used++;
   return 1;
}

static void sfd_unregister(int *sfd_p)
{
   poll_item_t **pi_p = &poll_list.pi;
   while (*pi_p != NULL)
   {
      poll_item_t *pi = *pi_p;
      if (pi->sfd == *sfd_p)
      {
         *sfd_p = -1;

         assert(poll_list.used > 0);
         poll_list.used--;

         *pi_p = pi->next;
         if (pi->cleanup)
            pi->cleanup(pi->context);
         free(pi);
         return;
      }

      pi_p = &(*pi_p)->next;
   }

   /* not registered */
   *sfd_p = -1;
}


/* ------------------------------------------------------------------------
   setup TCP listen socket
   ------------------------------------------------------------------------ */

int tcp_listen(int *sfd_p, const char *addr, uint8_t addr_l,
                           const char *port, uint8_t port_l)
{
   struct sockaddr_in sock_addr;
   uint32_t net_addr;
   uint16_t net_port;
   int32_t sock_opt;

   if (addr_l == 0)
      net_addr = INADDR_ANY;
   else {
      assert(addr != NULL);
      if (!addr_aton(&net_addr, addr, addr_l))
      {
         log_printf(LOG_ERROR, "tcp_listen: "
            "Invalid address '%.*s'", addr_l, addr);
         *sfd_p = -1;
         return 0;
      }
   }

   assert(port != NULL);
   assert(port_l != 0);
   if (!port_aton(&net_port, port, port_l))
   {
      log_printf(LOG_ERROR, "tcp_listen: "
         "Invalid port '%.*s'", port_l, port);
      *sfd_p = -1;
      return 0;
   }

   *sfd_p = socket(AF_INET, SOCK_STREAM, 0);
   if (*sfd_p == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "tcp_listen: "
         "Failed to create socket [%d] %s", err_no, strerror(err_no));
      return 0;
   }

   sock_opt = 1;
   if (setsockopt(*sfd_p, SOL_SOCKET, SO_REUSEADDR,
                  &sock_opt, sizeof(sock_opt)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_VERBOSE, "tcp_listen: "
         "setsockopt(SOL_SOCKET,SO_REUSEADDR) [%d] %s",
         err_no, strerror(err_no));
   }

   memset(&sock_addr, 0, sizeof(sock_addr));
   sock_addr.sin_family = AF_INET;
   sock_addr.sin_addr.s_addr = net_addr;
   sock_addr.sin_port = net_port;

   if (bind(*sfd_p, (void *)&sock_addr, sizeof(sock_addr)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "tcp_listen: "
         "Failed to bind socket [%d] %s", err_no, strerror(err_no));
      close(*sfd_p);
      *sfd_p = -1;
      return 0;
   }

   if (listen(*sfd_p, SOMAXCONN) == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "tcp_listen: "
         "Failed to set up listen socket [%d] %s",
         err_no, strerror(err_no));
      close(*sfd_p);
      *sfd_p = -1;
      return 0;
   }

   return 1;
}


/* ------------------------------------------------------------------------
   bind UDP socket
   ------------------------------------------------------------------------ */

int udp_bind(int *sfd_p, const char *addr, uint8_t addr_l,
                         const char *port, uint8_t port_l)
{
   struct sockaddr_in sock_addr;
   uint32_t net_addr;
   uint16_t net_port;
   int32_t sock_opt;

   if (addr_l == 0)
      net_addr = INADDR_ANY;
   else {
      assert(addr != NULL);
      if (!addr_aton(&net_addr, addr, addr_l))
      {
         log_printf(LOG_ERROR, "udp_bind: "
            "Invalid address '%.*s'", addr_l, addr);
         *sfd_p = -1;
         return 0;
      }
   }

   assert(port != NULL);
   assert(port_l != 0);
   if (!port_aton(&net_port, port, port_l))
   {
      log_printf(LOG_ERROR, "udp_bind: "
         "Invalid port '%.*s'", port_l, port);
      *sfd_p = -1;
      return 0;
   }

   *sfd_p = socket(AF_INET, SOCK_DGRAM, 0);
   if (*sfd_p == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "udp_bind: "
         "Failed to create socket [%d] %s", err_no, strerror(err_no));
      return 0;
   }

   sock_opt = 1;
   if (setsockopt(*sfd_p, SOL_SOCKET, SO_REUSEADDR,
                  &sock_opt, sizeof(sock_opt)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_VERBOSE, "udp_bind: "
         "setsockopt(SOL_SOCKET,SO_REUSEADDR) [%d] %s",
         err_no, strerror(err_no));
   }

   sock_opt = 1;
   if (setsockopt(*sfd_p, IPPROTO_IP, IP_PKTINFO,
                  &sock_opt, sizeof(sock_opt)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_VERBOSE, "udp_bind: "
         "setsockopt(IPPROTO_IP,IP_PKTINFO) [%d] %s",
         err_no, strerror(err_no));
   }

   memset(&sock_addr, 0, sizeof(sock_addr));
   sock_addr.sin_family = AF_INET;
   sock_addr.sin_addr.s_addr = net_addr;
   sock_addr.sin_port = net_port;

   if (bind(*sfd_p, (void *)&sock_addr, sizeof(sock_addr)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "udp_bind: "
         "Failed to bind socket [%d] %s", err_no, strerror(err_no));
      close(*sfd_p);
      *sfd_p = -1;
      return 0;
   }

   return 1;
}


/* ------------------------------------------------------------------------
   close socket
   ------------------------------------------------------------------------ */

void sfd_close(int *sfd_p)
{
   if (*sfd_p != -1)
   {
      if (close(*sfd_p) == -1)
      {
         int err_no = errno;
         log_printf(LOG_VERBOSE, "sfd_close: "
            "close [%d] %s", err_no, strerror(err_no));
      }

      sfd_unregister(sfd_p);
   }
}


/* ------------------------------------------------------------------------
   accept TCP connection
   ------------------------------------------------------------------------ */

int tcp_accept(int *sfd_p, int listen_sfd,
               char *peer_addr, uint8_t *peer_addr_l_p,
               char *peer_port, uint8_t *peer_port_l_p)
{
   struct sockaddr_in sock_addr;
   socklen_t sock_addr_l;
   int32_t sock_opt;

   assert(peer_addr != NULL);
   assert(peer_addr_l_p != NULL);
   assert(peer_port != NULL);
   assert(peer_port_l_p != NULL);

   sock_addr_l = sizeof(sock_addr);
   *sfd_p = accept(listen_sfd, (void *)&sock_addr, &sock_addr_l);
   if (*sfd_p == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "tcp_accept: "
         "Failed to accept connection [%d] %s", err_no, strerror(err_no));
      return 0;
   }

   sock_addr_l = sizeof(sock_addr);
   if (getpeername(*sfd_p, (void *)&sock_addr, &sock_addr_l) == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "tcp_accept: "
         "Failed to get peer info [%d] %s", err_no, strerror(err_no));
      close(*sfd_p);
      *sfd_p = -1;
      return 0;
   }

   addr_ntoa(peer_addr, peer_addr_l_p, sock_addr.sin_addr.s_addr);
   port_ntoa(peer_port, peer_port_l_p, sock_addr.sin_port);

   sock_opt = 1;
   if (setsockopt(*sfd_p, SOL_SOCKET, SO_KEEPALIVE,
                  &sock_opt, sizeof(sock_opt)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_VERBOSE, "tcp_accept: "
         "setsockopt(SOL_SOCKET,SO_KEEPALIVE) [%d] %s",
         err_no, strerror(err_no));
   }

   sock_opt = 1;
   if (setsockopt(*sfd_p, SOL_SOCKET, TCP_NODELAY,
                  &sock_opt, sizeof(sock_opt)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_VERBOSE, "tcp_accept: "
         "setsockopt(SOL_SOCKET,TCP_NODELAY) [%d] %s",
         err_no, strerror(err_no));
   }

   return 1;
}


/* ------------------------------------------------------------------------
   connect TCP
   ------------------------------------------------------------------------ */

int tcp_connect(int *sfd_p, const char *addr, uint8_t addr_l,
                            const char *port, uint8_t port_l)
{
   struct sockaddr_in sock_addr;
   uint32_t net_addr;
   uint16_t net_port;
   int32_t sock_opt;

   assert(addr != NULL);
   assert(addr_l != 0);
   assert(port != NULL);
   assert(port_l != 0);

   if (!addr_aton(&net_addr, addr, addr_l))
   {
      log_printf(LOG_ERROR, "tcp_connect: "
         "Invalid address '%.*s'", addr_l, addr);
      *sfd_p = -1;
      return 0;
   }

   if (!port_aton(&net_port, port, port_l))
   {
      log_printf(LOG_ERROR, "tcp_connect: "
         "Invalid port '%.*s'", port_l, port);
      *sfd_p = -1;
      return 0;
   }

   *sfd_p = socket(AF_INET, SOCK_STREAM, 0);
   if (*sfd_p == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "tcp_connect: "
         "Failed to create socket [%d] %s", err_no, strerror(err_no));
      return 0;
   }

   sock_opt = 1;
   if (setsockopt(*sfd_p, SOL_SOCKET, SO_REUSEADDR,
                  &sock_opt, sizeof(sock_opt)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_VERBOSE, "tcp_connect: "
         "setsockopt(SOL_SOCKET,SO_REUSEADDR) [%d] %s",
         err_no, strerror(err_no));
   }

   sock_opt = 1;
   if (setsockopt(*sfd_p, SOL_SOCKET, SO_KEEPALIVE,
                  &sock_opt, sizeof(sock_opt)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_VERBOSE, "tcp_connect: "
         "setsockopt(SOL_SOCKET,SO_KEEPALIVE) [%d] %s",
         err_no, strerror(err_no));
   }

   sock_opt = 1;
   if (setsockopt(*sfd_p, SOL_SOCKET, TCP_NODELAY,
                  &sock_opt, sizeof(sock_opt)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_VERBOSE, "tcp_connect: "
         "setsockopt(SOL_SOCKET,TCP_NODELAY) [%d] %s",
         err_no, strerror(err_no));
   }

   memset(&sock_addr, 0, sizeof(sock_addr));
   sock_addr.sin_family = AF_INET;
   sock_addr.sin_addr.s_addr = net_addr;
   sock_addr.sin_port = net_port;

   if (connect(*sfd_p, (void *)&sock_addr, sizeof(sock_addr)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "tcp_connect: "
         "Failed to connect socket [%d] %s", err_no, strerror(err_no));
      close(*sfd_p);
      *sfd_p = -1;
      return 0;
   }

   return 1;
}


/* ------------------------------------------------------------------------
   disconnect TCP
   ------------------------------------------------------------------------ */

void tcp_disconnect(int *sfd_p)
{
   if (*sfd_p != -1)
   {
      if (shutdown(*sfd_p, SHUT_RDWR) == -1)
      {
         int err_no = errno;
         log_printf(LOG_VERBOSE, "tcp_disconnect: "
            "shutdown(SHUT_RDWR) [%d] %s", err_no, strerror(err_no));
         close(*sfd_p);
      }
      else if (close(*sfd_p) == -1)
      {
         int err_no = errno;
         log_printf(LOG_VERBOSE, "tcp_disconnect: "
            "close [%d] %s", err_no, strerror(err_no));
      }

      sfd_unregister(sfd_p);
   }
}


/* ------------------------------------------------------------------------
   connect UDP
   ------------------------------------------------------------------------ */

int udp_connect(int *sfd_p, const char *addr, uint8_t addr_l,
                            const char *port, uint8_t port_l,
                const char *source_addr, uint8_t source_addr_l,
                const char *source_port, uint8_t source_port_l)
{
   struct sockaddr_in sock_addr;
   uint32_t net_addr;
   uint16_t net_port;
   int32_t sock_opt;

   assert(addr != NULL);
   assert(addr_l != 0);
   assert(port != NULL);
   assert(port_l != 0);

   if (!addr_aton(&net_addr, addr, addr_l))
   {
      log_printf(LOG_ERROR, "udp_connect: "
         "Invalid address '%.*s'", addr_l, addr);
      *sfd_p = -1;
      return 0;
   }

   if (!port_aton(&net_port, port, port_l))
   {
      log_printf(LOG_ERROR, "udp_connect: "
         "Invalid port '%.*s'", port_l, port);
      *sfd_p = -1;
      return 0;
   }

   *sfd_p = socket(AF_INET, SOCK_DGRAM, 0);
   if (*sfd_p == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "udp_connect: "
         "Failed to create socket [%d] %s", err_no, strerror(err_no));
      return 0;
   }

   sock_opt = 1;
   if (setsockopt(*sfd_p, SOL_SOCKET, SO_REUSEADDR,
                  &sock_opt, sizeof(sock_opt)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_VERBOSE, "udp_connect: "
         "setsockopt(SOL_SOCKET,SO_REUSEADDR) [%d] %s",
         err_no, strerror(err_no));
   }

   if (source_port_l)
   {
      uint32_t net_source_addr;
      uint16_t net_source_port;

      if (source_addr_l == 0)
         net_source_addr = INADDR_ANY;
      else {
         assert(source_addr != NULL);
         if (!addr_aton(&net_source_addr, source_addr, source_addr_l))
         {
            log_printf(LOG_ERROR, "udp_connect: "
               "Invalid address '%.*s'", source_addr_l, source_addr);
            *sfd_p = -1;
            return 0;
         }
      }

      assert(source_port != NULL);
      if (!port_aton(&net_source_port, source_port, source_port_l))
      {
         log_printf(LOG_ERROR, "udp_connect: "
            "Invalid port '%.*s'", source_port_l, source_port);
         *sfd_p = -1;
         return 0;
      }

      memset(&sock_addr, 0, sizeof(sock_addr));
      sock_addr.sin_family = AF_INET;
      sock_addr.sin_addr.s_addr = net_source_addr;
      sock_addr.sin_port = net_source_port;

      if (bind(*sfd_p, (void *)&sock_addr, sizeof(sock_addr)) == -1)
      {
         int err_no = errno;
         log_printf(LOG_ERROR, "udp_connect: "
            "Failed to bind socket [%d] %s", err_no, strerror(err_no));
         close(*sfd_p);
         *sfd_p = -1;
         return 0;
      }
   }

   memset(&sock_addr, 0, sizeof(sock_addr));
   sock_addr.sin_family = AF_INET;
   sock_addr.sin_addr.s_addr = net_addr;
   sock_addr.sin_port = net_port;

   if (connect(*sfd_p, (void *)&sock_addr, sizeof(sock_addr)) == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "udp_connect: "
         "Failed to connect socket [%d] %s", err_no, strerror(err_no));
      close(*sfd_p);
      *sfd_p = -1;
      return 0;
   }

   return 1;
}


/* ------------------------------------------------------------------------
   disconnect UDP
   ------------------------------------------------------------------------ */

void udp_disconnect(int *sfd_p)
{
   if (*sfd_p != -1)
   {
      struct sockaddr_in sock_addr;

      memset(&sock_addr, 0, sizeof(sock_addr));
      sock_addr.sin_family = AF_UNSPEC;

      if (connect(*sfd_p, (void *)&sock_addr, sizeof(sock_addr)) == -1)
      {
         int err_no = errno;
         if (err_no != EAFNOSUPPORT)
         {
            log_printf(LOG_VERBOSE, "udp_disconnect: "
               "connect(AF_UNSPEC) [%d] %s", err_no, strerror(err_no));
            close(*sfd_p);
            sfd_unregister(sfd_p);
            return;
         }
      }

      if (close(*sfd_p) == -1)
      {
         int err_no = errno;
         log_printf(LOG_VERBOSE, "udp_disconnect: "
            "close [%d] %s", err_no, strerror(err_no));
      }

      sfd_unregister(sfd_p);
   }
}


/* ------------------------------------------------------------------------
   get local address
   ------------------------------------------------------------------------ */

int sfd_local_addr(int sfd, char *local_addr, uint8_t *local_addr_l_p,
                            char *local_port, uint8_t *local_port_l_p)
{
   struct sockaddr_in sock_addr;
   socklen_t sock_addr_l;

   assert(local_addr != NULL);
   assert(local_addr_l_p != NULL);
   assert(local_port != NULL);
   assert(local_port_l_p != NULL);

   sock_addr_l = sizeof(sock_addr);
   if (getsockname(sfd, (void *)&sock_addr, &sock_addr_l) == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "sfd_local_addr: "
         "Failed to get local info [%d] %s", err_no, strerror(err_no));
      return 0;
   }

   addr_ntoa(local_addr, local_addr_l_p, sock_addr.sin_addr.s_addr);
   port_ntoa(local_port, local_port_l_p, sock_addr.sin_port);
   return 1;
}


/* ------------------------------------------------------------------------
   transmit data
   ------------------------------------------------------------------------ */

int sfd_transmit(int sfd, const void *data_p, uint16_t data_l)
{
   const char *p = data_p;
   while (data_l)
   {
      ssize_t l = send(sfd, p, data_l, MSG_NOSIGNAL);
      if (l == -1)
      {
         int err_no = errno;
         if (err_no == EINTR)
            continue;

         log_printf(LOG_DETAIL, "Failed to send data [%d] %s",
            err_no, strerror(err_no));
         return 0;
      }

      assert(l <= data_l);
      p += l;
      data_l -= l;
   }

   return 1;
}


/* ------------------------------------------------------------------------
   receive data
   ------------------------------------------------------------------------ */

int sfd_receive(int sfd, void *data_p, uint16_t data_l)
{
   char *p;

   if (data_l == 0)
      return 2;

   p = data_p;
   while (data_l)
   {
      ssize_t l = recv(sfd, p, data_l, 0);
      if (l == 0)
         return 2;

      if (l == -1)
      {
         int err_no = errno;
         if (err_no == EINTR)
            continue;

         log_printf(LOG_DETAIL, "Failed to receive data [%d] %s",
            err_no, strerror(err_no));
         return 0;
      }

      assert(l <= data_l);
      p += l;
      data_l -= l;
   }

   return 1;
}

int udp_receive(int sfd, void *data_p, uint16_t data_l,
                char *peer_addr, uint8_t *peer_addr_l_p,
                char *peer_port, uint8_t *peer_port_l_p,
                char *local_addr, uint8_t *local_addr_l_p,
                char *local_port, uint8_t *local_port_l_p)
{
   assert(peer_addr != NULL);
   assert(peer_addr_l_p != NULL);
   assert(peer_port != NULL);
   assert(peer_port_l_p != NULL);

   for (;;)
   {
      struct msghdr msg;
      struct iovec iov;
      struct sockaddr_in sock_addr;
      ssize_t l;
      unsigned char cmsg_buf[256];

      memset(&msg, 0, sizeof(msg));
      msg.msg_name = &sock_addr;
      msg.msg_namelen = sizeof(sock_addr);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_control = cmsg_buf;
      msg.msg_controllen = sizeof(cmsg_buf);

      iov.iov_base = data_p;
      iov.iov_len = data_l;

      l = recvmsg(sfd, &msg, 0);
      if (l == -1)
      {
         int err_no = errno;
         if (err_no == EINTR)
            continue;

         log_printf(LOG_DETAIL, "Failed to receive UDP data [%d] %s",
            err_no, strerror(err_no));
         return -1;
      }

      assert(l <= data_l);

      addr_ntoa(peer_addr, peer_addr_l_p, sock_addr.sin_addr.s_addr);
      port_ntoa(peer_port, peer_port_l_p, sock_addr.sin_port);

      if (local_addr_l_p)
      {
         struct cmsghdr *cmsg;
         assert(local_addr != NULL);

         for (cmsg = CMSG_FIRSTHDR(&msg);
              cmsg != NULL;
              cmsg = CMSG_NXTHDR(&msg, cmsg))
         {
            if (   cmsg->cmsg_level == IPPROTO_IP
                && cmsg->cmsg_type == IP_PKTINFO)
            {
               struct in_pktinfo *pktinfo = (void *)CMSG_DATA(cmsg);
               addr_ntoa(local_addr, local_addr_l_p,
                         pktinfo->ipi_spec_dst.s_addr);
               break;
            }
         }
      }

      if (local_port_l_p)
      {
         socklen_t sock_addr_l = sizeof(sock_addr);
         assert(local_port != NULL);

         if (getsockname(sfd, (void *)&sock_addr, &sock_addr_l) == -1)
         {
            int err_no = errno;
            log_printf(LOG_ERROR, "udp_receive: "
               "Failed to get local info [%d] %s", err_no, strerror(err_no));
            return 0;
         }

         port_ntoa(local_port, local_port_l_p, sock_addr.sin_port);
      }

      return l;
   }
}


/* ------------------------------------------------------------------------
   get number of bytes immediately available for reading
   ------------------------------------------------------------------------ */

int sfd_available(int sfd)
{
   int available;
   if (ioctl(sfd, FIONREAD, &available) == -1)
   {
      int err_no = errno;
      log_printf(LOG_ERROR, "sfd_available: "
         "ioctl(FIONREAD) [%d] %s", err_no, strerror(err_no));
      return -1;
   }

   return available;
}


/* ------------------------------------------------------------------------
   utilities
   ------------------------------------------------------------------------ */

int is_addr(const char *p, int l, int *l_p)
{
   int addr_l = 0, octet;

   for (octet = 0; octet < 4; octet++)
   {
      int octet_i, octet_v;

      if (octet > 0)
      {
         if (addr_l < l && p[addr_l] == '.')
            addr_l++;
         else
            break;
      }

      octet_v = 0;
      for (octet_i = 0; octet_i < 3; octet_i++)
         if (addr_l < l && p[addr_l] >= '0' && p[addr_l] <= '9')
            octet_v = octet_v * 10 + p[addr_l++] - '0';
         else
            break;

      if (octet_i == 0 || octet_v > 255)
         break;
   }

   if (   octet == 4
       && (   addr_l == l
           || (p[addr_l] != '.' && (p[addr_l] < '0' || p[addr_l] > '9'))))
   {
      *l_p = addr_l;
      return 1;
   }

   *l_p = addr_l < l ? addr_l + 1 : l;
   return 0;
}

void addr_ntoa(char *to, uint8_t *l_p, uint32_t addr)
{
   addr = ntohl(addr);
   *l_p = (uint8_t)sprintf(to, "%u.%u.%u.%u",
                           (addr >> 24) & 0xff, (addr >> 16) & 0xff,
                           (addr >> 8) & 0xff, addr & 0xff);
}

int addr_aton(uint32_t *addr_p, const char *addr, uint8_t addr_l)
{
   char tmp[16];

   if (addr_l < sizeof(tmp))
   {
      in_addr_t addr_decoded;

      memcpy(tmp, addr, addr_l);
      tmp[addr_l] = '\0';

      addr_decoded = inet_addr(tmp);
      if (addr_decoded != -1)
      {
         *addr_p = addr_decoded;
         return 1;
      }
   }

   *addr_p = 0;
   return 0;
}

int is_port(const char *p, int l, int *l_p)
{
   int port_l = 0, port_v = 0;
   while (port_l < l)
   {
      if (   (port_v == 0 && p[port_l] >= '1' && p[port_l] <= '9')
          || (port_v != 0 && p[port_l] >= '0' && p[port_l] <= '9'))
      {
         port_v = port_v * 10 + p[port_l++] - '0';
      }
      else
         break;
   }

   if (port_l > 0 && port_l <= 5 && port_v > 0 && port_v < 65536)
   {
      *l_p = port_l;
      return 1;
   }

   *l_p = port_l < l ? port_l + 1 : l;
   return 0;
}

void port_ntoa(char *to, uint8_t *l_p, uint16_t port)
{
   *l_p = (uint8_t)sprintf(to, "%u", ntohs(port));
}

int port_aton(uint16_t *port_p, const char *port, uint8_t port_l)
{
   char tmp[6];

   if (port_l < sizeof(tmp))
   {
      char *end_p;
      long int port_decoded;

      memcpy(tmp, port, port_l);
      tmp[port_l] = '\0';

      errno = 0;
      port_decoded = strtol(tmp, &end_p, 10);
      if (   errno == 0 && *end_p == '\0'
          && port_decoded > 0 && port_decoded < 65536)
      {
         *port_p = htons((uint16_t)port_decoded);
         return 1;
      }
   }

   *port_p = 0;
   return 0;
}
