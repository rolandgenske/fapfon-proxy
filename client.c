/* ------------------------------------------------------------------------
   (C) 2018 by Roland Genske <roland@genske.org>

   Workaround for FRITZ!App Fon SIP via VPN

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   2018-02-09 - v0.1
   2018-02-21 - v0.2, functionally complete
   2018-12-21 - v0.3, fix UDP REGISTER not recognized

   ------------------------------------------------------------------------ */

/* ------------------------------------------------------------------------
   dependencies
   ------------------------------------------------------------------------ */

#include "fapfon_proxy.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>


/* ------------------------------------------------------------------------
   client context
   ------------------------------------------------------------------------ */

enum protocol_t
{
   P_TCP,
   P_UDP
};

typedef struct
{
   int sfd;
   addr_t peer, local;
   buf_t buf;
   packet_t packet;
}
endpoint_t;

typedef struct client_context
{
   struct client_context *next;
   u_int32_t id;
   int connected;

   char *contact_id;
   int16_t contact_id_l;

   struct
   {
      endpoint_t tcp, udp;
      addr_t contact, rtp;
   }
   fon;

   struct
   {
      endpoint_t tcp, udp;
   }
   box;
}
client_context_t;

static client_context_t *client_list;
static u_int32_t client_id;


/* ------------------------------------------------------------------------
   temporary network receive buffer
   ------------------------------------------------------------------------ */

static buf_t tmp_buf;


/* ------------------------------------------------------------------------
   modify address/port
   ------------------------------------------------------------------------ */

static int modify_addr_port(packet_t *packet, data_t *d,
                            const addr_t *from, const addr_t *to)
{
   for (;;)
   {
      /* locate next address */

      int addr_i, addr_l,
          port_i, port_l;

      if ((addr_i = addr_find(d, &addr_l)) == -1)
      {
         /* no more addresses present */
         break;
      }

      if (from && (   addr_l != from->addr_l
                   || memcmp(d->p + addr_i, from->addr, addr_l)))
      {
         /* from address does not match */
         d->i = addr_i + addr_l;
         continue;
      }

      if (!data_modify(packet, d, addr_i, addr_l, to->addr, to->addr_l))
         return 0;

      addr_l = to->addr_l;
      if ((port_i = port_find(d, addr_i, addr_l, &port_l)) != -1)
      {
         if (!data_modify(packet, d, port_i, port_l, to->port, to->port_l))
            return 0;

         d->i = port_i + to->port_l;
      }
      else
         d->i = addr_i + addr_l;
   }

   return 1;
}


/* ------------------------------------------------------------------------
   modify header
   ------------------------------------------------------------------------ */

static int modify_header(packet_t *packet,
                         const addr_t *from, const addr_t *to)
{
   data_t d;

   /* before Via header */

   d.p = packet->buf.p;
   d.i = packet->method.len;
   d.l = packet->via_line.offs;

   if (!modify_addr_port(packet, &d, from, to))
      return 0;

   /* after Via header */

   d.i = packet->via_line.offs + packet->via_line.len;
   d.l = packet->header.len;

   return modify_addr_port(packet, &d, from, to);
}


/* ------------------------------------------------------------------------
   modify data
   ------------------------------------------------------------------------ */

static int modify_data(packet_t *packet,
                       const addr_t *from, const addr_t *to)
{
   if (packet->data.len)
   {
      data_t d;

      d.p = packet->buf.p + packet->header.len;
      d.i = 0;
      d.l = packet->data.len;

      if (!modify_addr_port(packet, &d, from, to))
         return 0;
   }

   return 1;
}


/* ------------------------------------------------------------------------
   modify Via rport
   ------------------------------------------------------------------------ */

static int modify_via_rport(packet_t *packet, const addr_t *to)
{
   data_t d;

   d.p = packet->buf.p;
   d.i = packet->via.offs;
   d.l = d.i + packet->via.len;

   while (d.i < d.l)
   {
      if (   d.p[d.i++] == ';'
          && d.l - d.i > 6
          && !strncasecmp(packet->buf.p + d.i, "rport=", 6))
      {
         int port_l;

         d.i += 6;
         if (is_port(packet->buf.p + d.i, d.l - d.i, &port_l))
         {
            if (!data_modify(packet, &d,
                             d.i, port_l,
                             to->port, to->port_l))
            {
               return 0;
            }

            port_l = to->port_l;
         }

         d.i += port_l;
      }
   }

   return 1;
}


/* ------------------------------------------------------------------------
   modify Content-Length
   ------------------------------------------------------------------------ */

static int modify_content_length(packet_t *packet)
{
   data_t d;
   char tmp[16];
   int tmp_l = sprintf(tmp, " %d", packet->data.len);

   d.p = packet->buf.p;
   d.i = packet->content_length.offs;
   d.l = packet->content_length.len;

   return data_modify(packet, &d, d.i, d.l, tmp, tmp_l);
}


/* ------------------------------------------------------------------------
   get contact identifier if present
   ------------------------------------------------------------------------ */

static int16_t contact_id(const packet_t *packet,
                          const loc_t *loc, int16_t *l_p)
{
   int i = loc->offs, l = i + loc->len;
   if (i < l && packet->buf.p[i] == '<')
      i++;

   if (l - i > 4 && !strncasecmp(packet->buf.p + i, "sip:", 4))
   {
      int contact_id_i = i += 4;
      while (i < l && packet->buf.p[i] != '@')
         i++;

      if (i < l && i > contact_id_i)
      {
         *l_p = i - contact_id_i;
         return contact_id_i;
      }
   }

   return -1;
}


/* ------------------------------------------------------------------------
   disconnect client
   ------------------------------------------------------------------------ */

static void client_disconnect(client_context_t *client)
{
   tcp_disconnect(client->fon.tcp.sfd != -1 ? &client->fon.tcp.sfd
                                            : &client->fon.udp.sfd);
}


/* ------------------------------------------------------------------------
   process Fon to Box message
   ------------------------------------------------------------------------ */

static int fon_to_box(client_context_t *client,
                      endpoint_t *from_ep, endpoint_t *to_ep)
{
   static const char log_prefix[] = "First Fon TCP message not recognized";

   while (client->contact_id == NULL)
   {
      /* TCP connection, first message */

      int16_t contact_id_i, contact_id_l;

      assert(client->contact_id_l == 0);

      if (from_ep->packet.method.len == 0)
      {
         log_printf(LOG_VERBOSE, "%s, SIP method expected", log_prefix);
         return 0;
      }

      if (from_ep->packet.contact.offs == 0)
      {
         log_printf(LOG_VERBOSE, "%s, Contact header expected", log_prefix);
         return 0;
      }

      if ((contact_id_i = contact_id(&from_ep->packet,
                                     &from_ep->packet.contact,
                                     &contact_id_l)) != -1)
      {
         client_context_t *cl;
         char *contact_id;
         data_t d;
         int addr_i, addr_l, port_i, port_l;

         for (cl = client_list; cl != NULL; cl = cl->next)
         {
            if (   cl->contact_id != NULL
                && contact_id_l == cl->contact_id_l
                && !strncasecmp(from_ep->packet.buf.p + contact_id_i,
                                cl->contact_id, cl->contact_id_l))
            {
               /* contact identifier already registered */

               if (cl->connected)
               {
                  /* assume stale connection and disconnect it */

                  log_printf(LOG_VERBOSE, "[%u]"
                     " Disconnecting stale connection [%u]",
                     client->id, cl->id);

                  client_disconnect(cl);
               }

               break;
            }
         }

         contact_id = malloc(contact_id_l + 1);
         if (contact_id == NULL)
         {
            log_printf(LOG_ERROR, "fon_to_box:"
               " Memory allocation failed (%d bytes)",
               contact_id_l + 1);

            return 0;
         }

         d.p = from_ep->packet.buf.p;
         d.i = contact_id_i;
         d.l = from_ep->packet.contact.offs + from_ep->packet.contact.len;

         memcpy(contact_id, d.p + d.i, contact_id_l);
         contact_id[contact_id_l] = '\0';

         client->contact_id = contact_id;
         client->contact_id_l = contact_id_l;

         d.i += contact_id_l + 1;
         if (   (addr_i = addr_find(&d, &addr_l)) == d.i
             && (port_i = port_find(&d, addr_i, addr_l, &port_l)) != -1)
         {
            memcpy(client->fon.contact.addr, d.p + addr_i, addr_l);
            client->fon.contact.addr[addr_l] = '\0';
            client->fon.contact.addr_l = addr_l;

            memcpy(client->fon.contact.port, d.p + port_i, port_l);
            client->fon.contact.port[port_l] = '\0';
            client->fon.contact.port_l = port_l;

            log_printf(LOG_VERBOSE, "[%u] %.*s Contact '%.*s' @%.*s:%.*s",
               client->id,
               from_ep->packet.method.len, from_ep->packet.buf.p,
               client->contact_id_l, client->contact_id,
               client->fon.contact.addr_l, client->fon.contact.addr,
               client->fon.contact.port_l, client->fon.contact.port);

            break;
         }
      }

      log_printf(LOG_VERBOSE,
         "%s, failed to decode Contact header", log_prefix);
      return 0;
   }

   if (client->fon.contact.addr_l)
   {
      /* TCP connection */

      if (!modify_header(&from_ep->packet,
                         &client->fon.contact, &to_ep->local))
      {
         log_printf(LOG_VERBOSE,
            "Fon message header address modification failed");
         return 0;
      }

      if (!modify_data(&from_ep->packet,
                       &client->fon.contact, &from_ep->peer))
      {
         log_printf(LOG_VERBOSE,
            "Fon message data address modification failed");
         return 0;
      }
   }
   else if (from_ep->packet.data.len)
   {
      /* UDP connection */

      if (client->fon.rtp.addr_l == 0)
      {
         /* first SDP message, locate RTP peer address */

         data_t d;

         d.p = from_ep->packet.buf.p + from_ep->packet.header.len;
         d.i = 0;
         d.l = from_ep->packet.data.len;

         for (;;)
         {
            int addr_i, addr_l;

            if ((addr_i = addr_find(&d, &addr_l)) == -1)
               break;

            if (   (   addr_l == from_ep->peer.addr_l
                    && !memcmp(d.p + addr_i, from_ep->peer.addr, addr_l))
                || (   addr_l == to_ep->peer.addr_l
                    && !memcmp(d.p + addr_i, to_ep->peer.addr, addr_l)))
            {
               d.i = addr_i + addr_l;
               continue;
            }

            memcpy(client->fon.rtp.addr, d.p + addr_i, addr_l);
            client->fon.rtp.addr[addr_l] = '\0';
            client->fon.rtp.addr_l = addr_l;

            log_printf(LOG_VERBOSE, "[%u] %.*s%sRTP peer %.*s",
               client->id,
               from_ep->packet.method.len, from_ep->packet.buf.p,
               from_ep->packet.method.len ? " " : "",
               client->fon.rtp.addr_l, client->fon.rtp.addr);

            break;
         }
      }

      if (client->fon.rtp.addr_l)
      {
         if (!modify_data(&from_ep->packet,
                          &client->fon.rtp, &from_ep->peer))
         {
            log_printf(LOG_VERBOSE,
               "Fon message data address modification failed");
            return 0;
         }
      }
   }

   return 1;
}


/* ------------------------------------------------------------------------
   process Box to Fon message
   ------------------------------------------------------------------------ */

static int box_to_fon(client_context_t *client,
                      endpoint_t *from_ep, endpoint_t *to_ep)
{
   if (!modify_via_rport(&from_ep->packet, &to_ep->peer))
   {
      log_printf(LOG_VERBOSE,
         "Box message Via header modification failed");
      return 0;
   }

   if (client->fon.contact.addr_l)
   {
      /* TCP connection */

      if (!modify_header(&from_ep->packet,
                         &from_ep->local, &client->fon.contact))
      {
         log_printf(LOG_VERBOSE,
            "Box message header address modification failed");
         return 0;
      }

      if (!modify_data(&from_ep->packet,
                       &to_ep->peer, &client->fon.contact))
      {
         log_printf(LOG_VERBOSE,
            "Box message data address modification failed");
         return 0;
      }
   }
   else if (client->fon.rtp.addr_l)
   {
      /* UDP connection */

      if (!modify_data(&from_ep->packet,
                       &to_ep->peer, &client->fon.rtp))
      {
         log_printf(LOG_VERBOSE,
            "Box message data address modification failed");
         return 0;
      }
   }

   return 1;
}


/* ------------------------------------------------------------------------
   dump packet
   ------------------------------------------------------------------------ */

static void dump_packet(const char *from, const addr_t *from_addr,
                        const char *to, const addr_t *to_addr,
                        const packet_t *packet, enum protocol_t protocol)
{
   int i = 0, l = packet->header.len + packet->data.len, col = 0;

   log_printf(LOG_DUMP, "%s %s%s%.*s:%.*s -> %s%s%.*s:%.*s Size %d",
      protocol == P_TCP ? "TCP" : "UDP",
      from ? from : "", from ? " " : "",
      from_addr->addr_l, from_addr->addr, from_addr->port_l, from_addr->port,
      to ? to : "", to ? " " : "",
      to_addr->addr_l, to_addr->addr, to_addr->port_l, to_addr->port, l);

   while (i < l)
   {
      char c = packet->buf.p[i++];
      if (c == '\n')
      {
         col = 0;
         fputs("\\n\n", stdout);
      }
      else {
         col++;
         if (c == '\r')
            fputs("\\r", stdout);
         else if (c < 32 || c > 127)
            fprintf(stdout, "\\x%02x", c);
         else
            fputc(c, stdout);
      }
   }

   if (col)
      fputc('\n', stdout);

   fflush(stdout);
}


/* ------------------------------------------------------------------------
   process client socket event
   ------------------------------------------------------------------------ */

static void client_packet(client_context_t *client,
                          endpoint_t *from_ep, endpoint_t *to_ep)
{
   const char *from, *to;
   int from_dump, to_dump, ok;
   enum protocol_t protocol;
   enum { D_FON_TO_BOX, D_BOX_TO_FON } direction;

   if (from_ep == &client->fon.tcp)
   {
      assert(to_ep == &client->box.tcp);

      from = "Fon";
      from_dump = options.log_dump & LOG_DUMP_FON;

      to = "Box";
      to_dump = options.log_dump & LOG_DUMP_BOX;

      protocol = P_TCP;
      direction = D_FON_TO_BOX;
   }
   else if (from_ep == &client->fon.udp)
   {
      assert(to_ep == &client->box.udp);

      from = "Fon";
      from_dump = options.log_dump & LOG_DUMP_FON;

      to = "Box";
      to_dump = options.log_dump & LOG_DUMP_BOX;

      protocol = P_UDP;
      direction = D_FON_TO_BOX;
   }
   else if (from_ep == &client->box.tcp)
   {
      assert(to_ep == &client->fon.tcp);

      from = "Box";
      from_dump = options.log_dump & LOG_DUMP_BOX;

      to = "Fon";
      to_dump = options.log_dump & LOG_DUMP_FON;

      protocol = P_TCP;
      direction = D_BOX_TO_FON;
   }
   else {
      assert(from_ep == &client->box.udp);
      assert(to_ep == &client->fon.udp);

      from = "Box";
      from_dump = options.log_dump & LOG_DUMP_BOX;

      to = "Fon";
      to_dump = options.log_dump & LOG_DUMP_FON;

      protocol = P_UDP;
      direction = D_BOX_TO_FON;
   }

   if (from_dump)
      dump_packet(from, &from_ep->peer, NULL, &from_ep->local,
                  &from_ep->packet, protocol);

   if (direction == D_FON_TO_BOX)
      ok = fon_to_box(client, from_ep, to_ep);
   else
      ok = box_to_fon(client, from_ep, to_ep);
   if (!ok)
   {
      log_printf(LOG_VERBOSE, "[%u] Message to %.*s:%.*s/%s"
         " modification failed - disconnecting",
         client->id,
         to_ep->peer.addr_l, to_ep->peer.addr,
         to_ep->peer.port_l, to_ep->peer.port,
         protocol == P_TCP ? "tcp" : "udp");

      client_disconnect(client);
      return;
   }

   if (!modify_content_length(&from_ep->packet))
   {
      log_printf(LOG_VERBOSE, "[%u] Message to %.*s:%.*s/%s"
         " Content-Length header modification failed - disconnecting",
         client->id,
         to_ep->peer.addr_l, to_ep->peer.addr,
         to_ep->peer.port_l, to_ep->peer.port,
         protocol == P_TCP ? "tcp" : "udp");

      client_disconnect(client);
      return;
   }

   if (to_dump)
      dump_packet(NULL, &to_ep->local, to, &to_ep->peer,
                  &from_ep->packet, protocol);

   if (!sfd_transmit(to_ep->sfd, from_ep->packet.buf.p,
                     from_ep->packet.header.len + from_ep->packet.data.len))
   {
      log_printf(LOG_VERBOSE, "[%u]"
         " Failed to transmit to %.*s:%.*s/%s - disconnecting",
         client->id,
         to_ep->peer.addr_l, to_ep->peer.addr,
         to_ep->peer.port_l, to_ep->peer.port,
         protocol == P_TCP ? "tcp" : "udp");

      client_disconnect(client);
   }
}

void on_client_event(int sfd, void *context, int sfd_event)
{
   client_context_t *client = context;
   endpoint_t *from_ep, *to_ep;
   int available, ok;
   enum protocol_t protocol;

   if (!client->connected)
   {
      /* disconnecting, ignore event */
      return;
   }

   if (sfd == client->fon.tcp.sfd)
   {
      from_ep = &client->fon.tcp;
      to_ep = &client->box.tcp;
      protocol = P_TCP;
   }
   else if (sfd == client->fon.udp.sfd)
   {
      from_ep = &client->fon.udp;
      to_ep = &client->box.udp;
      protocol = P_UDP;
   }
   else if (sfd == client->box.tcp.sfd)
   {
      from_ep = &client->box.tcp;
      to_ep = &client->fon.tcp;
      protocol = P_TCP;
   }
   else {
      assert(sfd == client->box.udp.sfd);

      from_ep = &client->box.udp;
      to_ep = &client->fon.udp;
      protocol = P_UDP;
   }

   assert(to_ep->sfd != -1);

   if (   (sfd_event & ~SFD_EVENT_DATA)
       || (available = sfd_available(from_ep->sfd)) == -1
       || !buf_resize(&tmp_buf, available)
       || (ok = sfd_receive(from_ep->sfd, tmp_buf.p, available)) == 2)
   {
      client_disconnect(client);
      return;
   }
   if (!ok)
   {
      log_printf(LOG_VERBOSE, "[%u]"
         " Failed to receive from %.*s:%.*s/%s - disconnecting",
         client->id,
         from_ep->peer.addr_l, from_ep->peer.addr,
         from_ep->peer.port_l, from_ep->peer.port,
         protocol == P_TCP ? "tcp" : "udp");

      client_disconnect(client);
      return;
   }

   if (!next_packet(&from_ep->packet, tmp_buf.p, available))
   {
      log_printf(LOG_VERBOSE, "[%u]"
         " Packet from %.*s:%.*s/%s not recognized - disconnecting",
         client->id,
         from_ep->peer.addr_l, from_ep->peer.addr,
         from_ep->peer.port_l, from_ep->peer.port,
         protocol == P_TCP ? "tcp" : "udp");

      client_disconnect(client);
      return;
   }

   if (from_ep->packet.status == PACKET_INCOMPLETE)
   {
      if (protocol == P_UDP)
      {
         log_printf(LOG_VERBOSE, "[%u]"
            " Packet from %.*s:%.*s/udp incomplete - disconnecting",
            client->id,
            from_ep->peer.addr_l, from_ep->peer.addr,
            from_ep->peer.port_l, from_ep->peer.port);

         client_disconnect(client);
      }

      return;
   }

   assert(from_ep->packet.status == PACKET_READY);
   client_packet(client, from_ep, to_ep);
}


/* ------------------------------------------------------------------------
   setup client connection
   ------------------------------------------------------------------------ */

static void client_cleanup(void *context)
{
   client_context_t *client = context, **client_p;

   assert(client->fon.tcp.sfd == -1);
   client->connected = 0;

   if (client->fon.udp.sfd != -1)
   {
      udp_disconnect(&client->fon.udp.sfd);
      /* recursive invocation, registered on same client */
      return;
   }
   if (client->box.tcp.sfd != -1)
   {
      tcp_disconnect(&client->box.tcp.sfd);
      /* recursive invocation, registered on same client */
      return;
   }
   if (client->box.udp.sfd != -1)
   {
      udp_disconnect(&client->box.udp.sfd);
      /* recursive invocation, registered on same client */
      return;
   }

   client_p = &client_list;
   while (*client_p != NULL)
   {
      if (*client_p == client)
      {
         *client_p = client->next;
         break;
      }

      client_p = &(*client_p)->next;
   }

   log_printf(LOG_DETAIL, "[%u] Disconnect", client->id);

   buf_cleanup(&client->fon.tcp.buf);
   buf_cleanup(&client->fon.udp.buf);

   buf_cleanup(&client->box.tcp.buf);
   buf_cleanup(&client->box.udp.buf);

   free(client->contact_id);
   free(client);
}

void client_tcp_setup(int sfd)
{
   client_context_t *client = calloc(1, sizeof(client_context_t));
   if (client == NULL)
   {
      log_printf(LOG_ERROR, "client_tcp_setup:"
         " Memory allocation failed (%u bytes)",
         (unsigned int)sizeof(client_context_t));

      return;
   }

   client->next = client_list;
   client->id = ++client_id;
   client_list = client;
   client->connected = 1;
   client->fon.udp.sfd = client->box.tcp.sfd = client->box.udp.sfd = -1;

   if (   tcp_accept(&client->fon.tcp.sfd, sfd,
               client->fon.tcp.peer.addr, &client->fon.tcp.peer.addr_l,
               client->fon.tcp.peer.port, &client->fon.tcp.peer.port_l)
       && sfd_local_addr(client->fon.tcp.sfd,
               client->fon.tcp.local.addr, &client->fon.tcp.local.addr_l,
               client->fon.tcp.local.port, &client->fon.tcp.local.port_l)
       && sfd_register(client->fon.tcp.sfd, client, client_cleanup))
   {
      log_printf(LOG_DETAIL, "[%u] Connect %.*s:%.*s/tcp",
         client->id,
         client->fon.tcp.peer.addr_l, client->fon.tcp.peer.addr,
         client->fon.tcp.peer.port_l, client->fon.tcp.peer.port);

      client->box.tcp.peer = options.box;
      if (   tcp_connect(&client->box.tcp.sfd,
                  client->box.tcp.peer.addr, client->box.tcp.peer.addr_l,
                  client->box.tcp.peer.port, client->box.tcp.peer.port_l)
          && sfd_local_addr(client->box.tcp.sfd,
                  client->box.tcp.local.addr, &client->box.tcp.local.addr_l,
                  client->box.tcp.local.port, &client->box.tcp.local.port_l)
          && sfd_register(client->box.tcp.sfd, client, client_cleanup))
      {
         return;
      }

      log_printf(LOG_VERBOSE,
         "[%u] Box connection to %.*s:%.*s/tcp failed",
         client->id,
         client->box.tcp.peer.addr_l, client->box.tcp.peer.addr,
         client->box.tcp.peer.port_l, client->box.tcp.peer.port);
   }

   log_printf(LOG_DETAIL, "[%u] Client initialization failed", client->id);
   tcp_disconnect(&client->fon.tcp.sfd);
}

void client_udp_setup(int sfd)
{
   client_context_t *client;
   packet_t packet;
   addr_t peer, local;
   int available;
   int16_t contact_id_i, contact_id_l;

   if (   (available = sfd_available(sfd)) == -1
       || !buf_resize(&tmp_buf, available)
       || (available = udp_receive(sfd, tmp_buf.p, available,
               peer.addr, &peer.addr_l, peer.port, &peer.port_l,
               local.addr, &local.addr_l, local.port, &local.port_l)) == -1)
   {
      return;
   }

   memset(&packet, 0, sizeof(packet));
   if (!next_packet(&packet, tmp_buf.p, available))
   {
      log_printf(LOG_VERBOSE, "Packet from %.*s:%.*s/udp not recognized",
         peer.addr_l, peer.addr, peer.port_l, peer.port);

      buf_cleanup(&packet.buf);
      return;
   }

   if (packet.status == PACKET_INCOMPLETE)
   {
      log_printf(LOG_VERBOSE, "Packet from %.*s:%.*s/udp incomplete",
         peer.addr_l, peer.addr, peer.port_l, peer.port);

      buf_cleanup(&packet.buf);
      return;
   }

   assert(packet.status == PACKET_READY);
   if (packet.method.len)
   {
      /* SIP method: contact identifier expected in From header */
      contact_id_i = contact_id(&packet, &packet.from, &contact_id_l);
   }
   else {
      /* SIP status: contact identifier expected in To header */
      contact_id_i = contact_id(&packet, &packet.to, &contact_id_l);
   }
   if (contact_id_i == -1)
   {
      log_printf(LOG_VERBOSE, "Packet from %.*s:%.*s/udp not recognized,"
         " failed to decode %s header",
         peer.addr_l, peer.addr, peer.port_l, peer.port,
         packet.method.len ? "From" : "To");

      buf_cleanup(&packet.buf);
      return;
   }

   for (client = client_list; client != NULL; client = client->next)
   {
      if (   client->contact_id != NULL
          && contact_id_l == client->contact_id_l
          && !strncasecmp(packet.buf.p + contact_id_i,
                          client->contact_id, client->contact_id_l))
      {
         break;
      }
   }

   if (packet.method.len == 8 && !strncasecmp(packet.buf.p, "REGISTER", 8))
   {
      if (   client
          && (   client->fon.udp.sfd == -1
              || peer.addr_l != client->fon.udp.peer.addr_l
              || memcmp(peer.addr, client->fon.udp.peer.addr, peer.addr_l)
              || peer.port_l != client->fon.udp.peer.port_l
              || memcmp(peer.port, client->fon.udp.peer.port, peer.port_l)))
      {
         /* new registration, same contact, different address,
            disconnect if connected */

         if (client->connected)
            client_disconnect(client);

         client = NULL;
      }

      if (client == NULL)
      {
         client = calloc(1, sizeof(client_context_t));
         if (client == NULL)
         {
            log_printf(LOG_ERROR, "client_udp_setup:"
               " Memory allocation failed (%u bytes)",
               (unsigned int)sizeof(client_context_t));

            buf_cleanup(&packet.buf);
            return;
         }

         client->id = ++client_id;
         client->fon.tcp.sfd = client->fon.udp.sfd =
         client->box.tcp.sfd = client->box.udp.sfd = -1;

         client->contact_id = malloc(contact_id_l + 1);
         if (client->contact_id == NULL)
         {
            log_printf(LOG_ERROR, "client_udp_setup:"
               " Memory allocation failed (%d bytes)",
               contact_id_l + 1);

            buf_cleanup(&packet.buf);
            return;
         }

         memcpy(client->contact_id, packet.buf.p + contact_id_i, contact_id_l);
         client->contact_id[contact_id_l] = '\0';
         client->contact_id_l = contact_id_l;

         client->next = client_list;
         client_list = client;
      }
      else if (!client->connected)
      {
         /* disconnecting, ignore packet */
         buf_cleanup(&packet.buf);
         return;
      }
   }
   else {
      if (client == NULL)
      {
         log_printf(LOG_VERBOSE, "Packet from %.*s:%.*s/udp ignored,"
            " contact '%.*s' not found",
            peer.addr_l, peer.addr, peer.port_l, peer.port,
            contact_id_l, packet.buf.p + contact_id_i);

         buf_cleanup(&packet.buf);
         return;
      }

      if (!client->connected)
      {
         /* disconnecting, ignore packet */
         buf_cleanup(&packet.buf);
         return;
      }
   }

   if (client->fon.udp.sfd != -1)
   {
      log_printf(LOG_VERBOSE, "Packet from %.*s:%.*s/udp ignored,"
         " contact '%.*s' already connected",
         peer.addr_l, peer.addr, peer.port_l, peer.port,
         contact_id_l, packet.buf.p + contact_id_i);

      buf_cleanup(&packet.buf);
      return;
   }

   assert(client->box.udp.sfd == -1);

   client->fon.udp.peer = peer;
   client->fon.udp.local = local;
   if (   udp_connect(&client->fon.udp.sfd,
               client->fon.udp.peer.addr, client->fon.udp.peer.addr_l,
               client->fon.udp.peer.port, client->fon.udp.peer.port_l,
               client->fon.udp.local.addr, client->fon.udp.local.addr_l,
               client->fon.udp.local.port, client->fon.udp.local.port_l)
       && sfd_register(client->fon.udp.sfd, client, client_cleanup))
   {
      client->box.udp.peer = options.box;
      if (   udp_connect(&client->box.udp.sfd,
                  client->box.udp.peer.addr, client->box.udp.peer.addr_l,
                  client->box.udp.peer.port, client->box.udp.peer.port_l,
                  NULL, 0, NULL, 0)
          && sfd_local_addr(client->box.udp.sfd,
                  client->box.udp.local.addr, &client->box.udp.local.addr_l,
                  client->box.udp.local.port, &client->box.udp.local.port_l)
          && sfd_register(client->box.udp.sfd, client, client_cleanup))
      {
         if (!client->connected)
         {
            client->connected = 1;

            if (options.log_level > LOG_DETAIL)
            {
               log_printf(LOG_VERBOSE, "[%u] Connect %.*s:%.*s/udp,"
                  " contact '%.*s'",
                  client->id,
                  client->fon.udp.peer.addr_l, client->fon.udp.peer.addr,
                  client->fon.udp.peer.port_l, client->fon.udp.peer.port,
                  client->contact_id_l, client->contact_id);
            }
            else {
               log_printf(LOG_DETAIL, "[%u] Connect %.*s:%.*s/udp",
                  client->id,
                  client->fon.udp.peer.addr_l, client->fon.udp.peer.addr,
                  client->fon.udp.peer.port_l, client->fon.udp.peer.port);
            }
         }

         client->fon.udp.packet = packet;
         client_packet(client, &client->fon.udp, &client->box.udp);
         return;
      }

      log_printf(LOG_VERBOSE,
         "[%u] Box connection to %.*s:%.*s/udp failed",
         client->id,
         client->box.udp.peer.addr_l, client->box.udp.peer.addr,
         client->box.udp.peer.port_l, client->box.udp.peer.port);
   }

   log_printf(LOG_DETAIL, "[%u] Client UDP initialization failed"
      " - disconnecting", client->id);
   buf_cleanup(&packet.buf);
   client_disconnect(client);
}
