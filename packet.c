/* ------------------------------------------------------------------------
   (C) 2018 by Roland Genske <roland@genske.org>

   Workaround for FRITZ!App Fon SIP via VPN

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   2018-02-09 - v0.1
   2018-02-21 - v0.2, functionally complete
   2021-10-18 - v0.4, additional diagnostics when packet not recognized
              - v0.4, ignore keep-alive packets

   ------------------------------------------------------------------------ */

/* ------------------------------------------------------------------------
   dependencies
   ------------------------------------------------------------------------ */

#include "fapfon_proxy.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>


/* ------------------------------------------------------------------------
   protocol buffer
   ------------------------------------------------------------------------ */

#define BUF_RESIZE_INCREMENT 1024

void buf_cleanup(buf_t *buf)
{
   free(buf->p);
   buf->p = NULL;
   buf->allocated = 0;
   buf->used = 0;
}

int buf_resize(buf_t *buf, uint32_t size)
{
   if (size > buf->allocated)
   {
      /* multiple of BUF_RESIZE_INCREMENT >= size */
      uint32_t allocate = (  (size + BUF_RESIZE_INCREMENT - 1)
                           / BUF_RESIZE_INCREMENT) * BUF_RESIZE_INCREMENT;

      if (allocate > 65535)
      {
         log_printf(LOG_ERROR, "buf_resize:"
            " Packet size exceeds 64K (%u bytes)",
            allocate);
         return 0;
      }

      char *p = realloc(buf->p, allocate);
      if (p == NULL)
      {
         log_printf(LOG_ERROR, "buf_resize:"
            " Memory allocation failed (%u bytes)",
            allocate);
         return 0;
      }

      buf->p = p;
      buf->allocated = allocate;
   }

   return 1;
}

static int buf_append(buf_t *buf, const void *add_data, uint32_t add_size)
{
   if (buf_resize(buf, buf->used + add_size))
   {
      memcpy(buf->p + buf->used, add_data, add_size);
      buf->used += add_size;
      return 1;
   }

   return 0;
}


/* ------------------------------------------------------------------------
   packet assembly
   ------------------------------------------------------------------------ */

#define SIP_MAX_LEN (6 * 1024)

static void reset_packet(packet_t *packet)
{
   packet->header.len = packet->data.len = 0;
   packet->method.len = 0;
   packet->current_line.offs = packet->current_line.len = 0;
   packet->via_line.offs = packet->via_line.len = 0;
   packet->via.offs = packet->via.len = 0;
   packet->from.offs = packet->from.len = 0;
   packet->to.offs = packet->to.len = 0;
   packet->contact.offs = packet->contact.len = 0;
   packet->content_length.offs = packet->content_length.len = 0;
}

int next_packet(packet_t *packet, const void *next_data, uint32_t next_size)
{
   static const char log_prefix[] = "Failed to process packet";

   if (packet->status == PACKET_READY)
   {
      /* previous packet processed, start new packet */

      uint32_t packet_l = packet->header.len + packet->data.len;
      assert(packet_l <= packet->buf.used);
      if (packet_l < packet->buf.used)
         memmove(packet->buf.p, packet->buf.p + packet_l,
                 packet->buf.used - packet_l);

      packet->buf.used -= packet_l;
      reset_packet(packet);
   }

   packet->status = PACKET_INCOMPLETE;

   if (packet->buf.used + next_size > 2 * SIP_MAX_LEN)
   {
      log_printf(LOG_VERBOSE, "%s: Packet too large (%u bytes)",
         log_prefix, packet->buf.used + next_size);
      packet->status = PACKET_ERROR;
      return 0;
   }

   if (!buf_append(&packet->buf, next_data, next_size))
   {
      log_printf(LOG_VERBOSE, "%s", log_prefix);
      packet->status = PACKET_ERROR;
      return 0;
   }

   if (packet->header.len == 0)
   {
      /* header, get next line */

      uint32_t buf_i = packet->current_line.offs + packet->current_line.len;
      for (;;)
      {
         while (   buf_i < packet->buf.used
                && packet->buf.p[buf_i] != '\r'
                && packet->buf.p[buf_i] != '\n')
         {
            buf_i++;
            packet->current_line.len++;
         }

         if (packet->current_line.len > SIP_MAX_LEN)
         {
            log_printf(LOG_VERBOSE, "%s: Header line too long (%u bytes)",
               log_prefix, packet->current_line.len);
            log_dump(LOG_VERBOSE, packet->buf.p, buf_i);
            packet->status = PACKET_ERROR;
            return 0;
         }

         if (buf_i == packet->buf.used)
            break;

         if (packet->buf.p[buf_i] == '\r')
         {
            if (++buf_i == packet->buf.used)
               break;

            if (packet->buf.p[buf_i] != '\n')
            {
               log_printf(LOG_VERBOSE, "%s: Header line not terminated",
                  log_prefix);
               log_dump(LOG_VERBOSE, packet->buf.p, buf_i);
               packet->status = PACKET_ERROR;
               return 0;
            }
         }
         buf_i++;

         if (packet->current_line.len == 0)
         {
            /* header complete */

            uint32_t packet_l;
            int ok = 1;

            if (packet->current_line.offs == 0)
            {
               /* ignore keep-alive packet */

               if (buf_i < packet->buf.used)
                  memmove(packet->buf.p, packet->buf.p + buf_i,
                          packet->buf.used - buf_i);

               packet->buf.used -= buf_i;
               reset_packet(packet);

               buf_i = 0;
               continue;
            }

            if (packet->via.offs == 0)
            {
               log_printf(LOG_VERBOSE, "%s: No Via header", log_prefix);
               ok = 0;
            }
            if (packet->from.offs == 0)
            {
               log_printf(LOG_VERBOSE, "%s: No From header", log_prefix);
               ok = 0;
            }
            if (packet->to.offs == 0)
            {
               log_printf(LOG_VERBOSE, "%s: No To header", log_prefix);
               ok = 0;
            }
            if (packet->content_length.offs == 0)
            {
               log_printf(LOG_VERBOSE, "%s: No Content-Length header",
                  log_prefix);
               ok = 0;
            }

            if (!ok)
            {
               log_dump(LOG_VERBOSE, packet->buf.p, buf_i);
               packet->status = PACKET_ERROR;
               return 0;
            }

            packet->header.len = buf_i;
            packet_l = packet->header.len + packet->data.len;
            if (packet->buf.used >= packet_l)
               packet->status = PACKET_READY;

            return 1;
         }

         /* line complete */

         if (packet->current_line.offs == 0)
         {
            /* first line, must be SIP method or status */

            int ok = packet->current_line.len > 8;
            assert(packet->method.len == 0);

            /* SIP status line starts with "SIP/2.0 " */
            if (ok && strncasecmp(packet->buf.p, "SIP/2.0 ", 8))
            {
               /* SIP method line ends with " SIP/2.0" */
               if (strncasecmp(packet->buf.p + packet->current_line.len - 8,
                               " SIP/2.0", 8))
               {
                  ok = 0;
               }
               else {
                  /* get method */

                  while (packet->method.len < packet->current_line.len)
                  {
                     if (   (   packet->buf.p[packet->method.len] < 'A'
                             || packet->buf.p[packet->method.len] > 'Z')
                         && (   packet->buf.p[packet->method.len] < 'a'
                             || packet->buf.p[packet->method.len] > 'z'))
                     {
                        break;
                     }

                     packet->method.len++;
                  }

                  if (   packet->method.len == 0
                      || packet->method.len == packet->current_line.len
                      || packet->buf.p[packet->method.len] != ' ')
                  {
                     ok = 0;
                  }
               }
            }

            if (!ok)
            {
               log_printf(LOG_VERBOSE, "%s: "
                  "SIP method or status not recognized",
                  log_prefix);
               log_dump(LOG_VERBOSE, packet->buf.p, buf_i);
               packet->status = PACKET_ERROR;
               return 0;
            }
         }
         else {
            /* header line, get line tag */

            const char *p = packet->buf.p + packet->current_line.offs;
            uint32_t l = 0, i;
            int ok;

            while (l < packet->current_line.len)
            {
               if (   (p[l] < 'A' || p[l] > 'Z')
                   && (p[l] < 'a' || p[l] > 'z')
                   && p[l] != '-')
               {
                  break;
               }

               l++;
            }

            if (l == 0 || l == packet->current_line.len || p[l] != ':')
               ok = 0;
            else {
               i = l + 1;
               while (i < packet->current_line.len && p[i] == ' ')
                  i++;

               ok = i < packet->current_line.len;
            }

            if (!ok)
            {
               log_printf(LOG_VERBOSE, "%s: SIP header not recognized",
                  log_prefix);
               log_dump(LOG_VERBOSE, packet->buf.p, buf_i);
               packet->status = PACKET_ERROR;
               return 0;
            }

            while (ok)
            {
               if (l == 3 && !strncasecmp("Via", p, l))
               {
                  if (packet->via.offs)
                  {  
                     ok = 0;
                     break;
                  }

                  assert(packet->via_line.offs == 0);
                  packet->via_line.offs = packet->current_line.offs;
                  packet->via_line.len = packet->current_line.len;

                  packet->via.offs = packet->current_line.offs + i;
                  packet->via.len = packet->current_line.len - i;
               }
               else if (l == 4 && !strncasecmp("From", p, l))
               {
                  if (packet->from.offs)
                  {  
                     ok = 0;
                     break;
                  }

                  packet->from.offs = packet->current_line.offs + i;
                  packet->from.len = packet->current_line.len - i;
               }
               else if (l == 2 && !strncasecmp("To", p, l))
               {
                  if (packet->to.offs)
                  {  
                     ok = 0;
                     break;
                  }

                  packet->to.offs = packet->current_line.offs + i;
                  packet->to.len = packet->current_line.len - i;
               }
               else if (l == 7 && !strncasecmp("Contact", p, l))
               {
                  if (packet->contact.offs)
                  {  
                     /* multiple Contact header lines may occur,
                        the first one is used */
                     break;
                  }

                  packet->contact.offs = packet->current_line.offs + i;
                  packet->contact.len = packet->current_line.len - i;
               }
               else if (l == 14 && !strncasecmp("Content-Length", p, l))
               {
                  if (packet->content_length.offs)
                  {  
                     ok = 0;
                     break;
                  }

                  assert(packet->data.len == 0);

                  packet->content_length.offs = packet->current_line.offs + l+1;
                  packet->content_length.len = packet->current_line.len - l-1;

                  /* get content length */

                  if (i == packet->current_line.len || p[i] < '0' || p[i] > '9')
                     ok = 0;
                  else {
                     while (   i < packet->current_line.len
                            && p[i] >= '0' && p[i] <= '9')
                     {
                        packet->data.len = packet->data.len * 10 + p[i++] - '0';
                     }

                     ok = i == packet->current_line.len;
                  }

                  if (!ok)
                  {
                     log_printf(LOG_VERBOSE, "%s: "
                        "Content-Length header not recognized",
                        log_prefix);
                     log_dump(LOG_VERBOSE, packet->buf.p, buf_i);
                     packet->status = PACKET_ERROR;
                     return 0;
                  }
               }

               break;
            }

            if (!ok)
            {
               log_printf(LOG_VERBOSE, "%s: Duplicate %.*s header",
                  log_prefix, l, p);
               log_dump(LOG_VERBOSE, packet->buf.p, buf_i);
               packet->status = PACKET_ERROR;
               return 0;
            }
         }

         packet->current_line.offs = buf_i;
         packet->current_line.len = 0;
      }
   }
   else {
      /* data */

      uint32_t packet_l = packet->header.len + packet->data.len;
      if (packet->buf.used >= packet_l)
         packet->status = PACKET_READY;
   }

   return 1;
}


/* ------------------------------------------------------------------------
   protocol data
   ------------------------------------------------------------------------ */

static void loc_adjust(loc_t *loc, int i, int l, int l_diff)
{
   if (i < loc->offs)
   {
      assert(i + l <= loc->offs);
      loc->offs += l_diff;
   }
   else if (i < loc->offs + loc->len)
   {
      assert(i + l <= loc->offs + loc->len);
      loc->len += l_diff;
   }
}

int data_modify(packet_t *packet, data_t *data,
                int replace_i, int replace_l,
                const char *with, int with_l)
{
   int is_data, i;
   if (data->p == packet->buf.p)
   {
      /* replace in header */
      assert(replace_i + replace_l <= packet->header.len);
      assert(replace_i + with_l <= packet->header.len);
      i = replace_i;
      is_data = 0;
   }
   else {
      /* replace in data */
      assert(data->p == packet->buf.p + packet->header.len);
      assert(replace_i + replace_l <= packet->data.len);
      assert(replace_i + with_l <= packet->data.len);
      i = replace_i + packet->header.len;
      is_data = 1;
   }

   if (with_l != replace_l || memcmp(data->p + i, with, with_l))
   {
      int l_diff = with_l - replace_l;
      if (l_diff)
      {
         if (!buf_resize(&packet->buf, packet->buf.used + l_diff))
            return 0;

         memmove(packet->buf.p + i + with_l,
                 packet->buf.p + i + replace_l,
                 packet->buf.used - i - replace_l);

         packet->buf.used += l_diff;
         if (is_data)
         {
            packet->data.len += l_diff;
            data->p = packet->buf.p + packet->header.len;
         }
         else {
            packet->header.len += l_diff;
            data->p = packet->buf.p;

            loc_adjust(&packet->via_line, i, replace_l, l_diff);
            loc_adjust(&packet->via, i, replace_l, l_diff);
            loc_adjust(&packet->from, i, replace_l, l_diff);
            loc_adjust(&packet->to, i, replace_l, l_diff);
            loc_adjust(&packet->contact, i, replace_l, l_diff);
            loc_adjust(&packet->content_length, i, replace_l, l_diff);
         }

         if (replace_i + replace_l <= data->i)
            data->i += l_diff;
         data->l += l_diff;
      }

      memcpy(packet->buf.p + i, with, with_l);
   }

   return 1;
}

int addr_find(const data_t *data, int *addr_l_p)
{
   int i = data->i;
   while (i < data->l)
   {
      int addr_l;
      if (is_addr(data->p + i, data->l - i, &addr_l))
      {
         *addr_l_p = addr_l;
         return i;
      }

      i += addr_l;
   }

   return -1;
}

int port_find(const data_t *data, int addr_i, int addr_l, int *port_l_p)
{
   int i = addr_i + addr_l;
   if (i < data->l && data->p[i] == ':')
   {
      if (++i < data->l)
      {
         int port_l;
         if (is_port(data->p + i, data->l - i, &port_l))
         {
            *port_l_p = port_l;
            return i;
         }
      }
   }

   return -1;
}
