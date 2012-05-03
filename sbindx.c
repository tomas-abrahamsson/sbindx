#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <netdb.h>
#include <assert.h>
#include <poll.h>
#include <errno.h>

static int eval_command(char *);
static char *is_cmd(char *s, char *cmd);
static int cmd_socket(char *arg);
static int cmd_bind(char *arg);
static int cmd_sctp_bindx(char *arg);
static int cmd_listen(char *arg);
static int cmd_recv(char *arg);
static int cmd_sleep(char *arg);
static int cmd_usage(char *arg);
static void hexdump(char *linelead, unsigned char *msg, int msglen);
static char char_or_dot(unsigned char c);
static int getaddrport(int family, char *addrstr0, struct addrinfo **addr_res);
static void print_addr_info(struct addrinfo *addr, char *addrstr);
static int verify_addr_family_indicator(char *arg);
static int parse_addr(char *arg, char *dest, int *addrlen);

static char *progname;
static int s=-1;
static int port=-1;
static char *default_portstr="10499";

int
main(int argc, char **argv)
{
    int i;

    progname=argv[0];

    for (i=1; i < argc; i++)
	if (!eval_command(argv[i]))
	{
	    fprintf(stderr, "Cmd failed. Aborting.\n");
	    return 1;
	}

    printf("All succeeded.\n");
    return 0;
}

static int
eval_command(char *cmd)
{
    char *arg;

    if      ((arg = is_cmd(cmd, "socket:")))     return cmd_socket(arg);
    else if ((arg = is_cmd(cmd, "bind:")))       return cmd_bind(arg);
    else if ((arg = is_cmd(cmd, "sctp_bindx:"))) return cmd_sctp_bindx(arg);
    else if ((arg = is_cmd(cmd, "listen")))      return cmd_listen(arg);
    else if ((arg = is_cmd(cmd, "recv")))        return cmd_recv(arg);
    else if ((arg = is_cmd(cmd, "sleep:")))      return cmd_sleep(arg);
    else if ((arg = is_cmd(cmd, "--help")))      return cmd_usage(arg);
    else if ((arg = is_cmd(cmd, "-h")))          return cmd_usage(arg);
    else if ((arg = is_cmd(cmd, "help")))        return cmd_usage(arg);
    else
    {
	fprintf(stderr, "Invalid cmd: \"%s\"\n", cmd);
	return 0;
    }
}

static char *
is_cmd(char *s, char *cmd)
{
    int l = strlen(cmd);
    if (strncmp(s, cmd, l) == 0)
	return s+l;
    else
	return NULL;
}

static int
cmd_socket(char *arg)
{
    int value;

    if (arg[0] == '6')
    {
	printf("Creating an ipv6 socket...\n");
	if ((s = socket(PF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
	{
	    perror("socket");
	    return 0;
	}
	printf("socket created\n");
    }
    else if (arg[0] == '4')
    {
	printf("Creating an ipv4 socket...\n");
	if ((s = socket(PF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0)
	{
	    perror("socket");
	    return 0;
	}
	printf("socket created\n");
    }
    else
    {
	fprintf(stderr, "Invalid socket arg: \"%s\".\n", arg);
	fprintf(stderr, "Expected 4 | 6.\n");
	return 0;
    }

    value = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0)
    {
	perror("setsockopt");
	return 0;
    }
    printf("reuseaddr set\n\n");
    return 1;
}

static int
getaddrport(int family, char *addrstr0, struct addrinfo **addr_res)
{
    char *slash;
    char *portstr;
    int len=strlen(addrstr0);
    char addrstr[len+1];
    struct addrinfo hints;
    int gai_res;
    char port_as_str[30];

    strcpy(addrstr, addrstr0); /* work on a copy */
    if ((slash = strchr(addrstr, '/')) != NULL)
    {
	portstr = slash+1;
	*slash = '\0';
    }
    else if (port == -1)
    {
	portstr = default_portstr; /* default */
    }
    else if (port != -1)
    {
        sprintf(port_as_str, "%d", port); /* use previous value if not set */
        portstr = port_as_str;
    }


    memset(&hints, '\0', sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = family;
    hints.ai_socktype = SOCK_SEQPACKET;
    gai_res = getaddrinfo(addrstr, portstr, &hints, addr_res);
    if (gai_res == 0 && port == -1)
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)(*addr_res)->ai_addr;
        port = ntohs(addr->sin_port); /* save to default */
    }
    return gai_res;
}

static int
cmd_bind(char *arg)
{
    char *addrstr = arg;
    struct sockaddr_storage sockaddr;
    int addrlen;

    printf("binding...\n");
    if (s == -1)
    {
	fprintf(stderr,
		"Attempted bind command without previous socket command.\n"
		"Aborting.\n");
	return 0;
    }


    if (!verify_addr_family_indicator(addrstr))
    {
        fprintf(stderr, "Invalid bind cmd: \"%s\"\n", arg);
        fprintf(stderr, "Expected: "
                "4:<ipv4addr>[/port] | "
                "6:<ipv6addr>[/port] , "
                "...\n");
        return 0;
    }

    if (!parse_addr(addrstr, (char *)&sockaddr, &addrlen))
        return 0;

    if (bind(s, (struct sockaddr *)&sockaddr, addrlen) < 0)
    {
        perror("bind");
        return 0;
    }
    printf("socket bound\n\n");

    return 1;
}

static int
cmd_sctp_bindx(char *arg)
{
    char *s2;
    char bindx_addrs[10000];
    int addroffs=0;
    int addrcnt=0;
    int done=0;

    printf("sctp_bindx-ing...\n");
    if (s == -1)
    {
	fprintf(stderr,
		"Attempted sctp_bindx command without previous socket command.\n"
		"Aborting.\n");
	return 0;
    }

    s2 = arg;
    while (!done)
    {
        char addrstr[1000];
        memset(addrstr, '\0', 1000);
        char *comma;
        int addrlen;

        if ((comma = strchr(s2, ',')) != NULL)
            strncpy(addrstr, s2, comma-s2);
        else
            strcpy(addrstr, s2);

        /* Will it fit? */
        if (addroffs > (10000 - sizeof(struct sockaddr_in6)))
        {
            fprintf(stderr, "sctp_bindx: address dest overflow!\n");
            return 0;
        }

        if (!verify_addr_family_indicator(addrstr))
        {
            fprintf(stderr, "Invalid sctp_bindx address: \"%s\"\n", arg);
            fprintf(stderr, "Expected: "
                    "4:<ipv4addr>[/port] | "
                    "6:<ipv6addr>[/port] , "
                    "...\n");
            return 0;
        }

        if (!parse_addr(addrstr, bindx_addrs+addroffs, &addrlen))
            return 0;

        addrcnt++;
        addroffs += addrlen;

        if (comma != NULL)
            s2=comma+1;
        else
            done=1;
    }

    printf("Calling sctp_bindx...\n");
    if (sctp_bindx(s, (struct sockaddr *)bindx_addrs, addrcnt,
                   SCTP_BINDX_ADD_ADDR) < 0)
    {
	perror("sctp_bind");
	return 0;
    }
    printf("Calling sctp_bindx...ok, done\n\n");
    return 1;
}

static int
cmd_listen(char *arg)
{
    printf("calling listen()...\n");
    if (listen(s, 5) < 0)
    {
        perror("listen");
        return 0;
    }
    printf("calling listen()...done\n\n");
    return 1;
}

static int
cmd_recv(char *arg)
{
    int done=0;
    struct pollfd pfd;

    printf("receiving...\n");
    while (!done)
    {
        int poll_done=0;
        int recv_res;
        size_t msgmaxlen=8192;
        unsigned char msg[msgmaxlen];
        struct sockaddr_storage from;
        socklen_t fromlen;
        struct sctp_sndrcvinfo sinfo;
        int msgflags;

        while (!poll_done)
        {
            pfd.fd=s;
            pfd.events=POLLRDNORM;
            switch (poll(&pfd, 1, -1))
            {
                case 1:
                    poll_done=1;
                    break;
                case -1:
                    switch (errno)
                    {
                        case EINTR:
                            break;
                        default:
                            perror("poll");
                            return 0;
                    }
                case 0:
                    fprintf(stderr, "poll returned 0 ==> Timeout. How?!\n");
                    return 0;
            }
        }

        fromlen = sizeof(struct sockaddr_storage);
        recv_res = sctp_recvmsg(s, msg, msgmaxlen,
                                (struct sockaddr *)&from, &fromlen,
                                &sinfo, &msgflags);
        if (recv_res < 0)
        {
            perror("sctp_recvmsg");
            return 0;
        }
        else
        {
            int msglen = recv_res;
            char host[100] = {'\0',};
            char serv[100] = {'\0',};

            printf("Got a message: %d bytes!\n", recv_res);
            assert(getnameinfo((struct sockaddr *)&from, fromlen,
                               host, 99, serv, 99,
                               NI_NUMERICHOST | NI_NUMERICSERV) >= 0);
            printf("  from     = %s/%s\n", host, serv);
            printf("  assoc_id = %d\n", sinfo.sinfo_assoc_id);
            printf("  stream   = %d\n", sinfo.sinfo_stream);
            hexdump("  ", msg, msglen);

            if (msglen == 1 && msg[0] == 'q')
            {
                printf("Got msg consisting of only 'q', done.\n\n");
                return 1;
            }
        }
    }
    return 1;
}

static int
cmd_sleep(char *arg)
{
    int nseconds;
    if (sscanf(arg, "%d", &nseconds) == 1)
    {
	printf("sleeping %d seconds...\n", nseconds);
	sleep(nseconds);
	return 1;
    }
    else
    {
	fprintf(stderr, "failed to interpret \"%s\" as an integer.\n", arg);
	return 0;
    }
}

static int
cmd_usage(char *arg)
{
    printf("Usage: %s [command ...]\n", progname);
    printf("Commands:\n");
    printf("  socket:4|6\n");
    printf("  bind:4:ADDR[/PORT]|6:ADDR[/PORT]\n");
    printf("  sctp_bindx:4:ADDR[/PORT]|6:ADDR[/PORT],...\n");
    printf("  listen\n");
    printf("  recv -- receives until it gets a message containing only 'q'\n");
    printf("  sleep:SECONDS\n");
    printf("\n");
    printf("If PORT is omitted, it defaults to previously specified port.\n");
    printf("If PORT never specified, it defaults %s.\n", default_portstr);
    return 1;
}

static void
hexdump(char *linelead, unsigned char *msg, int msglen)
{
            int i, b;

            for (b=0; b < msglen; b += 16)
            {
                printf("%s", linelead);
                for (i=0; i < 16; i++)
                    if (b+i < msglen) printf("%s%02x", (i==0)?"":" ", msg[b+i]);
                    else              printf("%s  ", (i==0)?"":" ");
                printf("   ");
                for (i=0; i < 16; i++)
                    if (b+i < msglen)
                        printf("%c", char_or_dot(msg[b+i]));
                printf("\n");
            }
}

static char
char_or_dot(unsigned char c)
{
    unsigned char uc = (unsigned char)c;
    if (uc < ' ')
        return '.';
    if (uc >= 127)
        return '.';
    return c;
}

static int
verify_addr_family_indicator(char *arg)
{
    if (is_cmd(arg, "4:") != NULL)
        return 1;
    else if (is_cmd(arg, "6:") != NULL)
        return 1;
    else
        return 0;
}

static int
parse_addr(char *arg, char *dest, int *addrlen)
{
    char *addrstr;

    if ((addrstr = is_cmd(arg, "4:")))
    {
	struct addrinfo *addr_res;
	int gai_res = getaddrport(AF_INET, addrstr, &addr_res);

	if (gai_res == 0)
	{
            print_addr_info(addr_res, addrstr);
            memmove(dest, addr_res->ai_addr, addr_res->ai_addrlen);
            *addrlen = addr_res->ai_addrlen;
            freeaddrinfo(addr_res);
            return 1;
	}
	else
	{
	    perror("getaddrinfo");
	    fprintf(stderr, "getaddrinfo failed for \"%s\": %s\n",
		    addrstr, gai_strerror(gai_res));
	    return 0;
	}
    }
    else if ((addrstr = is_cmd(arg, "6:")))
    {
	struct addrinfo *addr_res;
	int gai_res = getaddrport(AF_INET6, addrstr, &addr_res);

	if (gai_res == 0)
	{
            print_addr_info(addr_res, addrstr);
            memmove(dest, addr_res->ai_addr, addr_res->ai_addrlen);
            *addrlen = addr_res->ai_addrlen;
            freeaddrinfo(addr_res);
            return 1;
	}
	else
	{
	    perror("getaddrinfo");
	    fprintf(stderr, "getaddrinfo failed for \"%s\": %s\n",
		    addrstr, gai_strerror(gai_res));
	    return 0;
	}
    }
    else
    {
        /* Internal error if we ever end up here... */
        assert(0);
    }
    return 1;
}

static void
print_addr_info(struct addrinfo *addr_res, char *addrstr)
{
    struct addrinfo *addr;
    int naddrs;
    int i;

    for (naddrs = 0, addr=addr_res; addr != NULL; addr = addr->ai_next)
	naddrs++;

    for (i = 0, addr=addr_res; addr != NULL; addr = addr->ai_next)
    {
	struct sockaddr *saddr = addr->ai_addr;
	char host[100] = {'\0',};
	char serv[100] = {'\0',};
	int gni_res;
	gni_res = getnameinfo(saddr, addr->ai_addrlen,
			      host, 99, serv, 99,
			      NI_NUMERICHOST | NI_NUMERICSERV);
	if (gni_res == 0)
        {
            if (i == 0)
            {
                printf("resolved \"%s\" to %s/%s", addrstr, host, serv);
            }
            else
            {
                if (i == 1)
                    printf("; ignored %d addrs: ", naddrs-1);

                printf("%s%s/%s", (i==1)?"":", ", host, serv);
            }

        }
        else
        {
            fprintf(stderr,
                    "%s\?\?(%s)\n",
                    (i==0)?"":" ",
                    gai_strerror(gni_res));
        }

	i++;
    }
    printf("\n");
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-offsets-alist:'((substatement-open . 0))
 * indent-tabs-mode:nil
 * compile-command:"gcc -Wall -g -o sbindx sbindx.c -lsctp"
 * End:
 *
 * Linux:
 * compile-command:"gcc -Wall -g -o sbindx sbindx.c -lsctp"
 *
 * Solaris/Openindiana:
 * compile-command:"gcc -Wall -g -o sbindx sbindx.c -lsocket -lnsl -lsctp"
 * http://pdconsec.net/blogs/davidr/archive/2011/07/19/solaris-express-static-ips-the-right-way.aspx
 *
 * FreeBSD:
 * compile-command:"gcc -Wall -g -o sbindx sbindx.c"
 */
