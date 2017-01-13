#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libwebsockets.h>


static int callback_http(struct lws *wsi,
                         enum lws_callback_reasons reason, void *user,
                         void *in, size_t len)
{
	switch (reason) {
	    case LWS_CALLBACK_ESTABLISHED:
	    	break;
		/**< (VH) after the server completes a handshake with an incoming
		 * client.  If you built the library with ssl support, in is a
		 * pointer to the ssl struct associated with the connection or NULL.*/
	    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	    	break;
		/**< the request client connection has been unable to complete a
		 * handshake with the remote server.  If in is non-NULL, you can
		 * find an error string of length len where it points to
		 *
		 * Diagnostic strings that may be returned include
		 *
		 *     	"getaddrinfo (ipv6) failed"
		 *     	"unknown address family"
		 *     	"getaddrinfo (ipv4) failed"
		 *     	"set socket opts failed"
		 *     	"insert wsi failed"
		 *     	"lws_ssl_client_connect1 failed"
		 *     	"lws_ssl_client_connect2 failed"
		 *     	"Peer hung up"
		 *     	"read failed"
		 *     	"HS: URI missing"
		 *     	"HS: Redirect code but no Location"
		 *     	"HS: URI did not parse"
		 *     	"HS: Redirect failed"
		 *     	"HS: Server did not return 200"
		 *     	"HS: OOM"
		 *     	"HS: disallowed by client filter"
		 *     	"HS: disallowed at ESTABLISHED"
		 *     	"HS: ACCEPT missing"
		 *     	"HS: ws upgrade response not 101"
		 *     	"HS: UPGRADE missing"
		 *     	"HS: Upgrade to something other than websocket"
		 *     	"HS: CONNECTION missing"
		 *     	"HS: UPGRADE malformed"
		 *     	"HS: PROTOCOL malformed"
		 *     	"HS: Cannot match protocol"
		 *     	"HS: EXT: list too big"
		 *     	"HS: EXT: failed setting defaults"
		 *     	"HS: EXT: failed parsing defaults"
		 *     	"HS: EXT: failed parsing options"
		 *     	"HS: EXT: Rejects server options"
		 *     	"HS: EXT: unknown ext"
		 *     	"HS: Accept hash wrong"
		 *     	"HS: Rejected by filter cb"
		 *     	"HS: OOM"
		 *     	"HS: SO_SNDBUF failed"
		 *     	"HS: Rejected at CLIENT_ESTABLISHED"
		 */
	    case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
	    	break;
		/**< this is the last chance for the client user code to examine the
		 * http headers and decide to reject the connection.  If the
		 * content in the headers is interesting to the
		 * client (url, etc) it needs to copy it out at
		 * this point since it will be destroyed before
		 * the CLIENT_ESTABLISHED call */
	    case LWS_CALLBACK_CLIENT_ESTABLISHED:
	    	break;
		/**< after your client connection completed
		 * a handshake with the remote server */
	    case LWS_CALLBACK_CLOSED:
	    	break;
		/**< when the websocket session ends */
	    case LWS_CALLBACK_CLOSED_HTTP:
	    	break;
		/**< when a HTTP (non-websocket) session ends */
	    case LWS_CALLBACK_RECEIVE:
	    	break;
		/**< data has appeared for this server endpoint from a
		 * remote client, it can be found at *in and is
		 * len bytes long */
	    case LWS_CALLBACK_RECEIVE_PONG:
	    	break;
		/**< servers receive PONG packets with this callback reason */
	    case LWS_CALLBACK_CLIENT_RECEIVE:
	    	break;
		/**< data has appeared from the server for the client connection, it
		 * can be found at *in and is len bytes long */
	    case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
	    	break;
		/**< clients receive PONG packets with this callback reason */
	    case LWS_CALLBACK_CLIENT_WRITEABLE:
	    	break;
		/**<  If you call lws_callback_on_writable() on a connection, you will
		 * get one of these callbacks coming when the connection socket
		 * is able to accept another write packet without blocking.
		 * If it already was able to take another packet without blocking,
		 * you'll get this callback at the next call to the service loop
		 * function.  Notice that CLIENTs get LWS_CALLBACK_CLIENT_WRITEABLE
		 * and servers get LWS_CALLBACK_SERVER_WRITEABLE. */
	    case LWS_CALLBACK_SERVER_WRITEABLE:
	    	break;
		/**< See LWS_CALLBACK_CLIENT_WRITEABLE */
	    case LWS_CALLBACK_HTTP:
	    {
	        void *universal_response = "Hello, World! This is libwebsocket test !!";
	        lws_write(wsi, universal_response, strlen(universal_response), LWS_WRITE_HTTP);
	        printf("[LWS_CALLBACK_HTTP]: exit");
	        break;
	    }
		/**< an http request has come from a client that is not
		 * asking to upgrade the connection to a websocket
		 * one.  This is a chance to serve http content,
		 * for example, to send a script to the client
		 * which will then open the websockets connection.
		 * in points to the URI path requested and
		 * lws_serve_http_file() makes it very
		 * simple to send back a file to the client.
		 * Normally after sending the file you are done
		 * with the http connection, since the rest of the
		 * activity will come by websockets from the script
		 * that was delivered by http, so you will want to
		 * return 1; to close and free up the connection. */
	    case LWS_CALLBACK_HTTP_BODY:
	    	break;
		/**< the next len bytes data from the http
		 * request body HTTP connection is now available in in. */
	    case LWS_CALLBACK_HTTP_BODY_COMPLETION:
	    	break;
		/**< the expected amount of http request body has been delivered */
	    case LWS_CALLBACK_HTTP_FILE_COMPLETION:
	    	break;
		/**< a file requested to be sent down http link has completed. */
	    case LWS_CALLBACK_HTTP_WRITEABLE:
	    	break;
		/**< you can write more down the http protocol link now. */
	    case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
	    	break;
		/**< called when a client connects to
		 * the server at network level; the connection is accepted but then
		 * passed to this callback to decide whether to hang up immediately
		 * or not, based on the client IP.  in contains the connection
		 * socket's descriptor. Since the client connection information is
		 * not available yet, wsi still pointing to the main server socket.
		 * Return non-zero to terminate the connection before sending or
		 * receiving anything. Because this happens immediately after the
		 * network connection from the client, there's no websocket protocol
		 * selected yet so this callback is issued only to protocol 0. */
	    case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
	    	break;
		/**< called when the request has
		 * been received and parsed from the client, but the response is
		 * not sent yet.  Return non-zero to disallow the connection.
		 * user is a pointer to the connection user space allocation,
		 * in is the URI, eg, "/"
		 * In your handler you can use the public APIs
		 * lws_hdr_total_length() / lws_hdr_copy() to access all of the
		 * headers using the header enums lws_token_indexes from
		 * libwebsockets.h to check for and read the supported header
		 * presence and content before deciding to allow the http
		 * connection to proceed or to kill the connection. */
	    case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
	    	break;
		/**< A new client just had
		 * been connected, accepted, and instantiated into the pool. This
		 * callback allows setting any relevant property to it. Because this
		 * happens immediately after the instantiation of a new client,
		 * there's no websocket protocol selected yet so this callback is
		 * issued only to protocol 0. Only wsi is defined, pointing to the
		 * new client, and the return value is ignored. */
	    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
	    	break;
		/**< called when the handshake has
		 * been received and parsed from the client, but the response is
		 * not sent yet.  Return non-zero to disallow the connection.
		 * user is a pointer to the connection user space allocation,
		 * in is the requested protocol name
		 * In your handler you can use the public APIs
		 * lws_hdr_total_length() / lws_hdr_copy() to access all of the
		 * headers using the header enums lws_token_indexes from
		 * libwebsockets.h to check for and read the supported header
		 * presence and content before deciding to allow the handshake
		 * to proceed or to kill the connection. */
	    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
	    	break;
		/**< if configured for
		 * including OpenSSL support, this callback allows your user code
		 * to perform extra SSL_CTX_load_verify_locations() or similar
		 * calls to direct OpenSSL where to find certificates the client
		 * can use to confirm the remote server identity.  user is the
		 * OpenSSL SSL_CTX* */
	    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
	    	break;
		/**< if configured for
		 * including OpenSSL support, this callback allows your user code
		 * to load extra certifcates into the server which allow it to
		 * verify the validity of certificates returned by clients.  user
		 * is the server's OpenSSL SSL_CTX* */
	    case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
	    	break;
		/**< if the libwebsockets vhost was created with the option
		 * LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT, then this
		 * callback is generated during OpenSSL verification of the cert
		 * sent from the client.  It is sent to protocol[0] callback as
		 * no protocol has been negotiated on the connection yet.
		 * Notice that the libwebsockets context and wsi are both NULL
		 * during this callback.  See
		 *  http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
		 * to understand more detail about the OpenSSL callback that
		 * generates this libwebsockets callback and the meanings of the
		 * arguments passed.  In this callback, user is the x509_ctx,
		 * in is the ssl pointer and len is preverify_ok
		 * Notice that this callback maintains libwebsocket return
		 * conventions, return 0 to mean the cert is OK or 1 to fail it.
		 * This also means that if you don't handle this callback then
		 * the default callback action of returning 0 allows the client
		 * certificates. */
	    case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	    	break;
		/**< this callback happens
		 * when a client handshake is being compiled.  user is NULL,
		 * in is a char **, it's pointing to a char * which holds the
		 * next location in the header buffer where you can add
		 * headers, and len is the remaining space in the header buffer,
		 * which is typically some hundreds of bytes.  So, to add a canned
		 * cookie, your handler code might look similar to:
		 *
		 *	char **p = (char **)in;
		 *
		 *	if (len < 100)
		 *		return 1;
		 *
		 *	*p += sprintf(*p, "Cookie: a=b\x0d\x0a");
		 *
		 *	return 0;
		 *
		 * Notice if you add anything, you just have to take care about
		 * the CRLF on the line you added.  Obviously this callback is
		 * optional, if you don't handle it everything is fine.
		 *
		 * Notice the callback is coming to protocols[0] all the time,
		 * because there is no specific protocol negotiated yet. */
	    case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY:
	    	break;
		/**< When the server handshake code
		 * sees that it does support a requested extension, before
		 * accepting the extension by additing to the list sent back to
		 * the client it gives this callback just to check that it's okay
		 * to use that extension.  It calls back to the requested protocol
		 * and with in being the extension name, len is 0 and user is
		 * valid.  Note though at this time the ESTABLISHED callback hasn't
		 * happened yet so if you initialize user content there, user
		 * content during this callback might not be useful for anything.
		 * Notice this callback comes to protocols[0]. */
	    case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
	    	break;
		/**< When a client
		 * connection is being prepared to start a handshake to a server,
		 * each supported extension is checked with protocols[0] callback
		 * with this reason, giving the user code a chance to suppress the
		 * claim to support that extension by returning non-zero.  If
		 * unhandled, by default 0 will be returned and the extension
		 * support included in the header to the server.  Notice this
		 * callback comes to protocols[0]. */
	    case LWS_CALLBACK_PROTOCOL_INIT:
	    	break;
		/**< One-time call per protocol, per-vhost using it, so it can
		 * do initial setup / allocations etc */
	    case LWS_CALLBACK_PROTOCOL_DESTROY:
	    	break;
		/**< One-time call per protocol, per-vhost using it, indicating
		 * this protocol won't get used at all after this callback, the
		 * vhost is getting destroyed.  Take the opportunity to
		 * deallocate everything that was allocated by the protocol. */
	    case LWS_CALLBACK_WSI_CREATE:
	    	break;
		/**< outermost (earliest) wsi create notification to protocols[0] */
	    case LWS_CALLBACK_WSI_DESTROY:
	    	break;
		/**< outermost (latest) wsi destroy notification to protocols[0] */
	    case LWS_CALLBACK_GET_THREAD_ID:
	    	break;
		/**< lws can accept callback when writable requests from other
		 * threads, if you implement this callback and return an opaque
		 * current thread ID integer. */

		/* external poll() management support */
	    case LWS_CALLBACK_ADD_POLL_FD:
	    	break;
		/**< lws normally deals with its poll() or other event loop
		 * internally, but in the case you are integrating with another
		 * server you will need to have lws sockets share a
		 * polling array with the other server.  This and the other
		 * POLL_FD related callbacks let you put your specialized
		 * poll array interface code in the callback for protocol 0, the
		 * first protocol you support, usually the HTTP protocol in the
		 * serving case.
		 * This callback happens when a socket needs to be
		 * added to the polling loop: in points to a struct
		 * lws_pollargs; the fd member of the struct is the file
		 * descriptor, and events contains the active events
		 *
		 * If you are using the internal lws polling / event loop
		 * you can just ignore these callbacks. */
	    case LWS_CALLBACK_DEL_POLL_FD:
	    	break;
		/**< This callback happens when a socket descriptor
		 * needs to be removed from an external polling array.  in is
		 * again the struct lws_pollargs containing the fd member
		 * to be removed.  If you are using the internal polling
		 * loop, you can just ignore it. */
	    case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
	    	break;
		/**< This callback happens when lws wants to modify the events for
		 * a connection.
		 * in is the struct lws_pollargs with the fd to change.
		 * The new event mask is in events member and the old mask is in
		 * the prev_events member.
		 * If you are using the internal polling loop, you can just ignore
		 * it. */
	    case LWS_CALLBACK_LOCK_POLL:
	    	break;
		/**< These allow the external poll changes driven
		 * by lws to participate in an external thread locking
		 * scheme around the changes, so the whole thing is threadsafe.
		 * These are called around three activities in the library,
		 *	- inserting a new wsi in the wsi / fd table (len=1)
		 *	- deleting a wsi from the wsi / fd table (len=1)
		 *	- changing a wsi's POLLIN/OUT state (len=0)
		 * Locking and unlocking external synchronization objects when
		 * len == 1 allows external threads to be synchronized against
		 * wsi lifecycle changes if it acquires the same lock for the
		 * duration of wsi dereference from the other thread context. */
	    case LWS_CALLBACK_UNLOCK_POLL:
	    	break;
		/**< See LWS_CALLBACK_LOCK_POLL, ignore if using lws internal poll */

	    case LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY:
	    	break;
		/**< if configured for including OpenSSL support but no private key
		 * file has been specified (ssl_private_key_filepath is NULL), this is
		 * called to allow the user to set the private key directly via
		 * libopenssl and perform further operations if required; this might be
		 * useful in situations where the private key is not directly accessible
		 * by the OS, for example if it is stored on a smartcard.
		 * user is the server's OpenSSL SSL_CTX* */
	    case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
	    	break;
		/**< The peer has sent an unsolicited Close WS packet.  in and
		 * len are the optional close code (first 2 bytes, network
		 * order) and the optional additional information which is not
		 * defined in the standard, and may be a string or non-human- readable data.
		 * If you return 0 lws will echo the close and then close the
		 * connection.  If you return nonzero lws will just close the
		 * connection. */

	    case LWS_CALLBACK_WS_EXT_DEFAULTS:
	    	break;
		/**<  */

	    case LWS_CALLBACK_CGI:
	    	break;
		/**<  */
	    case LWS_CALLBACK_CGI_TERMINATED:
	    	break;
		/**<  */
	    case LWS_CALLBACK_CGI_STDIN_DATA:
	    	break;
		/**<  */
	    case LWS_CALLBACK_CGI_STDIN_COMPLETED:
	    	break;
		/**<  */
	    case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
	    	break;
		/**<  */
	    case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
	    	break;
		/**<  */
	    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	    	break;
		/**<  */
	    case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	    	break;
		/**<  */
	    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
	    	break;
		/**<  */
	    case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
	    	break;
		/**<  */
	    case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
	    	break;
		/**<  */
	    case LWS_CALLBACK_CHECK_ACCESS_RIGHTS:
	    	break;
		/**<  */
	    case LWS_CALLBACK_PROCESS_HTML:
	    	break;
		/**<  */
	    case LWS_CALLBACK_ADD_HEADERS:
	    	break;
		/**<  */
	    case LWS_CALLBACK_SESSION_INFO:
	    	break;
		/**<  */

	    case LWS_CALLBACK_GS_EVENT:
	    	break;
		/**<  */
	    case LWS_CALLBACK_HTTP_PMO:
	    	break;
		/**< per-mount options for this connection, called before
		 * the normal LWS_CALLBACK_HTTP when the mount has per-mount
		 * options
		 */
	    case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
	    	break;
		/**< when doing an HTTP type client connection, you can call
		 * lws_client_http_body_pending(wsi, 1) from
		 * LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER to get these callbacks
		 * sending the HTTP headers.
		 *
		 * From this callback, when you have sent everything, you should let
		 * lws know by calling lws_client_http_body_pending(wsi, 0)
		 */

		/****** add new things just above ---^ ******/

	    case LWS_CALLBACK_USER:
	    	break;
		/**<  user code can use any including / above without fear of clashes */

	    default:
	    	break;
	}

    return 0;
}

/* list of supported protocols and callbacks */

static struct lws_protocols protocols[] = {
    /* first protocol must always be HTTP handler */

    {
        "http-only",    /* name */
        callback_http,  /* callback */
        0               /* per_session_data_size */
    },
    {
        NULL, NULL, 0   /* End of list */
    }

};

int main(void) {

    struct lws_context *context;
    struct lws_context_creation_info info;

    memset(&info, 0, sizeof info);

    info.port = 9090;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    context = lws_create_context(&info);

    if (context == NULL) {
        fprintf(stderr, "libwebsocket init failed\n");
        return -1;
    }

    printf("starting server...\n");

    // infinite loop, the only option to end this serer is
    // by sending SIGTERM. (CTRL+C)
    while (1) {
        lws_service(context, 50);
        // libwebsocket_service will process all waiting events with their
        // callback functions and then wait 50 ms.
        // (this is single threaded webserver and this will keep
        // our server from generating load while there are not
        // requests to process)
    }

    lws_context_destroy(context);

    return 0;
}
