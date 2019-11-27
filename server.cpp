#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <time.h>

struct header {
    char magic1;
    char magic2;
    char opcode;
    char payload_len;

    uint32_t token;
    uint32_t msg_id;
};

const int h_size = sizeof(struct header);

// These are the constants indicating the states.
// CAUTION: These states have nothing to do with the states on the client.
#define STATE_OFFLINE 0
#define STATE_ONLINE 1
#define STATE_MSG_FORWARD 2
// Now you can define other states in a similar fashion.

// These are the events
// CAUTION: These events have nothing to do with the states on the client.
#define EVENT_NET_LOGIN 80
#define EVENT_NET_POST 81
// Now you can define other events from the network...

#define EVENT_NET_INVALID 255

// These are the constants indicating the opcodes.
// CAUTION: These opcodes must agree on both sides.
#define OPCODE_RESET 0x00
#define OPCODE_MUST_LOGIN_FIRST_ERROR 0xF0
#define OPCODE_LOGIN 0x10
// Now you can define other opcodes in a similar fashion...

// This is a data structure that holds important information on a session.
struct session {
    char client_id[32];  // Assume the client ID is less than 32 characters.
    struct sockaddr_in client_addr;  // IP address and port of the client
                                     // for receiving messages from the
                                     // server.
    time_t last_time;  // The last time when the server receives a message
                       // from this client.
    uint32_t token;    // The token of this session.
    int state = 0;         // The state of this session, 0 is "OFFLINE", etc.

    // TODO: You may need to add more information such as the subscription
    // list, password, etc.
};

// TODO: You may need to add more structures to hold global information
// such as all registered clients, the list of all posted messages, etc.
// Initially all sessions are in the OFFLINE state.

int main() {
    int returned;
    int socket_file_descriptor;
    struct sockaddr_in server_address, client_address;
    char send_buffer[1024];
    char recv_buffer[1024];
    int recv_len;
    socklen_t len;

    // You may need to use a std::map to hold all the sessions to find a
    // session given a token. I just use an array just for demonstration.
    // Assume we are dealing with at most 16 clients, and this array of
    // the session structure is essentially our user database.
    struct session session_array[16];

    // Now you need to load all users' information and fill this array.
    // Optionally, you can just hardcode each user.

    // This current_session is a variable temporarily hold the session upon
    // an event.
    struct session *current_session;
    int token;

    socket_file_descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_file_descriptor < 0) {
        printf("socket() error: %s.\n", strerror(errno));
        return -1;
    }

    // The servaddr is the address and port number that the server will
    // keep receiving from.
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(32000);

    bind(socket_file_descriptor, (struct sockaddr *)&server_address, sizeof(server_address));

    // Same as that in the client code.
    struct header *ph_send = (struct header *)send_buffer;
    struct header *ph_recv = (struct header *)recv_buffer;

    while (1) {
        // Note that the program will still block on recvfrom()
        // You may call select() only on this socket file descriptor with
        // a timeout, or set a timeout using the socket options.

        len = sizeof(client_address);
        recv_len =
            recvfrom(socket_file_descriptor,               // socket file descriptor
                     recv_buffer,          // receive buffer
                     sizeof(recv_buffer),  // number of bytes to be received
                     0,
                     (struct sockaddr *)&client_address,  // client address
                     &len);  // length of client address structure

        if (recv_len <= 0) {
            printf("recvfrom() error: %s.\n", strerror(errno));
            return -1;
        }

        // Now we know there is an event from the network
        // TODO: Figure out which event and process it according to the
        // current state of the session referred.

        int token = extract_token_from_the_received_binary_msg(...)
            // This is the current session we are working with.
            struct session *cs = find_the_session_by_token(...) int event =
                parse_the_event_from_the_datagram(...)

                // Record the last time that this session is active.
                current_session->last_time = time();

        if (event == EVENT_LOGIN) {
            // For a login message, the current_session should be NULL and
            // the token is 0. For other messages, they should be valid.

            char *id_password = recv_buffer + h_size;

            char *delimiter = strchr(id_password, '&');
            char *password = delimiter + 1;
            *delimiter = 0;  // Add a null terminator
            // Note that this null terminator can break the user ID
            // and the password without allocating other buffers.
            char *user_id = id_password;

            delimiter = strchr(password, '\n');
            *delimiter = 0;  // Add a null terminator
            // Note that since we did not process it on the client side,
            // and since it is always typed by a user, there must be a
            // trailing new line. We just write a null terminator on this
            // place to terminate the password string.

            // The server need to reply a msg anyway, and this reply msg
            // contains only the header
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->payload_len = 0;
            ph_send->msg_id = 0;

            int login_success = check_id_password(user_id, password);
            if (login_success > 0) {
                // This means the login is successful.

                ph_send->opcode = OPCODE_SUCCESSFUL_LOGIN_ACK;
                ph_send->token = generate_a_random_token();

                cs = find_this_client_in_the_session_array();
                cs->state = ONLINE;
                cs->token = ph_send->token;
                cs->last_time = right_now();
                cs->client_addr = client_address;

            } else {
                ph_send->opcode = OPCODE_FAILED_LOGIN_ACK;
                ph_send->token = 0;
            }

            sendto(socket_file_descriptor, send_buffer, h_size, 0, (struct sockaddr *)&client_address,
                   sizeof(client_address));

        } else if (event == EVENT_NET_POST) {
            // TODO: Check the state of the client that sends this post msg,
            // i.e., check cs->state.

            // Now we assume it is ONLINE, because I do not want to ident
            // the following code in another layer.

            for
                each target session subscribed to this publisher {
                    char *text = recv_buffer + h_size;
                    char *payload = send_buffer + h_size;

                    // This formatting the "<client_a>some_text" in the payload
                    // of the forward msg, and hence, the client does not need
                    // to format it, i.e., the client can just print it out.
                    snprintf(payload, sizeof(send_buffer) - h_size, "<%s>%s",
                             cs->client_id, text);

                    int m = strlen(payload);

                    // "target" is the session structure of the target client.
                    target->state = STATE_MSG_FORWARD;

                    ph_send->magic1 = MAGIC_1;
                    ph_send->magic2 = MAGIC_2;
                    ph_send->opcode = OPCODE_FORWARD;
                    ph_send->payload_len = m;
                    ph_send->msg_id = 0;  // Note that I didn't use msg_id here.

                    sendto(socket_file_descriptor, send_buffer, h_size, 0,
                           (struct sockaddr *)&target->client_addr,
                           sizeof(target->client_addr));
                }

            // TODO: send back the post ack to this publisher.

            // TODO: put the posted text line into a global list.

        } else if (event == ...) {
            // TODO: process other events
        }

        time_t current_time = time();

        // Now you may check the time of clients, i.e., scan all sessions.
        // For each session, if the current time has passed 5 minutes plus
        // the last time of the session, the session expires.
        // TODO: check session liveliness

    }  // This is the end of the while loop

    return 0;
}  // This is the end of main()