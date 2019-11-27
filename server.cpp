#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <time.h>
#include <unordered_map>
#include <vector>
using namespace std;

struct header {
    char magic1;
    char magic2;
    char opcode;
    char payload_len;

    uint32_t token;
    uint32_t message_id;
};

const int header_size = sizeof(struct header);

#define MAGIC_1 'R'
#define MAGIC_2 'S'

#define STATE_OFFLINE 0
#define STATE_ONLINE 1
#define STATE_MSG_FORWARD 2

#define EVENT_NET_LOGIN 80
#define EVENT_NET_POST 81
#define EVENT_NET_LOGOUT 82
#define EVENT_NET_FORWARD_ACK 83
#define EVENT_NET_RETRIEVE 84
#define EVENT_NET_SUBSCRIBE 85
#define EVENT_NET_UNSUBSCRIBE 86
#define EVENT_NET_RESET 87
#define EVENT_NET_INVALID 255

#define OPCODE_RESET 0x00
#define OPCODE_MUST_LOGIN_FIRST_ERROR 0xF0
#define OPCODE_LOGIN 0x10
#define OPCODE_SUCCESSFUL_LOGIN_ACK 0x80
#define OPCODE_FAILED_LOGIN_ACK 0x81
#define OPCODE_SUBSCRIBE 0x20
#define OPCODE_SUCCESSFUL_SUBSCRIBE_ACK 0x90
#define OPCODE_FAILED_SUBSCRIBE_ACK 0x91
#define OPCODE_UNSUBSCRIBE 0x21
#define OPCODE_SUCCESSFUL_UNSUBSCRIBE_ACK 0xA0
#define OPCODE_FAILED_UNSUBSCRIBE_ACK 0xA1
#define OPCODE_POST 0x30
#define OPCODE_POST_ACK 0xB0
#define OPCODE_FORWARD 0xB1
#define OPCODE_FORWARD_ACK 0x31
#define OPCODE_RETRIEVE 0x40
#define OPCODE_RETRIEVE_ACK 0xC0
#define OPCODE_END_RETRIEVE_ACK 0xC1
#define OPCODE_LOGOUT 0x1F
#define OPCODE_LOGOUT_ACK 0x8F

struct session {
    char client_id[32];  // Assume the client ID is less than 32 characters.
    char password[32];
    struct sockaddr_in client_addr;  // IP address and port of the client
                                     // for receiving messages from the
                                     // server.
    time_t last_time;  // The last time when the server receives a message
                       // from this client.
    uint32_t token;    // The token of this session.
    int state =
        STATE_OFFLINE;  // The state of this session, 0 is "OFFLINE", etc.
    // TODO: You may need to add more information such as the subscription
    // list, password, etc.
    vector<uint32_t> subscription_list_tokens;
};

struct message {
    int message_id;
    char *content;
};

vector<message> message_list;
int token;
unordered_map<uint32_t, session> session_map;
session master_sessions[16] = {0};
int returned;
int socket_file_descriptor;
struct sockaddr_in server_address, client_address;
char send_buffer[1024];
char recv_buffer[1024];
struct header *send_buffer_header = (struct header *)send_buffer;
struct header *recv_buffer_header = (struct header *)recv_buffer;
int recv_length;
socklen_t client_address_length;

// TODO: You may need to add more structures to hold global information
// such as all registered clients, the list of all posted messages, etc.
// Initially all sessions are in the OFFLINE state.
void clear_send_buffer() {
    memset(&send_buffer, 0, sizeof(send_buffer));
    send_buffer_header->magic1 = MAGIC_1;
    send_buffer_header->magic2 = MAGIC_2;
}

void clear_recv_buffer() {
    memset(&recv_buffer, 0, sizeof(recv_buffer));
    recv_buffer_header->magic1 = MAGIC_1;
    recv_buffer_header->magic2 = MAGIC_2;
}

session *find_session_by_token(uint32_t token) {
    if (session_map.find(token) != session_map.end()) {
        return &session_map[token];
    } else {
        return NULL;
    }
}

int parse_network_event() {
    switch (recv_buffer_header->opcode) {
        case OPCODE_RESET:
            return EVENT_NET_RESET;
        case OPCODE_LOGIN:
            return EVENT_NET_LOGIN;
        case OPCODE_SUBSCRIBE:
            return EVENT_NET_SUBSCRIBE;
        case OPCODE_UNSUBSCRIBE:
            return EVENT_NET_UNSUBSCRIBE;
        case OPCODE_POST:
            return EVENT_NET_POST;
        case OPCODE_FORWARD_ACK:
            return EVENT_NET_FORWARD_ACK;
        case OPCODE_RETRIEVE:
            return EVENT_NET_RETRIEVE;
        case OPCODE_LOGOUT:
            return EVENT_NET_LOGOUT;
        default:
            return EVENT_NET_INVALID;
    }
}

int identify_sessions(char *user_id, char *password) {
    for (int i = 0; i < 2; i++) {
        if (strcmp(master_sessions[i].client_id, user_id) == 0 &&
            strcmp(master_sessions[i].password, password) == 0) {
            return i;
        }
    }
    return -1;
}
int main() {
    // You may need to use a std::map to hold all the sessions to find a
    // session given a token. I just use an array just for demonstration.
    // Assume we are dealing with at most 16 clients, and this array of
    // the session structure is essentially our user database.

    strcpy(master_sessions[0].client_id, "user1");
    strcpy(master_sessions[1].client_id, "user2");
    strcpy(master_sessions[2].client_id, "user3");
    strcpy(master_sessions[0].password, "password1");
    strcpy(master_sessions[1].password, "password2");
    strcpy(master_sessions[2].password, "password3");

    // This current_session is a variable temporarily hold the session upon
    // an event.
    session *current_session;

    socket_file_descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_file_descriptor < 0) {
        printf("socket() error: %s.\n", strerror(errno));
        return -1;
    }

    // The servaddr is the address and port number that the server will
    // keep receiving from.
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_address.sin_port = htons(32000);

    bind(socket_file_descriptor, (struct sockaddr *)&server_address,
         sizeof(server_address));

    // Same as that in the client code.

    while (1) {
        // Note that the program will still block on recvfrom()
        // You may call select() only on this socket file descriptor with
        // a timeout, or set a timeout using the socket options.
        clear_send_buffer();
        clear_recv_buffer();
        client_address_length = sizeof(client_address);
        recv_length = recvfrom(
            socket_file_descriptor,  // socket file descriptor
            recv_buffer,             // receive buffer
            sizeof(recv_buffer),     // number of bytes to be received
            0,
            (struct sockaddr *)&client_address,  // client address
            &client_address_length);  // length of client address structure

        if (recv_length <= 0) {
            printf("recvfrom() error: %s.\n", strerror(errno));
            return -1;
        }

        // Now we know there is an event from the network
        // TODO: Figure out which event and process it according to the
        // current state of the session referred.

        uint32_t token = recv_buffer_header->token;
        // This is the current session we are working with.
        current_session = find_session_by_token(token);
        // if (current_session == NULL) {
        //     printf("Invalid token received!\n");
        //     continue;
        // }
        int event = parse_network_event();

        // Record the last time that this session is active.
        current_session->last_time = time(NULL);

        if (event == EVENT_NET_LOGIN) {
            // For a login message, the current_session should be NULL and
            // the token is 0. For other messages, they should be valid.

            char *id_password = recv_buffer + header_size;

            char *ampersand = strchr(id_password, '&');
            char *password = ampersand + 1;
            *ampersand = '\0';  // Add a null terminator
            // Note that this null terminator can break the user ID
            // and the password without allocating other buffers.
            char *user_id = id_password;

            char *newline = strchr(password, '\n');
            *newline = '\0';  // Add a null terminator
            // Note that since we did not process it on the client side,
            // and since it is always typed by a user, there must be a
            // trailing new line. We just write a null terminator on this
            // place to terminate the password string.

            // The server need to reply a msg anyway, and this reply msg
            // contains only the header
            send_buffer_header->payload_len = 0;
            send_buffer_header->message_id = 0;

            int master_session_index = identify_sessions(user_id, password);
            if (master_session_index > -1) {
                send_buffer_header->opcode = OPCODE_SUCCESSFUL_LOGIN_ACK;
                send_buffer_header->token = generate_a_random_token();

                cs = find_this_client_in_the_session_array();
                cs->state = ONLINE;
                cs->token = send_buffer_header->token;
                cs->last_time = right_now();
                cs->client_addr = client_address;

            } else {
                send_buffer_header->opcode = OPCODE_FAILED_LOGIN_ACK;
                send_buffer_header->token = 0;
            }

            sendto(socket_file_descriptor, send_buffer, header_size, 0,
                   (struct sockaddr *)&client_address, sizeof(client_address));

        } else if (event == EVENT_NET_POST) {
            // TODO: Check the state of the client that sends this post msg,
            // i.e., check cs->state.

            // Now we assume it is ONLINE, because I do not want to ident
            // the following code in another layer.

            for
                each target session subscribed to this publisher {
                    char *text = recv_buffer + header_size;
                    char *payload = send_buffer + header_size;

                    // This formatting the "<client_a>some_text" in the payload
                    // of the forward msg, and hence, the client does not need
                    // to format it, i.e., the client can just print it out.
                    snprintf(payload, sizeof(send_buffer) - header_size,
                             "<%s>%s", cs->client_id, text);

                    int m = strlen(payload);

                    // "target" is the session structure of the target client.
                    target->state = STATE_MSG_FORWARD;

                    send_buffer_header->magic1 = MAGIC_1;
                    send_buffer_header->magic2 = MAGIC_2;
                    send_buffer_header->opcode = OPCODE_FORWARD;
                    send_buffer_header->payload_len = m;
                    send_buffer_header->message_id =
                        0;  // Note that I didn't use message_id here.

                    sendto(socket_file_descriptor, send_buffer, header_size, 0,
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