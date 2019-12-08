#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <time.h>
#include <algorithm>
#include <unordered_map>
#include <vector>
using namespace std;

struct header {
    char magic1;
    char magic2;
    unsigned char opcode;
    unsigned char payload_len;

    uint32_t token;
    uint32_t message_id;
};

#define header_size (sizeof(struct header))

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
    char *poster;
};

vector<message> message_list;
int token;
unordered_map<uint32_t, session> session_map;
session master_sessions[16] = {0};
int returned;
int socket_file_descriptor;
struct sockaddr_in server_address, client_address;
char send_buffer[1024] = {0};
char recv_buffer[1024] = {0};
struct header *send_buffer_header = (struct header *)send_buffer;
struct header *recv_buffer_header = (struct header *)recv_buffer;
int recv_length;
socklen_t client_address_length;
session *current_session;

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

void send_send_buffer(int num_bytes) {
    sendto(socket_file_descriptor, send_buffer, num_bytes, 0,
           (struct sockaddr *)&client_address, sizeof(client_address));
}

session *find_session_by_token(uint32_t token) {
    // if (session_map.find(token) != session_map.end()) {
    //     return &session_map[token];
    // } else {
    //     return NULL;
    // }
    for (int i = 0; i <= 2; i++) {
        if (master_sessions[i].token == token) {
            return &master_sessions[i];
        }
    }
    return NULL;
}

uint32_t find_token_by_client_id(char *client_id) {
    for (int i = 0; i <= 2; i++) {
        if (!strcmp(master_sessions[i].client_id, client_id)) {
            return master_sessions[i].token;
        }
    }
    return 0;
}

void send_reset(session *sesh) {
    sesh->state = STATE_OFFLINE;
    sesh->token = 0;
    printf("Session of client with id %s destroyed.\n", sesh->client_id);

    send_buffer_header->opcode = OPCODE_RESET;
    send_buffer_header->payload_len = 0;
    send_buffer_header->token = token;
    send_buffer_header->message_id = 0;

    send_send_buffer(header_size);
    clear_send_buffer();
    clear_recv_buffer();
}

bool is_valid_token(uint32_t token) { return current_session->token == token; }

int identify_sessions(char *user_id, char *password) {
    for (int i = 0; i <= 2; i++) {
        if (strcmp(master_sessions[i].client_id, user_id) == 0 &&
            strcmp(master_sessions[i].password, password) == 0) {
            return i;
        }
    }
    return -1;
}

// Taken from:
// https://stackoverflow.com/a/7622902
uint32_t generate_random_token() {
    srand(time(NULL));
    uint32_t token = rand() & 0xff;
    token |= (rand() & 0xff) << 8;
    token |= (rand() & 0xff) << 16;
    token |= (rand() & 0xff) << 24;
    return token;
}

void handle_login_event() {
    //printf("Enter handle login event\n");
    char *id_password = recv_buffer + header_size;
    // printf("opcode is 0x%hhx\n", *(recv_buffer + header_size));
    // printf("id and password is %s\n", id_password);
    char *ampersand = strchr(id_password, '&');
    if (ampersand == NULL) {
        printf("null\n");
    }
    char *password = ampersand + 1;
    // printf("About to put null terminator\n");
    // printf("%p\n", ampersand);

    *ampersand = '\0';  // Add a null terminator
    //printf("Put null terminator\n");

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
    int master_session_index = identify_sessions(user_id, password);
    if (master_session_index > -1) {
        current_session = &master_sessions[master_session_index];
        if (current_session->state != STATE_OFFLINE) {
            send_reset(current_session);
            return;
        }

        current_session->state = STATE_ONLINE;
        current_session->token = send_buffer_header->token;
        current_session->client_addr = client_address;

        send_buffer_header->opcode = OPCODE_SUCCESSFUL_LOGIN_ACK;
        send_buffer_header->token = generate_random_token();

    } else {
        current_session = NULL;

        send_buffer_header->opcode = OPCODE_FAILED_LOGIN_ACK;
        send_buffer_header->token = 0;
    }

    send_buffer_header->payload_len = 0;
    send_buffer_header->message_id = 0;

    send_send_buffer(header_size);
    //printf("Exit handle login event\n");
}

void handle_post_event() {
    if (current_session->state != STATE_ONLINE) {
        send_reset(current_session);
        return;
    }

    char *text = recv_buffer + header_size;

    char *newline = strchr(text, '\n');
    *newline = '\0';
    for (int i = 0; i <= 2; i++) {
        session *target_session = &master_sessions[i];
        vector<uint32_t> target_session_subscription_list_tokens =
            target_session->subscription_list_tokens;
        if (target_session->state == STATE_ONLINE &&
            find(target_session_subscription_list_tokens.begin(),
                 target_session_subscription_list_tokens.end(),
                 current_session->token) !=
                target_session_subscription_list_tokens.end()) {
            char *payload = send_buffer + header_size;

            // This formatting the "<client_a>some_text" in the payload
            // of the forward msg, and hence, the client does not need
            // to format it, i.e., the client can just print it out.
            snprintf(payload, sizeof(send_buffer) - header_size, "<%s>%s",
                     current_session->client_id, text);

            // "target" is the session structure of the target client.
            target_session->state = STATE_MSG_FORWARD;

            send_buffer_header->opcode = OPCODE_FORWARD;
            send_buffer_header->payload_len = strlen(payload);
            send_buffer_header->message_id =
                0;  // Note that I didn't use message_id here.

            sendto(socket_file_descriptor, send_buffer, header_size, 0,
                   (struct sockaddr *)&target_session->client_addr,
                   sizeof(target_session->client_addr));
        }
    }

    clear_send_buffer();
    send_buffer_header->opcode = OPCODE_POST_ACK;
    send_buffer_header->payload_len = 0;
    send_buffer_header->message_id = 0;
    send_send_buffer(header_size);

    message msg;
    strcpy(msg.content, text);
    strcpy(msg.poster, current_session->client_id);

    message_list.push_back(msg);
}

void handle_logout_event() {
    if (current_session->state != STATE_ONLINE) {
        send_reset(current_session);
        return;
    }

    current_session->state = STATE_OFFLINE;
    current_session->token = 0;

    send_buffer_header->opcode = OPCODE_LOGOUT_ACK;
    send_buffer_header->payload_len = 0;
    send_buffer_header->message_id = 0;

    send_send_buffer(header_size);
}

void handle_forward_ack() {
    if (current_session->state != STATE_MSG_FORWARD) {
        send_reset(current_session);
        return;
    }

    current_session->state = STATE_ONLINE;
}

void handle_retrieve() {
    if (current_session->state != STATE_ONLINE) {
        send_reset(current_session);
        return;
    }

    int num_messages_sent = 0;
    int num_messages = recv_buffer_header->payload_len;

    for (int i = message_list.size() - 1;
         i >= 0 && num_messages_sent < num_messages; i--) {
        message msg = message_list[i];
        vector<uint32_t> recipient_subscription_list_tokens =
            current_session->subscription_list_tokens;

        for (int j = 0; i < recipient_subscription_list_tokens.size(); j++) {
            uint32_t recipient_subscription_token =
                recipient_subscription_list_tokens[j];
            session *sesh = find_session_by_token(recipient_subscription_token);
            if (sesh != NULL && !strcmp(msg.poster, sesh->client_id)) {
                clear_send_buffer();
                char *payload = send_buffer + header_size;
                snprintf(payload, sizeof(send_buffer) - header_size, "<%s>%s",
                         sesh->client_id, msg.content);

                send_buffer_header->opcode = OPCODE_RETRIEVE_ACK;
                send_buffer_header->payload_len = strlen(payload);
                send_buffer_header->message_id = 0;

                send_send_buffer(header_size);
                num_messages_sent++;
            }
        }
    }

    clear_send_buffer();
    send_buffer_header->opcode = OPCODE_END_RETRIEVE_ACK;
    send_buffer_header->payload_len = 0;
    send_buffer_header->message_id = 0;
    send_send_buffer(header_size);
}

void handle_subscribe() {
    if (current_session->state != STATE_ONLINE) {
        send_reset(current_session);
        return;
    }

    char *subscription_id = recv_buffer + header_size;

    char *newline = strchr(subscription_id, '\n');
    *newline = '\0';

    u_int32_t token = find_token_by_client_id(subscription_id);
    if (token != 0) {
        current_session->subscription_list_tokens.push_back(token);
        send_buffer_header->opcode = OPCODE_SUCCESSFUL_SUBSCRIBE_ACK;
    } else {
        send_buffer_header->opcode = OPCODE_FAILED_SUBSCRIBE_ACK;
    }
    send_send_buffer(header_size);
}

void handle_unsubscribe() {
    if (current_session->state != STATE_ONLINE) {
        send_reset(current_session);
        return;
    }

    char *unsubscription_id = recv_buffer + header_size;

    char *newline = strchr(unsubscription_id, '\n');
    *newline = '\0';

    u_int32_t token = find_token_by_client_id(unsubscription_id);
    if (token != 0) {
        vector<uint32_t>::iterator token_position =
            find(current_session->subscription_list_tokens.begin(),
                 current_session->subscription_list_tokens.end(), token);
        if (token_position != current_session->subscription_list_tokens.end()) {
            current_session->subscription_list_tokens.erase(token_position);

            send_buffer_header->opcode = OPCODE_SUCCESSFUL_UNSUBSCRIBE_ACK;
        } else {
            send_buffer_header->opcode = OPCODE_FAILED_UNSUBSCRIBE_ACK;
        }
    } else {
        send_buffer_header->opcode = OPCODE_FAILED_UNSUBSCRIBE_ACK;
    }
    send_send_buffer(header_size);
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

        // printf("recv length is %d\n", recv_length);
        // printf("address of recv buffer is %p\n", recv_buffer);
        // printf("address of recv buffer header is %p\n", recv_buffer_header);
        // printf("address of recv buffer header magicno1 is %p\n", &recv_buffer_header->magic1);
        //printf("payload is %c\n", (char*) recv_buffer + 1);
        //printf("first magicno is %c\n", *(recv_buffer_header + 1));
        if (recv_length <= 0) {
            printf("recvfrom() error: %s.\n", strerror(errno));
            return -1;
        }

        // Now we know there is an event from the network
        // TODO: Figure out which event and process it according to the
        // current state of the session referred.

        uint32_t token = recv_buffer_header->token;
        current_session = find_session_by_token(token);
        int event = parse_network_event();

        if (current_session == NULL && event != EVENT_NET_LOGIN) {
            printf("Invalid token received!\n");
            continue;
        }

        if (current_session != NULL) {
            uint32_t client_token = recv_buffer_header->token;
            if (!is_valid_token(client_token)) {
                send_reset(current_session);
                continue;
            }
        }

        if (event == EVENT_NET_LOGIN) {
            handle_login_event();
        } else if (event == EVENT_NET_POST) {
            handle_post_event();
        } else if (event == EVENT_NET_LOGOUT) {
            handle_logout_event();
        } else if (event == EVENT_NET_FORWARD_ACK) {
            handle_forward_ack();
        } else if (event == EVENT_NET_RETRIEVE) {
            handle_retrieve();
        } else if (event == EVENT_NET_SUBSCRIBE) {
            handle_subscribe();
        } else if (event == EVENT_NET_UNSUBSCRIBE) {
            handle_unsubscribe();
        } else if (event == EVENT_NET_RESET) {
            send_reset(current_session);
        } else if (event == EVENT_NET_INVALID) {
            printf("Invalid network event!\n");
            continue;
        }

        if (current_session != NULL) {
            current_session->last_time = time(NULL);
        }
        // Now you may check the time of clients, i.e., scan all sessions.
        // For each session, if the current time has passed 5 minutes plus
        // the last time of the session, the session expires.
        // TODO: check session liveliness

        for (int i = 0; i <= 2; i++) {
            session *sesh = &master_sessions[i];
            if (sesh->state != STATE_OFFLINE &&
                difftime(time(NULL), sesh->last_time) > 300) {
                printf("Client with id %s timed out.\n", sesh->client_id);

                send_reset(sesh);
            }
        }
    }

    return 0;
}