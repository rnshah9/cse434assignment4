#include "client.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct header {
    char magic1;
    char magic2;
    char opcode;
    char payload_len;

    uint32_t token;
    uint32_t message_id;
};

#define MAGIC_1 'R'
#define MAGIC_2 'S'

#define STATE_OFFLINE 0
#define STATE_LOGIN_SENT 1
#define STATE_ONLINE 2
#define STATE_LOGOUT_SENT 3
#define STATE_POST_SENT 4
#define STATE_RETRIEVE_SENT 5
#define STATE_SUBSCRIBE_SENT 6
#define STATE_UNSUBSCRIBE_SENT 7

#define EVENT_USER_LOGIN 0
#define EVENT_USER_POST 1
#define EVENT_USER_SUBSCRIBE 2
#define EVENT_USER_UNSUBSCRIBE 3
#define EVENT_USER_RETRIEVE 4
#define EVENT_USER_LOGOUT 5
#define EVENT_USER_INVALID 79

#define EVENT_NET_LOGIN_SUCCESSFUL 80
#define EVENT_NET_POST_ACK 81
#define EVENT_NET_LOGIN_FAILED 82
#define EVENT_NET_LOGOUT_ACK 83
#define EVENT_NET_SUBSCRIBE_ACK 84
#define EVENT_NET_UNSUBSCRIBE_ACK 85
#define EVENT_NET_RETRIEVE_ACK 86
#define EVENT_NET_END_RETRIEVE_ACK 87
#define EVENT_NET_FORWARD 88
#define EVENT_NET_MUST_LOGIN_FIRST_ERROR 89
#define EVENT_NET_RESET 90

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

#define header_size (sizeof(struct header))

char user_input[1024];

uint32_t token;  // Assume the token is a 32-bit integer
int state;
int returned;
int socket_file_descriptor = 0;
char send_buffer[1024];
char recv_buffer[1024];
struct sockaddr_in server_address;
struct sockaddr_in my_address;
int maximum_file_descriptor;
fd_set read_set;
struct header *send_buffer_header = (struct header *)send_buffer;
struct header *recv_buffer_header = (struct header *)recv_buffer;

void state_error(char *custom_message) {
    printf(custom_message);
    printf("Error: State is currently %d\n", state);
}

void send_reset() {
    state = STATE_OFFLINE;
    token = 0;
    printf("Session destroyed due to unexpected state.\n");

    send_buffer_header->opcode = OPCODE_RESET;
    send_buffer_header->payload_len = 0;
    send_buffer_header->token = token;
    send_buffer_header->message_id = 0;

    send_send_buffer(header_size);
    clear_send_buffer();
    clear_recv_buffer();
}

int parse_user_event(char *user_input) {
    if (strncmp(user_input, "login#", 6) == 0) {
        return EVENT_USER_LOGIN;
    } else if (strncmp(user_input, "post#", 5) == 0) {
        return EVENT_USER_POST;
    } else if (strncmp(user_input, "subscribe#", 10) == 0) {
        return EVENT_USER_SUBSCRIBE;
    } else if (strncmp(user_input, "unsubscribe#", 12) == 0) {
        return EVENT_USER_UNSUBSCRIBE;
    } else if (strncmp(user_input, "retrieve#", 9) == 0) {
        return EVENT_USER_RETRIEVE;
    } else if (strncmp(user_input, "logout#", 7) == 0) {
        return EVENT_USER_LOGOUT;
    } else {
        return EVENT_USER_INVALID;
    }
}

// todo: state transitions
int parse_network_event(char *recv_buffer) {
    header *received_header = (header *)recv_buffer;
    switch (received_header->opcode) {
        case OPCODE_MUST_LOGIN_FIRST_ERROR:
            return EVENT_NET_MUST_LOGIN_FIRST_ERROR;
        case OPCODE_SUCCESSFUL_LOGIN_ACK:
            return EVENT_NET_LOGIN_SUCCESSFUL;
        case OPCODE_FAILED_LOGIN_ACK:
            return EVENT_NET_LOGIN_FAILED;
        case OPCODE_POST_ACK:
            return EVENT_NET_POST_ACK;
        case OPCODE_SUCCESSFUL_SUBSCRIBE_ACK:
        case OPCODE_FAILED_SUBSCRIBE_ACK:
            return EVENT_NET_SUBSCRIBE_ACK;
        case OPCODE_SUCCESSFUL_UNSUBSCRIBE_ACK:
        case OPCODE_FAILED_UNSUBSCRIBE_ACK:
            return EVENT_NET_UNSUBSCRIBE_ACK;
        case OPCODE_RETRIEVE_ACK:
            return EVENT_NET_RETRIEVE_ACK;
        case OPCODE_END_RETRIEVE_ACK:
            return EVENT_NET_END_RETRIEVE_ACK;
        case OPCODE_FORWARD:
            return EVENT_NET_FORWARD;
        case OPCODE_LOGOUT_ACK:
            return EVENT_NET_LOGOUT_ACK;
        case OPCODE_RESET:
            return EVENT_NET_RESET;
        default:
            return EVENT_NET_INVALID;
    }
}
void send_send_buffer(int num_bytes) {
    sendto(socket_file_descriptor, send_buffer, num_bytes, 0,
           (struct sockaddr *)&server_address, sizeof(server_address));
}

void send_login_message(char *user_input) {
    char *id_password = user_input + 6;  // skip the "login#"
    int id_password_length = strlen(id_password);

    send_buffer_header->opcode = OPCODE_LOGIN;
    send_buffer_header->payload_len = id_password_length;
    send_buffer_header->token = 0;
    send_buffer_header->message_id = 0;

    memcpy(send_buffer_header + header_size, id_password, id_password_length);
    send_send_buffer(header_size + id_password_length);
}

void send_post_message(char *user_input) {
    char *text = user_input + 5;  // skip the "post#"
    int text_length = strlen(text);

    send_buffer_header->opcode = OPCODE_POST;
    send_buffer_header->payload_len = text_length;
    send_buffer_header->token = token;
    send_buffer_header->message_id = 0;

    memcpy(send_buffer + header_size, text, text_length);
    send_send_buffer(header_size + text_length);
}

void send_subscribe_message(char *user_input) {
    char *client_id = user_input + strlen("subscribe#");
    int client_id_length = strlen(client_id);

    send_buffer_header->opcode = OPCODE_SUBSCRIBE;
    send_buffer_header->payload_len = client_id_length;
    send_buffer_header->token = token;
    send_buffer_header->message_id = 0;

    memcpy(send_buffer + header_size, client_id, client_id_length);
    send_send_buffer(header_size + client_id_length);
}

void send_unsubscribe_message(char *user_input) {
    char *client_id = user_input + strlen("unsubscribe#");
    int client_id_length = strlen(client_id);

    send_buffer_header->opcode = OPCODE_UNSUBSCRIBE;
    send_buffer_header->payload_len = client_id_length;
    send_buffer_header->token = token;
    send_buffer_header->message_id = 0;

    memcpy(send_buffer + header_size, client_id, client_id_length);
    send_send_buffer(header_size + client_id_length);
}
void send_retrieve_message(char *user_input) {
    char* newline = strchr(user_input, '\n');
    *newline = '\0';
    
    char *num_messages_string = user_input + strlen("retrieve#");
    int num_messages = atoi(num_messages_string);

    send_buffer_header->opcode = OPCODE_RETRIEVE;
    send_buffer_header->payload_len = (num_messages < 126) ? num_messages : 126;
    send_buffer_header->token = token;
    send_buffer_header->message_id = 0;

    send_send_buffer(header_size);
}

void send_logout_message() {
    send_buffer_header->opcode = OPCODE_LOGOUT;
    send_buffer_header->payload_len = 0;
    send_buffer_header->token = token;
    send_buffer_header->message_id = 0;
    send_send_buffer(header_size);
}

void send_forward_ack() {
    send_buffer_header->opcode = OPCODE_FORWARD_ACK;
    send_buffer_header->payload_len = 0;
    send_buffer_header->token = token;
    send_buffer_header->message_id = 0;
    send_send_buffer(header_size);
}

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

int main() {
    FD_ZERO(&read_set);
    socket_file_descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_file_descriptor < 0) {
        printf("socket() error: %s.\n", strerror(errno));
        return -1;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_address.sin_port = htons(32000);

    memset(&my_address, 0, sizeof(my_address));
    my_address.sin_family = AF_INET;
    my_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    my_address.sin_port = htons(41000 + rand() % 1000);

    returned = bind(socket_file_descriptor, (struct sockaddr *)&my_address,
                    sizeof(my_address));
    if (returned < 0) {
        printf("binding error!!!");
    }

    maximum_file_descriptor =
        socket_file_descriptor +
        1;  // Note that the file descriptor of stdin is "0"

    state = STATE_OFFLINE;
    int event;

    // This is a pointer of the type "struct header" but it always points
    // to the first byte of the "send_buffer", i.e., if we dereference this
    // pointer, we get the first 12 bytes in the "send_buffer" in the format
    // of the structure, which is very convenient.
    // So as the receive buffer.

    while (1) {
        FD_SET(fileno(stdin), &read_set);
        FD_SET(socket_file_descriptor, &read_set);

        select(maximum_file_descriptor, &read_set, NULL, NULL, NULL);

        clear_recv_buffer();
        clear_send_buffer();

        if (FD_ISSET(fileno(stdin), &read_set)) {
            fgets(user_input, sizeof(user_input), stdin);
            event = parse_user_event(user_input);
            printf("Event number is: %d\n", event);

            if (event == EVENT_USER_LOGIN) {
                if (state == STATE_OFFLINE) {
                    send_login_message(user_input);
                    state = STATE_LOGIN_SENT;
                } else {
                    state_error("Not offline!");
                }
            } else if (event == EVENT_USER_POST) {
                if (state == STATE_ONLINE) {
                    send_post_message(user_input);
                    state = STATE_POST_SENT;
                } else {
                    state_error("Not yet online! ");
                }

            } else if (event == EVENT_USER_SUBSCRIBE) {
                if (state == STATE_ONLINE) {
                    send_subscribe_message(user_input);
                    state = STATE_SUBSCRIBE_SENT;
                } else {
                    state_error("Not yet online! ");
                }
            } else if (event == EVENT_USER_UNSUBSCRIBE) {
                if (state == STATE_ONLINE) {
                    send_unsubscribe_message(user_input);
                    state = STATE_UNSUBSCRIBE_SENT;
                } else {
                    state_error("Not yet online! ");
                }
            } else if (event == EVENT_USER_RETRIEVE) {
                if (state == STATE_ONLINE) {
                    send_retrieve_message(user_input);
                    state = STATE_RETRIEVE_SENT;
                } else {
                    state_error("Not yet online! ");
                }
            } else if (event == EVENT_USER_LOGOUT) {
                if (state == STATE_ONLINE) {
                    send_logout_message();
                    state = STATE_LOGOUT_SENT;
                } else {
                    state_error("Not yet online! ");
                }
            } else if (event == EVENT_USER_INVALID) {
                printf("Invalid user event!\n");
            }
            //     else if (event == EVENT_USER_RESET) {
            //     // TODO: You may add another command like "reset#" so as to
            //     // facilitate testing. In this case, a user just need to
            //     // type this line to generate a reset message.

            //     // You can add more commands as you like to help debugging.
            //     // For example, I can add a command "state#" to instruct the
            //     // client program to print the current state without chang
            //     // -ing anything.
            // }
        }
        clear_recv_buffer();
        clear_send_buffer();
        if (FD_ISSET(socket_file_descriptor, &read_set)) {
            returned = recv(socket_file_descriptor, recv_buffer,
                            sizeof(recv_buffer), 0);

            event = parse_network_event(recv_buffer);
            // todo: state transitions
            if (event == EVENT_NET_LOGIN_SUCCESSFUL) {
                if (state == STATE_LOGIN_SENT) {
                    token = recv_buffer_header->token;
                    printf("login_ack#successful\n");
                    state = STATE_ONLINE;
                } else {
                    send_reset();
                }
            } else if (event == EVENT_NET_LOGIN_FAILED) {
                if (state == STATE_LOGIN_SENT) {
                    printf("login_ack#failed\n");
                    state = STATE_OFFLINE;
                } else {
                    send_reset();
                }
            } else if (event == EVENT_NET_FORWARD) {
                if (state == STATE_ONLINE) {
                    char *text = recv_buffer + header_size;
                    printf("%s\n", text);
                    send_forward_ack();
                    // Note that no state change is needed.
                } else {
                    send_reset();
                }
            } else if (event == EVENT_NET_MUST_LOGIN_FIRST_ERROR) {
                if (state == STATE_OFFLINE) {
                    printf("Must login first!\n");
                } else {
                    send_reset();
                }
            } else if (event == EVENT_NET_POST_ACK) {
                if (state == STATE_POST_SENT) {
                    printf("post_ack#successful\n");
                    state = STATE_ONLINE;
                } else {
                    send_reset();
                }
            } else if (event == EVENT_NET_SUBSCRIBE_ACK) {
                if (state == STATE_SUBSCRIBE_SENT) {
                    printf("subscribe_ack#%s\n",
                           recv_buffer_header->opcode ==
                                   OPCODE_SUCCESSFUL_SUBSCRIBE_ACK
                               ? "successful"
                               : "failed");
                    state = STATE_ONLINE;
                } else {
                    send_reset();
                }
            } else if (event == EVENT_NET_UNSUBSCRIBE_ACK) {
                if (state == STATE_UNSUBSCRIBE_SENT) {
                    printf("unsubscribe_ack#%s\n",
                           recv_buffer_header->opcode ==
                                   OPCODE_SUCCESSFUL_UNSUBSCRIBE_ACK
                               ? "successful"
                               : "failed");
                    state = STATE_ONLINE;
                } else {
                    send_reset();
                }
            } else if (event == EVENT_NET_RETRIEVE_ACK) {  // todo: check
                if (state == STATE_RETRIEVE_SENT) {
                    char payload[1024];
                    memcpy(payload, recv_buffer + header_size,
                           recv_buffer_header->payload_len);
                    payload[recv_buffer_header->payload_len] = '\0';
                    printf("%s\n", payload);
                } else {
                    send_reset();
                }
            } else if (event == EVENT_NET_END_RETRIEVE_ACK) {
                if (state == STATE_RETRIEVE_SENT) {
                    state = STATE_ONLINE;
                } else {
                    send_reset();
                }
            } else if (event == EVENT_NET_LOGOUT_ACK) {
                if (state == STATE_LOGOUT_SENT) {
                    clear_recv_buffer();
                    clear_send_buffer();
                    token = 0;
                    state = STATE_OFFLINE;
                    printf("logout_ack#successful\n");
                } else {
                    send_reset();
                }
            } else if (event == EVENT_NET_RESET) {
                send_reset();
            }
            else if (event == EVENT_NET_INVALID) {
                printf("Invalid network event!\n");
            }
        }

        // Now we finished processing the pending event. Just go back to the
        // beginning of the loop and waiting for another event.
        // Note that you can set a timeout for the select() function
        // to allow it to return regularly and check timeout related events.
    }
}