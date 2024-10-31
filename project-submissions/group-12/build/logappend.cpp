#include <bits/stdc++.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
using namespace std;

#define PORT 8080
#define BUFFER_SIZE 1024*1024
#include "ciphering.cpp"
#include "input_validation.cpp"
void send_info(string &s, int &sockfd){

    string encript_str =str_encription(s);
    send(sockfd, encript_str.c_str(), encript_str.size(), 0);
    cout << "Message sent to server" << endl;
}
void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method(); // Use TLS_client_method for compatibility

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int startLogAppendClient(const string& message) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    initialize_openssl();
    SSL_CTX *ctx = create_context();

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cout << "Socket creation error" << endl;
        return 255;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        cout << "Invalid address/ Address not supported" << endl;
        return 255;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        cout << "Connection Failed" << endl;
        return 255;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        string en_mess =str_encription(message);
        SSL_write(ssl, en_mess.c_str(), en_mess.length());
        cout << "Message sent" << endl;

        int valread = SSL_read(ssl, buffer, BUFFER_SIZE);
        buffer[valread] = '\0';
        string decript_str =str_decription(string(buffer));
        cout << decript_str << endl;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}

int main(int argc, char *argv[]) {
    string info="";
    info +=string(argv[0]);
    info =info.substr(2,info.length()-2);
    for (int i = 1; i < argc; i++) {
        info +=" ";
        info +=string(argv[i]);
    }
    if(!input_validation(info)){
        cout<<"Not valid info";
        return 255;
    }
    if(string(argv[0])=="./logappend" && string(argv[1])=="-B"){
        string filepath=string(argv[2]);
        ifstream file(filepath);
        if(!file.is_open()){
            cout<<"Invalid";
            return 255;
        }
        string line;
        while(getline(file,line)){
            line="logappend "+line;
            startLogAppendClient(line);
        }
        file.close();
    }
    else return startLogAppendClient(info);
    return 0;
}