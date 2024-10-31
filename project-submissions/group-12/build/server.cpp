#include <bits/stdc++.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ciphering.cpp"
#include <filesystem>
#include "sha256.cpp" // Comment out the SHA-256 include
using namespace std;

#define PORT 8080
#define BUFFER_SIZE 1024*1024
#define Secret_key 1234
void deleteLastLine(const string& filePath) {
    if (!filesystem::exists(filePath)) {
        cerr << "Error: File does not exist.\n";
        return;
    }

    ifstream inputFile(filePath);
    if (!inputFile) {
        cerr << "Error: Unable to open the file for reading.\n";
        return;
    }
    vector<string> lines;
    string line;
    while (getline(inputFile, line)) {
        lines.push_back(line);
    }
    inputFile.close();

    // If the file is empty, do nothing
    if (lines.empty()) {
        cout << "The file is already empty.\n";
        return;
    }
    lines.pop_back();

    ofstream outputFile(filePath, ios::trunc);
    if (!outputFile) {
        cerr << "Error: Unable to open the file for writing.\n";
        return;
    }
    for (size_t i = 0; i < lines.size(); ++i) {
        outputFile << lines[i];
        if (i < lines.size() - 1) {
            outputFile << '\n';
        }
    }
    outputFile.close();
}
struct LogEntry {
    int timestamp;
    string name;
    int type;     // 0 = employee, 1 = guest
    string status;  // "arrival" or "leaving"
    int roomId;
};
LogEntry parseLogLine(const string& line) {
    
    stringstream ss(str_decription(line));
    LogEntry entry;

    ss >> entry.timestamp >> entry.name >> entry.type >> entry.status >> entry.roomId;
    return entry;
}
bool createCSV(string &filename) {
    ofstream file(filename);
    if (!file) {
        return false;
    }
    file.close();
    return true;
}

bool store_csv(vector<string>& info) {
    string filePath = info[2];
    if (!filesystem::exists(filePath)) {
        ofstream createFile(filePath);
        if (!createFile) {
            return false;
        }
        createFile.close();
    }
    ofstream file;
    file.open(filePath, ios::app);
    if (!file) {
        return false;
    }

    vector<string> data(5);
    data[0] = info[7];
    data[1] = info[3];
    data[2] = info[4];
    data[3] = info[5];
    data[4] = info[6] != "" ? info[6] : "-1";
    // string s ="";
    string temp ="";
    for (auto word : data) {
        // s +=word +" ";
        temp += word +" ";
    }
    file << str_encription(temp) <<  endl;
    // file << s << endl;
    file.flush();
    file.close();
    return true;
}

bool check_logappend_query(vector<string> &info){
    string filePath=info[2];
    if(!filesystem::exists(filePath) && info[5]=="L") return false;
    else if(!filesystem::exists(filePath)){
        if(info[5]=="A" && info[6]!=""){
            return false;
        }else{
            return true;
        }
    }
    else{
        ifstream file(filePath);
        if (!file) {
            return false;
        }
        string line;
        string curr="L";
        int time=-1;
        int time1=-1;
        vector<string> v;
        while (getline(file, line)) {
            stringstream ss(str_decription(line));
            string word;
            vector<string> words;
            while (ss >> word) {
                words.push_back(word);
            }
            
            if((info[3]==words[1])&&(info[4]==words[2])) {curr=words[3];time=stoi(words[0]);v=words;}
            time1=stoi(words[0]);
        }
        file.close();
        bool flg =false;
        for(auto i : v){
            cout << i << " ";
        }
        cout << endl;
        if(!v.empty()){
            if(info[5]=="A" && info[6]==""){
                if(v[3]=="L"  && v[4]=="-1"){
                    flg =true;
                }
            }
            if(info[5]=="A" && info[6]!=""){
                if(v[3]=="A" && v[4]=="-1") flg =true;
                if(v[3]=="L" && v[4]!="-1") flg =true;
            }
            if(info[5]=="L" && info[6]!=""){
                if(v[3]=="A" && v[4] == info[6]) flg =true;
            }
            if(info[5]=="L" && info[6]==""){
                if(v[3]=="L" && v[4]!="-1") flg =true;
                if(v[3]=="A" && v[4]=="-1") flg =true;
            }
        }else{
            if(info[5]=="A" && info[6]==""){
                flg =true;
            }
        }
        if(flg ==false){
            return false;
        }
        if(time1>=stoi(info[7])) return false;
        if(time==-1) {return true;}
        else{
            if(stoi(info[7])<time) return false;
        }
        return true;
    }
}
string process_Squery(const string& filePath) {
    ifstream file(filePath);
    if (!file) {
        return "";
    }
    set<string> employeesInCampus;
    set<string> guestsInCampus;
    map<int, map<string,int>> roomOccupancy;

    string line;
    while (getline(file, line)) {
        LogEntry entry = parseLogLine(line);
        if (entry.status == "A" && entry.roomId==-1) {
            if (entry.type == 0) employeesInCampus.insert(entry.name);
            else guestsInCampus.insert(entry.name);
        } else if (entry.status == "L" && entry.roomId==-1) {
            if (entry.type == 0) employeesInCampus.erase(entry.name);
            else guestsInCampus.erase(entry.name);
        }
        else if(entry.status == "L" && entry.roomId!=-1){
            roomOccupancy[entry.roomId][entry.name]--;
            if(roomOccupancy[entry.roomId][entry.name]==0){
                roomOccupancy[entry.roomId].erase(entry.name);
                if(roomOccupancy[entry.roomId].empty()){
                    roomOccupancy.erase(entry.roomId);
                }
            }
        }
        else roomOccupancy[entry.roomId][entry.name]++;
    }

    file.close();
    string response ="";
    for (auto it = employeesInCampus.begin(); it != employeesInCampus.end(); ++it) {
        if (it != employeesInCampus.begin()) response +=",";
        // cout << *it;
        response +=*it;
    }
    response +=" ";
    for (auto it = guestsInCampus.begin(); it != guestsInCampus.end(); ++it) {
        if (it != guestsInCampus.begin()) response +=",";
        // cout << *it;
        response +=*it;
    }
    response +=" ";
    for (auto rooms: roomOccupancy) {
        int roomId =rooms.first;
        if(roomId==-1) continue;
        response += to_string(roomId) +":";
        bool flg = true;
        for (auto occupant : rooms.second) {
            if (!flg) response +=",";
            response +=occupant.first;
            flg = false;
        }
        response +=" ";
    }
    return response;
}
string getVisitedRooms(const string& filePath, const string& name, int type) {
    string response ="";
    ifstream file(filePath);
    if (!file) {
        cerr << "Error: Unable to open the file.\n";
        return "";
    }

    vector<int> visitedRooms;
    set<int> uniqueRooms;

    string line;
    while (getline(file, line)) {
        LogEntry entry = parseLogLine(line);
        if (entry.name == name && entry.type == type) {
            if (uniqueRooms.find(entry.roomId) == uniqueRooms.end()) {
                visitedRooms.push_back(entry.roomId);
                uniqueRooms.insert(entry.roomId);
            }
        }
    }

    file.close();
    bool first = true;
    for (int roomId : visitedRooms) {
        if(roomId==-1) continue;
        if (!first) response +=",";
        response +=to_string(roomId);
        first = false;
    }
    response +=" ";
    return response;
}
string  getTotalTimeSpent(const string& filePath, const string& name, int type,int currentTime) {
    string response ="";
    ifstream file(filePath);
    if (!file) {
        cerr << "Error: Unable to open the file.\n";
        return "";
    }

    int totalTime = 0; 
    int lastentry = -1;
    int time_arrived=0;
    bool isCurrentlyInCampus = false;
    string line;
    while (getline(file, line)) {
        LogEntry entry = parseLogLine(line);
        if (entry.name == name && entry.type == type) {
            if (entry.status == "A" && entry.roomId==-1) {
                time_arrived=entry.timestamp;
                isCurrentlyInCampus = true;
            } else if (entry.status == "L" && entry.roomId == -1) {
                // Calculate the time spent from last arrival to this leaving
                totalTime += (entry.timestamp - time_arrived);
                isCurrentlyInCampus = false;
            }
        }
        lastentry=entry.timestamp;
    }
    file.close();
    if (isCurrentlyInCampus) {
        if(currentTime==-1){
            totalTime+=(lastentry-time_arrived);
        }
        else totalTime += (currentTime - time_arrived);
    }
    if (totalTime > 0) {
        response +=to_string(totalTime) +" ";
    }else{
        return "0";
    }
    return response;
}
string  process_Iquery(vector<string> info) {
    string response ="";
    ifstream file(info[2]);
    if (!file) {
        cerr << "Error: Unable to open the file.\n";
        return "";
    }
    string line;
    int length =info.size();
    set<string> names;
    for(int i =3; i<length; i++){
        names.insert(info[i]);
    }
    int tot_ppl =length-3;
    map<string,set<string>> ppl_room;
    map<string,map<string,int>> res;
    bool first =false;
    while(getline(file, line)){
        LogEntry entry = parseLogLine(line);
        if(names.find(entry.name)==names.end()){
            continue;
        }
        string room =to_string(entry.roomId);
        if(room =="-1"){
            continue;
        }
        if(entry.status =="A"){
            ppl_room[room].insert(entry.name);
            res[room][entry.name]++;
        }else{
            res[room][entry.name]--;
            if(res[room][entry.name]==0){
                ppl_room[room].erase(entry.name);
                res[room].erase(entry.name);
            }
            
        }
        if(ppl_room[room].size()==tot_ppl){
            if(first){
                response +=",";
            }
            response +=room;
            first =true;
        }
    }

    file.close();
    return response;
}
string process_log_read(vector<string> &info){
    string filePath=info[2];
    if(info[5]=="S"){
        return process_Squery(filePath);
    }
    else if(info[5]=="R"){
        return getVisitedRooms(filePath,info[3],stoi(info[4]));
    }
    else if(info[5]=="T"){
        return getTotalTimeSpent(filePath,info[3],stoi(info[4]),stoi(info[7]));
    }else{
        return process_Iquery(info);
    }
}
string q_process(vector<string> &info){
    if(info[0]=="logappend"){
        if(!check_logappend_query(info)){
            cout  << "0" << endl;
            return "Invalid";
        }
        else store_csv(info);
    }else{
        return process_log_read(info);
    }
    return "Successfully_executed";
}

pair<bool,string> user_key(string file_path){
    ifstream file;
    file.open("keys.csv");
    string line;
    while(getline(file,line)){
        stringstream ss(line);
        string a,b;
        ss >> a;
        ss >> b;
        if(file_path ==str_decription(a)){
            return {true,b};
        }
    }
    return {false,"NA"};
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

    method = TLS_server_method(); // Use TLS_server_method for compatibility

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // Set the key and cert
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void startServer() {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    initialize_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Binding the socket to the network address and port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    cout << "Server is listening on port " << PORT << endl;

    while (true) {
        int new_socket;
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            char buffer[BUFFER_SIZE];
            int valread = SSL_read(ssl, buffer, BUFFER_SIZE);
            cout << "Received: " << buffer << endl;
            string response;
            string decrypt_str =str_decription(string(buffer));
            cout << decrypt_str << endl;
            bool flag=false;
            vector<string> info =str_break(decrypt_str);
            string info_type, info_key, file_path;
            info_type =info[0];
            // info_key =key_hashing(info[1]);
            info_key =info[1];
            file_path =info[2];
            auto res =user_key(file_path);
            if(res.first ==true && res.second!=sha256(info_key)){
                response ="key Invalid";
            }else{
                if(res.first ==false && info_type =="logappend"){
                    ofstream file;
                    file.open("keys.csv", ios::app);
                    file << str_encription(file_path) << " " << sha256(info_key);
                    file << endl;
                    file.close();
                }
                response =q_process(info);
            }
            // cout << response << endl;
            if(response.size()==0){
                response ="Invalid";
            }
            response =str_encription(response);
            SSL_write(ssl, response.c_str(), response.size());
            cout << "Response sent" << endl;
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(new_socket);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

int main() {
    startServer();
    return 0;
}