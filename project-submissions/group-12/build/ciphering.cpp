#include <bits/stdc++.h>
using namespace std;

#define public_key  3
#define private_key 12355
#define mod         18841

bool is_numer(string &s){
    for(int i=0;i<s.size();i++){
        if(!isdigit(s[i])) return false;
    }
    return true;
}

string res(string s){
    if(s.empty()){
        return "";
    }
    int val =stoi(s);
    return to_string(val);
}
long long int encrypt(double message)
{
    int e = public_key;
    long long int encrpyted_text = 1;
    while (e--) {
        encrpyted_text *= message;
        encrpyted_text %= mod;
    }
    return encrpyted_text;
}

long long int decrypt(int encrpyted_text)
{
    int d = private_key;
    long long int decrypted = 1;
    while (d--) {
        decrypted *= encrpyted_text;
        decrypted %= mod;
    }
    return decrypted;
}

vector<int> encoder(string message)
{
    vector<int> form;
    // calling the encrypting function in encoding function
    for (auto& letter : message)
        form.push_back(encrypt((int)letter));
    return form;
}
string decoder(vector<int> encoded)
{
    string s;
    // calling the decrypting function decoding function
    for (auto& num : encoded)
        s += decrypt(num);
    return s;
}

string str_encription(string message)
{
    vector<int> temp =encoder(message);
    string temp1 ="";
    for(int i : temp){
        string res =to_string(i);
        temp1 +=to_string(res.size()) +res;
    }
    return temp1;
}
string str_decription(string encoded)
{
    if(encoded.empty()){
        return "";
    }
    int cnt =encoded[0]-'0';
    cout << cnt << endl;
    int i =1;
    vector<int> val;
    string temp ="";
    while(i<=encoded.size()){
        if(cnt==0){
            cnt =encoded[i]-'0';
            val.push_back(stoi(temp));
            temp ="";
        }else{
            temp +=encoded[i];
            cnt--;
        }
        i++;
    }
    return decoder(val);
}
vector<string> str_break_I(vector<string> &tokens){
    vector<string> v1(3);
    vector<string> v2;
    vector<string> ans;
    v1[0]=tokens[0];
    for(int i=1;i<tokens.size();i++){
        if(tokens[i]=="-K"){
            v1[1]=tokens[i+1];
            i++;
        }
        else if(tokens[i]=="-I") continue;
        else if(tokens[i]=="-E"||tokens[i]=="-G"){
            v2.push_back(tokens[i+1]);
            i++;
        }
        else v1[2]=tokens[i];
    }
    ans.push_back(v1[0]);
    ans.push_back(v1[1]);
    ans.push_back(v1[2]);
    for(int i=0;i<v2.size();i++){
        ans.push_back(v2[i]);
    }
    return ans;
}
vector<string> str_break(string &s){
    vector<string> ans(8,"");
    vector<string> tokens;
    stringstream ss(s);
    string word;
    while (ss >> word) {
        tokens.push_back(word);
    }
    ans[0] = tokens[0];
    if(tokens[0]=="logread"){
        for(int i=1;i<tokens.size();i++){
            if(tokens[i]=="-I") return str_break_I(tokens);
        }
        for(int i=1;i<tokens.size();i++){
            string token = tokens[i];
            if(token == "-K"){
                ans[1]=tokens[i+1];
                i++;
            }
            else if(token=="-S"||token=="-R"){
                ans[5]=token.substr(1,1);
            }
            else if(token=="-T"){
                ans[5]=token.substr(1,1);
                if(is_numer(tokens[i+1])) {ans[7]=tokens[i+1];i++;}
                else ans[7]="-1";
            }
            else if(token=="-G"){
                ans[3]=tokens[i+1];
                ans[4]="1";
                i++;
            }
            else if(token=="-E"){
                ans[3]=tokens[i+1];
                ans[4]="0";
                i++;
            }
            else{
                ans[2]=token;
            }
        }
    }
    else{
        for(int i=1;i<tokens.size();i++){
            string token=tokens[i];
            if(token=="-T"){
                ans[7]=tokens[i+1];
                i++;
            }
            else if(token=="-K"){
                ans[1]=tokens[i+1];
                i++;
            }
            else if(token=="-E"){
                ans[3]=tokens[i+1];
                ans[4]="0";
                i++;
            }
            else if(token=="-G"){
                ans[3]=tokens[i+1];
                ans[4]="1";
                i++;
            }
            else if(token=="-A"||token=="-L"){
                ans[5]=token.substr(1,1);
            }
            else if(token=="-R"){
                ans[6]=res(tokens[i+1]);
                i++;
            }
            else{
                ans[2]=token;
            }
        }
    }
    return ans;
}