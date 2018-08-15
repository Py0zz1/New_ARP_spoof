#include <iostream>
#include <cstring>
//#include <cstdio>
using namespace std;

class Session_table{
private:
    uint8_t sender_mac[6];
    char *sender_ip;

    uint8_t target_mac[6];
    char *target_ip;

    int S_find_chk=0;
    int T_find_chk=0;

public:
    //Session_table(char *_sender_ip, char *_target_ip);

    //    Session_table(uint8_t _sender_mac[],char *_sender_ip,
    //                  uint8_t _target_mac[],char *_target_ip);

    void set_IP(char *_sender_ip,char *_target_ip);
    char *get_S_IP();
    char *get_T_IP();
    int get_find_chk(int flag);
    void set_find_chk(int flag);
    void set_MAC(uint8_t _mac[],int flag);
    uint8_t *get_MAC(int flag);
    int CMP_MAC(uint8_t _mac[],int flag);
    void print_MAC(int flag);
    void show_table();

};
