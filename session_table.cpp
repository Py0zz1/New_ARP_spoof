#include <iostream>
#include <cstring>
#include "session_table.h"
//#include <cstdio>
using namespace std;


//Session_table::Session_table(char *_sender_ip, char *_target_ip)
//{
//    sender_ip = _sender_ip;
//    target_ip = _target_ip;
//}

void Session_table::set_IP(char *_sender_ip, char *_target_ip)
{
    sender_ip = _sender_ip;
    target_ip = _target_ip;
}

void Session_table::set_MAC(uint8_t _mac[],int flag)
{
    //flag 1 -> sender
    //flag 0 -> target
    if(flag)
        memcpy(sender_mac,_mac,6);
    else
        memcpy(target_mac,_mac,6);
}

uint8_t *Session_table::get_MAC(int flag)
{
    if(flag)
        return sender_mac;
    else
        return target_mac;
}

int Session_table::CMP_MAC(uint8_t _mac[], int flag)
{
    if(flag)
    {
        if(!(memcmp(sender_mac,_mac,6)))
            return 1;
    }
    else
    {
        if(!(memcmp(target_mac,_mac,6)))
            return 1;
    }
    return 0;
}

void Session_table::print_MAC(int flag)
{
    for(int i=0; i<6; i++)
    {
        if(flag)
            printf("%02X ",sender_mac[i]);
        else
            printf("%02X ",target_mac[i]);
    }
    printf("\n");
}

char *Session_table::get_S_IP()
{
    return sender_ip;
}

char *Session_table::get_T_IP()
{
    return target_ip;
}

void Session_table::set_find_chk(int flag)
{
    if(flag)
        S_find_chk = 1;
    else
        T_find_chk = 1;
}

int Session_table::get_find_chk(int flag)
{
    if(flag)
        return S_find_chk;
    else
        return T_find_chk;
}

void Session_table::show_table()
{
    cout << "[SENDER_INFO]\nIP:" << sender_ip << endl;
    cout << "MAC:";
    for(int i=0; i<6; i++)
        printf("%02X ",sender_mac[i]);

    cout << "\n[TARGET_INFO]\nIP:" << target_ip << endl;
    cout << "MAC:";
    for(int i=0; i<6; i++)
        printf("%02X ",target_mac[i]);
    cout << endl;
}

