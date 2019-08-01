/* ------------------------------------------------------------------------------------------------
 *
 *  Файл sniffer.c
 *  - содержит определения функций, описанных в файле sniffer.h.
 *
 * ----------------------------------------------------------------------------------------------- */
#include "sniffer.h"

/* ----------------------------------------------------------------------------------------------- */
// Функция захвата одного TCP-пакета.
// В качестве аргумента функции передается указатель на указатель объект, в который помещается
// длина захваченного пакета. В случае успеха возвращается указатель на начало
// канального уровня захваченного пакета, в случае ошибки - NULL.
const unsigned char* sniffTCPPacket(unsigned int *packetLen) {
    char pcapErrBuf[PCAP_ERRBUF_SIZE];   // Буффер для ошибок PCAP
    pcap_if_t* devicesListPointer;       // Список интерфейсов, доступных для захвата
    bpf_u_int32 ip;                      // IPv4-адрес используемого интерфейса
    bpf_u_int32 netmask;                 // Маска подсети используемого интерфейса
    pcap_t *sniffingHandle;              // Дескриптор сессии захвата пакетов
    char filterStr[] = "tcp";            // Текстовое описание фильтра для PCAP
    struct bpf_program compiledFilter;   // Скомпилированный PCAP-фильтр
    struct pcap_pkthdr pcapPacketHeader; // PCAP-заголовок с информацией о пакете
    const unsigned char* packet;         // Указатель на начало канального уровня захваченного пакета
    // Получение списка интерфейсов, доступных для захвата пакетов:
    if (pcap_findalldevs(&devicesListPointer, pcapErrBuf) == PCAP_ERROR) {
        printf("Ошибка обнаружения интерфейсов для захвата пакетов: %s\n", pcapErrBuf);
        return NULL;
    }
    if (devicesListPointer == NULL) {
        printf("Ни одного интерфейса для захвата найдено не было\n");
        return NULL;
    }
    printf("Попытка захвата TCP-пакета с интерфейса %s\n", devicesListPointer->name);
    // Получение IP-адреса и маски подсети для дальнейшей компиляции PCAP-фильтра:
    if (pcap_lookupnet(devicesListPointer->name, &ip, &netmask, pcapErrBuf) == PCAP_ERROR) {
        printf("Ошибка получения IP-адреса и маски подсети выбранного интерфейса: %s\n", pcapErrBuf);
        pcap_freealldevs(devicesListPointer);
        return NULL;
    }
    // Открытие выбранного интерфейса для захвата пакетов:
    sniffingHandle = pcap_create(devicesListPointer->name, pcapErrBuf);
    if (sniffingHandle == NULL) {
        printf("Ошибка открытия интерфейса для захвата: %s\n", pcapErrBuf);
        pcap_freealldevs(devicesListPointer);
        return NULL;
    }
    pcap_freealldevs(devicesListPointer);
    if (pcap_activate(sniffingHandle) != 0) {
        printf("Ошибка активации захвата пакетов: %s\n", pcap_geterr(sniffingHandle));
        pcap_close(sniffingHandle);
        return NULL;
    }
    // Установка Ethernet-заголовка канального уровня, если используется другой:
    if (pcap_datalink(sniffingHandle) != DLT_EN10MB)
        if (pcap_set_datalink(sniffingHandle, DLT_EN10MB) == PCAP_ERROR) {
            printf("Ошибка установки Ethernet-заголовка канального уровня: %s\n", pcap_geterr(sniffingHandle));
            pcap_close(sniffingHandle);
            return NULL;
        }
    // Компиляция фильтра для последующего его применения:
    if (pcap_compile(sniffingHandle, &compiledFilter, filterStr, 0, netmask) == PCAP_ERROR) {
        printf("Ошибка компиляции фильтра: %s\n", pcap_geterr(sniffingHandle));
        pcap_close(sniffingHandle);
        return NULL;
    }
    // Установка скомпилированного фильтра:
    if (pcap_setfilter(sniffingHandle, &compiledFilter) == PCAP_ERROR) {
        printf("Ошибка установки фильтра: %s\n", pcap_geterr(sniffingHandle));
        pcap_freecode(&compiledFilter);
        pcap_close(sniffingHandle);
        return NULL;
    }
    pcap_freecode(&compiledFilter);
    // Получение захваченного пакета:
    packet = pcap_next(sniffingHandle, &pcapPacketHeader);
    if (packet == NULL) {
        printf("Ошибка захвата пакета: %s\n", pcap_geterr(sniffingHandle));
        pcap_close(sniffingHandle);
        return NULL;
    }
    else
        printf("Захват успешен\n");
    pcap_close(sniffingHandle);
    *packetLen = pcapPacketHeader.len;
    return packet;
}

/* ----------------------------------------------------------------------------------------------- */
// Функция выводит на экран информацию об указанном IP-заголовке без опций.
void printIPHeader(const struct ip *header) {
    printf("IP-заголовок:\n-------------------------------------------------------------------------------\n");
    // Преобразование IP-адресов в сетевом порядке байт в читаемый формат:
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(header->ip_src), ip, INET_ADDRSTRLEN);
    printf("IP-адрес отправителя: %s; ", ip);
    inet_ntop(AF_INET, &(header->ip_dst), ip, INET_ADDRSTRLEN);
    printf("IP-адрес получателя: %s\n", ip);
    printf("Версия: %u; ", header->ip_v);
    printf("Размер заголовка: %u; ", header->ip_hl);
    printf("TOS(DSCP): %hhu; ", header->ip_tos);
    // Поля длиной больше 1 байта необходимо "развернуть" из сетевого big-endian в little-endian:
    printf("Длина пакета: %hu; ", ntohs(header->ip_len));
    printf("ID: %hu; ", ntohs(header->ip_id));
    printf("RF: %hu;\n", (ntohs(header->ip_off) & IP_RF) >> 15);
    printf("DF: %hu; ", (ntohs(header->ip_off) & IP_DF) >> 14);
    printf("MF: %hu; ", (ntohs(header->ip_off) & IP_MF) >> 13);
    printf("Fragment offset: %hu; ", ntohs(header->ip_off) & IP_OFFMASK);
    printf("TTL: %hhu; ", header->ip_ttl);
    printf("Протокол: %hhu; ", header->ip_p);
    printf("Контр. сумма: 0x%.2hX\n", ntohs(header->ip_sum));
    printf("-------------------------------------------------------------------------------\n\n");
}

/* ----------------------------------------------------------------------------------------------- */
// Функция выводит на экран информацию об указанном TCP-заголовке без опций.
void printTCPHeader(const struct tcphdr *header) {
    printf("TCP-заголовок:\n-------------------------------------------------------------------------------\n");
    // Поля длиной больше 1 байта необходимо "развернуть" из сетевого big-endian в little-endian:
    printf("Порт отправителя: %hu; ", ntohs(header->th_sport));
    printf("Порт получателя: %hu; ", ntohs(header->th_dport));
    printf("SEQ Num: %u; ", ntohl(header->th_seq));
    printf("ACK Num: %u;\n", ntohl(header->th_ack));
    printf("Data Offset: %u; ", header->th_off);
    printf("Reserved (and NS): %u; ", header->th_x2);
    printf("CWR: %hhu; ", (header->th_flags & TH_CWR) >> 7);
    printf("ECE: %hhu; ", (header->th_flags & TH_ECE) >> 6);
    printf("URG: %hhu; ", (header->th_flags & TH_URG) >> 5);
    printf("ACK: %hhu; ", (header->th_flags & TH_ACK) >> 4);
    printf("PSH: %hhu; ", (header->th_flags & TH_PUSH) >> 3);
    printf("RST: %hhu; ", (header->th_flags & TH_RST) >> 2);
    printf("SYN: %hhu; ", (header->th_flags & TH_SYN) >> 1);
    printf("FIN: %hhu;\n", (header->th_flags & TH_FIN));
    printf("Размер окна: %hu; ", ntohs(header->th_win));
    printf("Контр. сумма: 0x%.2hX; ", ntohs(header->th_sum));
    printf("Urgent ptr: 0x%.2hX\n", ntohs(header->th_urp));
    printf("-------------------------------------------------------------------------------\n\n");
}

/* ----------------------------------------------------------------------------------------------- */
