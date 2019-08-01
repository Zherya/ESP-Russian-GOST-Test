#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ESP.h"
#include "sniffer.h"

int main() {

/* Захват TCP-пакета:
 * ----------------------------------------------------------------------------------------------- */
    const struct ether_header *Ethernet;
    const struct ip *IP;
    unsigned int IPHeaderLen;
    const struct tcphdr *TCP;
    unsigned int TCPHeaderLen;
    const unsigned char *sniffPayload;
    unsigned int sniffPayloadLen;
    unsigned int sniffPacketLen;
    const unsigned char *sniffPacket = sniffTCPPacket(&sniffPacketLen);
    if (sniffPacket == NULL) {
        printf("Пакет не был захвачен");
        return 0;
    } else
        printf("Длина захваченного пакета - %u байт(а)\n", sniffPacketLen);

    Ethernet = (const struct ether_header *)sniffPacket;

    IP = (const struct ip*)(sniffPacket + ETHER_HDR_LEN);
    // Проверка корректной длины IP-заголовка:
    IPHeaderLen = IP->ip_hl * 4;
    if (IPHeaderLen < 20 || IPHeaderLen > 60) {
        printf("Неверная длина IP-заголовка: %d\n", IPHeaderLen);
        return 0;
    }
    printIPHeader(IP);
    TCP = (const struct tcphdr *)(sniffPacket + ETHER_HDR_LEN + IPHeaderLen);
    // Проверка корректной длины TCP-заголовка:
    TCPHeaderLen = TCP->th_off * 4;
    if (TCPHeaderLen < 20 || TCPHeaderLen > 60) {
        printf("Неверная длина TCP-заголовка: %d\n", TCPHeaderLen);
        return 0;
    }
    printTCPHeader(TCP);
    sniffPayload = sniffPacket + ETHER_HDR_LEN + IPHeaderLen + TCPHeaderLen;
    sniffPayloadLen = sniffPacketLen - ETHER_HDR_LEN - IPHeaderLen - TCPHeaderLen;
    char *sniffPacketStr = ak_ptr_to_hexstr(sniffPacket, sniffPacketLen, ak_false);
    printf("Захваченный пакет = %s\n", sniffPacketStr);
    free(sniffPacketStr);
    if (sniffPayloadLen) {
        char *sniffPayloadStr = ak_ptr_to_hexstr(sniffPayload, sniffPayloadLen, ak_false);
        printf("Захваченные полезные данные = %s\n", sniffPayloadStr);
        free(sniffPayloadStr);
    }
    printf("Длина захваченных полезных данных - %u байт(а)\n", sniffPayloadLen);
    printf("-------------------------------------------------------------------------------\n");

/* ----------------------------------------------------------------------------------------------- */


/* Получение ESP-пакетов для туннельного (в payload помещается пакет, начиная с IP-заголовка) режима:
 * ----------------------------------------------------------------------------------------------- */
    // Инициализируем библиотеку, указывая в качестве стандартного
    // потока вывода библиотеки поток ошибок (stderr):
    if (ak_libakrypt_create(ak_function_log_stderr) != ak_true)
        return ak_libakrypt_destroy(); // В случае ошибки завершаем работу

    AEAD_Algorithm algoritms[4] = {KUZNYECHIK_ENCR, KUZNYECHIK_MAC, MAGMA_ENCR, MAGMA_MAC};
    size_t ESPPacketLen;
    unsigned char *ESPPacket;
    unsigned char protoID = 4; /* IPv4 */

    // Проведем цикл для каждого AEAD-алгоритма:
    for (int i = 0; i < 4; ++i) {
        printf("\n\nТуннельный режим работы ESP ");
        switch (algoritms[i]) {
            case KUZNYECHIK_ENCR: printf("(\"Кузнечик\" с шифрованием)\n");
                break;
            case KUZNYECHIK_MAC: printf("(\"Кузнечик\" без шифрования)\n");
                break;
            case MAGMA_ENCR: printf("(\"Магма\" с шифрованием)\n");
                break;
            case MAGMA_MAC: printf("(\"Магма\" без шифрования)\n");
                break;
        }
        printf("-------------------------------------------------------------------------------\n");
        printf("-------------------------------------------------------------------------------\n");
        printf("-------------------------------------------------------------------------------\n");
        ESPPacket = ESP_getPacket((unsigned char*)IP, IPHeaderLen + TCPHeaderLen + sniffPayloadLen,
                                  protoID, algoritms[i], &ESPPacketLen);
        if (ESPPacket == NULL) {
            printf("Ошибка генерации ESP-пакета\n");
            return ak_libakrypt_destroy();
        }
        printf("Пакет до шифрования:\n");
        ESP_printPacket(ESPPacket, ESPPacketLen, algoritms[i], ak_false);
        if (ESP_encryptPacket(ESPPacket, ESPPacketLen, algoritms[i]) != ak_true) {
            printf("Ошибка шифрования ESP-пакета\n");
            free(ESPPacket);
            return ak_libakrypt_destroy();
        }
        printf("Пакет после шифрования:\n");
        if (algoritms[i] == KUZNYECHIK_ENCR || algoritms[i] == MAGMA_ENCR)
            ESP_printPacket(ESPPacket, ESPPacketLen, algoritms[i], ak_true);
        else
            ESP_printPacket(ESPPacket, ESPPacketLen, algoritms[i], ak_false);
        printf("-------------------------------------------------------------------------------\n");
        printf("-------------------------------------------------------------------------------\n");
        printf("-------------------------------------------------------------------------------\n");
        free(ESPPacket);
    }

/* ----------------------------------------------------------------------------------------------- */

/* Получение ESP-пакетов для транспортного (в payload помещается пакет, начиная с TCP-заголовка) режима:
 * ----------------------------------------------------------------------------------------------- */
    protoID = 6; /* TCP */

    // Проведем цикл для каждого AEAD-алгоритма:
    for (int i = 0; i < 4; ++i) {
        printf("\n\nТранспортный режим работы ESP ");
        switch (algoritms[i]) {
            case KUZNYECHIK_ENCR: printf("(\"Кузнечик\" с шифрованием)\n");
                break;
            case KUZNYECHIK_MAC: printf("(\"Кузнечик\" без шифрования)\n");
                break;
            case MAGMA_ENCR: printf("(\"Магма\" с шифрованием)\n");
                break;
            case MAGMA_MAC: printf("(\"Магма\" без шифрования)\n");
                break;
        }
        printf("-------------------------------------------------------------------------------\n");
        printf("-------------------------------------------------------------------------------\n");
        printf("-------------------------------------------------------------------------------\n");
        ESPPacket = ESP_getPacket((unsigned char*)TCP, TCPHeaderLen + sniffPayloadLen,
                                  protoID, algoritms[i], &ESPPacketLen);
        if (ESPPacket == NULL) {
            printf("Ошибка генерации ESP-пакета\n");
            return ak_libakrypt_destroy();
        }
        printf("Пакет до шифрования:\n");
        ESP_printPacket(ESPPacket, ESPPacketLen, algoritms[i], ak_false);
        if (ESP_encryptPacket(ESPPacket, ESPPacketLen, algoritms[i]) != ak_true) {
            printf("Ошибка шифрования ESP-пакета\n");
            free(ESPPacket);
            return ak_libakrypt_destroy();
        }
        printf("Пакет после шифрования:\n");
        if (algoritms[i] == KUZNYECHIK_ENCR || algoritms[i] == MAGMA_ENCR)
            ESP_printPacket(ESPPacket, ESPPacketLen, algoritms[i], ak_true);
        else
            ESP_printPacket(ESPPacket, ESPPacketLen, algoritms[i], ak_false);
        printf("-------------------------------------------------------------------------------\n");
        printf("-------------------------------------------------------------------------------\n");
        printf("-------------------------------------------------------------------------------\n");
        free(ESPPacket);
    }

/* ----------------------------------------------------------------------------------------------- */
    return ak_libakrypt_destroy();
}
