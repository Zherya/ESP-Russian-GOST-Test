/* ------------------------------------------------------------------------------------------------
 *
 *  Файл ESP.h
 *  - содержит описания функций для работы с ESP-пакетами на основе российских криптографичесих
 *    алгоритмов с помощью библиотеки akrypt.
 *
 * ----------------------------------------------------------------------------------------------- */
#ifndef ESP_RUSSIAN_GOST_TEST_ESP_H
#define ESP_RUSSIAN_GOST_TEST_ESP_H

/* ----------------------------------------------------------------------------------------------- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ak_hmac.h>
#include <ak_mgm.h>

/* ----------------------------------------------------------------------------------------------- */
// Заголовок протокола IPSec ESP:
struct ESPHeader {
    unsigned int SPI;
    unsigned int SeqNum;
};

/* ----------------------------------------------------------------------------------------------- */
// Перечисление, содержащее идентификаторы возможных для использования
// в протоколе IPSec ESP российских криптографических AEAD-алгоритмов:
typedef enum {
    KUZNYECHIK_ENCR,
    KUZNYECHIK_MAC,
    MAGMA_ENCR,
    MAGMA_MAC
} AEAD_Algorithm;

/* ----------------------------------------------------------------------------------------------- */
// Вычисление значения функции KDF256(Kin, label, seed) из документа Р 50.1.113–2016.
// В случае успеха функция возвращает указатель на буфер (ak_buffer) со значением функции KDF256.
// Буфер должен быть очищен с помощью ak_buffer_delete().
// В случае неудачи возвращается NULL.
// Контекст структуры ak_hmac уже должен быть проинициализирован функцией
// ak_hmac_context_create_streebog256().
// Библиотека akrypt перед вызовом функции должна быть проинициализирована
// функцией ak_libakrypt_create().
ak_buffer KDF256(ak_hmac HMAC256, ak_uint8 *keyIn, const size_t keySize, const ak_uint8 *label,
                 const size_t labelSize, const ak_uint8 *seed, const size_t seedSize);

// Тестирование функции KDF256 согласно документу Р 50.1.113–2016.
// Функция возвращает ak_true в случае успешного тестирования KDF256 и ak_false - иначе.
// Контекст структуры ak_hmac уже должен быть проинициализирован функцией
// ak_hmac_context_create_streebog256().
// Библиотека akrypt перед вызовом функции должна быть проинициализирована
// функцией ak_libakrypt_create().
int testKDF256(ak_hmac HMAC256);

/* ----------------------------------------------------------------------------------------------- */
// Тестирование функции HMAC256 согласно документу Р 50.1.113–2016.
// Функция возвращает ak_true в случае успешного тестирования HMAC256 и ak_false - иначе.
// Контекст структуры ak_hmac уже должен быть проинициализирован функцией
// ak_hmac_context_create_streebog256().
// Библиотека akrypt перед вызовом функции должна быть проинициализирована
// функцией ak_libakrypt_create().
int testHMAC256(ak_hmac HMAC256);

/* ----------------------------------------------------------------------------------------------- */
// Вычисления значения функции ESPTREE(K, i1, i2, i3) из стандарта использования IPSec ESP.
// В случае успеха функция возвращает указатель на буфер (ak_buffer)
// со значением функции ESPTREE. Буфер должен быть очищен с помощью ak_buffer_delete().
// В случае неудачи возвращается NULL.
// Библиотека akrypt перед вызовом функции должна быть проинициализирована
// функцией ak_libakrypt_create().
ak_buffer ESP_TREE(ak_uint8 *key, const size_t keySize, unsigned short i1,
                  unsigned short i2, unsigned short i3);

/* ----------------------------------------------------------------------------------------------- */
// Получение указателя на тестовый Initialization Vector.
// В качестве аргументов выступают указатели на параметры диверсификации i1, i2, i3,
// в которые будут записаны соответствующие значения из IV в сетевом порядке байт
// для дальнейшей передачи этих параметров функции ESPTREE.
// Полученный указатель в дальнейшем должен быть передан функции free()
// для освобождения выделенных ресурсов. В случае неудачи возвращается NULL.
unsigned char* ESP_getIV();

// Получение указателя на завершающую часть ESP-пакета (ESP Trailer).
// В качестве аргументов выступает длина полезных данных пакета, которые необходимо выровнять;
// ID протокола в полезных данных для заполнения поля Next Header, а также указатель, по адресу которого
// записывается размер возвращаемого ESP Trailer'а. Функция возвращает в случае успеха указатель
// на ESP Trailer. Полученный указатель в дальнейшем должен быть передан функции free() для освобождения
// выделенных ресурсов. В случае неудачи возвращается NULL.
unsigned char* ESP_getTrailer(const size_t payloadLen, const unsigned char protoID, size_t *trailerLen);

// Получение незашифрованного ESP-пакета с полезными данным payload и с ID протокола в payload,
// равным protoID, а также полем ICV длины, определяемой по AEAD-алгоритму algorithm.
// В параметр ESPPacketLen записывается длина получившегося пакета. В случае успеха функция
// возвращает указатель на полученный пакет. Полученный указатель в дальнейшем должен быть передан
// функции free() для освобождения выделенных ресурсов. В случае неудачи возвращается NULL.
unsigned char* ESP_getPacket(const unsigned char *payload, const size_t payloadLen,
                            const unsigned char protoID, AEAD_Algorithm algorithm, size_t *ESPPacketLen);

/* ----------------------------------------------------------------------------------------------- */
// Получение указателя на корневой ключ и секретную соль для заданного AEAD-алгоритма algorithm.
// В аргументы указатели keySize и saltSize записываются соответствующие размеры в байтах.
// Функция возвращает в случае успеха указатель на непрерывные данные размера keySize + saltSize,
// первые keySize байт из которых представляют собой корневой ключ,
// а остальные saltSize - секретную соль. Полученный указатель в дальнейшем должен быть передан
// функции free() для освобождения выделенных ресурсов. Функция также выводит на экран значения
// ключа и соли. В случае неудачи возвращается NULL.
unsigned char* ESP_getRootKeyAndSalt(size_t *keySize, size_t *saltSize, AEAD_Algorithm algorithm);

// Получение указателя на одноразовый вектор (nonce) для AEAD-режима шифрования.
// В качестве аргументов выступают указатель на C из ESP IV;
// указатель на salt, а также размер salt в байтах и указатель на размер nonce, куда записывается
// размер возвращаемых данных. Функция возвращает в случае успеха указатель на nonce.
// Полученный указатель в дальнейшем должен быть передан функции free() для освобождения
// выделенных ресурсов. Функция также выводит на экран значение nonce.
// В случае неудачи возвращается NULL.
unsigned char* ESP_getNonce(const unsigned char *C, const unsigned char *salt, size_t saltSize, size_t *nonceSize);

// Шифрование и/или вычисление имитовставки заданного ESP-пакета с помощью AEAD-алгоритма
// algorithm. В случае шифрования и вычисления имитовставки на место полезных данных и
// ESP Trailer пакета записывается шифртекст, а в поле ICV записывается имитовставка.
// В случае вычисления только имитовставки в исходный пакет записывается только ICV.
// В случае успеха возвращается ak_true, в случае неудачи - ak_false.
// Библиотека akrypt перед вызовом функции должна быть проинициализирована
// функцией ak_libakrypt_create().
int ESP_encryptPacket(unsigned char *packet, const size_t packetLen, AEAD_Algorithm algorithm);

/* ----------------------------------------------------------------------------------------------- */
// Вывод на экран информации о заданном ESP-пакете packet. Длина ICV определяется на основе
// AEAD-алгоритма algorithm, а флаг encrypted, если установлен, указывает на то, что
// пакет содержит зашифрованные данные.
void ESP_printPacket(const unsigned char *packet, const size_t packetLen, AEAD_Algorithm algorithm, bool_t encrypted);

/* ----------------------------------------------------------------------------------------------- */
#endif //ESP_RUSSIAN_GOST_TEST_ESP_H
