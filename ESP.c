/* ------------------------------------------------------------------------------------------------
 *
 *  Файл ESP.c
 *  - содержит определения функций, описанных в файле ESP.h.
 *
 * ----------------------------------------------------------------------------------------------- */
#include "ESP.h"

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
                 const size_t labelSize, const ak_uint8 *seed, const size_t seedSize) {
    // Формируем входные данные для HMAC256 согласно определению KDF256:
    const size_t inDataSize = labelSize + seedSize + 4;
    ak_uint8 *inData = malloc(inDataSize);
    inData[0] = 0x01;
    memcpy(inData + 1, label, labelSize);
    inData[labelSize + 1] = 0x00;
    memcpy(inData + labelSize + 2, seed, seedSize);
    inData[labelSize + seedSize + 2] = 0x01;
    inData[labelSize + seedSize + 3] = 0x00;

    if (ak_hmac_context_set_key(HMAC256, keyIn, keySize, ak_true) != ak_error_ok) {
        ak_error_message(ak_error_get_value(), "ak_hmac_context_set_key", "Ошибка установления ключа");
        return NULL;
    }

    return ak_hmac_context_ptr(HMAC256, inData, inDataSize, NULL);
}

/* ----------------------------------------------------------------------------------------------- */
// Тестирование функции KDF256 согласно документу Р 50.1.113–2016.
// Функция возвращает ak_true в случае успешного тестирования KDF256 и ak_false - иначе.
// Контекст структуры ak_hmac уже должен быть проинициализирован функцией
// ak_hmac_context_create_streebog256().
// Библиотека akrypt перед вызовом функции должна быть проинициализирована
// функцией ak_libakrypt_create().
int testKDF256(ak_hmac HMAC256) {
    /* ТЕСТ KDF256:
     * Ключ диверсификации Kin (из стандарта):
     * 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
     * 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
     * Запись ключа, как есть: */
    ak_uint8 Kin[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    /* label (из стандарта):
     * 26 bd b8 78
     * Запись label, как есть: */
    ak_uint8 label[4] = {0x26, 0xbd, 0xb8, 0x78};

    /* seed (из стандарта):
     * af 21 43 41 45 65 63 78
     * Запись seed, как есть: */
    ak_uint8 seed[8] = {0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78};

    /* KDF256(Kin, label, seed) (из стандарта):
     * a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34
     * 01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9
     * Запись результата, как есть: */
    ak_uint8 GOSTResPtr[32] = {0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45,
                               0x34,
                               0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e,
                               0xd9};

    ak_buffer KDFOut;
    // Ф-я возвращает указатель на буфер с результатом, а если возникла ошибка, то NULL:
    if ((KDFOut = KDF256(HMAC256, Kin, 32, label, 4, seed, 8)) == NULL) {
        ak_error_message(ak_error_get_value(), "KDF256", "Ошибка вычисления KDF256");
        return ak_false;
    }
    bool_t res = ak_ptr_is_equal(GOSTResPtr, ak_buffer_get_ptr(KDFOut), ak_buffer_get_size(KDFOut));
    ak_buffer_delete(KDFOut);
    return res;
}

/* ----------------------------------------------------------------------------------------------- */
// Тестирование функции HMAC256 согласно документу Р 50.1.113–2016.
// Функция возвращает ak_true в случае успешного тестирования HMAC256 и ak_false - иначе.
// Контекст структуры ak_hmac уже должен быть проинициализирован функцией
// ak_hmac_context_create_streebog256().
// Библиотека akrypt перед вызовом функции должна быть проинициализирована
// функцией ak_libakrypt_create().
int testHMAC256(ak_hmac HMAC256) {
    /* ТЕСТ HMAC256:
     * Ключ K (из стандарта):
     * 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
     * 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
     * Запись ключа, как есть: */
    ak_uint8 K[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    /* Данные T (из стандарта):
     * 01 26 bd b8 78 00 af 21 43 41 45 65 63 78 01 00
     * Запись данных, как есть: */
    ak_uint8 T[16] = {0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00};

    /* HMAC256(K,T) (из стандарта):
     * a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34
     * 01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9
     * Запись результата, как есть: */
    ak_uint8 GOSTResPtr[32] = {0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45,
                               0x34,
                               0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e,
                               0xd9};

    if (ak_hmac_context_set_key(HMAC256, K, 32, ak_true) != ak_error_ok) {
        ak_error_message(ak_error_get_value(), "ak_hmac_context_set_key", "Ошибка установления ключа");
        return ak_false;
    }
    ak_buffer HMACOut;
    // Если аргумент (последний) выходного буфера принимает значение NULL,
    // то ф-я возвращает указатель на буфер с результатом, а если возникла ошибка, то NULL:
    if ((HMACOut = ak_hmac_context_ptr(HMAC256, T, 16, NULL)) == NULL) {
        ak_error_message(ak_error_get_value(), "ak_hmac_context_ptr", "Ошибка вычисления HMAC256");
        return ak_false;
    }
    bool_t res = ak_ptr_is_equal(GOSTResPtr, ak_buffer_get_ptr(HMACOut), ak_buffer_get_size(HMACOut));
    ak_buffer_delete(HMACOut);
    return res;
}

/* ----------------------------------------------------------------------------------------------- */
// Вычисления значения функции ESPTREE(K, i1, i2, i3) из стандарта использования IPSec ESP.
// В случае успеха функция возвращает указатель на буфер (ak_buffer)
// со значением функции ESPTREE. Буфер должен быть очищен с помощью ak_buffer_delete().
// В случае неудачи возвращается NULL.
// Библиотека akrypt перед вызовом функции должна быть проинициализирована
// функцией ak_libakrypt_create().
ak_buffer ESP_TREE(ak_uint8 *key, const size_t keySize, unsigned short i1,
                  unsigned short i2, unsigned short i3) {
    ak_uint8 l1[6] = "level1";
    ak_uint8 l2[6] = "level2";
    ak_uint8 l3[6] = "level3";
    ak_hmac HMAC256 = malloc(sizeof(struct hmac));
    if (HMAC256 == NULL) {
        printf("Ошибка выделения памяти под структуру hmac\n");
        return NULL;
    }
    if ((ak_hmac_context_create_streebog256(HMAC256)) != ak_error_ok) {
        ak_error_message(ak_error_get_value(), "ak_hmac_context_create_streebog256", "Ошибка инициализации контекста HMAC256");
        free(HMAC256);
        return NULL;
    }
    if (testHMAC256(HMAC256) != ak_true || testKDF256(HMAC256) != ak_true) {
        printf("Тест HMAC256 или KDF256 не успешен\n");
        ak_hmac_context_destroy(HMAC256);
        free(HMAC256);
        return NULL;
    }

    ak_buffer lvl1Out = KDF256(HMAC256, key, keySize, l1, 6, (ak_uint8*)&i1, 2);
    if (lvl1Out == NULL) {
        ak_error_message(ak_error_get_value(), "KDF256", "Ошибка вычисления KDF256");
        ak_hmac_context_destroy(HMAC256);
        free(HMAC256);
        return NULL;
    }
    ak_buffer lvl2Out = KDF256(HMAC256, ak_buffer_get_ptr(lvl1Out), ak_buffer_get_size(lvl1Out),
                               l2, 6, (ak_uint8*)&i2, 2);
    if (lvl2Out == NULL) {
        ak_error_message(ak_error_get_value(), "KDF256", "Ошибка вычисления KDF256");
        ak_buffer_delete(lvl1Out);
        ak_hmac_context_destroy(HMAC256);
        free(HMAC256);
        return NULL;
    }
    ak_buffer_delete(lvl1Out);
    ak_buffer lvl3Out = KDF256(HMAC256, ak_buffer_get_ptr(lvl2Out), ak_buffer_get_size(lvl2Out),
                               l3, 6, (ak_uint8*)&i3, 2);
    ak_buffer_delete(lvl2Out);
    ak_hmac_context_destroy(HMAC256);
    free(HMAC256);

    return lvl3Out;
}
/* ----------------------------------------------------------------------------------------------- */
// Получение указателя на тестовый Initialization Vector.
// В качестве аргументов выступают указатели на параметры диверсификации i1, i2, i3,
// в которые будут записаны соответствующие значения из IV в сетевом порядке байт
// для дальнейшей передачи этих параметров функции ESPTREE.
// Полученный указатель в дальнейшем должен быть передан функции free()
// для освобождения выделенных ресурсов. В случае неудачи возвращается NULL.
unsigned char* ESP_getIV() {
    // Initialization Vector (IV), 8 байт: i1 | i2 | i3 | C,
    // где i1 - 1 байт; i2, i3 - 2 байта; i1, i2, i3 - параметры диверсификации;
    // С - 3 байта - порядковый номер сообщения.
    unsigned char *IV = malloc(8);
    if (IV == NULL)
        return NULL;
    // Параметры диверсификации i2, i3 записаны в сетевом порядке байт, чтобы записать их
    // в таком виде в вектор инициализации, а также, чтобы передать все три параметра
    // в таком виде в функцию ESPTREE. При этом в IV параметр i1 имеет размер в 1 байт:
    unsigned char i1 = 13;
    unsigned short i2 = htons(714), i3 = htons(1340);
    IV[0] = i1; // i1
    memcpy(IV + 1, &i2, 2); // i2
    memcpy(IV + 3, &i3, 2); // i3
    unsigned char C[3] = {0x00, 0x00, 0x01}; // Число 1 в сетевом порядке байт;
    memcpy(IV + 5, C, 3);
    return IV;
}

/* ----------------------------------------------------------------------------------------------- */
// Получение указателя на завершающую часть ESP-пакета (ESP Trailer).
// В качестве аргументов выступает длина полезных данных пакета, которые необходимо выровнять;
// ID протокола в полезных данных для заполнения поля Next Header, а также указатель, по адресу которого
// записывается размер возвращаемого ESP Trailer'а. Функция возвращает в случае успеха указатель
// на ESP Trailer. Полученный указатель в дальнейшем должен быть передан функции free() для освобождения
// выделенных ресурсов. В случае неудачи возвращается NULL.
unsigned char* ESP_getTrailer(const size_t payloadLen, const unsigned char protoID, size_t *trailerLen) {
    /*  - ESP-Trailer:
     *      - Padding, 0-255 байт - заполнение (первый байт = 1, второй - 2 и т.д.)
     *                              для кратности четырем передаваемых данных,
     *                              заполнения, его длины и поля Next Header
     *      - Pad Length (1 байт) - длина заполнения
     *      - Next Header (1 байт) - ID протокола в поле передаваемых данных */
    // Определим минимальную длину заполнения, удовлетворяющую условию кратности четырем:
    size_t alignedDataLen = payloadLen + 2; // 2 байта на Pad Length и Next Header
    while (alignedDataLen % 4 != 0)
        ++alignedDataLen;
    *trailerLen = alignedDataLen - payloadLen;
    unsigned char *ESPTrailer = malloc(*trailerLen);
    if (ESPTrailer == NULL)
        return NULL;
    // Заполним Padding по указаному выше правилу:
    for (unsigned char i = 0, padLen = *trailerLen - 2; i < padLen; ++i)
        ESPTrailer[i] = i + 1;
    // Заполним Pad Length и Next Header:
    ESPTrailer[*trailerLen - 2] = *trailerLen - 2;
    ESPTrailer[*trailerLen - 1] = protoID;
    return ESPTrailer;
}

/* ----------------------------------------------------------------------------------------------- */
// Получение незашифрованного ESP-пакета с полезными данным payload и с ID протокола в payload,
// равным protoID, а также полем ICV длины, определяемой по AEAD-алгоритму algorithm.
// В параметр ESPPacketLen записывается длина получившегося пакета. В случае успеха функция
// возвращает указатель на полученный пакет. Полученный указатель в дальнейшем должен быть передан
// функции free() для освобождения выделенных ресурсов. В случае неудачи возвращается NULL.
unsigned char* ESP_getPacket(const unsigned char *payload, const size_t payloadLen,
                            const unsigned char protoID, AEAD_Algorithm algorithm, size_t *ESPPacketLen) {
    // Заполнение структур и полей ESP произвольными константными значениями
    // для последующего вычисления тестовых значений:
//------------------------------------------------------------------------
/* ESP-пакет имеет следующий формат:
 *  - ESP-заголовок:
 *      - Security Parameter Index (SPI), 4 байта в сетевом порядке байт
 *      - Sequence Number (SN), 4 байта в сетевом порядке байт
 *
 *  - ESP-payload:
 *      - Initialization Vector (IV), 8 байт: i1 | i2 | i3 | C, где i1 - 1 байт; i2, i3 - 2 байта
 *                     С - 3 байта - порядковый номер сообщения; i1, i2, i3 - параметры диверсификации
 *      - Передаваемые данные + опциональное заполнение для сокрытия длины
 *
 *  - ESP-Trailer:
 *      - Padding, 0-255 байт - заполнение (первый байт = 1, второй = 2 и т.д.)
 *                              для кратности четырем передаваемых данных,
 *                              заполнения, его длины и поля Next Header
 *      - Pad Length (1 байт) - длина заполнения
 *      - Next Header (1 байт) - ID протокола в поле передаваемых данных
 *
 *  - Integrity Check Value (ICV) - контрольная сумма, 96 бит (12 байт) для Кузнечика,
 *                                                     64 бита (8 байт) для Магмы */
//------------------------------------------------------------------------

    // Заполним поля ESP-заголовка и смежных структур согласно стандарту ESP,
    // используя сетевой порядок байт, где это указано.

    // ESP Header:
    struct ESPHeader ESPHead;
    ESPHead.SPI = htonl(14000); // Значения 0-255 не используются
    ESPHead.SeqNum = htonl(1);

    // IV:
    unsigned char *IV = ESP_getIV();
    if (IV == NULL)
        return NULL;

    // ESP Trailer:
    size_t ESPTrailerLen;
    unsigned char *ESPTrailer = ESP_getTrailer(payloadLen, protoID, &ESPTrailerLen);
    if (ESPTrailer == NULL) {
        free(IV);
        return NULL;
    }

    // ICV:
    size_t ICVLen;
    if (algorithm == KUZNYECHIK_ENCR || algorithm == KUZNYECHIK_MAC)
        // Для Кузнечика ICV имеет размер 96 бит (12 байт):
        ICVLen = 12;
    else
        // Для Магмы - 64 бита (8 байт):
        ICVLen = 8;
    unsigned char *ICV = malloc(ICVLen);
    if (ICV == NULL) {
        free(IV);
        free(ESPTrailer);
        return NULL;
    }
    // Заполним ICV нулями:
    for (int i = 0; i < ICVLen; ++i)
        ICV[i] = 0x00;

    // Теперь можно вычислить общую длину пакета:
    *ESPPacketLen = 8 /*ESP Header*/ + 8 /*IV*/ + payloadLen + ESPTrailerLen + ICVLen;
    // И выделить под него память:
    unsigned char *ESPPacket = malloc(*ESPPacketLen);
    if (ESPPacket == NULL) {
        free(IV);
        free(ESPTrailer);
        free(ICV);
        return NULL;
    }

    // Скопируем все "части" пакета воедино:
    memcpy(ESPPacket, &ESPHead, 8); // ESP Header
    memcpy(ESPPacket + 8, IV, 8); // IV
    memcpy(ESPPacket + 16, payload, payloadLen); // Payload
    memcpy(ESPPacket + 16 + payloadLen, ESPTrailer, ESPTrailerLen); // ESP Trailer
    memcpy(ESPPacket + 16 + payloadLen + ESPTrailerLen, ICV, ICVLen); // ICV
    free(IV);
    free(ESPTrailer);
    free(ICV);

    return ESPPacket;

}

/* ----------------------------------------------------------------------------------------------- */
// Получение указателя на корневой ключ и секретную соль для заданного AEAD-алгоритма algorithm.
// В аргументы указатели keySize и saltSize записываются соответствующие размеры в байтах.
// Функция возвращает в случае успеха указатель на непрерывные данные размера keySize + saltSize,
// первые keySize байт из которых представляют собой корневой ключ,
// а остальные saltSize - секретную соль. Полученный указатель в дальнейшем должен быть передан
// функции free() для освобождения выделенных ресурсов. Функция также выводит на экран значения
// ключа и соли. В случае неудачи возвращается NULL.
unsigned char* ESP_getRootKeyAndSalt(size_t *keySize, size_t *saltSize, AEAD_Algorithm algorithm) {
    *keySize = 32; // 32 байта = 256 бит
    if (algorithm == KUZNYECHIK_ENCR || algorithm == KUZNYECHIK_MAC)
        *saltSize = 12; // 12 байт = 96 бит
    if (algorithm == MAGMA_ENCR || algorithm == MAGMA_MAC)
        *saltSize = 4; // 4 байта = 32 бита
    unsigned char *keyAndSalt = malloc(*keySize + *saltSize);
    if (keyAndSalt == NULL)
        return NULL;
    // Заполним значения ключа и соли:
    for (size_t i = 0, size = *keySize + *saltSize; i < size; ++i)
        keyAndSalt[i] = i;
    // Выведем результаты на экран:
    char *keyStr = ak_ptr_to_hexstr(keyAndSalt, *keySize, ak_false);
    char *saltStr = ak_ptr_to_hexstr(keyAndSalt + *keySize, *saltSize, ak_false);
    printf("Корневой ключ = 0x%s\nСекретная соль = 0x%s\n", keyStr, saltStr);
    free(keyStr); free(saltStr);
    return keyAndSalt;
}

/* ----------------------------------------------------------------------------------------------- */
// Получение указателя на одноразовый вектор (nonce) для AEAD-режима шифрования.
// В качестве аргументов выступают указатель на IV, откуда берется 3 последних байта C;
// указатель на salt, а также размер salt в байтах и указатель на размер nonce, куда записывается
// размер возвращаемых данных. Функция возвращает в случае успеха указатель на nonce.
// Полученный указатель в дальнейшем должен быть передан функции free() для освобождения
// выделенных ресурсов. Функция также выводит на экран значение nonce.
// В случае неудачи возвращается NULL.
unsigned char* ESP_getNonce(const unsigned char *C, const unsigned char *salt, size_t saltSize, size_t *nonceSize) {
    // Формат nonce: zero | C | salt, где zero - 1 нулевой байт, С - порядковый номер из IV, 3 байта
    //                                    salt - секретная соль
    *nonceSize = 1 + 3 + saltSize;
    unsigned char *nonce = malloc(*nonceSize);
    if (nonce == NULL)
        return NULL;
    nonce[0] = 0;
    memcpy(nonce + 1, C, 3);
    memcpy(nonce + 4, salt, saltSize);
    // Выведем результат на экран:
    char *nonceStr = ak_ptr_to_hexstr(nonce, *nonceSize, ak_false);
    printf("Одноразовый вектор (nonce) = 0x%s\n", nonceStr);
    free(nonceStr);
    return nonce;
}

/* ----------------------------------------------------------------------------------------------- */
// Шифрование и/или вычисление имитовставки заданного ESP-пакета с помощью AEAD-алгоритма
// algorithm. В случае шифрования и вычисления имитовставки на место полезных данных и
// ESP Trailer пакета записывается шифртекст, а в поле ICV записывается имитовставка.
// В случае вычисления только имитовставки в исходный пакет записывается только ICV.
// В случае успеха возвращается ak_true, в случае неудачи - ak_false.
// Библиотека akrypt перед вызовом функции должна быть проинициализирована
// функцией ak_libakrypt_create().
int ESP_encryptPacket(unsigned char *packet, const size_t packetLen, AEAD_Algorithm algorithm) {
    // Шифруются: передаваемые данные и ESP-Trailer.
    // Имитозащита (считается контрольная сумма от): ESP-заголовок, IV, payload и ESP-Trailer

    // Вычислим длину ICV:
    unsigned char ICVLen;
    if (algorithm == KUZNYECHIK_ENCR || algorithm == KUZNYECHIK_MAC)
        // Для Кузнечика ICV имеет размер 96 бит (12 байт):
        ICVLen = 12;
    else
        // Для Магмы - 64 бита (8 байт):
        ICVLen = 8;

    // Вычислим длину данных для шифрования и выделим соответствующию память:
    size_t plainDataLen;
    unsigned char *plainData;
    if (algorithm == KUZNYECHIK_ENCR || algorithm == MAGMA_ENCR) {
        // Шифруются полезные данные пакета и ESP Trailer:
        plainDataLen = packetLen - 16 /*ESP Header,IV*/ - ICVLen;
        // Выделим новую память, чтобы скопировать туда данные для шифрования,
        // а шифртекст поместить сразу в пакет на место открытых данных:
        plainData = malloc(plainDataLen);
        if (plainData == NULL) {
            printf("Ошибка выделения памяти под открытый текст\n");
            return ak_false;
        }
        memcpy(plainData, packet + 16, plainDataLen);
    }
    else {
        // В случае режимов без шифрования обнуляем соответствующие значения:
        plainDataLen = 0;
        plainData = NULL;
    }

    // Получим значение корневого ключа и соли:
    size_t rootKeySize, saltSize;
    unsigned char *salt, *rootKey = ESP_getRootKeyAndSalt(&rootKeySize, &saltSize, algorithm);
    if (rootKey == NULL) {
        printf("Ошибка получения корневого ключа и соли\n");
        free(plainData);
        return ak_false;
    } else
        salt = rootKey + rootKeySize;

    // Получим значение одноразового (инициализирующего) вектора nonce:
    size_t nonceSize;
    unsigned char *nonce = ESP_getNonce(packet + 13 /*C*/, salt, saltSize, &nonceSize);
    if (nonce == NULL) {
        printf("Ошибка получения вектора nonce\n");
        free(plainData);
        free(rootKey);
        return ak_false;
    }

    // Получим ключ шифрования сообщения:
    // Параметры диверсификации берутся из ESP IV:
    unsigned short i1 = packet[8], i2 = *((unsigned short *)(packet + 9)), i3 = *((unsigned short *)(packet + 11));
    // Параметры i2, i3 помещаются в ESPTREE как были в IV, то есть в сетевом порядке байт:
    ak_buffer msgKey = ESP_TREE(rootKey, rootKeySize, i1, i2, i3);
    if (msgKey == NULL) {
        printf("Ошибка получения ключа шифрования сообщения\n");
        free(plainData);
        free(rootKey);
        free(nonce);
        return ak_false;
    }
    free(rootKey);

    // Определим размер дополнительных аутентифицируемых данных (AAD):
    size_t AADSize;
    if (algorithm == KUZNYECHIK_ENCR || algorithm == MAGMA_ENCR)
        // Если производится шифрование, то AAD = ESP Header:
        AADSize = 8;
    else
        // Иначе AAD = весь пакет (без ICV, очевидно):
        AADSize = packetLen - ICVLen;

    // Установим ключ шифрования сообщения:
    struct bckey keyContext;
    if (algorithm == KUZNYECHIK_ENCR || algorithm == KUZNYECHIK_MAC) {
        if (ak_bckey_context_create_kuznechik(&keyContext) != ak_error_ok) {
            ak_error_message(ak_error_get_value(), "ak_bckey_context_create_kuznechik",
                             "Ошибка установления контекста \"Кузнечика\"");
            free(plainData);
            free(nonce);
            ak_buffer_delete(msgKey);
            return ak_false;
        }
    } else {
        if (ak_bckey_context_create_magma(&keyContext) != ak_error_ok) {
            ak_error_message(ak_error_get_value(), "ak_bckey_context_create_magma",
                             "Ошибка установления контекста \"Магмы\"");
            free(plainData);
            free(nonce);
            ak_buffer_delete(msgKey);
            return ak_false;
        }
    }
    if (ak_bckey_context_set_key(&keyContext, ak_buffer_get_ptr(msgKey), ak_buffer_get_size(msgKey), ak_true) != ak_error_ok) {
        ak_error_message(ak_error_get_value(), "ak_bckey_context_set_key",
                         "Ошибка установления ключа шифрования");
        free(plainData);
        free(nonce);
        ak_buffer_delete(msgKey);
        ak_bckey_context_destroy(&keyContext);
        return ak_false;
    }
    ak_buffer_delete(msgKey);

    // Наконец, применяем шифрование:
    if (algorithm == KUZNYECHIK_ENCR || algorithm == MAGMA_ENCR)
        ak_bckey_context_encrypt_mgm(&keyContext,     // Ключ для шифрования
                                                      // (для режимов без шифрования - NULL)
                                     &keyContext,     // Ключ для вычисления имитовставки
                                     packet,          // Указатель на начало AAD
                                     AADSize,         // Размер AAD
                                     plainData,       // Указатель на начало открытого текста
                                                      // (для режимов без шифрования - NULL)
                                     packet + 16,     // Указатель на область данных, куда сохранять шифртекст
                                                      // (для режимов без шифрования - NULL)
                                     plainDataLen,    // Размер открытого текста
                                                      // (для режимов без шифрования - 0)
                                     nonce,           // Указатель на начало одноразового вектора
                                     nonceSize,       // Размер одноразового вектора
                                     packet + packetLen - ICVLen, // Указатель на область данных, куда сохранять ICV
                                     ICVLen);                     // Ожидаемая длина ICV. Для Кузнечика она меньше
                                                                  // длины блока, и усекаются младшие (правые) биты,
                                                                  // что и требуется стандартом ESP
    else
        ak_bckey_context_encrypt_mgm(NULL,            // Ключ для шифрования
                                                      // (для режимов без шифрования - NULL)
                                     &keyContext,     // Ключ для вычисления имитовставки
                                     packet,          // Указатель на начало AAD
                                     AADSize,         // Размер AAD
                                     NULL,            // Указатель на начало открытого текста
                                                      // (для режимов без шифрования - NULL)
                                     NULL,            // Указатель на область данных, куда сохранять шифртекст
                                                      // (для режимов без шифрования - NULL)
                                     0,               // Размер открытого текста
                                                      // (для режимов без шифрования - 0)
                                     nonce,           // Указатель на начало одноразового вектора
                                     nonceSize,       // Размер одноразового вектора
                                     packet + packetLen - ICVLen, // Указатель на область данных, куда сохранять ICV
                                     ICVLen);                     // Ожидаемая длина ICV. Для Кузнечика она меньше
                                                                  // длины блока, и усекаются младшие (правые) биты,
                                                                  // что и требуется стандартом ESP

    // Если указатель на область данных, куда сохранять ICV, равен не равен NULL (как сейчас), то
    // всегда возвращается NULL, поэтому проверим наличие ошибок с помощью соотв. функции:
    if (ak_error_get_value() != ak_error_ok) {
        ak_error_message(ak_error_get_value(), "ak_bckey_context_encrypt_mgm", "Ошибка шифрования");
        free(plainData);
        free(nonce);
        ak_bckey_context_destroy(&keyContext);
        return ak_false;
    }

    return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
// Вывод на экран информации о заданном ESP-пакете packet. Длина ICV определяется на основе
// AEAD-алгоритма algorithm, а флаг encrypted, если установлен, указывает на то, что
// пакет содержит зашифрованные данные.
void ESP_printPacket(const unsigned char *packet, const size_t packetLen, AEAD_Algorithm algorithm, bool_t encrypted) {
    if ((algorithm == KUZNYECHIK_MAC || algorithm == MAGMA_MAC) && encrypted) {
        // Если используется алгоритм без шифрования, но при этом флаг
        // encrypted выставлен, то ошибка:
        printf("ESP_printPacket(): Несоответствие параметров пакета\n");
        return;
    }

    // Для начала сразу определим все длины:
    // Определим длину ICV по алгоритму шифрования:
    unsigned char ICVLen;
    if (algorithm == KUZNYECHIK_ENCR || algorithm == KUZNYECHIK_MAC)
        // Для Кузнечика ICV имеет размер 96 бит (12 байт):
        ICVLen = 12;
    else
        // Для Магмы - 64 бита (8 байт):
        ICVLen = 8;

    // Длина ESP Trailer:
    unsigned char padLen;
    unsigned short trailerLen;
    if (encrypted) {
        // Если пакет зашифрован, то ESP Trailer входит в полезные данные:
        trailerLen = 0;
        padLen = 0;
    } else {
        // Для незашифрованного пакета имеет место ненулевой ESP Trailer:
        // По адресу packetLen - ICVLen - 1 находится Next Header,
        // а по адресу packetLen - ICVLen - 2 находится Pad Length, найдем его:
        padLen = packet[packetLen - ICVLen - 2];
        trailerLen = padLen + 2 /*Pad Length,Next Header*/;
    }

    // Длина полезных данных:
    size_t payloadLen;
    payloadLen = packetLen - 16 /*ESP Header,IV*/ - trailerLen - ICVLen;

    printf("\nESP-пакет:\n");
    printf("-------------------------------------------------------------------------------\n");
    printf("Длина пакета - %lu байт(а)\n", packetLen);
    printf("-------------------------------------\n");
    printf("ESP Header = 0x");
    // Шестнадцатеричное представление ESP Header (с 0 по 7 байт):
    for (int i = 0; i < 8; ++i)
        //.2 в строке формата задает точность вывода
        // (минимальное число цифр, в данном случае старший
        // разряд байта по необходимости дополняется нулем):
        printf("%.2hhX", packet[i]);
    // Разбор ESP Header по полям:
    struct ESPHeader *ESPHead = (struct ESPHeader *)packet;
    printf(":  SPI = 0x%.2X; ", ntohl(ESPHead->SPI));
    printf("SN = 0x%.2X\n", ntohl(ESPHead->SeqNum));
    printf("-------------------------------------\n");

    // Шестнадцатеричное представление IV (с 8 по 15 байт):
    printf("IV = 0x");
    for (int i = 8; i < 16; ++i)
        printf("%.2hhX", packet[i]);
    // Разбор IV по полям:
    // Первый байт IV (8-ой от начала пакета) - это параметр i1:
    printf(":  i1 = 0x%.2hhX; ", packet[8]);
    // Второй и третий - i2:
    unsigned short *i1and2 = (unsigned short *)(packet + 9);
    printf("i2 = 0x%.2hX; ", ntohs(*i1and2));
    // Четвертый и пятый - i3:
    i1and2 = (unsigned short *)(packet + 11);
    printf("i3 = 0x%.2hX; ", ntohs(*i1and2));
    // Последние три байта - это порядковый номер сообщения C:
    printf("С = 0x");
    for (int i = 13; i < 16; ++i)
        printf("%.2hhX", packet[i]);
    printf("\n-------------------------------------\n");

    if (payloadLen) {
        // Полезные данные пакета располагаются со смещения 16:
        if (encrypted)
            printf("Encrypted ");
        printf("Payload = 0x");
        for (int i = 16, end = i + payloadLen; i < end; ++i)
            printf("%.2hhX", packet[i]);
        printf("\n");
    }
    printf("Длина полезных данных - %lu байт(а)\n", payloadLen);
    printf("-------------------------------------\n");

    if (!encrypted) {
        // ESP Trailer располагается по смещению 16 + payloadLen:
        // Шестнадцатеричное представление ESP Trailer:
        printf("ESP Trailer = 0x");
        for (int i = 16 + payloadLen, end = i + trailerLen; i < end; ++i)
            printf("%.2hhX", packet[i]);
        printf(":  ");
        // Разбор ESP Trailer по полям:
        // В начале располагается Padding:
        if (padLen) {
            printf("Padding = 0x");
            for (int i = 16 + payloadLen, end = i + padLen; i < end; ++i)
                printf("%.2hhX", packet[i]);
            printf("; ");
        }
        // Затем поля Pad Length и Next Header:
        printf("Pad Length = 0x%.2hhX; ", packet[packetLen - ICVLen - 2]);
        printf("Next Header = 0x%.2hhX\n", packet[packetLen - ICVLen - 1]);
        printf("-------------------------------------\n");
    }

    // Шестнадцатеричное представление ICV:
    printf("ICV = 0x");
    for (int i = 16 + payloadLen + trailerLen; i < packetLen; ++i)
        printf("%.2hhX", packet[i]);
    printf(":\nДлина ICV - %hhu байт(а)\n", ICVLen);
    printf("-------------------------------------------------------------------------------\n");
}

/* ----------------------------------------------------------------------------------------------- */
