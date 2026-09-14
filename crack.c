//This program brute-forces a given password hash by trying all possible
//passwords of a given length.
//
//Usage:
//crack <threads> <keysize> <target>
//
//Where <threads> is the number of threads to use, <keysize> is the maximum
//password length to search, and <target> is the target password hash.
//
//For example:
//
//./crack 1 5 na3C5487Wz4zw
//
//Should return the password 'apple'


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <crypt.h>

#define MAX_KEYSIZE 8

bool found = false;
char *foundPassword;
pthread_mutex_t foundMutex = PTHREAD_MUTEX_INITIALIZER;

struct threadData {
    int threadId;
    int keySize;
    char *target_hash;
    char salt[3];
    char start; // starting letter for this thread
    char end;   // ending letter for this thread
    struct crypt_data cdata;
};

void *passwordCrack(void *arg) {
    struct threadData pwd = *(struct threadData*)arg;

    char current[pwd.keySize + 1];
    current[pwd.keySize] = '\0';  // null-terminate the string

    //initialize current to all 'a'
    for (int i = 0; i < pwd.keySize; ++i) {
        current[i] = 'a';
    }

    //set first letter to this thread's start
    current[0] = pwd.start;

    while (1) {
        pthread_mutex_lock(&foundMutex);
        bool alreadyFound = found;
        pthread_mutex_unlock(&foundMutex);
        if (alreadyFound) return NULL;
        if (current[0] > pwd.end) break;

        //guess
        char *encrypted = crypt_r(current, pwd.salt, &pwd.cdata);
        if (strcmp(encrypted, pwd.target_hash) == 0) {
            pthread_mutex_lock(&foundMutex);
            if (!found) {
                found = true;
                foundPassword = strdup(current);
                printf("FOUND: %s\n", current);
            }
            pthread_mutex_unlock(&foundMutex);
            return NULL;
        }

        //increment as if base-26
        for (int i = pwd.keySize - 1; i >= 0; --i) {
            if (current[i] < 'z') {
                current[i]++;
                break;
            }
            else {
                current[i] = 'a';
                if (i == 0 && current[0] >= pwd.end)
                    return NULL;
            }
        }
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <threadsNum> <keySize> <target_hash>\n", argv[0]);
        return 1;
    }

    int threadsNum = atoi(argv[1]);
    int keySize = atoi(argv[2]);
    char *target_hash = argv[3];

    pthread_t threads[threadsNum];
    struct threadData structArr[threadsNum];

    int base = 26 / threadsNum;
    int remainder = 26 % threadsNum;
    int startOffset = 0;

    for (int i = 0; i < threadsNum; i++) {
        int rangeSize = base + (i < remainder ? 1 : 0);

        structArr[i].threadId = i;
        structArr[i].keySize = keySize;
        structArr[i].target_hash = target_hash;

        structArr[i].salt[0] = target_hash[0];
        structArr[i].salt[1] = target_hash[1];
        structArr[i].salt[2] = '\0';

        structArr[i].start = 'a' + startOffset;
        structArr[i].end = 'a' + startOffset + rangeSize - 1;

        memset(&structArr[i].cdata, 0, sizeof(struct crypt_data));

        startOffset += rangeSize;

        pthread_create(&threads[i], NULL, passwordCrack, &structArr[i]);
    }

    for (int i = 0; i < threadsNum; ++i) {
        pthread_join(threads[i], NULL);
    }

    if (found) {
        printf("Password cracked: %s\n", foundPassword);
    } else {
        printf("Password not found.\n");
    }

    return 0;
}
