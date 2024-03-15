#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>
#include <modsecurity/rules_set.h>
#define NUM_THREADS     5

char main_rule_uri[] = "basic_rules.conf";
RulesSet *rules = NULL;
ModSecurity *modsec = NULL;

int thids[NUM_THREADS];

void *PrintHello(void *threadid) {
    long tid;
    tid = (long)threadid;
    thids[tid] = 1;

    printf("Hello World! It's me, thread #%ld!\n", tid);

    Transaction *transaction;

    for(int i = 0; i < 10; i++) {
        transaction = msc_new_transaction(modsec, rules, NULL);

        msc_process_connection(transaction, "127.0.0.1", 12345, "127.0.0.1", 80);
        msc_process_uri(transaction,
            "http://www.modsecurity.org/test?foo=herewego",
            "GET", "1.1");
        msc_add_request_header(transaction,
            (const unsigned char *) "User-Agent",
            (const unsigned char *) "Basic ModSecurity example");
        msc_process_request_headers(transaction);
        msc_process_request_body(transaction);
        msc_add_response_header(transaction,
            (const unsigned char *) "Content-type",
            (const unsigned char *) "text/html");
        msc_process_response_headers(transaction, 200, "HTTP 1.0");
        msc_process_response_body(transaction);
        msc_process_logging(transaction);
        msc_transaction_cleanup(transaction);

        if (tid%2 == 0) {
            usleep(100);
        }
        else {
            usleep(100);
        }
    }
    printf("Thread #%ld exits\n", tid);
    thids[tid] = 2;
    pthread_exit(NULL);
}

int main (int argc, char *argv[]) {
    pthread_t threads[NUM_THREADS];
    int rc;
    void * res;
    long t;
    const char *error = NULL;
    int ret;

    modsec = msc_init();

    msc_set_connector_info(modsec, "ModSecurity-test v0.0.1-alpha (Simple " \
        "example on how to use ModSecurity API");

    rules = msc_create_rules_set();

    ret = msc_rules_add_file(rules, main_rule_uri, &error);
    if (ret < 0) {
        fprintf(stderr, "Problems loading the rules --\n");
        fprintf(stderr, "%s\n", error);
        return 1;
    }


    for(t = 0; t < NUM_THREADS; t++) {
        thids[t] = 0;
        printf("In main: creating thread %ld\n", t);
        rc = pthread_create(&threads[t], NULL, PrintHello, (void *)t);
        if (rc) {
            printf("ERROR; return code from pthread_create() is %d\n", rc);
            return 1;
        }
    }

    int total_exitted = 0;
    while(total_exitted < NUM_THREADS) {
        for(int i = 0; i < NUM_THREADS; i++) {
            if (thids[i] == 2) {
                pthread_join(threads[i], &res);
                total_exitted++;
            }
        }
    }

    //msc_rules_cleanup(rules);
    //msc_cleanup(modsec);

    //pthread_exit(NULL);
}
