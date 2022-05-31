/* 
    The input and output buffers are implemented in circular arrays. The buffer has three types of users (reader, counter, writer). Each user has a semaphore to count the number of slots it can process. For index i, semaphore s==1, the user can process buffer[i+1]. The encryption thread is the writer (consumer) for input buffer and reader (producer) for output buffer. Thus, it has two semaphores.  

    To handle key resets, the input counter thread is blocked. The output counter signals after counting a character. When the total input and output characters counted are equivalent, it is safe to reset the key. Then, the input counter thread is resumed.

    When the input reader reaches EOF, it sets is_exit to true. Mutex m_exit_flag synchronizes access to is_exit between threads. Input reader tracks total number of inputs in global variable n_count. Other threads does similarly using their respective local variable. Threads aside (input reader) stops when EOF is reached and it has processed n_count characters. When EOF is reached, n_count becomes read-only, thus no locks needed.
*/

#include "encrypt-module.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>

/* Function declarations */
void* reader_t();
void* incount_t();
void* encrypt_t();
void* outcount_t();
void* writer_t();
void display_counts();
bool get_exit_flag();

/* Synchronization tools */
pthread_mutex_t m_block_incount; // to stop input counter thread when key reset is request
pthread_mutex_t m_outcount_safe; // synchronize access to out count operations
pthread_cond_t c_reset_ready;     // system ready for key reset
pthread_mutex_t m_exit_flag; // true when reached EOF, otherwise false

/* Semaphores to synchronize access to in/out buffer 
s1 for reading into in buffer, s4 for reading into out buffer. Both initialized to respective buffer size because buffer is empty at start. 
*/
sem_t   s1, // Number of input buffer free slots
        s2, // Number of uncounted chars in input buffer
        s3, // Number of input buffer chars ready to encrypt
        s4, // Number of output buffer free slots
        s5, // Number of uncounted chars in output buffer
        s6; // Number of output buffer chars ready to write


/* Shared Variables */
int in_size;    // input buffer size
int out_size;   // output buffer size
int* p_inbuf;   // pointer to input buffer
int* p_outbuf;  // pointer to output buffer
int n_read; // number of total character reads
bool is_exit; // true if EOF reached, otherwise false

/* Prepare for key reset by indirectly blocking all threads */
void reset_requested() {
    printf("Reset requested.\n");
    pthread_mutex_lock(&m_block_incount); // block input counter thread
    pthread_mutex_lock(&m_outcount_safe);
    while (get_input_total_count() != get_output_total_count()) {
        /* Wait until all counted inputs are encrypted and counted */
        pthread_cond_wait(&c_reset_ready, &m_outcount_safe);
    }
    pthread_mutex_unlock(&m_outcount_safe);
    display_counts();
}

/* Resume encryption after a key reset */
void reset_finished() {
    printf("Reset finished.\n\n");
    pthread_mutex_unlock(&m_block_incount); // resume incount thread
}

/* True if reached EOF, false otherwise */
bool get_exit_flag() {
    pthread_mutex_lock(&m_exit_flag);
    bool flag = is_exit;
    pthread_mutex_unlock(&m_exit_flag);
    return flag;
}

/* Print input and output counts */
void display_counts() {
    // Print input results
    printf("Total input count with current key is %d.\n", get_input_total_count());
    for (int i = 65; i <= 90; i++) {
        int count = get_input_count((char) i);
        printf("%c:%d ", (char) i, count);
    }
    printf("\n");

    // Print output results
    printf("Total output count with current key is %d.\n", get_output_total_count());
    for (int i = 65; i <= 90; i++) {
        int count = get_output_count((char) i);
        printf("%c:%d ", (char) i, count);
    }
    printf("\n");
}

/* Read inputs and insert into input buffer */
void* reader_t() {
    int c; /* Current input */
    int i = 0;
    while ((c = read_input()) != EOF) {
        sem_wait(&s1);
        i = n_read % in_size;
        p_inbuf[i] = c;
        n_read++;
        sem_post(&s2); /* Signal incount thread */
    }
    /* Notify other threads to prepare to exit */
    pthread_mutex_lock(&m_exit_flag);
    is_exit = true;
    pthread_mutex_unlock(&m_exit_flag);
    sem_post(&s2);
}

/* Count inputs and signal encryption thread */
void* incount_t() {
    int c;
    int n_count = 0;
    int i = 0;
    while (1) {
        sem_wait(&s2); /* Wait for new inputs */
        if (get_exit_flag()) {
            /* Exit when reader thread completed and processed all inputs */
            if (n_count == n_read) {
                sem_post(&s3);
                break;
            }
        }
        /* Count input and increment index */
        c = p_inbuf[i];
        count_input(c);
        n_count++;
        i = n_count % in_size;
        sem_post(&s3); /* Signal encryption thread */

        /* Stop processing if reset requested */
        pthread_mutex_lock(&m_block_incount);
        pthread_mutex_unlock(&m_block_incount);
    }
}

/* Encrypt input buffer and read into output buffer */
void* encrypt_t() {
    int c;
    int i_pre = 0;
    int i_post = 0;
    int n_encrypt = 0;
    while (1) {
        sem_wait(&s3); /* Wait for inputs */
        if (get_exit_flag()) {
            /* Exit when reader thread completed and processed all inputs */
            if (n_encrypt == n_read) {
                sem_post(&s5);
                break;
            }
        }
        /* Read and encrypt a slot from input buffer */
        c = p_inbuf[i_pre];
        sem_post(&s1); // input buffer slot i-1 can be overwritten now
        c = caesar_encrypt(c);
        n_encrypt++;
        i_pre = n_encrypt % in_size;

        /* Wait for available slot in output buffer and write into it */
        sem_wait(&s4);
        p_outbuf[i_post] = c;
        i_post = (i_post + 1) % out_size;
        sem_post(&s5); /* Signal output counter thread */
    }
}

/* Count characters in output buffer and signal writer thread */
void* outcount_t() {
    int c;
    int n_count = 0;
    int i = 0;
    while (1) {
        sem_wait(&s5);
        if (get_exit_flag()) {
            /* Exit when reader thread completed and processed all inputs */
            if (n_count == n_read) {
                sem_post(&s6);
                break;
            }
        }
        /* Count output and increment index */
        c = p_outbuf[i];
        pthread_mutex_lock(&m_outcount_safe);
        count_output(c);
        pthread_mutex_unlock(&m_outcount_safe);
        pthread_cond_signal(&c_reset_ready);
        n_count++;
        i = n_count % out_size;
        sem_post(&s6); /* Signal writer thread */
    }
}

/* Write character in output buffer to file and signal encryption thread (available space in output buffer) */
void* writer_t() {
    int c;
    int i = 0;
    int n_write = 0;
    while (1) {
        sem_wait(&s6);
        if (get_exit_flag())  {
            /* Exit when reader thread completed and processed all inputs */
            if (n_write == n_read) {
                break; /* Does not have to signal encryption thread */
            }
        }
        /* Write output to file */
        c = p_outbuf[i];
        n_write++;
        i = n_write % out_size;
        /* Signal encryption thread -- p_outbuf[i-1] can be overwritten */
        sem_post(&s4);
        write_output(c);
    }
}

/* Program entry point -- prompt user for program settings, initialize synchronization tools, start threads and print final count */
int main(int argc, char** argv) {
    if (argc != 3) {
        /* Check if user provides two arguments */
        printf("Please enter two arguments in the following format:\n");
        printf("[input_file_name] [output_file_name]\n");
        exit(0);
    }
    /* Prompt for buffer sizes */
    printf("Enter input buffer size: ");
    scanf("%d", &in_size);
    printf("Enter output buffer size: ");
    scanf("%d", &out_size);
    printf("\n");
    p_inbuf = calloc(in_size, sizeof(int));
    p_outbuf = calloc(out_size, sizeof(int));

    /* Initialize encrypt-module */
    init(argv[1], argv[2]);

    /* Initialize shared variables and sync tools */
    is_exit = false;
    pthread_mutex_init(&m_block_incount, NULL);
    pthread_mutex_init(&m_outcount_safe, NULL);
    pthread_mutex_init(&m_exit_flag, NULL);
    pthread_cond_init(&c_reset_ready, NULL);
    sem_init(&s1, 0, in_size);
    sem_init(&s2, 0, 0);
    sem_init(&s3, 0, 0);
    sem_init(&s4, 0, out_size);
    sem_init(&s5, 0, 0);
    sem_init(&s6, 0, 0);

    /* Create, initialize and start threads */
    pthread_t t1, t2, t3, t4, t5;
    pthread_create(&t1, NULL, &reader_t, NULL);
    pthread_create(&t2, NULL, &incount_t, NULL);
    pthread_create(&t3, NULL, &encrypt_t, NULL);
    pthread_create(&t4, NULL, &outcount_t, NULL);
    pthread_create(&t5, NULL, &writer_t, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    pthread_join(t4, NULL);
    pthread_join(t5, NULL); /* All threads have completed after this line */

    /* Print final input and output counts  */
    printf("End of file reached.\n");
    display_counts();

    /* Cleanup sync tools and dynamic buffers */
    pthread_mutex_destroy(&m_outcount_safe);
    pthread_mutex_destroy(&m_block_incount);
    pthread_mutex_destroy(&m_exit_flag);
    pthread_cond_destroy(&c_reset_ready);
    sem_destroy(&s1);                                              
    sem_destroy(&s2);                                                                                                                            
    sem_destroy(&s3);                                                                                                                             
    sem_destroy(&s4);                                                                                                                             
    sem_destroy(&s5);                                                                                                                             
    sem_destroy(&s6);  
    free(p_inbuf);
    free(p_outbuf);

    return 0;
}