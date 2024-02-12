#include "profile.h"

// Array to hold profile statistics for each domain
profile_stats_t profiles[MAX_DOMAINS];

// Function to clear all profiles
void profile_clear_all() {
    memset(profiles, 0, sizeof(profile_stats_t) * MAX_DOMAINS);
}

// Function to start profiling for a domain
void profile_start(uint32_t domain) {
    // If the domain has not been used before, initialize its statistics
    if (profiles[domain].domain_id == 0) {
        profiles[domain].domain_id = domain;
        profiles[domain].min_time = UINT64_MAX;
    }

    // Get the current time
    struct timeval start_time;
    gettimeofday(&start_time, NULL);
    profiles[domain].start_time = start_time.tv_sec * 1000000ULL + start_time.tv_usec;
}

// Function to stop profiling for a domain and update statistics
void profile_stop(uint32_t domain) {
    // Get the current time
    struct timeval stop_time;
    gettimeofday(&stop_time, NULL);
    uint64_t end_time = stop_time.tv_sec * 1000000ULL + stop_time.tv_usec;

    // Calculate the time elapsed
    uint64_t elapsed_time = end_time - profiles[domain].start_time;

    // Update statistics
    if (elapsed_time < profiles[domain].min_time) {
        profiles[domain].min_time = elapsed_time;
    }
    if (elapsed_time > profiles[domain].max_time) {
        profiles[domain].max_time = elapsed_time;
    }
    profiles[domain].total_time += elapsed_time;
    profiles[domain].num_samples++;
}

// Function to print profile statistics for all domains
void profile_dump_all() {
    printf("%-10s %-10s %-10s %-10s %-10s\n", "Domain", "Min (us)", "Max (us)", "Avg (us)", "Total (us)");
    for (int i = 0; i < MAX_DOMAINS; i++) {
        if (profiles[i].domain_id != 0) {
            double avg_time = (double)profiles[i].total_time / profiles[i].num_samples;
            printf("%-10d %-10lu %-10lu %-10.2f %-10lu\n", profiles[i].domain_id, profiles[i].min_time, profiles[i].max_time, avg_time, profiles[i].total_time);
        }
    }
}