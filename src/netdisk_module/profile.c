#include "profile.h"

// Array to hold profile statistics for each domain
profile_stats_t profiles[MAX_DOMAINS];

// Function to clear all profiles
void profile_clear_all() { memset(profiles, 0, sizeof(profile_stats_t) * MAX_DOMAINS); }

// Function to start profiling for a domain
void profile_start(uint32_t domain) {
  // If the domain has not been used before, initialize its statistics
  if (profiles[domain].domain_id == 0) {
    profiles[domain].domain_id = domain;
    profiles[domain].min_time = UINT64_MAX;
  }

  // Get the current time
  profiles[domain].start_time = ktime_get_ns();
}

// Function to stop profiling for a domain and update statistics
void profile_stop(uint32_t domain) {
  // Get the current time
  uint64_t end_time = ktime_get_ns();

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
  pr_info("%-10s %-10s %-10s %-10s %-10s\n", "Domain", "Min (ns)", "Max (ns)", "Avg (ns)", "Total (ns)");
  for (int i = 0; i < MAX_DOMAINS; i++) {
    if (profiles[i].domain_id != 0) {
      double avg_time = (double)profiles[i].total_time / profiles[i].num_samples;
      pr_info("%-10d %-10llu %-10llu %-10.2f %-10llu\n", profiles[i].domain_id, profiles[i].min_time, profiles[i].max_time, avg_time, profiles[i].total_time);
    }
  }
}
