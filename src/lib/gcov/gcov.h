/* SPDX-License-Identifier: GPL-2.0-only OR License-Ref-kk-custom */
/*
 * Copyright (C) 2019, 2023 Kernkonzept GmbH.
 * Author(s): Marcus Haehnel <marcus.haehnel@kernkonzept.com>
 *
 * This file is based on Linux v4.14.73 & v6.0.9 kernel/gcov/{gcov_4_7.c,gcov.h}
 */
/*
 *  This code provides functions to handle gcc's profiling data format
 *  introduced with gcc 4.7.
 *
 *  This file is based heavily on gcc_3_4.c file.
 *
 *  For a better understanding, refer to gcc source:
 *  gcc/gcov-io.h
 *  libgcc/libgcov.c
 *
 *  Uses gcc-internal data definitions.
 */

#pragma once
typedef unsigned long u32;
typedef unsigned long long u64;

/*
 * Profiling data types used for gcc 3.4 and above - these are defined by
 * gcc and need to be kept as close to the original definition as possible to
 * remain compatible.
 */
#define GCOV_DATA_MAGIC		((unsigned int) 0x67636461)
#define GCOV_TAG_FUNCTION	((unsigned int) 0x01000000)
#define GCOV_TAG_COUNTER_BASE	((unsigned int) 0x01a10000)
#define GCOV_TAG_FOR_COUNTER(count)					\
	(GCOV_TAG_COUNTER_BASE + ((unsigned int) (count) << 17))

typedef long long gcov_type;

struct gcov_info;

#if (__GNUC__ >= 10)
#define GCOV_COUNTERS 8
#elif (__GNUC__ >= 7)
#define GCOV_COUNTERS 9
#elif (__GNUC__ > 5) || (__GNUC__ == 5 && __GNUC_MINOR__ >= 1)
#define GCOV_COUNTERS 10
#elif __GNUC__ == 4 && __GNUC_MINOR__ >= 9
#define GCOV_COUNTERS 9
#else
#define GCOV_COUNTERS 8
#endif

#define GCOV_TAG_FUNCTION_LENGTH 3

/* Since GCC 12.1 sizes are in BYTES and not in WORDS (4B). */
#if (__GNUC__ >= 12)
#define GCOV_UNIT_SIZE                          4
#else
#define GCOV_UNIT_SIZE                          1
#endif


/**
 * struct gcov_ctr_info - information about counters for a single function
 * @num: number of counter values for this type
 * @values: array of counter values for this type
 *
 * This data is generated by gcc during compilation and doesn't change
 * at run-time with the exception of the values array.
 */
struct gcov_ctr_info
{
  unsigned int num;
  gcov_type *values;
};

/**
 * struct gcov_fn_info - profiling meta data per function
 * @key: comdat key
 * @ident: unique ident of function
 * @lineno_checksum: function lineo_checksum
 * @cfg_checksum: function cfg checksum
 * @ctrs: instrumented counters
 *
 * This data is generated by gcc during compilation and doesn't change
 * at run-time.
 *
 * Information about a single function.  This uses the trailing array
 * idiom. The number of counters is determined from the merge pointer
 * array in gcov_info.  The key is used to detect which of a set of
 * comdat functions was selected -- it points to the gcov_info object
 * of the object file containing the selected comdat function.
 */
struct gcov_fn_info
{
  const struct gcov_info *key;
  unsigned int ident;
  unsigned int lineno_checksum;
  unsigned int cfg_checksum;
  struct gcov_ctr_info ctrs[0];
};

/**
 * struct gcov_info - profiling data per object file
 * @version: gcov version magic indicating the gcc version used for compilation
 * @next: list head for a singly-linked list
 * @stamp: uniquifying time stamp
 * @filename: name of the associated gcov data file
 * @merge: merge functions (null for unused counter type)
 * @n_functions: number of instrumented functions
 * @functions: pointer to pointers to function information
 *
 * This data is generated by gcc during compilation and doesn't change
 * at run-time with the exception of the next pointer.
 */
struct gcov_info
{
  unsigned int version;
  struct gcov_info *next;
  unsigned int stamp;
  char const *filename;
  void (*merge[GCOV_COUNTERS])(gcov_type *, unsigned int);
  unsigned int n_functions;
  struct gcov_fn_info **functions;
};

/**
 * Outputs the gcov data from a gcov_info structure
 *
 * \param info Pointer to the gcov_info structure with the data to output
 */
void
convert_to_gcda(struct gcov_info *info);

/**
 * Process data from gcov_info for output
 *
 * \param tmp The gcov_info data that shall be output.
 *
 * The main function that must be implemented by a output backend to process
 * the gcov data.
 *
 */
void
output_gcov_data(struct gcov_info *tmp);
