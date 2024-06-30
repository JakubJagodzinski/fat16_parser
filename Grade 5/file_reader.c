#include "file_reader.h"
#include "tested_declarations.h"
#include "rdebug.h"
#include "tested_declarations.h"
#include "rdebug.h"

enum boot_sector_error_t {
    ERROR_BOOT_SECTOR_ALL_OK,
    ERROR_BOOT_SECTOR_NULL_PTR,
    ERROR_BOOT_SECTOR_WRONG_NUMBER_OF_FATS,
    ERROR_BOOT_SECTOR_WRONG_EOS_MARKER,
    ERROR_BOOT_SECTOR_WRONG_NUMBER_OF_SECTORS,
};

void set_volume_statistics(struct volume_t *pvolume) {
    pvolume->root_dir_size = (pvolume->boot_sector.root_dir_capacity * sizeof(struct dir_info_t)) / (int) pvolume->boot_sector.bytes_per_sector;
    if ((pvolume->boot_sector.root_dir_capacity * sizeof(struct dir_info_t)) % (int) pvolume->boot_sector.bytes_per_sector) {
        pvolume->root_dir_size += 1;
    }
    pvolume->boot_sector_position = 0;
    pvolume->first_fat_position = pvolume->boot_sector_position + pvolume->boot_sector.number_of_reserved_sectors;
    pvolume->second_fat_position = pvolume->first_fat_position + pvolume->boot_sector.sectors_per_fat;
    pvolume->root_dir_position = pvolume->second_fat_position + pvolume->boot_sector.sectors_per_fat;
    pvolume->second_cluster_position = pvolume->root_dir_position + pvolume->root_dir_size;
}

int boot_sector_validate(struct boot_sector_t *boot_sector) {
    if (boot_sector == NULL) {
        return ERROR_BOOT_SECTOR_NULL_PTR;
    }
    if (boot_sector->number_of_fats != 2) {
        return ERROR_BOOT_SECTOR_WRONG_NUMBER_OF_FATS;
    }
    if (boot_sector->end_of_sector_marker != FAT_END_OF_SECTOR_MARKER) {
        return ERROR_BOOT_SECTOR_WRONG_EOS_MARKER;
    }
    if (!(boot_sector->small_number_of_sectors ^ boot_sector->large_number_of_sectors)) {
        return ERROR_BOOT_SECTOR_WRONG_NUMBER_OF_SECTORS;
    }
    return ERROR_BOOT_SECTOR_ALL_OK;
}

struct disk_t *disk_open_from_file(const char *volume_file_name) {
    if (volume_file_name == NULL) {
        errno = EFAULT;
        return NULL;
    }
    struct disk_t *pdisk = calloc(1, sizeof(struct disk_t));
    if (pdisk == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    pdisk->f = fopen(volume_file_name, "rb");
    if (pdisk->f == NULL) {
        free(pdisk);
        errno = ENOENT;
        return NULL;
    }
    uint8_t buffer[FAT_BYTES_PER_SECTOR];
    while (fread(buffer, FAT_BYTES_PER_SECTOR, 1, pdisk->f) == 1) {
        ++pdisk->total_sectors;
    }
    return pdisk;
}

int disk_read(struct disk_t *pdisk, int32_t first_sector, void *buffer, int32_t sectors_to_read) {
    if (pdisk == NULL || pdisk->f == NULL || buffer == NULL) {
        errno = EFAULT;
        return -1;
    }
    if ((uint32_t) (first_sector + sectors_to_read) > pdisk->total_sectors + 1) {
        errno = ERANGE;
        return -1;
    }
    fseek(pdisk->f, first_sector * FAT_BYTES_PER_SECTOR, SEEK_SET);
    return (int) fread(buffer, FAT_BYTES_PER_SECTOR, sectors_to_read, pdisk->f);
}

int disk_close(struct disk_t *pdisk) {
    if (pdisk == NULL) {
        errno = EFAULT;
        return -1;
    }
    fclose(pdisk->f);
    free(pdisk);
    return 0;
}

struct volume_t *fat_open(struct disk_t *pdisk, uint32_t first_sector) {
    if (pdisk == NULL) {
        errno = EFAULT;
        return NULL;
    }
    struct volume_t *pvolume = calloc(1, sizeof(struct volume_t));
    if (pvolume == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    pvolume->pdisk = pdisk;
    if (disk_read(pdisk, (int) first_sector, &pvolume->boot_sector, 1) != 1) {
        fat_close(pvolume);
        return NULL;
    }
    if (boot_sector_validate(&pvolume->boot_sector) != 0) {
        fat_close(pvolume);
        errno = EINVAL;
        return NULL;
    }
    set_volume_statistics(pvolume);
    size_t bytes_per_fat = pvolume->boot_sector.sectors_per_fat * pvolume->boot_sector.bytes_per_sector;
    pvolume->first_fat = malloc(bytes_per_fat);
    pvolume->second_fat = malloc(bytes_per_fat);
    if (pvolume->first_fat == NULL || pvolume->second_fat == NULL) {
        fat_close(pvolume);
        errno = ENOMEM;
        return NULL;
    }
    int fat_1_result = disk_read(pdisk, (int) pvolume->first_fat_position, pvolume->first_fat, pvolume->boot_sector.sectors_per_fat);
    int fat_2_result = disk_read(pdisk, (int) pvolume->second_fat_position, pvolume->second_fat, pvolume->boot_sector.sectors_per_fat);
    if (fat_1_result != pvolume->boot_sector.sectors_per_fat || fat_2_result != pvolume->boot_sector.sectors_per_fat || memcmp(pvolume->first_fat, pvolume->second_fat, bytes_per_fat) != 0) {
        fat_close(pvolume);
        errno = EINVAL;
        return NULL;
    }
    size_t root_dir_bytes = pvolume->root_dir_size * pvolume->boot_sector.bytes_per_sector;
    pvolume->root_dir = malloc(root_dir_bytes);
    if (pvolume->root_dir == NULL) {
        fat_close(pvolume);
        errno = ENOMEM;
        return NULL;
    }
    if (disk_read(pdisk, (int) pvolume->root_dir_position, pvolume->root_dir, (int) pvolume->root_dir_size) != (int) pvolume->root_dir_size) {
        fat_close(pvolume);
        errno = EINVAL;
        return NULL;
    }
    return pvolume;
}

int fat_close(struct volume_t *pvolume) {
    if (pvolume == NULL) {
        errno = EFAULT;
        return -1;
    }
    free(pvolume->first_fat);
    free(pvolume->second_fat);
    free(pvolume->root_dir);
    free(pvolume);
    return 0;
}

int to_upper(const char c) {
    return c >= 'a' && c <= 'z' ? c + 'A' - 'a' : c;
}

int ignore_case_strcmp(const char *first, const char *second, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if (to_upper(*(first + i)) != to_upper(*(second + i))) {
            return 1;
        }
    }
    return 0;
}

struct file_t *file_open(struct volume_t *pvolume, const char *file_name) {
    if (pvolume == NULL || file_name == NULL) {
        errno = EFAULT;
        return NULL;
    }
    struct dir_info_t *file_info = find_dir_or_file_by_path(pvolume, file_name, SEEK_FILE);
    if (file_info == NULL) {
        return NULL;
    }
    struct file_t *file = malloc(sizeof(struct file_t));
    if (file == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    file->pvolume = pvolume;
    file->info = (void *) file_info;
    file->clusters_chain = get_chain_fat16(pvolume->first_fat, pvolume->boot_sector.sectors_per_fat * pvolume->boot_sector.bytes_per_sector, file->info->first_cluster_low_bytes);
    file->position = 0;
    if (file->clusters_chain == NULL) {
        free(file);
        errno = ENOMEM;
        return NULL;
    }
    return file;
}

size_t read_cluster(void *buffer, size_t bytes_per_cluster, struct file_t *stream) {
    if (buffer == NULL || bytes_per_cluster < 1 || stream == NULL || stream->pvolume == NULL) {
        return 0;
    }
    uint16_t current_cluster = *(stream->clusters_chain->clusters + stream->position / bytes_per_cluster);
    if (current_cluster == *((uint16_t *) stream->pvolume->first_fat)) {
        return 0;
    }
    lba_t sector_number = stream->pvolume->second_cluster_position + (current_cluster - 2) * stream->pvolume->boot_sector.sectors_per_cluster;
    if (disk_read(stream->pvolume->pdisk, (int) sector_number, (uint8_t *) buffer, stream->pvolume->boot_sector.sectors_per_cluster) == -1) {
        errno = ERANGE;
        return 0;
    }
    return bytes_per_cluster;
}

size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream) {
    if (ptr == NULL || stream == NULL || size < 1 || nmemb < 1) {
        errno = EFAULT;
        return -1;
    }
    size_t bytes_per_cluster = stream->pvolume->boot_sector.sectors_per_cluster * stream->pvolume->boot_sector.bytes_per_sector;
    uint8_t *data_block = malloc(bytes_per_cluster);
    if (data_block == NULL) {
        errno = ENOMEM;
        return -1;
    }
    if (stream->position % bytes_per_cluster != 0) {
        if (read_cluster(data_block, bytes_per_cluster, stream) == 0) {
            free(data_block);
            errno = ERANGE;
            return -1;
        }
    }
    uint8_t *data_block_ptr = data_block;
    data_block_ptr += stream->position % bytes_per_cluster;
    uint8_t *buffer_ptr = (uint8_t *) ptr;
    size_t elements_read = 0;
    for (size_t i = 0; i < nmemb && stream->position < stream->info->size; ++i) {
        size_t j;
        for (j = 0; j < size && stream->position < stream->info->size; ++j) {
            if (stream->position % bytes_per_cluster == 0) {
                if (read_cluster(data_block, bytes_per_cluster, stream) == 0) {
                    free(data_block);
                    errno = ERANGE;
                    return -1;
                }
                data_block_ptr = data_block;
            }
            *buffer_ptr++ = *data_block_ptr++;
            ++stream->position;
        }
        if (j == size) {
            ++elements_read;
        }
    }
    free(data_block);
    return elements_read;
}

int32_t file_seek(struct file_t *stream, int32_t offset, int whence) {
    if (stream == NULL) {
        errno = EFAULT;
        return -1;
    }
    switch (whence) {
        case SEEK_SET:
            stream->position = offset;
            break;
        case SEEK_CUR:
            stream->position += offset;
            break;
        case SEEK_END:
            stream->position = stream->info->size + offset;
            break;
        default:
            errno = EINVAL;
            return -1;
    }
    return 0;
}

int file_close(struct file_t *stream) {
    if (stream == NULL) {
        errno = EFAULT;
        return -1;
    }
    free(stream->clusters_chain->clusters);
    free(stream->clusters_chain);
    free(stream->info);
    free(stream);
    return 0;
}

void *find_dir_or_file_by_path(struct volume_t *pvolume, const char *path, enum seek_type_t seek_type) {
    struct dir_t *pdir = malloc(sizeof(struct dir_t));
    if (pdir == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    size_t root_dir_size_in_bytes = pvolume->root_dir_size * pvolume->boot_sector.bytes_per_sector;
    pdir->info = malloc(root_dir_size_in_bytes * sizeof(uint8_t));
    if (pdir->info == NULL) {
        dir_close(pdir);
        errno = ENOMEM;
        return NULL;
    }
    memcpy(pdir->info, pvolume->root_dir, root_dir_size_in_bytes);
    pdir->capacity = pvolume->boot_sector.root_dir_capacity;
    pdir->position = 0;
    if (strcmp("\\", path) == 0) {
        if (seek_type == SEEK_FILE) {
            dir_close(pdir);
            errno = EISDIR;
            return NULL;
        }
        return pdir;
    }
    char *path_copy = strdup(path);
    if (path_copy == NULL) {
        dir_close(pdir);
        errno = ENOMEM;
        return NULL;
    }
    char *current = path_copy;
    if (*current == '\\') {
        ++current;
    }
    do {
        char *next = strchr(current, '\\');
        if (next) {
            *next++ = '\0';
        }
        char fat_dir_info_name[FAT_DIR_INFO_NAME_LEN] = {0};
        if (strlen(current) <= FAT_DIR_ENTRY_NAME_LEN) {
            convert_to_fat_dir_info_name(fat_dir_info_name, current);
        }
        char fat_dir_info_long_name[FAT_LFN_NAME_LEN + 1] = {0};
        while (pdir->position < pdir->capacity) {
            int is_lfn = 0;
            if ((((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_LONG_FILE_NAME) != FAT_ATTRIBUTE_LONG_FILE_NAME) && (*(pdir->info + pdir->position)->name == '\0' || *(pdir->info + pdir->position)->name == FAT_DIR_DELETED || ((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_VOLUME_LABEL) == FAT_ATTRIBUTE_VOLUME_LABEL)) {
                ++pdir->position;
                continue;
            }
            if (((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_LONG_FILE_NAME) == FAT_ATTRIBUTE_LONG_FILE_NAME) {
                int number_of_entries = ((struct lfn_dir_info_t *) (pdir->info + pdir->position))->ordinal_number - FAT_LFN_LAST_ENTRY;
                for (int i = 0; i < number_of_entries; ++i) {
                    int lfn_index = 0;
                    for (int j = 0; j < LFN_NAME_PART_ONE_SIZE; ++j) {
                        *(fat_dir_info_long_name + ((number_of_entries - 1 - i) * LFN_NAME_ENTRY_SIZE) + lfn_index++) = (char) *(((struct lfn_dir_info_t *) (pdir->info + pdir->position))->name_part_one + j);
                    }
                    for (int j = 0; j < LFN_NAME_PART_TWO_SIZE; ++j) {
                        *(fat_dir_info_long_name + ((number_of_entries - 1 - i) * LFN_NAME_ENTRY_SIZE) + lfn_index++) = (char) *(((struct lfn_dir_info_t *) (pdir->info + pdir->position))->name_part_two + j);
                    }
                    for (int j = 0; j < LFN_NAME_PART_THREE_SIZE; ++j) {
                        *(fat_dir_info_long_name + ((number_of_entries - 1 - i) * LFN_NAME_ENTRY_SIZE) + lfn_index++) = (char) *(((struct lfn_dir_info_t *) (pdir->info + pdir->position))->name_part_three + j);
                    }
                    ++pdir->position;
                }
                is_lfn = 1;
            }
            if (ignore_case_strcmp(fat_dir_info_name, (pdir->info + pdir->position)->name, FAT_DIR_INFO_NAME_LEN) == 0 || (strlen(current) == strlen(fat_dir_info_long_name) && ignore_case_strcmp(fat_dir_info_long_name, current, strlen(current)) == 0)) {
                if (((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_DIRECTORY) == FAT_ATTRIBUTE_DIRECTORY) {
                    if (memcmp(current, ".          ", FAT_DIR_INFO_NAME_LEN) != 0) {
                        struct clusters_chain_t *clusters_chain = get_chain_fat16(pvolume->first_fat, pvolume->boot_sector.sectors_per_fat * pvolume->boot_sector.bytes_per_sector, (pdir->info + pdir->position)->first_cluster_low_bytes);
                        if (clusters_chain == NULL) {
                            free(path_copy);
                            dir_close(pdir);
                            errno = ENOMEM;
                            return NULL;
                        }
                        lba_t total_sectors;
                        if ((pdir->info + pdir->position)->first_cluster_low_bytes == 0) {
                            total_sectors = pvolume->root_dir_size;
                        } else {
                            total_sectors = clusters_chain->size * pvolume->boot_sector.sectors_per_cluster;
                        }
                        size_t dir_info_size_in_bytes = total_sectors * pvolume->boot_sector.bytes_per_sector;
                        uint8_t *dir_info = malloc(dir_info_size_in_bytes * sizeof(uint8_t));
                        if (dir_info == NULL) {
                            free(path_copy);
                            free(clusters_chain->clusters);
                            free(clusters_chain);
                            dir_close(pdir);
                            errno = ENOMEM;
                            return NULL;
                        }
                        if ((pdir->info + pdir->position)->first_cluster_low_bytes == 0) {
                            disk_read(pvolume->pdisk, (int) pvolume->root_dir_position, dir_info, (int) pvolume->root_dir_size);
                        } else {
                            for (int i = 0; i < (int) clusters_chain->size; ++i) {
                                lba_t sector_number = pvolume->second_cluster_position + (*(clusters_chain->clusters + i) - 2) * pvolume->boot_sector.sectors_per_cluster;
                                disk_read(pvolume->pdisk, (int) sector_number, dir_info + (i * pvolume->boot_sector.sectors_per_cluster * pvolume->boot_sector.bytes_per_sector), (int) pvolume->boot_sector.sectors_per_cluster);
                            }
                        }
                        free(clusters_chain->clusters);
                        free(clusters_chain);
                        free(pdir->info);
                        pdir->info = (void *) dir_info;
                        pdir->position = 0;
                        pdir->capacity = dir_info_size_in_bytes / sizeof(struct dir_info_t);
                    }
                }
                if (seek_type == SEEK_FILE && (next == NULL || (is_lfn && ((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_DIRECTORY) != FAT_ATTRIBUTE_DIRECTORY))) {
                    if (((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_DIRECTORY) == FAT_ATTRIBUTE_DIRECTORY) {
                        free(path_copy);
                        dir_close(pdir);
                        errno = EISDIR;
                        return NULL;
                    }
                    free(path_copy);
                    struct dir_info_t *file_info = malloc(sizeof(struct dir_info_t));
                    if (file_info == NULL) {
                        dir_close(pdir);
                        errno = ENOMEM;
                        return NULL;
                    }
                    memcpy(file_info, (pdir->info + pdir->position), sizeof(struct dir_info_t));
                    dir_close(pdir);
                    return file_info;
                }
                break;
            }
            ++pdir->position;
        }
        if (pdir->position == pdir->capacity) {
            free(path_copy);
            dir_close(pdir);
            return NULL;
        }
        current = next;
    } while (current);
    free(path_copy);
    if (((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_DIRECTORY) != FAT_ATTRIBUTE_DIRECTORY) {
        dir_close(pdir);
        return NULL;
    }
    return pdir;
}

struct dir_t *dir_open(struct volume_t *pvolume, const char *dir_path) {
    if (pvolume == NULL || dir_path == NULL) {
        errno = EFAULT;
        return NULL;
    }
    return find_dir_or_file_by_path(pvolume, dir_path, SEEK_DIR);
}

int dir_read(struct dir_t *pdir, struct dir_entry_t *pentry) {
    if (pdir == NULL || pentry == NULL) {
        errno = EFAULT;
        return -1;
    }
    while (pdir->position < pdir->capacity) {
        if ((((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_LONG_FILE_NAME) != FAT_ATTRIBUTE_LONG_FILE_NAME) && (*(pdir->info + pdir->position)->name == '\0' || *(pdir->info + pdir->position)->name == FAT_DIR_DELETED || ((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_VOLUME_LABEL) == FAT_ATTRIBUTE_VOLUME_LABEL)) {
            ++pdir->position;
            continue;
        }
        if (((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_LONG_FILE_NAME) == FAT_ATTRIBUTE_LONG_FILE_NAME) {
            pentry->has_long_name = 1;
            char fat_dir_entry_long_name[FAT_LFN_NAME_LEN + 1] = {0};
            int number_of_entries = ((struct lfn_dir_info_t *) (pdir->info + pdir->position))->ordinal_number - FAT_LFN_LAST_ENTRY;
            for (int i = 0; i < number_of_entries; ++i) {
                int lfn_index = 0;
                for (int j = 0; j < LFN_NAME_PART_ONE_SIZE; ++j) {
                    *(fat_dir_entry_long_name + ((number_of_entries - 1 - i) * LFN_NAME_ENTRY_SIZE) + lfn_index++) = (char) *(((struct lfn_dir_info_t *) (pdir->info + pdir->position))->name_part_one + j);
                }
                for (int j = 0; j < LFN_NAME_PART_TWO_SIZE; ++j) {
                    *(fat_dir_entry_long_name + ((number_of_entries - 1 - i) * LFN_NAME_ENTRY_SIZE) + lfn_index++) = (char) *(((struct lfn_dir_info_t *) (pdir->info + pdir->position))->name_part_two + j);
                }
                for (int j = 0; j < LFN_NAME_PART_THREE_SIZE; ++j) {
                    *(fat_dir_entry_long_name + ((number_of_entries - 1 - i) * LFN_NAME_ENTRY_SIZE) + lfn_index++) = (char) *(((struct lfn_dir_info_t *) (pdir->info + pdir->position))->name_part_three + j);
                }
                ++pdir->position;
            }
            memcpy(pentry->long_name, fat_dir_entry_long_name, FAT_LFN_NAME_LEN);
        } else {
            pentry->has_long_name = 0;
            char fat_dir_entry_name[FAT_DIR_ENTRY_NAME_LEN] = {0};
            convert_to_fat_dir_entry_name(fat_dir_entry_name, (pdir->info + pdir->position)->name);
            memcpy(pentry->name, fat_dir_entry_name, FAT_DIR_ENTRY_NAME_LEN);
        }
        pentry->size = (pdir->info + pdir->position)->size;
        pentry->is_readonly = (((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_READ_ONLY) == FAT_ATTRIBUTE_READ_ONLY) ? 1 : 0;
        pentry->is_hidden = (((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_HIDDEN) == FAT_ATTRIBUTE_HIDDEN) ? 1 : 0;
        pentry->is_system = (((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_SYSTEM) == FAT_ATTRIBUTE_SYSTEM) ? 1 : 0;
        pentry->is_directory = (((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_DIRECTORY) == FAT_ATTRIBUTE_DIRECTORY) ? 1 : 0;
        pentry->is_archived = (((pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_ARCHIVED) == FAT_ATTRIBUTE_ARCHIVED) ? 1 : 0;
        ++pdir->position;
        return 0;
    }
    return 1;
}

int dir_close(struct dir_t *pdir) {
    if (pdir == NULL) {
        errno = EFAULT;
        return -1;
    }
    free(pdir->info);
    free(pdir);
    return 0;
}

uint16_t get_next_cluster(uint16_t current_cluster, void *buffer) {
    return *((uint16_t *) buffer + current_cluster);
}

struct clusters_chain_t *get_chain_fat16(const void *const buffer, size_t size, uint16_t first_cluster) {
    if (buffer == NULL || size < 1) {
        return NULL;
    }
    struct clusters_chain_t *fat16_clusters_chain = malloc(sizeof(struct clusters_chain_t));
    if (fat16_clusters_chain == NULL) {
        return NULL;
    }
    fat16_clusters_chain->clusters = malloc(sizeof(uint16_t));
    if (fat16_clusters_chain->clusters == NULL) {
        free(fat16_clusters_chain);
        return NULL;
    }
    fat16_clusters_chain->size = 1;
    *fat16_clusters_chain->clusters = first_cluster;
    uint16_t current_cluster = first_cluster;
    for (size_t i = 0; i < size; ++i) {
        current_cluster = get_next_cluster(current_cluster, (void *) buffer);
        if (current_cluster == *((uint16_t *) buffer)) {
            return fat16_clusters_chain;
        }
        uint16_t *clusters_ptr = realloc(fat16_clusters_chain->clusters, (fat16_clusters_chain->size + 1) * sizeof(uint16_t));
        if (clusters_ptr == NULL) {
            free(fat16_clusters_chain->clusters);
            free(fat16_clusters_chain);
            return NULL;
        }
        fat16_clusters_chain->clusters = clusters_ptr;
        *(fat16_clusters_chain->clusters + fat16_clusters_chain->size) = current_cluster;
        ++fat16_clusters_chain->size;
    }
    return fat16_clusters_chain;
}

int convert_to_fat_dir_info_name(char *fat_name, const char *file_name) {
    memset(fat_name, ' ', FAT_DIR_INFO_NAME_LEN);
    if (strcmp(file_name, ".") == 0 || strcmp(file_name, "..") == 0) {
        strncpy(fat_name, file_name, strlen(file_name));
    } else {
        char full_name[FAT_DIR_ENTRY_NAME_LEN] = {0};
        strcpy(full_name, file_name);
        char name[FAT_NAME_LEN + 1] = {0};
        char extension[FAT_EXTENSION_LEN + 1] = {0};
        char *extension_position = strchr(full_name, '.');
        if (extension_position) {
            *extension_position++ = '\0';
            strcpy(extension, extension_position);
        }
        strcpy(name, full_name);
        memcpy(fat_name, name, strlen(name));
        memcpy(fat_name + FAT_NAME_LEN, extension, strlen(extension));
    }
    return 0;
}

int convert_to_fat_dir_entry_name(char *fat_name, const char *file_name) {
    char name[FAT_NAME_LEN + 1] = {0};
    char extension[FAT_EXTENSION_LEN + 1] = {0};
    memcpy(name, file_name, FAT_NAME_LEN);
    memcpy(extension, file_name + FAT_NAME_LEN, FAT_EXTENSION_LEN);
    char *space_position = strchr(name, ' ');
    if (space_position) {
        *space_position = '\0';
    }
    space_position = strchr(extension, ' ');
    if (space_position) {
        *space_position = '\0';
    }
    size_t name_len = strlen(name);
    size_t extension_len = strlen(extension);
    memcpy(fat_name, name, name_len);
    if (extension_len) {
        *(fat_name + name_len) = '.';
        memcpy(fat_name + name_len + 1, extension, extension_len);
    }
    return 0;
}
