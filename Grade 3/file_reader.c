#include "file_reader.h"

enum boot_sector_error_t {
    ERROR_BOOT_SECTOR_ALL_OK,
    ERROR_BOOT_SECTOR_NULL_PTR,
    ERROR_BOOT_SECTOR_NUMBER_OF_FAT_COPIES,
    ERROR_BOOT_SECTOR_EOS_MARKER,
    ERROR_BOOT_SECTOR_NUMBER_OF_SECTORS,
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
        return ERROR_BOOT_SECTOR_NUMBER_OF_FAT_COPIES;
    }
    if (boot_sector->end_of_sector_marker != FAT_END_OF_SECTOR_MARKER) {
        return ERROR_BOOT_SECTOR_EOS_MARKER;
    }
    if (!(boot_sector->small_number_of_sectors ^ boot_sector->large_number_of_sectors)) {
        return ERROR_BOOT_SECTOR_NUMBER_OF_SECTORS;
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
    if (fat_1_result != pvolume->boot_sector.sectors_per_fat || fat_2_result != pvolume->boot_sector.sectors_per_fat ||
        memcmp(pvolume->first_fat, pvolume->second_fat, bytes_per_fat) != 0) {
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

struct file_t *file_open(struct volume_t *pvolume, const char *file_name) {
    if (pvolume == NULL || file_name == NULL) {
        errno = EFAULT;
        return NULL;
    }
    char file_name_copy[FAT_DIR_ENTRY_FULL_NAME_LEN];
    strcpy(file_name_copy, file_name);
    char converted_name[FAT_DIR_INFO_FULL_NAME_LEN];
    memset(converted_name, ' ', FAT_DIR_INFO_FULL_NAME_LEN);
    char *dot_position = strchr(file_name_copy, '.');
    char *extension_position = NULL;
    if (dot_position) {
        extension_position = dot_position + 1;
        *dot_position = '\0';
    }
    memcpy(converted_name, file_name_copy, strlen(file_name_copy));
    if (extension_position) {
        memcpy(converted_name + FAT_NAME_LEN, extension_position, strlen(extension_position));
    }
    struct dir_info_t *dir_info = (void *) pvolume->root_dir;
    uint8_t file_found = 0;
    for (uint16_t i = 0; i < pvolume->boot_sector.root_dir_capacity; ++i) {
        if (memcmp(dir_info->name, converted_name, FAT_DIR_INFO_FULL_NAME_LEN) == 0) {
            if (dir_info->attributes & FAT_ATTRIBUTE_DIRECTORY) {
                errno = EISDIR;
                return NULL;
            }
            file_found = 1;
            break;
        }
        ++dir_info;
    }
    if (file_found == 0) {
        errno = ENOENT;
        return NULL;
    }
    struct file_t *file = malloc(sizeof(struct file_t));
    if (file == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    file->pvolume = pvolume;
    file->info = dir_info;
    file->clusters_chain = get_chain_fat16(pvolume->first_fat, pvolume->boot_sector.sectors_per_fat * pvolume->boot_sector.bytes_per_sector, file->info->first_cluster_low_bytes);
    file->position = 0;
    if (file->clusters_chain == NULL) {
        free(file);
        errno = ENOMEM;
        return NULL;
    }
    return file;
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
    uint8_t *data_block_ptr = data_block;
    uint8_t *buffer_ptr = (uint8_t *) ptr;
    size_t elements_read = 0;
    if (stream->position % bytes_per_cluster != 0) {
        uint16_t current_cluster = *(stream->clusters_chain->clusters + stream->position / bytes_per_cluster);
        if (current_cluster == *((uint16_t *) stream->pvolume->first_fat)) {
            free(data_block);
            return elements_read;
        }
        lba_t sector_number = stream->pvolume->second_cluster_position + (current_cluster - 2) * stream->pvolume->boot_sector.sectors_per_cluster;
        if (disk_read(stream->pvolume->pdisk, (int) sector_number, data_block, stream->pvolume->boot_sector.sectors_per_cluster) == -1) {
            errno = ERANGE;
            free(data_block);
            return -1;
        }
        data_block_ptr = data_block;
        data_block_ptr += stream->position % bytes_per_cluster;
    }
    for (size_t i = 0; i < nmemb && stream->position < stream->info->size; ++i) {
        size_t j;
        for (j = 0; j < size && stream->position < stream->info->size; ++j) {
            if (stream->position % bytes_per_cluster == 0) {
                uint16_t current_cluster = *(stream->clusters_chain->clusters + stream->position / bytes_per_cluster);
                if (current_cluster == *((uint16_t *) stream->pvolume->first_fat)) {
                    free(data_block);
                    return elements_read;
                }
                lba_t sector_number = stream->pvolume->second_cluster_position + (current_cluster - 2) * stream->pvolume->boot_sector.sectors_per_cluster;
                if (disk_read(stream->pvolume->pdisk, (int) sector_number, data_block, stream->pvolume->boot_sector.sectors_per_cluster) == -1) {
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
    free(stream);
    return 0;
}

struct dir_t *dir_open(struct volume_t *pvolume, const char *dir_path) {
    if (pvolume == NULL || dir_path == NULL) {
        errno = EFAULT;
        return NULL;
    }
    if (strcmp("\\", dir_path) != 0) {
        errno = ENOENT;
        return NULL;
    }
    struct dir_t *dir = malloc(sizeof(struct dir_t));
    if (dir == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    dir->info = (void *) pvolume->root_dir;
    dir->capacity = pvolume->boot_sector.root_dir_capacity;
    dir->position = 0;
    return dir;
}

int dir_read(struct dir_t *pdir, struct dir_entry_t *pentry) {
    if (pdir == NULL || pentry == NULL) {
        errno = EFAULT;
        return -1;
    }
    while (pdir->position < pdir->capacity) {
        if (*(pdir->info + pdir->position)->name == '\0' || *(pdir->info + pdir->position)->name == FAT_DIR_DELETED || (pdir->info + pdir->position)->attributes & FAT_ATTRIBUTE_VOLUME_LABEL) {
            ++pdir->position;
            continue;
        }
        char name_buffer[FAT_NAME_LEN + 1] = {0};
        char extension_buffer[FAT_EXTENSION_LEN + 1] = {0};
        memcpy(name_buffer, (pdir->info + pdir->position)->name, FAT_NAME_LEN);
        memcpy(extension_buffer, (pdir->info + pdir->position)->name + +FAT_NAME_LEN, FAT_EXTENSION_LEN);
        char *space_position = strchr(name_buffer, ' ');
        if (space_position) {
            *space_position = '\0';
        }
        space_position = strchr(extension_buffer, ' ');
        if (space_position) {
            *space_position = '\0';
        }
        size_t name_len = strlen(name_buffer);
        size_t extension_len = strlen(extension_buffer);
        char full_name[FAT_DIR_ENTRY_FULL_NAME_LEN] = {0};
        memcpy(full_name, name_buffer, name_len);
        if (extension_len) {
            *(full_name + name_len) = '.';
            memcpy(full_name + name_len + 1, extension_buffer, extension_len);
        }
        memcpy(pentry->name, full_name, FAT_DIR_ENTRY_FULL_NAME_LEN);
        pentry->size = (pdir->info + pdir->position)->size;
        pentry->is_directory = ((pdir->info + pdir->position)->attributes) & FAT_ATTRIBUTE_DIRECTORY;
        pentry->is_archived = ((pdir->info + pdir->position)->attributes) & FAT_ATTRIBUTE_ARCHIVED;
        pentry->is_hidden = ((pdir->info + pdir->position)->attributes) & FAT_ATTRIBUTE_HIDDEN;
        pentry->is_readonly = ((pdir->info + pdir->position)->attributes) & FAT_ATTRIBUTE_READ_ONLY;
        pentry->is_system = ((pdir->info + pdir->position)->attributes) & FAT_ATTRIBUTE_SYSTEM;
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
    memcpy(fat16_clusters_chain->clusters, &first_cluster, sizeof(uint16_t));
    fat16_clusters_chain->size = 1;
    uint16_t current_cluster = first_cluster;
    for (size_t i = 0; i < size; ++i) {
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
        *(fat16_clusters_chain->clusters + fat16_clusters_chain->size) = *((uint16_t *) buffer + current_cluster);
        ++fat16_clusters_chain->size;
        current_cluster = get_next_cluster(current_cluster, (void *) buffer);
    }
    return fat16_clusters_chain;
}
