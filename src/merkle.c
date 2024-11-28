#include <string.h>
#include "../inc/merkle.h"

/* Merkle Tree
    Merkle树是由多个层级组成的，每一层都是一个哈希数组。
    Merkle树用于验证数据的一致性，常用于区块链、分布式系统等领域。
*/

#define MERKLE_INIT_LEVELS 16 // 初始化Merkle树的最大层数
#define MERKLE_INIT_HASHES 16 // 每层初始化最多16个哈希节点

// 获取哈希函数的宽度
static uint32_t get_hash_width(hash_e c)
{
#define HASH_WIDTHS(_name, _width) _width,
    uint32_t hash_widths[] = {
        HASH_CODEC(HASH_WIDTHS) // 从宏定义HASH_CODEC中获取每种哈希算法的宽度
    };
#undef HASH_WIDTHS

    return hash_widths[c]; // 返回对应哈希算法的宽度
}

// 获取哈希函数
static hash_func get_hash_func(hash_e c)
{
#define HASH_FUNCS(_name, _width) &hash_##_name,
    hash_func hash_funcs[] = {
        HASH_CODEC(HASH_FUNCS) // 从宏定义HASH_CODEC中获取每种哈希算法的函数指针
    };
#undef HASH_FUNCS

    return hash_funcs[c]; // 返回对应哈希算法的哈希函数
}

// 初始化Merkle树
merkle_err_t merkle_init(merkle_t *m, hash_e c)
{
    merkle_err_t err;

    // 初始化Merkle树的各级哈希数组
    err = array_init(&m->levels, MERKLE_INIT_LEVELS, sizeof(array_t));
    if (err != MERKLE_OK)
    {
        return err; // 初始化失败，返回错误
    }

    m->hash_width = get_hash_width(c); // 获取哈希宽度
    m->hash_func = get_hash_func(c);   // 获取哈希函数

    return MERKLE_OK; // 初始化成功
}

// 反初始化，释放Merkle树占用的内存
void merkle_deinit(merkle_t *m)
{
    for (uint32_t i = 0; i < array_len(&m->levels); i++)
    {
        array_t *level = array_get(&m->levels, i);
        array_deinit(level); // 释放每一层的内存
    }

    array_deinit(&m->levels); // 释放树的顶层内存
}

// 获取Merkle树的根哈希
merkle_hash_t merkle_root(merkle_t *m)
{
    return array_get(array_get(&m->levels, array_len(&m->levels) - 1), 0);
}

// 向Merkle树中添加一个新的哈希值
merkle_err_t merkle_add(merkle_t *m, merkle_hash_t hash)
{
    merkle_err_t err;
    uint8_t hashcpy[m->hash_width]; // 用于存储拷贝的哈希
    size_t level_idx = 0;           // 当前层的索引
    int replace = 0;                // 是否替换上一级哈希

    memcpy(hashcpy, hash, m->hash_width); // 拷贝传入的哈希值

    do
    {
        array_t *level;
        merkle_hash_t *node;

        // 如果当前层数不足，创建新的一层
        if (array_len(&m->levels) == level_idx)
        {
            level = array_push(&m->levels);
            if (level == NULL)
            {
                return MERKLE_ERROR; // 内存分配失败，返回错误
            }

            // 初始化这一层的哈希数组
            err = array_init(level, MERKLE_INIT_HASHES, m->hash_width);
            if (err != MERKLE_OK)
            {
                return err; // 初始化失败，返回错误
            }
        }
        else
        {
            level = array_get(&m->levels, level_idx); // 获取当前层
        }

        // 处理当前层的哈希节点
        node = replace && array_len(level) > 0 ? array_top(level) : array_push(level);
        if (node == NULL)
        {
            return MERKLE_ERROR; // 内存分配失败，返回错误
        }

        memcpy(node, hashcpy, m->hash_width); // 将哈希值复制到当前节点

        // 如果是根层（只有一个节点），则停止
        if (array_len(level) == 1)
        {
            break;
        }

        // 如果当前层的哈希节点数量是偶数，合并最后两个哈希
        if (array_len(level) % 2 == 0)
        {
            m->hash_func(array_get(level, array_len(level) - 2), hashcpy); // 计算父节点的哈希
        }

        // 如果当前层是偶数个哈希，替换父节点的哈希；否则，直接推入父节点
        replace = replace || array_len(level) % 2 == 0;

        level_idx++; // 进入下一层
    } while (1);

    return MERKLE_OK; // 添加成功
}

// 初始化Merkle证明结构
#define MERKLE_PROOF_INIT_HASHES 4
merkle_err_t merkle_proof_init(merkle_proof_t *p, hash_e c)
{
    merkle_err_t err;

    // 初始化哈希数组
    err = array_init(&p->hashes, MERKLE_PROOF_INIT_HASHES, p->hash_width);
    if (err != MERKLE_OK)
    {
        return err;
    }

    // 初始化左右信息数组
    err = array_init(&p->left_right, MERKLE_PROOF_INIT_HASHES, sizeof(int));
    if (err != MERKLE_OK)
    {
        return err;
    }

    p->hash_width = get_hash_width(c); // 获取哈希宽度
    p->hash_func = get_hash_func(c);   // 获取哈希函数

    return MERKLE_OK; // 初始化成功
}

// 反初始化Merkle证明结构，释放内存
void merkle_proof_deinit(merkle_proof_t *p)
{
    array_deinit(&p->hashes);
    array_deinit(&p->left_right);
}

// 生成Merkle证明
merkle_err_t merkle_proof(merkle_proof_t *p, merkle_t *m, merkle_hash_t hash)
{
    int i;
    int level_idx = 0;
    merkle_hash_t node;
    merkle_hash_t p_hash;
    int *pos;

    if (array_len(&m->levels) < 2)
    {
        return MERKLE_ERROR; // 如果Merkle树没有足够的层级，返回错误
    }

    array_t *level = array_get(&m->levels, 0);
    for (i = 0; i < array_len(level); i++)
    {
        if (memcmp(hash, array_get(level, i), p->hash_width) == 0)
        {
            break; // 找到匹配的哈希值
        }
    }

    if (i >= array_len(level))
    {
        return MERKLE_NOTFOUND; // 没有找到该哈希值
    }

    do
    {
        // 如果i是偶数，兄弟节点在右边；如果是奇数，兄弟节点在左边
        if (i % 2 == 0)
        {
            if (i == array_len(level) - 1)
            {
                // 如果是最后一个节点，跳到上一层
                goto uplevel;
            }
            node = array_get(level, i + 1);
        }
        else
        {
            node = array_get(level, i - 1);
        }

        if (node == NULL)
        {
            return MERKLE_ERROR; // 错误，无法找到兄弟节点
        }

        p_hash = array_push(&p->hashes);
        if (p_hash == NULL)
        {
            return MERKLE_ERROR; // 内存分配失败，返回错误
        }
        memcpy(p_hash, node, p->hash_width); // 复制兄弟节点的哈希值

        pos = array_push(&p->left_right);
        if (pos == NULL)
        {
            return MERKLE_ERROR; // 内存分配失败，返回错误
        }
        *pos = i % 2 == 0; // 记录节点位置，偶数为右，奇数为左

    uplevel:
        // 计算父节点的位置
        i = i / 2;
        level_idx++;
        level = array_get(&m->levels, level_idx);
    } while (array_len(level) != 1); // 一直向上直到根节点

    return MERKLE_OK; // 生成证明成功
}

// 验证Merkle证明
merkle_err_t merkle_proof_validate(merkle_proof_t *p, merkle_hash_t root,
                                   merkle_hash_t hash, int *valid)
{
    int *pos;
    int left_right;
    uint8_t result[p->hash_width * 2]; // 存储合并后的哈希结果

    // 初始化结果哈希
    if (array_len(&p->hashes) < 1)
    {
        left_right = 0;
    }
    else
    {
        pos = array_get(&p->left_right, 0);
        left_right = *pos ? 0 : 1;
    }
    memcpy(result + (left_right * p->hash_width), hash, p->hash_width);

    // 遍历证明哈希，逐步计算根哈希
    for (int i = 0; i < array_len(&p->hashes); i++)
    {
        pos = array_get(&p->left_right, i);
        memcpy(result + ((*pos) * p->hash_width), array_get(&p->hashes, i), p->hash_width);

        left_right = 0;
        if (i < array_len(&p->hashes) - 1)
        {
            pos = array_get(&p->left_right, i + 1);
            left_right = *pos ? 0 : 1;
        }

        p->hash_func(result, result + (left_right * p->hash_width)); // 计算父节点哈希
    }

    *valid = memcmp(result, root, p->hash_width) == 0; // 判断计算出来的哈希是否与根哈希匹配
    return MERKLE_OK;                                  // 验证成功
}

// 打印Merkle树的哈希值
void merkle_print_hash(merkle_hash_t hash, int print_width)
{
    for (int i = 0; i < print_width; i++)
    {
        printf("%02x", hash[i]); // 打印每个字节的十六进制表示
    }
}

// 打印整个Merkle树
void merkle_print(merkle_t *m, int print_width)
{
    struct winsize w;
    int midpoint;

    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w); // 获取终端的宽度
    midpoint = w.ws_col / 2;              // 计算树的中点位置

    printf("%*s%s\n", midpoint, "", "."); // 打印树的顶端

    for (int i = array_len(&m->levels) - 1; i >= 0; i--)
    {
        int indent = midpoint - (print_width / 2) * (1 << (array_len(&m->levels) - i));
        array_t *level = array_get(&m->levels, i); // 获取当前层的哈希节点

        if (i != array_len(&m->levels) - 1)
        {
            indent -= (1 << (array_len(&m->levels) - i - 2)) - 1; // 调整缩进
        }
        if (indent < 0)
            indent = 0; // 保证缩进不小于0

        printf("%*s", indent, ""); // 打印空白缩进

        for (int j = 0; j < array_len(level); j++)
        {
            merkle_hash_t hash = array_get(level, j);

            if (j != 0)
                printf("|"); // 打印分隔符

            merkle_print_hash(hash, print_width); // 打印哈希值
        }

        printf("\n");
    }
}

// 打印Merkle证明
void merkle_proof_print(merkle_proof_t *p, int print_width)
{
    printf("=[");
    for (int i = 0; i < array_len(&p->hashes); i++)
    {
        merkle_hash_t hash = array_get(&p->hashes, i);

        merkle_print_hash(hash, print_width);
        if (i != array_len(&p->hashes) - 1)
        {
            printf(",");
        }
    }
    printf("]\n"); // 打印所有的证明哈希值
}
