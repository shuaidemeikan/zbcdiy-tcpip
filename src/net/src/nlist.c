#include "nlist.h"

/**
 * 初始化链表
 * @param list 待初始化的链表
 */
void nlist_init(nlist_t* list)
{
    list->first = list->last = (nlist_node_t*)0;
    list->count = 0;
}

/**
 * 从链表的头部插入一个节点
 * @param list 待被插入的链表
 * @param node 带插入的节点
 */
void nlist_insert_first(nlist_t* list, nlist_node_t* node)
{
    node->pre = (nlist_node_t*)0;
    node->next = list->first;

    if (nlist_is_empty(list))
        list->first = list->last = node;
    else
    {
        list->first->pre = node;
        list->first = node;
    }
    list->count++;
}

/**
 * 从链表的尾部插入一个节点
 * @param list 待被插入的链表
 * @param node 带插入的节点
 */
void nlist_insert_last(nlist_t* list, nlist_node_t* node)
{
    node->next = (nlist_node_t*)0;
    node->pre = list->last;
    if (nlist_is_empty(list))
        list->first = list->last = node;
    else
    {
        list->last->next = node;
        list->last = node;
    }
    list->count++;
}

/**
 * 从链表的任意一个节点的后面插入一个节点
 * @param list 待被插入的链表
 * @param pre 往该节点的后一个位置插入
 * @param node 带插入的节点
 */
void nlist_insert_after(nlist_t* list, nlist_node_t* pre, nlist_node_t* node)
{
    if (nlist_is_empty(list) || !pre)
    {
        nlist_insert_first(list, node);
        return;
    }
    node->next = pre->next;
    node->pre = pre;

    // 判断被插入节点后是否有节点，同时如果后面没节点了，那么就相当于是尾插入
    if (pre->next)
        pre->next->pre = node;
    else
        list->last = node;
    pre->next = node;
    (list->count)++;
}

/**
 * 从链表移除一个节点
 * @param list 待被移除节点的链表
 * @param node 待被移除的节点
 * @return 被移除的节点
 */
nlist_node_t* nlist_remove(nlist_t* list, nlist_node_t* node)
{   // 首先判断该节点是不是首尾结点
    if (node == list->first)
        list->first = node->next;
    if (node == list->last)
        list->last = node->pre;
    // 再根据该节点前后是否有节点来修改
    if (node->pre)
        node->pre->next = node->next;
    if (node->next)
        node->next->pre = node->pre;
    // 将该节点清空
    node->pre = node->next = (nlist_node_t*)0;
    // 修改链表内节点的数量
    (list->count)--;
    return node;
}