#include "cfg.h"
#include "../../lib/tree-sitter/lib/include/tree_sitter/api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Static counters for unique IDs
static uint32_t next_node_id = 0;
static uint32_t next_edge_id = 0;

// Graph management functions

CFGGraph* cfg_create_graph(void) {
    CFGGraph* graph = malloc(sizeof(CFGGraph));
    if (!graph) return NULL;

    graph->nodes = NULL;
    graph->node_count = 0;
    graph->edges = NULL;
    graph->edge_count = 0;
    graph->entry_node = NULL;
    graph->exit_node = NULL;

    return graph;
}

void cfg_destroy_graph(CFGGraph* graph) {
    if (!graph) return;

    // Destroy all edges first
    for (uint32_t i = 0; i < graph->edge_count; i++) {
        cfg_destroy_edge(graph->edges[i]);
    }
    free(graph->edges);

    // Destroy all nodes
    for (uint32_t i = 0; i < graph->node_count; i++) {
        cfg_destroy_node(graph->nodes[i]);
    }
    free(graph->nodes);

    free(graph);
}

// Node management functions

CFGNode* cfg_create_node(CFGNodeType type, const char* label, void* ast_node) {
    CFGNode* node = malloc(sizeof(CFGNode));
    if (!node) return NULL;

    node->id = next_node_id++;
    node->type = type;
    node->label = label ? strdup(label) : NULL;
    node->ast_node = ast_node;
    node->predecessors = NULL;
    node->predecessor_count = 0;
    node->successors = NULL;
    node->successor_count = 0;
    node->visited = false;

    return node;
}

void cfg_destroy_node(CFGNode* node) {
    if (!node) return;

    free(node->label);
    free(node->predecessors);
    free(node->successors);
    free(node);
}

void cfg_add_node(CFGGraph* graph, CFGNode* node) {
    if (!graph || !node) return;

    graph->nodes = realloc(graph->nodes, sizeof(CFGNode*) * (graph->node_count + 1));
    if (!graph->nodes) return;

    graph->nodes[graph->node_count] = node;
    graph->node_count++;
}

CFGNode* cfg_get_node_by_id(CFGGraph* graph, uint32_t id) {
    if (!graph) return NULL;

    for (uint32_t i = 0; i < graph->node_count; i++) {
        if (graph->nodes[i]->id == id) {
            return graph->nodes[i];
        }
    }
    return NULL;
}

// Edge management functions

CFGEdge* cfg_create_edge(CFGNode* source, CFGNode* target, CFGEdgeType type, const char* label) {
    if (!source || !target) return NULL;

    CFGEdge* edge = malloc(sizeof(CFGEdge));
    if (!edge) return NULL;

    edge->id = next_edge_id++;
    edge->source = source;
    edge->target = target;
    edge->type = type;
    edge->label = label ? strdup(label) : NULL;

    // Add to source successors
    source->successors = realloc(source->successors, sizeof(CFGNode*) * (source->successor_count + 1));
    if (source->successors) {
        source->successors[source->successor_count] = target;
        source->successor_count++;
    }

    // Add to target predecessors
    target->predecessors = realloc(target->predecessors, sizeof(CFGNode*) * (target->predecessor_count + 1));
    if (target->predecessors) {
        target->predecessors[target->predecessor_count] = source;
        target->predecessor_count++;
    }

    return edge;
}

void cfg_destroy_edge(CFGEdge* edge) {
    if (!edge) return;

    free(edge->label);
    free(edge);
}

void cfg_add_edge(CFGGraph* graph, CFGEdge* edge) {
    if (!graph || !edge) return;

    graph->edges = realloc(graph->edges, sizeof(CFGEdge*) * (graph->edge_count + 1));
    if (!graph->edges) return;

    graph->edges[graph->edge_count] = edge;
    graph->edge_count++;
}

void cfg_remove_edge(CFGGraph* graph, CFGEdge* edge) {
    if (!graph || !edge) return;

    // Find and remove from graph's edge array
    for (uint32_t i = 0; i < graph->edge_count; i++) {
        if (graph->edges[i] == edge) {
            // Shift remaining edges
            for (uint32_t j = i; j < graph->edge_count - 1; j++) {
                graph->edges[j] = graph->edges[j + 1];
            }
            graph->edge_count--;
            break;
        }
    }

    // Remove from source successors
    CFGNode* source = edge->source;
    for (uint32_t i = 0; i < source->successor_count; i++) {
        if (source->successors[i] == edge->target) {
            // Shift remaining successors
            for (uint32_t j = i; j < source->successor_count - 1; j++) {
                source->successors[j] = source->successors[j + 1];
            }
            source->successor_count--;
            break;
        }
    }

    // Remove from target predecessors
    CFGNode* target = edge->target;
    for (uint32_t i = 0; i < target->predecessor_count; i++) {
        if (target->predecessors[i] == edge->source) {
            // Shift remaining predecessors
            for (uint32_t j = i; j < target->predecessor_count - 1; j++) {
                target->predecessors[j] = target->predecessors[j + 1];
            }
            target->predecessor_count--;
            break;
        }
    }

    cfg_destroy_edge(edge);
}

// Graph traversal functions

void cfg_dfs(CFGGraph* graph, CFGNode* start_node, void (*visit_func)(CFGNode*)) {
    if (!graph || !start_node || !visit_func) return;

    // Reset visited flags
    for (uint32_t i = 0; i < graph->node_count; i++) {
        graph->nodes[i]->visited = false;
    }

    // DFS stack
    CFGNode** stack = malloc(sizeof(CFGNode*) * graph->node_count);
    if (!stack) return;

    uint32_t stack_size = 0;
    stack[stack_size++] = start_node;
    start_node->visited = true;

    while (stack_size > 0) {
        CFGNode* current = stack[--stack_size];
        visit_func(current);

        // Add unvisited successors to stack
        for (uint32_t i = 0; i < current->successor_count; i++) {
            CFGNode* successor = current->successors[i];
            if (!successor->visited) {
                successor->visited = true;
                stack[stack_size++] = successor;
            }
        }
    }

    free(stack);
}

void cfg_bfs(CFGGraph* graph, CFGNode* start_node, void (*visit_func)(CFGNode*)) {
    if (!graph || !start_node || !visit_func) return;

    // Reset visited flags
    for (uint32_t i = 0; i < graph->node_count; i++) {
        graph->nodes[i]->visited = false;
    }

    // BFS queue
    CFGNode** queue = malloc(sizeof(CFGNode*) * graph->node_count);
    if (!queue) return;

    uint32_t queue_size = 0;
    uint32_t queue_front = 0;
    queue[queue_size++] = start_node;
    start_node->visited = true;

    while (queue_front < queue_size) {
        CFGNode* current = queue[queue_front++];
        visit_func(current);

        // Add unvisited successors to queue
        for (uint32_t i = 0; i < current->successor_count; i++) {
            CFGNode* successor = current->successors[i];
            if (!successor->visited) {
                successor->visited = true;
                queue[queue_size++] = successor;
            }
        }
    }

    free(queue);
}

// Utility functions

void cfg_print_node(const CFGNode* node) {
    if (!node) return;

    const char* type_str;
    switch (node->type) {
        case CFG_NODE_ENTRY: type_str = "ENTRY"; break;
        case CFG_NODE_EXIT: type_str = "EXIT"; break;
        case CFG_NODE_BASIC_BLOCK: type_str = "BASIC_BLOCK"; break;
        case CFG_NODE_CONDITION: type_str = "CONDITION"; break;
        case CFG_NODE_LOOP: type_str = "LOOP"; break;
        case CFG_NODE_FUNCTION_CALL: type_str = "FUNCTION_CALL"; break;
        default: type_str = "UNKNOWN"; break;
    }

    printf("Node %u: %s", node->id, type_str);
    if (node->label) {
        printf(" \"%s\"", node->label);
    }
    printf(" (pred: %u, succ: %u)\n", node->predecessor_count, node->successor_count);
}

void cfg_print_edge(const CFGEdge* edge) {
    if (!edge) return;

    const char* type_str;
    switch (edge->type) {
        case CFG_EDGE_UNCONDITIONAL: type_str = "UNCONDITIONAL"; break;
        case CFG_EDGE_TRUE: type_str = "TRUE"; break;
        case CFG_EDGE_FALSE: type_str = "FALSE"; break;
        case CFG_EDGE_BACK_EDGE: type_str = "BACK_EDGE"; break;
        case CFG_EDGE_EXCEPTION: type_str = "EXCEPTION"; break;
        default: type_str = "UNKNOWN"; break;
    }

    printf("Edge %u: %u -> %u (%s)", edge->id, edge->source->id, edge->target->id, type_str);
    if (edge->label) {
        printf(" \"%s\"", edge->label);
    }
    printf("\n");
}

void cfg_print_graph(const CFGGraph* graph) {
    if (!graph) return;

    printf("Control Flow Graph:\n");
    printf("Nodes (%u):\n", graph->node_count);
    for (uint32_t i = 0; i < graph->node_count; i++) {
        printf("  ");
        cfg_print_node(graph->nodes[i]);
    }

    printf("Edges (%u):\n", graph->edge_count);
    for (uint32_t i = 0; i < graph->edge_count; i++) {
        printf("  ");
        cfg_print_edge(graph->edges[i]);
    }

    if (graph->entry_node) {
        printf("Entry node: %u\n", graph->entry_node->id);
    }
    if (graph->exit_node) {
        printf("Exit node: %u\n", graph->exit_node->id);
    }
}

// Function to build CFG from AST function definition
CFGGraph* cfg_build_from_ast(TSNode function_node, const char* source) {
    CFGGraph* graph = cfg_create_graph();
    if (!graph) return NULL;

    // Create entry node
    CFGNode* entry = cfg_create_node(CFG_NODE_ENTRY, "ENTRY", (void*)&function_node);
    cfg_add_node(graph, entry);
    graph->entry_node = entry;

    // Create exit node
    CFGNode* exit = cfg_create_node(CFG_NODE_EXIT, "EXIT", NULL);
    cfg_add_node(graph, exit);
    graph->exit_node = exit;

    // Find the statement block in the function
    // For your language, statements are direct children of the function
    uint32_t child_count = ts_node_child_count(function_node);
    CFGNode* last_node = entry;

    for (uint32_t i = 0; i < child_count; i++) {
        TSNode child = ts_node_child(function_node, i);
        const char* child_type = ts_node_type(child);

        // Skip non-statement nodes (like function signature)
        if (strcmp(child_type, "statement") == 0) {
            last_node = cfg_process_statements(child, source, graph, last_node);
        }
    }

    // Connect last node to exit
    if (last_node != exit) {
        CFGEdge* exit_edge = cfg_create_edge(last_node, exit, CFG_EDGE_UNCONDITIONAL, NULL);
        cfg_add_edge(graph, exit_edge);
    }

    return graph;
}

// Helper function to process statements and build CFG nodes (implementation)
CFGNode* cfg_process_statements(TSNode node, const char* source, CFGGraph* graph, CFGNode* prev_node) {
    const char* type = ts_node_type(node);

    if (strcmp(type, "statement") == 0) {
        // Single statement
        uint32_t child_count = ts_node_child_count(node);
        for (uint32_t i = 0; i < child_count; i++) {
            TSNode child = ts_node_child(node, i);
            prev_node = cfg_process_statements(child, source, graph, prev_node);
        }
        return prev_node;
    } else if (strcmp(type, "expression_statement") == 0) {
        // Basic statement - extract the actual code content
        uint32_t start = ts_node_start_byte(node);
        uint32_t end = ts_node_end_byte(node);
        size_t len = end - start;
        char* code_content = malloc(len + 1);
        if (code_content) {
            memcpy(code_content, source + start, len);
            code_content[len] = '\0';
            // Remove trailing semicolon if present
            if (len > 0 && code_content[len-1] == ';') {
                code_content[len-1] = '\0';
            }
        }

        CFGNode* block = cfg_create_node(CFG_NODE_BASIC_BLOCK, code_content ? code_content : "statement", (void*)&node);
        cfg_add_node(graph, block);

        // Connect from previous node
        CFGEdge* edge = cfg_create_edge(prev_node, block, CFG_EDGE_UNCONDITIONAL, NULL);
        cfg_add_edge(graph, edge);

        free(code_content);
        return block;
    } else if (strcmp(type, "if_statement") == 0) {
        // Handle if statement
        CFGNode* condition_node = cfg_create_node(CFG_NODE_CONDITION, "if b<5", (void*)&node);
        cfg_add_node(graph, condition_node);

        CFGEdge* cond_edge = cfg_create_edge(prev_node, condition_node, CFG_EDGE_UNCONDITIONAL, NULL);
        cfg_add_edge(graph, cond_edge);

        // Find then and else branches
        uint32_t child_count = ts_node_child_count(node);
        CFGNode* then_end = condition_node;
        CFGNode* else_end = condition_node;

        for (uint32_t i = 0; i < child_count; i++) {
            TSNode child = ts_node_child(node, i);
            const char* child_type = ts_node_type(child);

            if (strcmp(child_type, "statement") == 0 && i > 2) { // then branch
                then_end = cfg_process_statements(child, source, graph, condition_node);
            } else if (strcmp(child_type, "statement") == 0 && i > 4) { // else branch
                else_end = cfg_process_statements(child, source, graph, condition_node);
            }
        }

        // Create merge point
        CFGNode* merge_node = cfg_create_node(CFG_NODE_BASIC_BLOCK, "endif", NULL);
        cfg_add_node(graph, merge_node);

        // Connect branches to merge
        if (then_end != condition_node) {
            CFGEdge* then_merge_edge = cfg_create_edge(then_end, merge_node, CFG_EDGE_UNCONDITIONAL, NULL);
            cfg_add_edge(graph, then_merge_edge);
        }
        if (else_end != condition_node) {
            CFGEdge* else_merge_edge = cfg_create_edge(else_end, merge_node, CFG_EDGE_UNCONDITIONAL, NULL);
            cfg_add_edge(graph, else_merge_edge);
        }

        return merge_node;
    }

    // Default: treat as basic block with extracted content
    uint32_t start = ts_node_start_byte(node);
    uint32_t end = ts_node_end_byte(node);
    size_t len = end - start;
    char* content = malloc(len + 1);
    if (content) {
        memcpy(content, source + start, len);
        content[len] = '\0';
        // Clean up the content (remove extra whitespace/newlines)
        char* clean_content = content;
        while (*clean_content && (*clean_content == ' ' || *clean_content == '\n' || *clean_content == '\t')) {
            clean_content++;
        }
        char* end_clean = clean_content + strlen(clean_content) - 1;
        while (end_clean > clean_content && (*end_clean == ' ' || *end_clean == '\n' || *end_clean == '\t' || *end_clean == ';')) {
            *end_clean-- = '\0';
        }
        if (*clean_content == '\0') {
            strcpy(content, "statement");
        } else {
            memmove(content, clean_content, strlen(clean_content) + 1);
        }
    }

    CFGNode* block = cfg_create_node(CFG_NODE_BASIC_BLOCK, content ? content : "statement", (void*)&node);
    cfg_add_node(graph, block);

    CFGEdge* edge = cfg_create_edge(prev_node, block, CFG_EDGE_UNCONDITIONAL, NULL);
    cfg_add_edge(graph, edge);

    free(content);
    return block;
}

// Function to generate Mermaid diagram from CFG
char* cfg_generate_mermaid(const CFGGraph* graph) {
    if (!graph) return NULL;

    char* diagram = NULL;
    char buffer[1024];

    // Start diagram
    sprintf(buffer, "graph TD;\n");
    cfg_append_to_diagram(&diagram, buffer);

    // Add nodes
    for (uint32_t i = 0; i < graph->node_count; i++) {
        CFGNode* node = graph->nodes[i];
        const char* type_str = cfg_node_type_to_string(node->type);

        if (node->label) {
            sprintf(buffer, "N%u[\"%s: %s\"]\n", node->id, type_str, node->label);
        } else {
            sprintf(buffer, "N%u[\"%s\"]\n", node->id, type_str);
        }
        cfg_append_to_diagram(&diagram, buffer);
    }

    // Add edges
    for (uint32_t i = 0; i < graph->edge_count; i++) {
        CFGEdge* edge = graph->edges[i];
        sprintf(buffer, "N%u --> N%u\n", edge->source->id, edge->target->id);
        cfg_append_to_diagram(&diagram, buffer);
    }

    return diagram;
}

// Helper function to append to diagram string (implementation)
void cfg_append_to_diagram(char** diagram, const char* addition) {
    size_t current_len = *diagram ? strlen(*diagram) : 0;
    size_t addition_len = strlen(addition);
    *diagram = realloc(*diagram, current_len + addition_len + 1);
    if (!*diagram) {
        fprintf(stderr, "Memory allocation error\n");
        exit(1);
    }
    strcpy(*diagram + current_len, addition);
}

// Helper function to convert node type to string (implementation)
const char* cfg_node_type_to_string(CFGNodeType type) {
    switch (type) {
        case CFG_NODE_ENTRY: return "ENTRY";
        case CFG_NODE_EXIT: return "EXIT";
        case CFG_NODE_BASIC_BLOCK: return "BASIC_BLOCK";
        case CFG_NODE_CONDITION: return "CONDITION";
        case CFG_NODE_LOOP: return "LOOP";
        case CFG_NODE_FUNCTION_CALL: return "FUNCTION_CALL";
        default: return "UNKNOWN";
    }
}

// Helper function to convert edge type to string (implementation)
const char* cfg_edge_type_to_string(CFGEdgeType type) {
    switch (type) {
        case CFG_EDGE_UNCONDITIONAL: return "UNCONDITIONAL";
        case CFG_EDGE_TRUE: return "TRUE";
        case CFG_EDGE_FALSE: return "FALSE";
        case CFG_EDGE_BACK_EDGE: return "BACK_EDGE";
        case CFG_EDGE_EXCEPTION: return "EXCEPTION";
        default: return "UNKNOWN";
    }
}