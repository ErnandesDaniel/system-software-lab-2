#ifndef CFG_UTILS_H
#define CFG_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include "../../lib/tree-sitter/lib/include/tree_sitter/api.h"

// Forward declarations
typedef struct CFGNode CFGNode;
typedef struct CFGEdge CFGEdge;
typedef struct CFGGraph CFGGraph;

// Node types for control flow graph
typedef enum {
    CFG_NODE_ENTRY,
    CFG_NODE_EXIT,
    CFG_NODE_BASIC_BLOCK,
    CFG_NODE_CONDITION,
    CFG_NODE_LOOP,
    CFG_NODE_FUNCTION_CALL
} CFGNodeType;

// Edge types for control flow
typedef enum {
    CFG_EDGE_UNCONDITIONAL,
    CFG_EDGE_TRUE,
    CFG_EDGE_FALSE,
    CFG_EDGE_BACK_EDGE,
    CFG_EDGE_EXCEPTION
} CFGEdgeType;

// CFG Node structure
struct CFGNode {
    uint32_t id;                    // Unique node identifier
    CFGNodeType type;               // Type of the node
    char* label;                    // Human-readable label
    void* ast_node;                 // Pointer to corresponding AST node (optional)
    CFGNode** predecessors;         // Array of predecessor nodes
    uint32_t predecessor_count;     // Number of predecessors
    CFGNode** successors;           // Array of successor nodes
    uint32_t successor_count;       // Number of successors
    bool visited;                   // For traversal algorithms
};

// CFG Edge structure
struct CFGEdge {
    uint32_t id;                    // Unique edge identifier
    CFGNode* source;                // Source node
    CFGNode* target;                // Target node
    CFGEdgeType type;               // Type of edge
    char* label;                    // Optional edge label
};

// CFG Graph structure
struct CFGGraph {
    CFGNode** nodes;                // Array of all nodes
    uint32_t node_count;            // Number of nodes
    CFGEdge** edges;                // Array of all edges
    uint32_t edge_count;            // Number of edges
    CFGNode* entry_node;            // Entry point of the graph
    CFGNode* exit_node;             // Exit point of the graph
};

// Function prototypes

// Graph management
CFGGraph* cfg_create_graph(void);
void cfg_destroy_graph(CFGGraph* graph);

// Node management
CFGNode* cfg_create_node(CFGNodeType type, const char* label, void* ast_node);
void cfg_destroy_node(CFGNode* node);
void cfg_add_node(CFGGraph* graph, CFGNode* node);
CFGNode* cfg_get_node_by_id(CFGGraph* graph, uint32_t id);

// Edge management
CFGEdge* cfg_create_edge(CFGNode* source, CFGNode* target, CFGEdgeType type, const char* label);
void cfg_destroy_edge(CFGEdge* edge);
void cfg_add_edge(CFGGraph* graph, CFGEdge* edge);
void cfg_remove_edge(CFGGraph* graph, CFGEdge* edge);

// Graph traversal and analysis
// Function to build CFG from AST function definition
CFGGraph* cfg_build_from_ast(TSNode function_node, const char* source);

// Helper function to process statements and build CFG nodes
CFGNode* cfg_process_statements(TSNode node, const char* source, CFGGraph* graph, CFGNode* prev_node);

// Function to generate Mermaid diagram from CFG
char* cfg_generate_mermaid(const CFGGraph* graph);

// Helper function to append to diagram string
void cfg_append_to_diagram(char** diagram, const char* addition);

// Helper function to convert node type to string
const char* cfg_node_type_to_string(CFGNodeType type);

// Helper function to convert edge type to string
const char* cfg_edge_type_to_string(CFGEdgeType type);

#endif // CFG_UTILS_H
void cfg_dfs(CFGGraph* graph, CFGNode* start_node, void (*visit_func)(CFGNode*));
void cfg_bfs(CFGGraph* graph, CFGNode* start_node, void (*visit_func)(CFGNode*));

// Utility functions
void cfg_print_graph(const CFGGraph* graph);
void cfg_print_node(const CFGNode* node);
void cfg_print_edge(const CFGEdge* edge);