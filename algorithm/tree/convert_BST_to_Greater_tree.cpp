#include <iostream>
using namespace std;

struct TreeNode {
    int val;
    TreeNode *left;
    TreeNode *right;
    TreeNode(int x) : val(x), left(NULL), right(NULL) {}
};

class Solution {
public:
    TreeNode* convertBST(TreeNode* root) {
        dfs(root, 0);
        return root;
    }
    int dfs(TreeNode* root, int val) {
        if(root == NULL) return val;
        int right = dfs(root->right, val);
        int left = dfs(root->left, root->val + right);
        root->val = root->val + right;
        return left;
    }
};