#include <iostream>
#include <queue>
using namespace std;

struct TreeNode {
    int val;
    TreeNode *left;
    TreeNode *right;
    TreeNode(int x) : val(x), left(NULL), right(NULL) {}
};

class Solution {
public:
    int sumOfLeftLeaves(TreeNode* root) {
        if(root == NULL) return 0;
        int res = 0;
        queue<TreeNode*> q;
        q.push(root);
        while(!q.empty()) {
            int s = q.size();
            for(int i=0; i<s; i++) {
                TreeNode* t = q.front();
                q.pop();
                if(t->left) {
                    q.push(t->left);
                    if(t->left->left == NULL && t->left->right == NULL) {
                        res += t->left->val;
                    }
                }
                if(t->right) {
                    q.push(t->right);
                }
            }
        }
        return res;
    }
};