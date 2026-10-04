package core

// acNode 是自动机节点。
type acNode struct {
	next   map[byte]int
	fail   int
	output []int
}

type ahoCorasick struct {
	nodes    []acNode
	patterns []string
}

// newAhoCorasick 由一组模式构建自动机，空模式被忽略。
func newAhoCorasick(patterns []string) *ahoCorasick {
	ac := &ahoCorasick{
		nodes:    []acNode{{next: make(map[byte]int)}},
		patterns: patterns,
	}

	// 1) 构建 trie
	for pi, p := range patterns {
		if len(p) == 0 {
			continue
		}
		cur := 0
		for i := 0; i < len(p); i++ {
			c := p[i]
			nxt, ok := ac.nodes[cur].next[c]
			if !ok {
				nxt = len(ac.nodes)
				ac.nodes[cur].next[c] = nxt
				ac.nodes = append(ac.nodes, acNode{next: make(map[byte]int)})
			}
			cur = nxt
		}
		ac.nodes[cur].output = append(ac.nodes[cur].output, pi)
	}

	// 2) BFS 计算 fail 链并合并 output（fail 节点的模式是当前状态所表示串的后缀）
	queue := make([]int, 0, len(ac.nodes))
	for _, nxt := range ac.nodes[0].next {
		ac.nodes[nxt].fail = 0
		queue = append(queue, nxt)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for c, nxt := range ac.nodes[cur].next {
			f := ac.nodes[cur].fail
			for f != 0 {
				if to, ok := ac.nodes[f].next[c]; ok {
					f = to
					break
				}
				f = ac.nodes[f].fail
			}
			if f == 0 {
				if to, ok := ac.nodes[0].next[c]; ok {
					f = to
				}
			}
			ac.nodes[nxt].fail = f
			ac.nodes[nxt].output = append(ac.nodes[nxt].output, ac.nodes[f].output...)
			queue = append(queue, nxt)
		}
	}
	return ac
}

// containsAny 判断 text 是否包含任一模式作为子串。
func (ac *ahoCorasick) containsAny(text string) bool {
	return ac.match(text, 0)
}

// containsAnyShorterThan 判断 text 是否包含任一"长度小于 minLen"的模式作为子串。
func (ac *ahoCorasick) containsAnyShorterThan(text string, minLen int) bool {
	return ac.match(text, minLen)
}

func (ac *ahoCorasick) match(text string, minLen int) bool {
	cur := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		for cur != 0 {
			if nxt, ok := ac.nodes[cur].next[c]; ok {
				cur = nxt
				break
			}
			cur = ac.nodes[cur].fail
		}
		if cur == 0 {
			if nxt, ok := ac.nodes[0].next[c]; ok {
				cur = nxt
			}
		}
		for _, pi := range ac.nodes[cur].output {
			if minLen == 0 || len(ac.patterns[pi]) < minLen {
				return true
			}
		}
	}
	return false
}
