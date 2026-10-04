package core

import (
	"math/rand"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Aho-Corasick 关键词匹配的等价性测试
//
// 用 strings.Contains 参照实现对 AC 自动机做交叉验证，并锁定
// DOMAIN-KEYWORD 候选"不因与自身完全相同的剔除关键词被查杀"
// ---------------------------------------------------------------------------

func TestAhoCorasickContainsAny(t *testing.T) {
	cases := []struct {
		patterns []string
		text     string
		want     bool
	}{
		{[]string{"he", "she", "his", "hers"}, "ushers", true},
		{[]string{"he", "she", "his", "hers"}, "his", true},
		{[]string{"he", "she", "his", "hers"}, "xyz", false},
		{[]string{"abc"}, "xxabcxx", true},
		{[]string{"abc"}, "ab", false},
		{[]string{"abc"}, "abcd", true},
		{[]string{"a", "aa"}, "aa", true},
		{[]string{"a", "b"}, "c", false},
		{[]string{"", "foo"}, "barfoo", true}, // 空模式被忽略
		{[]string{}, "anything", false},
		{[]string{"中文"}, "包含中文在内", true},
		{[]string{"foobar"}, "foo", false},
	}
	for _, c := range cases {
		ac := newAhoCorasick(c.patterns)
		if got := ac.containsAny(c.text); got != c.want {
			t.Fatalf("patterns=%v text=%q: 期望 %v，实际 %v", c.patterns, c.text, c.want, got)
		}
	}
}

func TestAhoCorasickContainsAnyShorterThan(t *testing.T) {
	ac := newAhoCorasick([]string{"she", "he", "s"})
	if !ac.containsAnyShorterThan("she", 3) {
		t.Fatal("she 应命中更短的 he")
	}
	if ac.containsAnyShorterThan("he", 2) {
		t.Fatal("he 不应被自身或更长模式命中")
	}
	if !ac.containsAnyShorterThan("shes", 4) {
		t.Fatal("shes 应命中 she/he")
	}
	if ac.containsAnyShorterThan("he", 1) {
		t.Fatal("不存在长度小于 1 的模式，he 不应命中")
	}
}

// TestAhoCorasickEquivalence 随机交叉验证 AC 与 strings.Contains。
func TestAhoCorasickEquivalence(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	alphabet := []byte("abcd")
	randStr := func(maxLen int) string {
		n := rng.Intn(maxLen) + 1
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(b)
	}
	for iter := 0; iter < 500; iter++ {
		var patterns []string
		for i := 0; i < rng.Intn(6); i++ {
			patterns = append(patterns, randStr(4))
		}
		ac := newAhoCorasick(patterns)
		text := randStr(10)
		want := false
		for _, p := range patterns {
			if p != "" && strings.Contains(text, p) {
				want = true
				break
			}
		}
		if got := ac.containsAny(text); got != want {
			t.Fatalf("patterns=%v text=%q: 期望 %v，实际 %v", patterns, text, want, got)
		}
	}
}

// TestKeywordKillSemantics 锁定关键词查杀（DOMAIN-KEYWORD 特例）。
func TestKeywordKillSemantics(t *testing.T) {
	// DOMAIN-KEYWORD 候选：不被与自身完全相同的关键词查杀，但可被更短的子串关键词查杀。
	m := NewRuleMatcher(map[string]bool{"ads": true, "ad": true}, nil, NewSuffixTrie())
	if m.IsCrossKilled("ad", "DOMAIN-KEYWORD") {
		t.Fatal("候选 ad 不应被查杀（ads 非子串，ad==ad 被跳过）")
	}
	if !m.IsCrossKilled("ads", "DOMAIN-KEYWORD") {
		t.Fatal("候选 ads 应被更短子串关键词 ad 查杀")
	}

	only := NewRuleMatcher(map[string]bool{"ads": true}, nil, NewSuffixTrie())
	if only.IsCrossKilled("ads", "DOMAIN-KEYWORD") {
		t.Fatal("候选 ads 不应被与自身完全相同的关键词查杀")
	}

	// 非 KEYWORD 候选无此特例：完全相等也查杀。
	d := NewRuleMatcher(map[string]bool{"google": true}, nil, NewSuffixTrie())
	if !d.IsCrossKilled("google", "DOMAIN") {
		t.Fatal("DOMAIN 候选 google 应被关键词 google 查杀")
	}
}

// TestKeywordKillEquivalence 随机交叉验证整段关键词查杀路径（含 DOMAIN-KEYWORD 特例）与参照实现。
func TestKeywordKillEquivalence(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	alphabet := []byte("ab")
	randStr := func(maxLen int) string {
		n := rng.Intn(maxLen) + 1
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(b)
	}
	for iter := 0; iter < 300; iter++ {
		kwSet := map[string]bool{}
		var kws []string
		for i := 0; i < rng.Intn(5); i++ {
			k := randStr(4)
			if k == "" {
				continue
			}
			kwSet[k] = true
			kws = append(kws, k)
		}
		m := NewRuleMatcher(kwSet, nil, NewSuffixTrie())
		for i := 0; i < 50; i++ {
			cand := randStr(5)
			for _, typ := range []string{"DOMAIN", "DOMAIN-KEYWORD"} {
				got := m.IsCrossKilled(cand, typ)
				want := bruteKeywordKill(kws, cand, typ)
				if got != want {
					t.Fatalf("kws=%v cand=%q type=%s: AC=%v 暴力=%v", kws, cand, typ, got, want)
				}
			}
		}
	}
}

// bruteKeywordKill 是 IsCrossKilled 关键词部分的参照实现。
func bruteKeywordKill(kws []string, val, ruleType string) bool {
	for _, kw := range kws {
		if ruleType == "DOMAIN-KEYWORD" && val == kw {
			continue
		}
		if strings.Contains(val, kw) {
			return true
		}
	}
	return false
}
