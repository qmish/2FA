package service

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/qmish/2FA/internal/dto"
	"github.com/qmish/2FA/internal/models"
	"github.com/qmish/2FA/internal/repository"
)

type policyContext struct {
	user    *models.User
	groups  []models.Group
	ip      string
	channel models.AuthChannel
	method  models.SecondFactorMethod
	now     time.Time
}

func (s *Service) isPolicyAllowed(ctx context.Context, user *models.User, req dto.LoginRequest, method models.SecondFactorMethod) bool {
	if s.policies == nil || s.policyRules == nil || s.userGroups == nil || s.groupPolicies == nil {
		return true
	}
	groups, err := s.userGroups.ListGroups(ctx, user.ID)
	if err != nil {
		return false
	}
	policyIDs, ok := s.resolvePolicyIDs(ctx, groups)
	if !ok {
		return false
	}
	if len(policyIDs) == 0 {
		return true
	}
	policies := s.loadPolicies(ctx, policyIDs)
	if len(policies) == 0 {
		return true
	}
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Priority < policies[j].Priority
	})
	pctx := policyContext{
		user:    user,
		groups:  groups,
		ip:      req.IP,
		channel: req.Channel,
		method:  method,
		now:     s.now(),
	}
	for _, policy := range policies {
		if policy.Status != models.PolicyActive {
			continue
		}
		rules, err := s.policyRules.ListByPolicy(ctx, policy.ID)
		if err != nil {
			return false
		}
		if rulesMatch(rules, pctx) {
			return true
		}
	}
	return false
}

func (s *Service) resolvePolicyIDs(ctx context.Context, groups []models.Group) ([]string, bool) {
	ids := make(map[string]struct{})
	for _, group := range groups {
		policyID, err := s.groupPolicies.GetPolicy(ctx, group.ID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				continue
			}
			return nil, false
		}
		if policyID != "" {
			ids[policyID] = struct{}{}
		}
	}
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	return out, true
}

func (s *Service) loadPolicies(ctx context.Context, ids []string) []models.Policy {
	policies := make([]models.Policy, 0, len(ids))
	for _, id := range ids {
		policy, err := s.policies.GetByID(ctx, id)
		if err != nil {
			continue
		}
		policies = append(policies, *policy)
	}
	return policies
}

func rulesMatch(rules []models.PolicyRule, ctx policyContext) bool {
	if len(rules) == 0 {
		return true
	}
	byType := map[models.PolicyRuleType][]string{}
	for _, rule := range rules {
		byType[rule.RuleType] = append(byType[rule.RuleType], rule.RuleValue)
	}
	if !matchRuleSet(byType, models.RuleUser, func(value string) bool {
		return value == ctx.user.ID || value == ctx.user.Username || (ctx.user.Email != "" && value == ctx.user.Email)
	}) {
		return false
	}
	if !matchRuleSet(byType, models.RuleGroup, func(value string) bool {
		for _, group := range ctx.groups {
			if value == group.ID || value == group.Name {
				return true
			}
		}
		return false
	}) {
		return false
	}
	if !matchRuleSet(byType, models.RuleChannel, func(value string) bool {
		return value != "" && strings.EqualFold(value, string(ctx.channel))
	}) {
		return false
	}
	if !matchRuleSet(byType, models.RuleMethod, func(value string) bool {
		return value != "" && strings.EqualFold(value, string(ctx.method))
	}) {
		return false
	}
	if !matchRuleSet(byType, models.RuleIP, func(value string) bool {
		return matchIP(value, ctx.ip)
	}) {
		return false
	}
	if !matchRuleSet(byType, models.RuleTime, func(value string) bool {
		return matchTimeWindow(value, ctx.now)
	}) {
		return false
	}
	return true
}

func matchRuleSet(rules map[models.PolicyRuleType][]string, ruleType models.PolicyRuleType, matcher func(string) bool) bool {
	values := rules[ruleType]
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if matcher(strings.TrimSpace(value)) {
			return true
		}
	}
	return false
}

func matchIP(ruleValue string, ip string) bool {
	if ruleValue == "" || ip == "" {
		return false
	}
	if strings.Contains(ruleValue, "/") {
		_, cidr, err := net.ParseCIDR(ruleValue)
		if err != nil {
			return false
		}
		addr := net.ParseIP(ip)
		if addr == nil {
			return false
		}
		return cidr.Contains(addr)
	}
	return ruleValue == ip
}

func matchTimeWindow(ruleValue string, now time.Time) bool {
	parts := strings.Split(ruleValue, "-")
	if len(parts) != 2 {
		return false
	}
	start, err := time.Parse("15:04", strings.TrimSpace(parts[0]))
	if err != nil {
		return false
	}
	end, err := time.Parse("15:04", strings.TrimSpace(parts[1]))
	if err != nil {
		return false
	}
	nowMinutes := now.Hour()*60 + now.Minute()
	startMinutes := start.Hour()*60 + start.Minute()
	endMinutes := end.Hour()*60 + end.Minute()
	if startMinutes <= endMinutes {
		return nowMinutes >= startMinutes && nowMinutes <= endMinutes
	}
	return nowMinutes >= startMinutes || nowMinutes <= endMinutes
}
