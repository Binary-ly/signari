package flow

import (
	"fmt"
	"strings"
)


// checkSafety decides both properties for one flow.
func (fl *Flow) checkSafety() error {
	// create_user belongs to enrolment. Elsewhere it is an account-creation
	// primitive sitting in a flow that strangers can start.
	if fl.On != Enrolment {
		for i, st := range fl.Stages {
			for _, name := range st.stageNames() {
				if name == StageCreateUser {
					return fmt.Errorf("step %d is %s, which belongs to an enrolment flow; "+
						"a %s flow that can create accounts is a sign-up form nobody meant "+
						"to publish", i+1, StageCreateUser, fl.On)
				}
			}
		}
	}

	// Enrolment is exempt from the proof and order rules: there is no subject yet
	// to prove, which is what it is for. It pays for the exemption here -- an
	// enrolment flow may not reach a session.
	//
	// Sign-up decides who exists; it does not decide who is signed in. Collapsing
	// the two is how a self-service form becomes an account-creation-AND-login
	// endpoint, and the operator who wired it did not think they were building
	// that. Keeping the rule in this file rather than beside the other structural
	// checks is deliberate: it is the premise the exemption rests on, and a
	// reader working out whether the exemption is safe has to be able to see it.
	if fl.On == Enrolment {
		for i, st := range fl.Stages {
			for _, name := range st.stageNames() {
				if name == StageSession {
					return fmt.Errorf("step %d is %s, and this is an enrolment flow. "+
						"Enrolment creates the account; hand over to an authentication "+
						"flow to sign them in, so that issuing a session is always "+
						"something a flow subject to the proof rule did", i+1, StageSession)
				}
			}
		}
		return nil
	}

	if err := fl.checkOrder(); err != nil {
		return err
	}
	return fl.checkProof()
}

// guaranteedProver reports whether a step definitely proves the subject,
// whatever the conditions turn out to be.
//
// An unconditional proving stage qualifies. So does a one_of in which EVERY
// branch proves -- that is the whole value of the construct: the group is total,
// so exactly one branch runs, so if they all prove then the group proves.
//
// A conditional stage never qualifies, however likely its condition. "Almost
// always runs" is not a property a security argument can rest on.
func (st Step) guaranteedProver(d Designation) bool {
	if st.Stage != "" {
		return st.When == "" && st.Stage.proves(d)
	}
	for _, b := range st.OneOf {
		if !b.Stage.proves(d) {
			return false
		}
	}
	return len(st.OneOf) > 0
}

// mayProve reports whether a step could prove the subject on some path. Used
// only to write a better error message.
func (st Step) mayProve(d Designation) bool {
	for _, name := range st.stageNames() {
		if name.proves(d) {
			return true
		}
	}
	return false
}

// checkProof is property 1.
func (fl *Flow) checkProof() error {
	last := fl.Stages[len(fl.Stages)-1]
	reachesSession := false
	for _, name := range last.stageNames() {
		if name == StageSession {
			reachesSession = true
		}
	}
	if !reachesSession {
		// Ends in deny. Nothing is handed out, so there is nothing to prove.
		return nil
	}

	for _, st := range fl.Stages {
		if st.guaranteedProver(fl.On) {
			return nil
		}
	}

	// Unsafe. The message has to be worth reading, because the author believes
	// their flow authenticates somebody and is about to be told it does not.
	var hint string
	switch {
	case fl.On == Recovery && fl.hasAnyProver():
		hint = fmt.Sprintf("\n\nThis flow does authenticate, but with a factor that does "+
			"not count in a recovery flow. Recovery exists because a factor was lost, so "+
			"it may not accept the kind it replaces. What counts here: %s.",
			stageList(recoveryProving))
	case fl.hasConditionalProver():
		hint = "\n\nEvery stage here that proves anything is conditional, so there is a " +
			"path where none of them runs. If the conditions are meant to cover every " +
			"case, say so with `one_of:` -- its last branch is the default, which is what " +
			"makes the choice total and lets this check see that one branch always runs."
	default:
		hint = fmt.Sprintf("\n\nStages that prove who somebody is: %s. Note that %s is not "+
			"one of them -- it collects an identifier, and knowing a username is not "+
			"evidence of being its owner.", stageList(provingStages), StageIdentify)
	}
	return fmt.Errorf("this flow can reach %s without proving who the subject is%s",
		StageSession, hint)
}

// checkOrder is property 2.
//
// A stage that sets a credential must not run before one that checks a
// credential. The flow this exists to refuse looks entirely reasonable:
//
//	- identify
//	- enrol_mfa
//	- mfa
//	- session
//
// Read quickly, it enrols a factor and then demands it -- two factors' worth of
// words. What it does is let a stranger name an account, attach their own
// authenticator to it, present that authenticator, and be signed in as its
// owner. The mfa stage passes honestly; it is proof of possession of a secret
// created three steps earlier by the person being asked.
//
// The same shape catches password_change before any proof, which is the older
// and more obvious version of the same bug.
func (fl *Flow) checkOrder() error {
	proven := false
	for i, st := range fl.Stages {
		for _, name := range st.stageNames() {
			if !mutatingStages[name] {
				continue
			}
			if proven {
				continue
			}
			// The remedy names the stages that count IN THIS FLOW. In a recovery
			// flow the general list is actively misleading: it includes password,
			// and moving the change after a password check earns a second refusal
			// from checkProof for a different reason. An error that sends the
			// author to the next error is worse than terse.
			counts := provingStages
			narrowed := ""
			if fl.On == Recovery {
				counts = recoveryProving
				narrowed = " -- narrower here than elsewhere, because a recovery flow " +
					"may not accept the kind of factor it exists to replace"
			}
			return fmt.Errorf("step %d is %s, which changes the subject's credentials, but "+
				"nothing before it has proved who the subject is. %s\n\nMove it after a "+
				"stage that proves the subject (%s%s), or make the proving stage "+
				"unconditional if it is one -- a stage that only sometimes runs cannot be "+
				"what stops this",
				i+1, name, mutationRisk[name], stageList(counts), narrowed)
		}
		if st.guaranteedProver(fl.On) {
			proven = true
		}
	}
	return nil
}

// mutatingStages change what the subject can authenticate with in future.
var mutatingStages = map[StageName]bool{
	StageEnrolMFA:       true,
	StagePasswordChange: true,
	StageCreateUser:     true,
}

// mutationRisk says what goes wrong, per stage, in the words of what an
// attacker gets. An error that only says "this is unsafe" gets overridden by
// somebody who is sure it is fine in their case.
var mutationRisk = map[StageName]string{
	StageEnrolMFA: "Whoever reaches this step attaches an authenticator of their " +
		"own to the named account, and any later stage that checks a second factor " +
		"will then pass for them.",
	StagePasswordChange: "Whoever reaches this step sets the password on the " +
		"named account, having presented nothing to show it is theirs.",
	StageCreateUser: "Whoever reaches this step creates an account.",
}

func (fl *Flow) hasAnyProver() bool {
	for _, st := range fl.Stages {
		for _, name := range st.stageNames() {
			if provingStages[name] {
				return true
			}
		}
	}
	return false
}

func (fl *Flow) hasConditionalProver() bool {
	for _, st := range fl.Stages {
		if !st.guaranteedProver(fl.On) && st.mayProve(fl.On) {
			return true
		}
	}
	return false
}

func stageList(set map[StageName]bool) string {
	var out []string
	// Ranged over allStages rather than the map, so the order is the inventory's
	// order and the message is identical on every run.
	for _, n := range allStages {
		if set[n] {
			out = append(out, string(n))
		}
	}
	return strings.Join(out, ", ")
}
