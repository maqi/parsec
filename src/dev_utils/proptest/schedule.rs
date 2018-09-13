// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Bounded, BoundedBoxedStrategy, EnvironmentStrategy, EnvironmentValueTree};
use dev_utils::environment::Environment;
use dev_utils::schedule::{
    DelayDistribution, Request, RequestTiming, Schedule, ScheduleEvent, ScheduleOptions,
};
use proptest_crate::prelude::Just;
use proptest_crate::strategy::{NewTree, Strategy, ValueTree};
use proptest_crate::test_runner::TestRunner;
use std::collections::BTreeSet;

#[derive(Debug)]
pub struct ScheduleOptionsStrategy {
    pub local_step: BoundedBoxedStrategy<f64>,
    pub recv_trans: BoundedBoxedStrategy<f64>,
    pub failure: BoundedBoxedStrategy<f64>,
    pub vote_duplication: BoundedBoxedStrategy<f64>,
    pub delay_distr: BoundedBoxedStrategy<DelayDistribution>,
}

#[allow(unused)]
pub fn const_delay<T>(distr: T) -> BoundedBoxedStrategy<DelayDistribution>
where
    T: Strategy<Value = usize> + Bounded<Bound = usize> + 'static,
{
    let min = DelayDistribution::Constant(distr.min());
    let max = DelayDistribution::Constant(distr.max());
    let boxed_str = distr.prop_map(DelayDistribution::Constant).boxed();
    BoundedBoxedStrategy::from_boxed(boxed_str, min, max)
}

#[allow(unused)]
pub fn poisson_delay<T>(distr: T) -> BoundedBoxedStrategy<DelayDistribution>
where
    T: Strategy<Value = f64> + Bounded<Bound = f64> + 'static,
{
    let min = DelayDistribution::Poisson(distr.min());
    let max = DelayDistribution::Poisson(distr.max());
    let boxed_str = distr.prop_map(DelayDistribution::Poisson).boxed();
    BoundedBoxedStrategy::from_boxed(boxed_str, min, max)
}

#[allow(unused)]
pub fn arbitrary_delay<T, U>(cnst: T, poisson: U) -> BoundedBoxedStrategy<DelayDistribution>
where
    T: Strategy<Value = usize> + Bounded<Bound = usize> + 'static,
    U: Strategy<Value = f64> + Bounded<Bound = f64> + 'static,
{
    let min = DelayDistribution::Constant(cnst.min());
    let max = DelayDistribution::Poisson(poisson.max());
    let boxed_str = prop_oneof![
        cnst.prop_map(DelayDistribution::Constant),
        poisson.prop_map(DelayDistribution::Poisson),
    ].boxed();
    BoundedBoxedStrategy::from_boxed(boxed_str, min, max)
}

impl Default for ScheduleOptionsStrategy {
    fn default() -> ScheduleOptionsStrategy {
        ScheduleOptionsStrategy {
            local_step: Just(0.15).into(),
            recv_trans: Just(0.05).into(),
            failure: Just(0.0).into(),
            vote_duplication: Just(0.0).into(),
            delay_distr: Just(DelayDistribution::Poisson(4.0)).into(),
        }
    }
}

impl Strategy for ScheduleOptionsStrategy {
    type Value = ScheduleOptions;
    type Tree = ScheduleOptionsValueTree;

    fn new_tree(&self, runner: &mut TestRunner) -> NewTree<Self> {
        let max_sched = ScheduleOptions {
            prob_local_step: self.local_step.min(),
            prob_recv_trans: self.recv_trans.max(),
            prob_failure: self.failure.max(),
            prob_vote_duplication: self.vote_duplication.max(),
            delay_distr: self.delay_distr.max(),
            ..Default::default()
        };
        let min_sched = ScheduleOptions {
            prob_local_step: self.local_step.max(),
            prob_recv_trans: self.recv_trans.min(),
            prob_failure: self.failure.min(),
            prob_vote_duplication: self.vote_duplication.min(),
            delay_distr: self.delay_distr.min(),
            ..Default::default()
        };
        // order is important here - the default implementation bisects the first value first, then
        // switches to the next, and the next - so the values should be sorted in a rough order of
        // "importance"
        let (l_min, l_max) = (self.local_step.min(), self.local_step.max());
        (
            &self.failure,
            &self.vote_duplication,
            &self.recv_trans,
            (&self.local_step).prop_map(move |l| l_max + l_min - l),
            &self.delay_distr,
        )
            .prop_map(|(f, v, r, l, d)| ScheduleOptions {
                prob_failure: f,
                prob_vote_duplication: v,
                prob_recv_trans: r,
                prob_local_step: l,
                delay_distr: d,
                ..Default::default()
            }).new_tree(runner)
            .map(|t| ScheduleOptionsValueTree {
                max_sched,
                min_sched,
                generator: Box::new(t),
            })
    }
}

/// This struct is a wrapper around a mapped value tree that lets us implement Bounded
pub struct ScheduleOptionsValueTree {
    max_sched: ScheduleOptions,
    min_sched: ScheduleOptions,
    generator: Box<ValueTree<Value = ScheduleOptions>>,
}

impl Bounded for ScheduleOptionsValueTree {
    type Bound = ScheduleOptions;

    fn min(&self) -> ScheduleOptions {
        self.min_sched.clone()
    }

    fn max(&self) -> ScheduleOptions {
        self.max_sched.clone()
    }
}

impl ValueTree for ScheduleOptionsValueTree {
    type Value = ScheduleOptions;

    fn current(&self) -> ScheduleOptions {
        self.generator.current()
    }

    fn simplify(&mut self) -> bool {
        self.generator.simplify()
    }

    fn complicate(&mut self) -> bool {
        self.generator.complicate()
    }
}

#[derive(Debug, Default)]
pub struct ScheduleStrategy {
    pub env: EnvironmentStrategy,
    pub opts: ScheduleOptionsStrategy,
}

impl Strategy for ScheduleStrategy {
    type Value = (Environment, Schedule);
    type Tree = ScheduleValueTree;

    fn new_tree(&self, runner: &mut TestRunner) -> NewTree<Self> {
        self.env
            .new_tree(runner)
            .and_then(|e| self.opts.new_tree(runner).map(|o| (e, o)))
            .map(|(e, o)| ScheduleValueTree::new(e, o))
    }
}

pub struct ScheduleValueTree {
    env: EnvironmentValueTree,
    opts: ScheduleOptionsValueTree,
    max_schedule: Schedule,
    shrink_opts: bool,
}

impl ScheduleValueTree {
    pub fn new(env: EnvironmentValueTree, opts: ScheduleOptionsValueTree) -> Self {
        let mut max_env = env.max();
        let max_opts = opts.max();
        let max_schedule = Schedule::new(&mut max_env, &max_opts);
        ScheduleValueTree {
            env,
            opts,
            max_schedule,
            shrink_opts: true,
        }
    }
}

impl ScheduleValueTree {
    fn filtered_schedule(&self, env: &Environment) -> Schedule {
        let peers_set: BTreeSet<_> = env.network.peers.iter().map(|p| p.id.clone()).collect();
        let trans_set: BTreeSet<_> = env.observations.iter().collect();
        let result = self
            .max_schedule
            .events
            .iter()
            .filter(|&ev| match *ev {
                ScheduleEvent::LocalStep {
                    ref peer,
                    ref request_timing,
                    ..
                } => {
                    let request_ok = match *request_timing {
                        RequestTiming::Later => true,
                        RequestTiming::DuringThisStep(Request { ref recipient, .. })
                        | RequestTiming::DuringThisStepIfNewData(Request {
                            ref recipient, ..
                        }) => peers_set.contains(recipient),
                    };
                    request_ok && peers_set.contains(peer)
                }
                ScheduleEvent::Fail(ref peer) => peers_set.contains(peer),
                ScheduleEvent::VoteFor(ref peer, ref trans) => {
                    peers_set.contains(peer) && trans_set.contains(trans)
                }
            }).cloned()
            .collect();
        Schedule {
            events: result,
            num_observations: env.observations.len(),
        }
    }
}

impl ValueTree for ScheduleValueTree {
    type Value = (Environment, Schedule);

    fn current(&self) -> (Environment, Schedule) {
        trace!("Scheduling with options: {:?}", self.opts.current());
        let env = self.env.current();
        trace!(
            "{} peers, {} observations",
            env.network.peers.len(),
            env.observations.len()
        );
        let schedule = self.filtered_schedule(&env);
        trace!("{:?}", schedule);
        (env, schedule)
    }

    fn simplify(&mut self) -> bool {
        if self.shrink_opts {
            self.opts.simplify() || {
                self.shrink_opts = false;
                self.env.simplify()
            }
        } else {
            self.env.simplify()
        }
    }

    fn complicate(&mut self) -> bool {
        if self.shrink_opts {
            self.opts.complicate()
        } else {
            self.env.complicate()
        }
    }
}
