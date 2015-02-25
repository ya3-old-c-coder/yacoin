#ifndef BITCOIN_TIMESTAMPS_H
#define BITCOIN_TIMESTAMPS_H

// saironiq : block height where "no consecutive PoS blocks" rule activates
// Yacoin, updated to time.
//static const int nConsecutiveStakeSwitchHeight = 420000;
static const unsigned int CONSECUTIVE_STAKE_SWITCH_TIME = 1392241857;

// YACOIN TODO 
static const unsigned int STAKE_SWITCH_TIME = 2709614280; 
static const unsigned int TARGETS_SWITCH_TIME = 2709614280; 
//static const unsigned int CHAINCHECKS_SWITCH_TIME = 2709614280;
static const unsigned int STAKECURVE_SWITCH_TIME = 2709614280; 

static const unsigned int VALIDATION_SWITCH_TIME = 2709614280; 
static const unsigned int SIG_SWITCH_TIME = 2709614280; 

// Protocol switch time for fixed kernel modifier interval
static const unsigned int nModifierSwitchTime  = 2709614280;   
static const unsigned int nModifierTestSwitchTime = 2709614280; 

#endif
