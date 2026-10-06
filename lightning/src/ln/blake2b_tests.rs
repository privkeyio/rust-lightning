//! Tests for `option_blake2b` and `option_unified_sigs`.

use crate::events::{ClosureReason, Event};
use crate::ln::channelmanager::{self, PaymentId};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{self, BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::ln::outbound_payment::{Bolt11PaymentError, RetryableSendFailure};
use crate::offers::parse::Bolt12SemanticError;
use crate::util::config::UserConfig;
use crate::util::errors::APIError;

use bitcoin::sighash::SIGHASH_UNIFIED;
use bitcoin::{EcdsaSighashType, Transaction};

fn unified_config(anchors: bool) -> UserConfig {
	let mut config =
		if anchors { test_default_channel_config() } else { test_legacy_channel_config() };
	config.follow_blake2b = true;
	config
}

/// Returns the sighash type byte of every signature in the given input's witness.
fn witness_sighash_bytes(tx: &Transaction, input: usize) -> Vec<u8> {
	tx.input[input]
		.witness
		.iter()
		.filter(|item| item.len() >= 70 && item.len() <= 73 && item[0] == 0x30)
		.map(|sig| *sig.last().unwrap())
		.collect()
}

const UNIFIED_ALL: u8 = EcdsaSighashType::All as u8 | SIGHASH_UNIFIED;

#[test]
fn test_blake2b_features() {
	let mut config = UserConfig::default();
	config.follow_blake2b = true;
	let init = channelmanager::provided_init_features(&config);
	assert!(init.requires_blake2b());
	assert!(init.supports_unified_sigs() && !init.requires_unified_sigs());
	assert!(channelmanager::provided_node_features(&config).requires_blake2b());
	assert!(channelmanager::provided_bolt11_invoice_features(&config).requires_blake2b());
	assert!(channelmanager::provided_bolt12_invoice_features(&config).requires_blake2b());
	assert!(channelmanager::provided_channel_type_features(&config).requires_unified_sigs());

	let legacy = test_legacy_channel_config();
	let init = channelmanager::provided_init_features(&legacy);
	assert!(!init.supports_blake2b());
	assert!(!init.supports_unified_sigs());
}

fn do_test_unified_channel(anchors: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = unified_config(anchors);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, channel_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);
	for node in nodes.iter() {
		let channel_type = node.node.list_channels()[0].channel_type.clone().unwrap();
		assert!(channel_type.requires_unified_sigs());
		assert_eq!(channel_type.supports_anchors_zero_fee_htlc_tx(), anchors);
	}

	send_payment(&nodes[0], &[&nodes[1]], 10_000_000);

	for node in nodes.iter() {
		let txn = get_local_commitment_txn!(node, channel_id);
		assert_eq!(witness_sighash_bytes(&txn[0], 0), vec![UNIFIED_ALL, UNIFIED_ALL]);
	}

	let (_, _, closing_tx) = close_channel(&nodes[0], &nodes[1], &channel_id, funding_tx, true);
	assert_eq!(witness_sighash_bytes(&closing_tx, 0), vec![UNIFIED_ALL, UNIFIED_ALL]);
	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();
	check_closed_event(
		&nodes[0],
		1,
		ClosureReason::CounterpartyInitiatedCooperativeClosure,
		&[node_id_1],
		100000,
	);
	check_closed_event(
		&nodes[1],
		1,
		ClosureReason::LocallyInitiatedCooperativeClosure,
		&[node_id_0],
		100000,
	);
}

#[test]
fn test_unified_channel() {
	do_test_unified_channel(false);
	do_test_unified_channel(true);
}

#[test]
fn test_unified_htlc_timeout_tx() {
	// Without anchors the holder HTLC transaction has a single input, so both signatures commit
	// to it with the unified sighash.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = unified_config(false);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
	route_payment(&nodes[0], &[&nodes[1]], 3_000_000);

	let txn = get_local_commitment_txn!(nodes[0], channel_id);
	assert_eq!(txn.len(), 2);
	assert_eq!(witness_sighash_bytes(&txn[0], 0), vec![UNIFIED_ALL, UNIFIED_ALL]);
	assert_eq!(txn[1].input.len(), 1);
	assert_eq!(witness_sighash_bytes(&txn[1], 0), vec![UNIFIED_ALL, UNIFIED_ALL]);
}

#[test]
fn test_unified_channel_cannot_splice() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = unified_config(true);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
	let res = nodes[0].node.splice_channel(&channel_id, &nodes[1].node.get_our_node_id());
	match res {
		Err(APIError::APIMisuseError { err }) => assert!(err.contains("option_unified_sigs")),
		_ => panic!("Wrong result {:?}", res.err()),
	}
}

#[test]
fn test_unified_channel_type_required() {
	// A node following option_blake2b refuses a new channel which does not use unified signatures.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(
		2,
		&node_cfgs,
		&[Some(test_default_channel_config()), Some(unified_config(true))],
	);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_id_1, 100_000, 0, 42, None, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_id_1);
	assert!(!open_channel.common_fields.channel_type.as_ref().unwrap().supports_unified_sigs());
	nodes[1].node.handle_open_channel(node_id_0, &open_channel);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	match &events[..] {
		[MessageSendEvent::HandleError { action, .. }] => {
			let msg = match action {
				msgs::ErrorAction::SendErrorMessage { msg } => &msg.data,
				_ => panic!("Unexpected action {:?}", action),
			};
			assert!(msg.contains("option_unified_sigs"));
		},
		_ => panic!("Unexpected events {:?}", events),
	}
}

#[test]
fn test_unified_channel_type_required_outbound() {
	// A node following option_blake2b does not open a channel to a peer without unified signatures.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(
		2,
		&node_cfgs,
		&[Some(unified_config(true)), Some(test_default_channel_config())],
	);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_id_1 = nodes[1].node.get_our_node_id();

	let res = nodes[0].node.create_channel(node_id_1, 100_000, 0, 42, None, None);
	match res {
		Err(APIError::APIMisuseError { err }) => assert!(err.contains("option_unified_sigs")),
		_ => panic!("Wrong result {:?}", res),
	}
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
}

#[test]
fn test_refuse_bolt11_invoice_without_blake2b() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(
		2,
		&node_cfgs,
		&[Some(unified_config(true)), Some(test_default_channel_config())],
	);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let invoice = nodes[1].node.create_bolt11_invoice(Default::default()).unwrap();
	assert!(!invoice.features().unwrap().supports_blake2b());
	let res = nodes[0].node.pay_for_bolt11_invoice(
		&invoice,
		PaymentId([42; 32]),
		Some(10_000),
		Default::default(),
	);
	assert!(matches!(
		res,
		Err(Bolt11PaymentError::SendingFailed(RetryableSendFailure::RouteNotFound))
	));
}

#[test]
fn test_offers_set_and_require_blake2b() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(
		2,
		&node_cfgs,
		&[Some(unified_config(true)), Some(test_default_channel_config())],
	);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let offer = nodes[0].node.create_offer_builder().unwrap().build().unwrap();
	assert!(offer.offer_features().requires_blake2b());

	let legacy_offer = nodes[1].node.create_offer_builder().unwrap().build().unwrap();
	assert!(!legacy_offer.offer_features().supports_blake2b());
	let res = nodes[0].node.pay_for_offer(
		&legacy_offer,
		Some(10_000),
		PaymentId([1; 32]),
		Default::default(),
	);
	assert_eq!(res, Err(Bolt12SemanticError::UnknownRequiredFeatures));
}

#[test]
fn test_pay_bolt11_invoice_between_blake2b_nodes() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = unified_config(true);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let mut params = channelmanager::Bolt11InvoiceParameters::default();
	params.amount_msats = Some(50_000);
	let invoice = nodes[1].node.create_bolt11_invoice(params).unwrap();
	assert!(invoice.features().unwrap().requires_blake2b());

	let payment_hash = invoice.payment_hash();
	nodes[0]
		.node
		.pay_for_bolt11_invoice(&invoice, PaymentId(payment_hash.0), None, Default::default())
		.unwrap();
	check_added_monitors(&nodes[0], 1);
	let send_event = SendEvent::from_node(&nodes[0]);
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &send_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);

	let preimage = match &nodes[1].node.get_and_clear_pending_events()[..] {
		[Event::PaymentClaimable { purpose, .. }] => purpose.preimage().unwrap(),
		events => panic!("Unexpected events {:?}", events),
	};
	claim_payment(&nodes[0], &[&nodes[1]], preimage);
}
