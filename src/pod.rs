use std::{collections::HashMap, time::Instant};

use anyhow::{anyhow, Result};
use pod2::{
    backends::plonky2::{
        basetypes::DEFAULT_VD_SET,
        mainpod::Prover,
        mock::mainpod::MockProver,
        primitives::ec::schnorr::SecretKey,
        signer::Signer,
    },
    frontend::{MainPod, MainPodBuilder, Operation, SignedDict, SignedDictBuilder},
    middleware::{MainPodProver, Params, PublicKey, Value, VDSet},
};
use tracing::info;

pub struct Participant {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

impl Participant {
    pub fn new() -> Self {
        let sk = SecretKey::new_rand();
        let pk = sk.public_key();
        Self { sk, pk }
    }
}

/// Create the genesis SignedDict. An ephemeral admin key signs it.
/// `fields` are the initial integer values; `first_writer_pk` receives the baton.
pub fn create_genesis(
    params: &Params,
    fields: &HashMap<String, i64>,
    first_writer_pk: PublicKey,
) -> Result<SignedDict> {
    let mut builder = SignedDictBuilder::new(params);
    for (k, v) in fields {
        builder.insert(k.as_str(), Value::from(*v));
    }
    builder.insert("version", Value::from(0i64));
    builder.insert("prev_hash", Value::from(0i64));
    builder.insert("writer_pk", Value::from(first_writer_pk));

    let admin_sk = SecretKey::new_rand();
    let state = builder.sign(&Signer(admin_sk))?;
    state.verify()?;
    Ok(state)
}

/// Execute one write step.
/// `mock` selects MockProver (instant, no real ZK) vs the real Plonky2 prover.
pub fn write_step(
    params: &Params,
    prev_state: &SignedDict,
    writer_sk: SecretKey,
    next_pk: PublicKey,
    updates: &HashMap<String, i64>,
    mock: bool,
) -> Result<(MainPod, SignedDict)> {
    info!("  [pod] write_step: reading old_version");
    let old_version: i64 = prev_state
        .dict
        .get(&"version".into())
        .map_err(|e| anyhow!("{e}"))?
        .ok_or_else(|| anyhow!("missing version field"))?
        .as_int()
        .ok_or_else(|| anyhow!("version is not an integer"))?;
    let new_version = old_version + 1;
    info!("  [pod] old_version={} new_version={}", old_version, new_version);

    let (vd_set, prover): (VDSet, &dyn MainPodProver) = if mock {
        info!("  [pod] prover: MockProver");
        (VDSet::new(&[]), &MockProver {})
    } else {
        info!("  [pod] prover: Plonky2 — loading circuit (DEFAULT_VD_SET)...");
        let t = Instant::now();
        let vd = (*DEFAULT_VD_SET).clone();
        info!("  [pod] circuit loaded in {:.1}s", t.elapsed().as_secs_f32());
        (vd, &Prover {})
    };
    let mut mb = MainPodBuilder::new(params, &vd_set);

    info!("  [pod] cloning dict → no_writer");
    let mut no_writer = prev_state.dict.clone();
    info!("  [pod] deleting writer_pk");
    no_writer.delete(&"writer_pk".into())?;

    info!("  [pod] cloning → with_new_writer, inserting new writer_pk");
    let mut with_new_writer = no_writer.clone();
    with_new_writer.insert(&"writer_pk".into(), &Value::from(next_pk))?;

    info!("  [pod] cloning → with_values, applying {} field update(s)", updates.len());
    let mut with_values = with_new_writer.clone();
    for (field, val) in updates {
        info!("  [pod]   update {}={}", field, val);
        with_values.update(&field.as_str().into(), &Value::from(*val))?;
    }
    with_values.update(&"version".into(), &Value::from(new_version))?;
    info!("  [pod] with_values ready");

    info!("  [pod] pub_op: dict_signed_by");
    mb.pub_op(Operation::dict_signed_by(prev_state))?;

    info!("  [pod] priv_op: dict_contains(version)");
    let st_old_version = mb.priv_op(Operation::dict_contains(
        prev_state.dict.clone(),
        "version",
        old_version,
    ))?;

    info!("  [pod] priv_op: public_key_of");
    mb.priv_op(Operation::public_key_of(
        (prev_state, "writer_pk"),
        writer_sk.clone(),
    ))?;

    info!("  [pod] pub_op: sum_of");
    mb.pub_op(Operation::sum_of(new_version, st_old_version, 1i64))?;

    info!("  [pod] pub_op: dict_delete");
    mb.pub_op(Operation::dict_delete(
        Value::from(no_writer.clone()),
        Value::from(prev_state.dict.clone()),
        "writer_pk",
    ))?;

    info!("  [pod] priv_op: dict_insert");
    mb.priv_op(Operation::dict_insert(
        Value::from(with_new_writer.clone()),
        Value::from(no_writer.clone()),
        "writer_pk",
        Value::from(next_pk),
    ))?;

    info!("  [pod] priv_op: dict_update per field");
    let mut proof_dict = with_new_writer.clone();
    for (field, val) in updates {
        info!("  [pod]   dict_update {}", field);
        let mut next_dict = proof_dict.clone();
        next_dict.update(&field.as_str().into(), &Value::from(*val))?;
        mb.priv_op(Operation::dict_update(
            Value::from(next_dict.clone()),
            Value::from(proof_dict.clone()),
            field.as_str(),
            Value::from(*val),
        ))?;
        proof_dict = next_dict;
    }

    info!("  [pod] priv_op: dict_update(version)");
    mb.priv_op(Operation::dict_update(
        Value::from(with_values.clone()),
        Value::from(proof_dict),
        "version",
        new_version,
    ))?;

    info!("  [pod] computing prev_hash commitment");
    let c = Value::from(prev_state.dict.clone());
    let mut with_prev = with_values.clone();
    with_prev.update(&"prev_hash".into(), &c)?;

    info!("  [pod] pub_op: dict_update(prev_hash)");
    mb.pub_op(Operation::dict_update(
        Value::from(with_prev.clone()),
        Value::from(with_values.clone()),
        "prev_hash",
        c,
    ))?;

    info!("  [pod] mb.prove() — generating proof...");
    let t_prove = Instant::now();
    let proof = mb.prove(prover)?;
    info!("  [pod] proof generated in {:.1}s", t_prove.elapsed().as_secs_f32());

    info!("  [pod] proof.pod.verify()");
    let t_verify = Instant::now();
    proof.pod.verify()?;
    info!("  [pod] proof verified in {:.1}s", t_verify.elapsed().as_secs_f32());

    info!("  [pod] building new signed state");
    let mut new_state_builder = SignedDictBuilder::new(params);
    for item in with_prev.iter() {
        let (key, val) = item?;
        new_state_builder.insert(key, val);
    }
    let new_state = new_state_builder.sign(&Signer(writer_sk))?;
    new_state.verify()?;
    info!("  [pod] write_step complete");

    Ok((proof, new_state))
}

/// Extract all key/value pairs from a SignedDict as a JSON-friendly map.
/// Integer values become JSON numbers; everything else becomes a debug string.
pub fn state_to_json(sd: &SignedDict) -> serde_json::Value {
    info!("  [state_to_json] entering iter");
    let mut map = serde_json::Map::new();
    for item in sd.dict.iter() {
        info!("  [state_to_json] got item");
        if let Ok((key, val)) = item {
            let k = format!("{}", key);
            let v = if let Some(i) = val.as_int() {
                serde_json::Value::Number(i.into())
            } else {
                serde_json::Value::String(format!("{}", val))
            };
            map.insert(k, v);
        }
    }
    info!("  [state_to_json] done, {} keys", map.len());
    serde_json::Value::Object(map)
}
