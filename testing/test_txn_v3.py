# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Test PSBT with transaction version 3 support (bip-0431)
#

import pytest
from psbt import BasicPSBT
from io import BytesIO
from ctransaction import CTransaction
from constants import ADDR_STYLES_SINGLE


@pytest.mark.bitcoind
@pytest.mark.parametrize("outstyle", ADDR_STYLES_SINGLE)
@pytest.mark.parametrize("segwit_in", [True, False])
@pytest.mark.parametrize("wrapped_segwit_in", [True, False])
def test_txn_version_3(outstyle, segwit_in, wrapped_segwit_in, fake_txn, start_sign, end_sign,
                       cap_story, bitcoind, finalize_v2_v0_convert):
    psbt = fake_txn(2, 2, segwit_in=segwit_in, wrapped=wrapped_segwit_in, change_outputs=[0],
                    outstyles=[outstyle], psbt_v2=True)


    po = BasicPSBT().parse(psbt)
    po.txn_version = 3

    with BytesIO() as fd:
        po.serialize(fd)
        psbt_v3 = fd.getvalue()

    start_sign(psbt_v3)
    title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" not in story
    assert "Change back" in story
    assert "to script" not in story

    signed = end_sign(accept=True, finalize=False)
    assert signed

    po_signed = BasicPSBT().parse(signed)
    assert po_signed.version == 2
    assert po_signed.txn_version == 3
    assert po_signed.input_count is not None
    assert po_signed.output_count is not None

    for inp in po_signed.inputs:
        assert inp.previous_txid
        assert inp.prevout_idx is not None

    for out in po_signed.outputs:
        assert out.amount
        assert out.script

    resp = finalize_v2_v0_convert(po_signed)
    assert resp["complete"] is True


# EOF
