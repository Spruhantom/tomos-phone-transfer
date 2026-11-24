package org.tomos.transfer.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class TransferProgressTest {
    @Test
    fun emptyTransferHasZeroProgress() {
        assertEquals(0f, TransferProgress(0, 0, 0).fraction, 0f)
    }

    @Test
    fun partialTransferReportsFraction() {
        assertEquals(0.25f, TransferProgress(25, 100, 10).fraction, 0.0001f)
    }

    @Test
    fun completedTransferIsOne() {
        assertEquals(1f, TransferProgress(100, 100, 10).fraction, 0f)
    }

    @Test
    fun progressIsClampedToValidRange() {
        assertEquals(0f, TransferProgress(-10, 100, 0).fraction, 0f)
        assertEquals(1f, TransferProgress(120, 100, 0).fraction, 0f)
    }

    @Test
    fun nonPositiveTotalHasZeroProgress() {
        assertEquals(0f, TransferProgress(50, -1, 0).fraction, 0f)
    }
}
