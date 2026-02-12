/*
 * Copyright 2026 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.code_intelligence.jazzer.runtime;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;

public class CountersTrackerTest {

  @Test
  public void testEnsureCountersAllocated() {
    // Use unique ID to avoid overlap with other tests
    CountersTracker.ensureCountersAllocated(1000, 100);

    // Should not throw - idempotent with same numCounters
    CountersTracker.ensureCountersAllocated(1000, 100);
  }

  @Test
  public void testEnsureCountersAllocatedDifferentNumCountersThrows() {
    CountersTracker.ensureCountersAllocated(1001, 100);

    try {
      CountersTracker.ensureCountersAllocated(1001, 200);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("different numCounters"));
    }
  }

  @Test
  public void testEnsureCountersAllocatedInvalidNumCountersThrows() {
    try {
      CountersTracker.ensureCountersAllocated(1002, 0);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("must be positive"));
    }

    try {
      CountersTracker.ensureCountersAllocated(1003, -1);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("must be positive"));
    }
  }

  @Test
  public void testSetCounterFullForm() {
    CountersTracker.ensureCountersAllocated(1004, 10);

    // Should not throw
    CountersTracker.setCounter(1004, 0, (byte) 1);
    CountersTracker.setCounter(1004, 5, (byte) 42);
    CountersTracker.setCounter(1004, 9, (byte) 255);
  }

  @Test
  public void testSetCounterConvenienceOverloads() {
    CountersTracker.ensureCountersAllocated(1005, 10);

    // setCounter(id, value) - offset = 0
    CountersTracker.setCounter(1005, (byte) 42);

    // setCounter(id) - offset = 0, value = 1
    CountersTracker.setCounter(1005);
  }

  @Test
  public void testSetCounterNotAllocatedThrows() {
    try {
      CountersTracker.setCounter(9999999, 0, (byte) 1);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException e) {
      assertTrue(e.getMessage().contains("No counters allocated"));
    }
  }

  @Test
  public void testSetCounterOutOfBoundsThrows() {
    CountersTracker.ensureCountersAllocated(1006, 10);

    try {
      CountersTracker.setCounter(1006, -1, (byte) 1);
      fail("Expected IndexOutOfBoundsException");
    } catch (IndexOutOfBoundsException e) {
      // Expected
    }

    try {
      CountersTracker.setCounter(1006, 10, (byte) 1);
      fail("Expected IndexOutOfBoundsException");
    } catch (IndexOutOfBoundsException e) {
      // Expected
    }
  }

  @Test
  public void testSetCounterRangeFullForm() {
    CountersTracker.ensureCountersAllocated(1007, 100);

    // Should not throw
    CountersTracker.setCounterRange(1007, 0, 50, (byte) 1);
    CountersTracker.setCounterRange(1007, 0, 99, (byte) 1);
    CountersTracker.setCounterRange(1007, 50, 50, (byte) 1);
  }

  @Test
  public void testSetCounterRangeConvenienceOverloads() {
    CountersTracker.ensureCountersAllocated(1008, 100);

    // setCounterRange(id, toOffset, value) - fromOffset = 0
    CountersTracker.setCounterRange(1008, 50, (byte) 42);

    // setCounterRange(id, toOffset) - fromOffset = 0, value = 1
    CountersTracker.setCounterRange(1008, 99);
  }

  @Test
  public void testSetCounterRangeEmptyThrows() {
    CountersTracker.ensureCountersAllocated(1009, 100);

    try {
      // Empty range (fromOffset > toOffset) should throw
      CountersTracker.setCounterRange(1009, 50, 40, (byte) 1);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("must not be greater than"));
    }
  }

  @Test
  public void testSetCounterRangeNotAllocatedThrows() {
    try {
      CountersTracker.setCounterRange(9999998, 0, 5, (byte) 1);
      fail("Expected IllegalStateException");
    } catch (IllegalStateException e) {
      assertTrue(e.getMessage().contains("No counters allocated"));
    }
  }

  @Test
  public void testSetCounterRangeOutOfBoundsThrows() {
    CountersTracker.ensureCountersAllocated(1010, 10);

    try {
      CountersTracker.setCounterRange(1010, -1, 5, (byte) 1);
      fail("Expected IndexOutOfBoundsException");
    } catch (IndexOutOfBoundsException e) {
      assertTrue(e.getMessage().contains("non-negative"));
    }

    try {
      CountersTracker.setCounterRange(1010, 0, 10, (byte) 1);
      fail("Expected IndexOutOfBoundsException");
    } catch (IndexOutOfBoundsException e) {
      assertTrue(e.getMessage().contains("out of bounds"));
    }
  }

  @Test
  public void testConcurrentAllocation() throws InterruptedException {
    final int numThreads = 10;
    final int numAllocationsPerThread = 100;
    final ExecutorService executor = Executors.newFixedThreadPool(numThreads);
    final CountDownLatch startLatch = new CountDownLatch(1);
    final CountDownLatch doneLatch = new CountDownLatch(numThreads);
    final AtomicReference<Throwable> error = new AtomicReference<>();

    for (int t = 0; t < numThreads; t++) {
      final int threadId = t;
      executor.submit(
          () -> {
            try {
              startLatch.await();
              for (int i = 0; i < numAllocationsPerThread; i++) {
                // Use a large base ID to avoid overlap with other tests
                int id = 100000 + threadId * 200 + i;
                CountersTracker.ensureCountersAllocated(id, 10);
                // Also test that we can use the counters after allocation
                CountersTracker.setCounter(id, 0, (byte) 1);
              }
            } catch (Throwable e) {
              error.compareAndSet(null, e);
            } finally {
              doneLatch.countDown();
            }
          });
    }

    // Start all threads at once
    startLatch.countDown();

    // Wait for completion
    assertTrue("Threads didn't finish in time", doneLatch.await(30, TimeUnit.SECONDS));
    executor.shutdown();

    if (error.get() != null) {
      fail("Concurrent allocation failed: " + error.get().getMessage());
    }
  }

  @Test
  public void testConcurrentAllocationSameId() throws InterruptedException {
    final int numThreads = 10;
    final int sharedId = 200000; // Use unique ID to avoid overlap with other tests
    final int numCounters = 50;
    final ExecutorService executor = Executors.newFixedThreadPool(numThreads);
    final CountDownLatch startLatch = new CountDownLatch(1);
    final CountDownLatch doneLatch = new CountDownLatch(numThreads);
    final AtomicReference<Throwable> error = new AtomicReference<>();

    for (int t = 0; t < numThreads; t++) {
      executor.submit(
          () -> {
            try {
              startLatch.await();
              // All threads try to allocate the same ID - should be idempotent
              CountersTracker.ensureCountersAllocated(sharedId, numCounters);
              // All threads should be able to use the counters
              CountersTracker.setCounterRange(sharedId, numCounters - 1);
            } catch (Throwable e) {
              error.compareAndSet(null, e);
            } finally {
              doneLatch.countDown();
            }
          });
    }

    // Start all threads at once
    startLatch.countDown();

    // Wait for completion
    assertTrue("Threads didn't finish in time", doneLatch.await(30, TimeUnit.SECONDS));
    executor.shutdown();

    if (error.get() != null) {
      fail("Concurrent allocation failed: " + error.get().getMessage());
    }
  }

  @Test
  public void testMaximizePattern() {
    // Test the typical usage pattern for maximize()
    int id = 400000;
    int numCounters = 101; // For range [0, 100]

    CountersTracker.ensureCountersAllocated(id, numCounters);

    // Simulate maximize(50, id, 0, 100) - should set counters 0-50 to 1
    int value = 50;
    int minValue = 0;
    int steps = value - minValue;
    CountersTracker.setCounterRange(id, steps);

    // Should be able to call again with higher value
    value = 75;
    steps = value - minValue;
    CountersTracker.setCounterRange(id, steps);
  }
}
