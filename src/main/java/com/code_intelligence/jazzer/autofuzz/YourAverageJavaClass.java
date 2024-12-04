/*
 * Copyright 2024 Code Intelligence GmbH
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

package com.code_intelligence.jazzer.autofuzz;

import java.io.Closeable;
import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

// Returned by Meta when asked to construct a Class object. Its purpose is to be a relatively
// "interesting" Java data class that can serve as the target of methods that perform some kind of
// reflection or deserialization.
public class YourAverageJavaClass implements Cloneable, Closeable, Serializable {
  public byte aByte;
  public boolean aBoolean;
  public double aDouble;
  public float aFloat;
  public int anInt;
  public transient int transientInt;
  public long aLong;
  public short aShort;
  public volatile short volatileShort;
  public String string;
  public byte[] bytes;
  public List<YourAverageJavaClass> list;
  public Map<String, YourAverageJavaClass> map;

  // Everything below has been automatically generated (apart from a minor modification to clone());

  public YourAverageJavaClass(
      byte aByte,
      boolean aBoolean,
      double aDouble,
      float aFloat,
      int anInt,
      int transientInt,
      long aLong,
      short aShort,
      short volatileShort,
      String string) {
    this.aByte = aByte;
    this.aBoolean = aBoolean;
    this.aDouble = aDouble;
    this.aFloat = aFloat;
    this.anInt = anInt;
    this.transientInt = transientInt;
    this.aLong = aLong;
    this.aShort = aShort;
    this.volatileShort = volatileShort;
    this.string = string;
  }

  public YourAverageJavaClass() {}

  public YourAverageJavaClass(
      byte aByte,
      boolean aBoolean,
      double aDouble,
      float aFloat,
      int anInt,
      int transientInt,
      long aLong,
      short aShort,
      short volatileShort,
      String string,
      byte[] bytes,
      List<YourAverageJavaClass> list,
      Map<String, YourAverageJavaClass> map) {
    this.aByte = aByte;
    this.aBoolean = aBoolean;
    this.aDouble = aDouble;
    this.aFloat = aFloat;
    this.anInt = anInt;
    this.transientInt = transientInt;
    this.aLong = aLong;
    this.aShort = aShort;
    this.volatileShort = volatileShort;
    this.string = string;
    this.bytes = bytes;
    this.list = list;
    this.map = map;
  }

  public byte getaByte() {
    return aByte;
  }

  public void setaByte(byte aByte) {
    this.aByte = aByte;
  }

  public boolean isaBoolean() {
    return aBoolean;
  }

  public void setaBoolean(boolean aBoolean) {
    this.aBoolean = aBoolean;
  }

  public double getaDouble() {
    return aDouble;
  }

  public void setaDouble(double aDouble) {
    this.aDouble = aDouble;
  }

  public float getaFloat() {
    return aFloat;
  }

  public void setaFloat(float aFloat) {
    this.aFloat = aFloat;
  }

  public int getAnInt() {
    return anInt;
  }

  public void setAnInt(int anInt) {
    this.anInt = anInt;
  }

  public int getTransientInt() {
    return transientInt;
  }

  public void setTransientInt(int transientInt) {
    this.transientInt = transientInt;
  }

  public long getaLong() {
    return aLong;
  }

  public void setaLong(long aLong) {
    this.aLong = aLong;
  }

  public short getaShort() {
    return aShort;
  }

  public void setaShort(short aShort) {
    this.aShort = aShort;
  }

  public short getVolatileShort() {
    return volatileShort;
  }

  public void setVolatileShort(short volatileShort) {
    this.volatileShort = volatileShort;
  }

  public String getString() {
    return string;
  }

  public void setString(String string) {
    this.string = string;
  }

  public byte[] getBytes() {
    return bytes;
  }

  public void setBytes(byte[] bytes) {
    this.bytes = bytes;
  }

  public List<YourAverageJavaClass> getList() {
    return list;
  }

  public void setList(List<YourAverageJavaClass> list) {
    this.list = list;
  }

  public Map<String, YourAverageJavaClass> getMap() {
    return map;
  }

  public void setMap(Map<String, YourAverageJavaClass> map) {
    this.map = map;
  }

  @Override
  public YourAverageJavaClass clone() {
    try {
      YourAverageJavaClass clone = (YourAverageJavaClass) super.clone();
      clone.transientInt = transientInt + 1;
      clone.volatileShort = (short) (volatileShort - 1);
      return clone;
    } catch (CloneNotSupportedException e) {
      throw new AssertionError();
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof YourAverageJavaClass)) return false;
    YourAverageJavaClass that = (YourAverageJavaClass) o;
    return aByte == that.aByte
        && aBoolean == that.aBoolean
        && Double.compare(that.aDouble, aDouble) == 0
        && Float.compare(that.aFloat, aFloat) == 0
        && anInt == that.anInt
        && transientInt == that.transientInt
        && aLong == that.aLong
        && aShort == that.aShort
        && volatileShort == that.volatileShort
        && Objects.equals(string, that.string)
        && Arrays.equals(bytes, that.bytes)
        && Objects.equals(list, that.list)
        && Objects.equals(map, that.map);
  }

  @Override
  public int hashCode() {
    int result =
        Objects.hash(
            aByte,
            aBoolean,
            aDouble,
            aFloat,
            anInt,
            transientInt,
            aLong,
            aShort,
            volatileShort,
            string,
            list,
            map);
    result = 31 * result + Arrays.hashCode(bytes);
    return result;
  }

  @Override
  public String toString() {
    return "YourAverageJavaClass{"
        + "aByte="
        + aByte
        + ", aBoolean="
        + aBoolean
        + ", aDouble="
        + aDouble
        + ", aFloat="
        + aFloat
        + ", anInt="
        + anInt
        + ", transientInt="
        + transientInt
        + ", aLong="
        + aLong
        + ", aShort="
        + aShort
        + ", volatileShort="
        + volatileShort
        + ", string='"
        + string
        + '\''
        + ", bytes="
        + Arrays.toString(bytes)
        + ", list="
        + list
        + ", map="
        + map
        + '}';
  }

  @Override
  public void close() throws IOException {}
}
