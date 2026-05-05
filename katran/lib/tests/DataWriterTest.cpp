/* Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "katran/lib/ByteRangeWriter.h"
#include "katran/lib/FileWriter.h"
#include "katran/lib/IOBufWriter.h"

#include <folly/Range.h>
#include <folly/io/IOBuf.h>
#include <gtest/gtest.h>

#include <unistd.h>
#include <cstring>
#include <fstream>

namespace katran {

// ---- ByteRangeWriter ----

TEST(ByteRangeWriterTest, WriteData_WritesCorrectBytes) {
  std::string storage(64, '\0');
  folly::MutableByteRange buf(
      reinterpret_cast<uint8_t*>(storage.data()), storage.size());
  ByteRangeWriter writer(buf);

  writer.writeData("hello", 5);

  EXPECT_EQ(std::strncmp(storage.data(), "hello", 5), 0);
}

TEST(ByteRangeWriterTest, WriteData_AdvancesWrittenBytes) {
  std::string storage(64, '\0');
  folly::MutableByteRange buf(
      reinterpret_cast<uint8_t*>(storage.data()), storage.size());
  ByteRangeWriter writer(buf);

  writer.writeData("abc", 3);
  writer.writeData("xyz", 3);

  EXPECT_EQ(writer.writtenBytes(), 6);
}

TEST(ByteRangeWriterTest, Available_ReturnsTrueWhenEnoughSpace) {
  std::string storage(64, '\0');
  folly::MutableByteRange buf(
      reinterpret_cast<uint8_t*>(storage.data()), storage.size());
  ByteRangeWriter writer(buf);

  EXPECT_TRUE(writer.available(1));
  EXPECT_TRUE(writer.available(64));
}

TEST(ByteRangeWriterTest, Available_ReturnsFalseWhenNotEnoughSpace) {
  std::string storage(4, '\0');
  folly::MutableByteRange buf(
      reinterpret_cast<uint8_t*>(storage.data()), storage.size());
  ByteRangeWriter writer(buf);

  EXPECT_FALSE(writer.available(5));
}

// ---- IOBufWriter ----

TEST(IOBufWriterTest, WriteData_WritesCorrectBytes) {
  auto iobuf = folly::IOBuf::create(64);
  IOBufWriter writer(iobuf.get());

  const char* data = "test_data";
  writer.writeData(data, 9);

  EXPECT_EQ(iobuf->length(), 9);
  EXPECT_EQ(std::memcmp(iobuf->data(), data, 9), 0);
}

TEST(IOBufWriterTest, Available_ReturnsTrueWhenTailroom) {
  auto iobuf = folly::IOBuf::create(64);
  IOBufWriter writer(iobuf.get());

  EXPECT_TRUE(writer.available(64));
}

TEST(IOBufWriterTest, Available_ReturnsFalseWhenNoTailroom) {
  // IOBuf::create() rounds up capacity (e.g. to 64 bytes), so we can't rely
  // on a small allocation guaranteeing small tailroom. Fill the actual
  // tailroom completely, then verify available() returns false.
  auto iobuf = folly::IOBuf::create(4);
  IOBufWriter writer(iobuf.get());

  std::string filler(iobuf->tailroom(), 'x');
  writer.writeData(filler.data(), filler.size());

  EXPECT_EQ(iobuf->tailroom(), 0);
  EXPECT_FALSE(writer.available(1));
}

TEST(IOBufWriterTest, Restart_ClearsBuffer) {
  auto iobuf = folly::IOBuf::create(64);
  IOBufWriter writer(iobuf.get());

  writer.writeData("hello", 5);
  EXPECT_EQ(iobuf->length(), 5);

  EXPECT_TRUE(writer.restart());
  EXPECT_EQ(iobuf->length(), 0);
}

// ---- FileWriter ----

class FileWriterTest : public ::testing::Test {
 protected:
  void SetUp() override {
    char tmpPath[] = "/tmp/katran-filewriter-test-XXXXXX";
    int fd = ::mkstemp(tmpPath);
    ASSERT_GE(fd, 0);
    ::close(fd);
    tmpFilePath_ = tmpPath;
  }

  void TearDown() override {
    ::unlink(tmpFilePath_.c_str());
  }

  std::string tmpFilePath_;
};

TEST_F(FileWriterTest, WriteData_WritesCorrectBytes) {
  {
    FileWriter writer(tmpFilePath_);
    writer.writeData("hello world", 11);
    writer.stop();
  }
  std::ifstream file(tmpFilePath_);
  std::string content(
      (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  EXPECT_EQ(content, "hello world");
}

TEST_F(FileWriterTest, WrittenBytesTracked) {
  FileWriter writer(tmpFilePath_);
  writer.writeData("abc", 3);
  writer.writeData("defgh", 5);
  EXPECT_EQ(writer.writtenBytes(), 8);
}

TEST_F(FileWriterTest, Available_AlwaysReturnsTrue) {
  FileWriter writer(tmpFilePath_);
  EXPECT_TRUE(writer.available(0));
  EXPECT_TRUE(writer.available(1000000));
}

TEST_F(FileWriterTest, Restart_TruncatesAndAllowsReuse) {
  FileWriter writer(tmpFilePath_);
  writer.writeData("old content", 11);
  writer.restart();
  writer.writeData("new", 3);
  writer.stop();

  std::ifstream file(tmpFilePath_);
  std::string content(
      (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  EXPECT_EQ(content, "new");
}

TEST_F(FileWriterTest, Stop_FlushesDataToDisk) {
  FileWriter writer(tmpFilePath_);
  writer.writeData("data", 4);
  EXPECT_TRUE(writer.stop());

  // After stop(), data must be readable from disk (verifies flush + close).
  std::ifstream file(tmpFilePath_);
  std::string content(
      (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  EXPECT_EQ(content, "data");
}

} // namespace katran
