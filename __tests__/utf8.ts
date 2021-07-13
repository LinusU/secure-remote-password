import { encodeUtf8 } from "../src/utf8";

describe("encodeUtf8", () => {
  for (const input of [
    "ﾟ･✿ヾ╲(｡◕‿◕｡)╱✿･ﾟ",
    "𝌆",
    "🐵 🙈 🙉 🙊",
    "💩",
    "åß∂ƒ©˙∆˚¬…æ",
    "Hello, World!",
    "Powerلُلُصّبُلُلصّبُررً ॣ ॣh ॣ ॣ冗",
    "𝕿𝖍𝖊 𝖖𝖚𝖎𝖈𝖐 𝖇𝖗𝖔𝖜𝖓 𝖋𝖔𝖝 𝖏𝖚𝖒𝖕𝖘 𝖔𝖛𝖊𝖗 𝖙𝖍𝖊 𝖑𝖆𝖟𝖞 𝖉𝖔𝖌",
    "사회과학원 어학연구소",
  ]) {
    test(`should encode "${input}"`, () => {
      const actual = Buffer.from(encodeUtf8(input));
      const expected = Buffer.from(input, "utf8");
      expect(actual.equals(expected)).toBe(true);
    });
  }

  for (const input of [
    {
      name: "Sanity check",
      input: "abc123",
      expected: [0x61, 0x62, 0x63, 0x31, 0x32, 0x33],
    },
    {
      name: "Surrogate half (low)",
      input: "\uD800",
      expected: [0xef, 0xbf, 0xbd],
    },
    {
      name: "Surrogate half (high)",
      input: "\uDC00",
      expected: [0xef, 0xbf, 0xbd],
    },
    {
      name: "Surrogate half (low), in a string",
      input: "abc\uD800123",
      expected: [0x61, 0x62, 0x63, 0xef, 0xbf, 0xbd, 0x31, 0x32, 0x33],
    },
    {
      name: "Surrogate half (high), in a string",
      input: "abc\uDC00123",
      expected: [0x61, 0x62, 0x63, 0xef, 0xbf, 0xbd, 0x31, 0x32, 0x33],
    },
    {
      name: "Wrong order",
      input: "\uDC00\uD800",
      expected: [0xef, 0xbf, 0xbd, 0xef, 0xbf, 0xbd],
    },
  ]) {
    test(input.name, () => {
      const actual = Array.from(new Uint8Array(encodeUtf8(input.input)));
      expect(actual).toStrictEqual(input.expected);
    });
  }
});
