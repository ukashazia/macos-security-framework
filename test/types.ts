import {
  DigestBuilder,
  DigestType,
  ItemClass,
  ItemSearchOptions,
  SecRandom,
  SslProtocol,
  accessControlFlags,
  cipherSuites,
} from "../index.js";

const random: Buffer = new SecRandom().copyBytes(32);
const digest: Buffer = new DigestBuilder()
  .digestType(DigestType.Sha2)
  .length(256)
  .execute(random);
const search: ItemSearchOptions = new ItemSearchOptions()
  .class(ItemClass.Certificate)
  .loadRefs(true);
const protocol: SslProtocol = SslProtocol.Tls13;
const suites: Record<string, number> = cipherSuites();
const userPresence: number = accessControlFlags().userPresence;

void [digest, search, protocol, suites, userPresence];
