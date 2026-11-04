import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
public class CborRangeProbe {
 public static void main(String[] args) throws Exception {
  // Upstream #186 regression input: large declared length, only two data bytes.
  final int length=100000000;
  byte[] input={(byte)0x5a,(byte)(length>>>24),(byte)(length>>>16),(byte)(length>>>8),(byte)length,0,0};
  try(JsonParser parser=new CBORFactory().createParser(input)) {
   parser.nextToken();parser.getBinaryValue();System.out.println("UNEXPECTED_ACCEPT");
  } catch(OutOfMemoryError ex) {System.out.println("EAGER_ALLOCATION_OOME");}
    catch(java.io.IOException ex) {System.out.println("INPUT_REJECTED_WITHOUT_LARGE_ALLOCATION");}
 }
}
