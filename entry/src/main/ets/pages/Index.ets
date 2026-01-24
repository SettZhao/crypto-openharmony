import { Crypto } from '@harmony-lib/crypto'
import { buffer, util } from '@kit.ArkTS'

@Entry
@Component
struct Index {
  @State encrypto: string = ""
  build() {
    Row() {
      Column() {
        Button("BlowFish加密")
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .margin(10)
          .onClick(() => {
            try{
              // 每次点击都创建新的 buffer，避免数据被复用
              const inputBuf = buffer.from("test1235").buffer;
              const keyBuf = buffer.from("test1235").buffer;
              const ivBuf = buffer.from("test1235").buffer;
              
              let result = Crypto.Blowfish.encrypt(inputBuf, keyBuf, ivBuf, 0)
              console.log("result: ", buffer.from(result).toString("base64"))
              this.encrypto = buffer.from(result).toString("base64")
            }catch (e) {
              console.log("error: ", JSON.stringify(e.message))
            }

          })
          .width('70%')
        Button("BlowFish解密")
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .margin(10)
          .onClick(() => {
            try{
              // 每次点击都创建新的 buffer，避免数据被复用
              let base64 = new util.Base64Helper();
              const inputBuf = buffer.from(base64.decodeSync(this.encrypto)).buffer;
              const keyBuf = buffer.from("test1235").buffer;
              const ivBuf = buffer.from("test1235").buffer;
              let result = Crypto.Blowfish.decrypt(inputBuf, keyBuf, ivBuf, 0)
              console.log("result: ", buffer.from(result).toString())
            }catch (e) {
              console.log("error: ", JSON.stringify(e.message))
            }

          })
          .width('70%')
      }
      .justifyContent(FlexAlign.Center)
      .height('100%')
    }
    .justifyContent(FlexAlign.Center)
    .width('100%')
  }
}