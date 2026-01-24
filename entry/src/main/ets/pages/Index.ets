import { Crypto } from '@harmony-lib/crypto'
import { buffer } from '@kit.ArkTS'

@Entry
@Component
struct Index {
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
              const inputBuf = buffer.from("test1234").buffer;
              const keyBuf = buffer.from("test1234test1234").buffer;
              const ivBuf = buffer.from("test1234").buffer;
              
              let result = Crypto.Blowfish(inputBuf, keyBuf, ivBuf, 0)
              console.log("result: ", buffer.from(result).toString("base64"))
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