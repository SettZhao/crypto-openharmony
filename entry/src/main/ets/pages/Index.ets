@Entry
@Component
struct Index {
  build() {
    Row() {
      Column() {
        Button("test")
          .fontSize(20)
          .fontWeight(FontWeight.Bold)
          .margin(10)
          .onClick(() => {
            console.log("test")
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