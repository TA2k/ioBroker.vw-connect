.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv61/a;
.implements Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;
.implements Lz71/i;
.implements Lz71/d;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00ae\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u000c\n\u0002\u0010\"\n\u0002\u0008\u0005\n\u0002\u0010 \n\u0002\u0008\r\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0010\n\u0002\u0010\u0001\n\u0002\u00085\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u00022\u00020\u00032\u00020\u00042\u00020\u0005B\u0011\u0008\u0002\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0008\u0010\tB\u0011\u0008\u0010\u0012\u0006\u0010\u000b\u001a\u00020\n\u00a2\u0006\u0004\u0008\u0008\u0010\u000cB\u0011\u0008\u0010\u0012\u0006\u0010\u000b\u001a\u00020\r\u00a2\u0006\u0004\u0008\u0008\u0010\u000eJ\u0017\u0010\u0011\u001a\u00020\u000f2\u0006\u0010\u000b\u001a\u00020\nH\u0000\u00a2\u0006\u0004\u0008\u0010\u0010\u000cJ\u0017\u0010\u0011\u001a\u00020\u000f2\u0006\u0010\u000b\u001a\u00020\rH\u0000\u00a2\u0006\u0004\u0008\u0010\u0010\u000eJ\u000f\u0010\u0012\u001a\u00020\u000fH\u0016\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J\u000f\u0010\u0014\u001a\u00020\u000fH\u0016\u00a2\u0006\u0004\u0008\u0014\u0010\u0013J\u000f\u0010\u0015\u001a\u00020\u000fH\u0016\u00a2\u0006\u0004\u0008\u0015\u0010\u0013J\u000f\u0010\u0016\u001a\u00020\u000fH\u0016\u00a2\u0006\u0004\u0008\u0016\u0010\u0013J\u000f\u0010\u0017\u001a\u00020\u000fH\u0016\u00a2\u0006\u0004\u0008\u0017\u0010\u0013J\u000f\u0010\u0018\u001a\u00020\u000fH\u0016\u00a2\u0006\u0004\u0008\u0018\u0010\u0013J\u0017\u0010\u001b\u001a\u00020\u000f2\u0006\u0010\u001a\u001a\u00020\u0019H\u0016\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u0017\u0010\u001f\u001a\u00020\u000f2\u0006\u0010\u001e\u001a\u00020\u001dH\u0016\u00a2\u0006\u0004\u0008\u001f\u0010 J\u000f\u0010!\u001a\u00020\u000fH\u0016\u00a2\u0006\u0004\u0008!\u0010\u0013J\u0017\u0010$\u001a\u00020\u000f2\u0006\u0010#\u001a\u00020\"H\u0016\u00a2\u0006\u0004\u0008$\u0010%J\u0019\u0010\'\u001a\u00020\u000f2\u0008\u0010#\u001a\u0004\u0018\u00010&H\u0016\u00a2\u0006\u0004\u0008\'\u0010(J\u0017\u0010)\u001a\u00020\u000f2\u0006\u0010#\u001a\u00020\"H\u0016\u00a2\u0006\u0004\u0008)\u0010%J\u0017\u0010*\u001a\u00020\u000f2\u0006\u0010#\u001a\u00020\"H\u0016\u00a2\u0006\u0004\u0008*\u0010%J\u0017\u0010,\u001a\u00020\u000f2\u0006\u0010#\u001a\u00020+H\u0016\u00a2\u0006\u0004\u0008,\u0010-J\u0017\u0010.\u001a\u00020\u000f2\u0006\u0010#\u001a\u00020\"H\u0016\u00a2\u0006\u0004\u0008.\u0010%J\u0017\u0010/\u001a\u00020\u000f2\u0006\u0010#\u001a\u00020\u0019H\u0016\u00a2\u0006\u0004\u0008/\u0010\u001cJ\u0017\u00101\u001a\u00020\u000f2\u0006\u0010#\u001a\u000200H\u0016\u00a2\u0006\u0004\u00081\u00102J\u0019\u00104\u001a\u00020\u000f2\u0008\u0010#\u001a\u0004\u0018\u000103H\u0016\u00a2\u0006\u0004\u00084\u00105J\u0017\u00107\u001a\u00020\u000f2\u0006\u00106\u001a\u00020\u0019H\u0016\u00a2\u0006\u0004\u00087\u0010\u001cJ\u0017\u00109\u001a\u00020\u000f2\u0006\u00108\u001a\u00020\"H\u0016\u00a2\u0006\u0004\u00089\u0010%J\u0017\u0010;\u001a\u00020\u000f2\u0006\u0010:\u001a\u00020\"H\u0016\u00a2\u0006\u0004\u0008;\u0010%J\u0017\u0010=\u001a\u00020\u000f2\u0006\u0010<\u001a\u00020\"H\u0016\u00a2\u0006\u0004\u0008=\u0010%J\u0017\u0010?\u001a\u00020\u000f2\u0006\u0010>\u001a\u00020\"H\u0016\u00a2\u0006\u0004\u0008?\u0010%J\u001d\u0010B\u001a\u00020\u000f2\u000c\u0010A\u001a\u0008\u0012\u0004\u0012\u00020\u00190@H\u0016\u00a2\u0006\u0004\u0008B\u0010CJ\u001d\u0010E\u001a\u00020\u000f2\u000c\u0010D\u001a\u0008\u0012\u0004\u0012\u00020\u00190@H\u0016\u00a2\u0006\u0004\u0008E\u0010CJ\u001d\u0010H\u001a\u00020\u000f2\u000c\u0010G\u001a\u0008\u0012\u0004\u0012\u00020\u001d0FH\u0016\u00a2\u0006\u0004\u0008H\u0010IJ\u0017\u0010K\u001a\u00020\u000f2\u0006\u0010J\u001a\u00020\"H\u0016\u00a2\u0006\u0004\u0008K\u0010%J\u0019\u0010M\u001a\u00020\u000f2\u0008\u0010L\u001a\u0004\u0018\u00010&H\u0016\u00a2\u0006\u0004\u0008M\u0010(J\u000f\u0010N\u001a\u00020\u000fH\u0002\u00a2\u0006\u0004\u0008N\u0010\u0013J\u0019\u0010O\u001a\u00020\u000f2\u0008\u0010#\u001a\u0004\u0018\u000103H\u0002\u00a2\u0006\u0004\u0008O\u00105R\u0018\u0010P\u001a\u0004\u0018\u00010\n8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008P\u0010QR\u0018\u0010R\u001a\u0004\u0018\u00010\r8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008R\u0010SR\u001a\u0010U\u001a\u0008\u0012\u0004\u0012\u00020\u00060T8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008U\u0010VR \u0010\u0007\u001a\u0008\u0012\u0004\u0012\u00020\u00060W8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010X\u001a\u0004\u0008Y\u0010ZR \u0010[\u001a\u0008\u0012\u0004\u0012\u00020\"0W8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008[\u0010X\u001a\u0004\u0008[\u0010ZR\u0014\u0010\\\u001a\u00020\"8\u0002X\u0082D\u00a2\u0006\u0006\n\u0004\u0008\\\u0010]R\u001a\u0010^\u001a\u0008\u0012\u0004\u0012\u00020\"0T8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008^\u0010VR \u0010J\u001a\u0008\u0012\u0004\u0012\u00020\"0W8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008J\u0010X\u001a\u0004\u0008J\u0010ZR\u0014\u0010_\u001a\u00020\"8\u0002X\u0082D\u00a2\u0006\u0006\n\u0004\u0008_\u0010]R\u001a\u0010`\u001a\u0008\u0012\u0004\u0012\u00020\"0T8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008`\u0010VR \u0010a\u001a\u0008\u0012\u0004\u0012\u00020\"0W8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008a\u0010X\u001a\u0004\u0008a\u0010ZR\u0014\u0010b\u001a\u00020\"8\u0002X\u0082D\u00a2\u0006\u0006\n\u0004\u0008b\u0010]R\u001a\u0010c\u001a\u0008\u0012\u0004\u0012\u00020\"0T8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008c\u0010VR \u0010d\u001a\u0008\u0012\u0004\u0012\u00020\"0W8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008d\u0010X\u001a\u0004\u0008d\u0010ZR\u0014\u0010e\u001a\u00020\"8\u0002X\u0082D\u00a2\u0006\u0006\n\u0004\u0008e\u0010]R\u001a\u0010f\u001a\u0008\u0012\u0004\u0012\u00020\"0T8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008f\u0010VR \u0010g\u001a\u0008\u0012\u0004\u0012\u00020\"0W8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008g\u0010X\u001a\u0004\u0008g\u0010ZR\u0016\u0010i\u001a\u0004\u0018\u00010h8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008i\u0010jR\u001c\u0010k\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010&0T8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008k\u0010VR\"\u0010l\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010&0W8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008l\u0010X\u001a\u0004\u0008m\u0010ZR\u0014\u0010n\u001a\u00020+8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008n\u0010oR\u001a\u0010p\u001a\u0008\u0012\u0004\u0012\u00020+0T8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008p\u0010VR \u0010q\u001a\u0008\u0012\u0004\u0012\u00020+0W8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008q\u0010X\u001a\u0004\u0008r\u0010ZR\u0014\u0010s\u001a\u00020\"8\u0002X\u0082D\u00a2\u0006\u0006\n\u0004\u0008s\u0010]R\u001a\u0010t\u001a\u0008\u0012\u0004\u0012\u00020\"0T8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008t\u0010VR \u0010u\u001a\u0008\u0012\u0004\u0012\u00020\"0W8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008u\u0010X\u001a\u0004\u0008u\u0010ZR\u0014\u0010v\u001a\u00020\u00198\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008v\u0010wR\u001a\u0010x\u001a\u0008\u0012\u0004\u0012\u00020\u00190T8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008x\u0010VR \u0010y\u001a\u0008\u0012\u0004\u0012\u00020\u00190W8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008y\u0010X\u001a\u0004\u0008z\u0010ZR&\u0010{\u001a\u0008\u0012\u0004\u0012\u00020\u00190W8\u0016X\u0097\u0004\u00a2\u0006\u0012\n\u0004\u0008{\u0010X\u0012\u0004\u0008}\u0010\u0013\u001a\u0004\u0008|\u0010ZR\u0014\u0010~\u001a\u00020\"8\u0002X\u0082D\u00a2\u0006\u0006\n\u0004\u0008~\u0010]R\u001a\u0010\u007f\u001a\u0008\u0012\u0004\u0012\u00020\"0T8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u007f\u0010VR*\u0010\u0080\u0001\u001a\u0008\u0012\u0004\u0012\u00020\"0W8\u0016X\u0097\u0004\u00a2\u0006\u0015\n\u0005\u0008\u0080\u0001\u0010X\u0012\u0005\u0008\u0081\u0001\u0010\u0013\u001a\u0005\u0008\u0080\u0001\u0010ZR\u0016\u0010\u0082\u0001\u001a\u00020\"8\u0002X\u0082D\u00a2\u0006\u0007\n\u0005\u0008\u0082\u0001\u0010]R\u001c\u0010\u0083\u0001\u001a\u0008\u0012\u0004\u0012\u00020\"0T8\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u0083\u0001\u0010VR#\u0010\u0084\u0001\u001a\u0008\u0012\u0004\u0012\u00020\"0W8\u0016X\u0096\u0004\u00a2\u0006\u000e\n\u0005\u0008\u0084\u0001\u0010X\u001a\u0005\u0008\u0084\u0001\u0010ZR\u0016\u0010\u0085\u0001\u001a\u00020\"8\u0002X\u0082D\u00a2\u0006\u0007\n\u0005\u0008\u0085\u0001\u0010]R\u001c\u0010\u0086\u0001\u001a\u0008\u0012\u0004\u0012\u00020\"0T8\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u0086\u0001\u0010VR#\u0010\u0087\u0001\u001a\u0008\u0012\u0004\u0012\u00020\"0W8\u0016X\u0096\u0004\u00a2\u0006\u000e\n\u0005\u0008\u0087\u0001\u0010X\u001a\u0005\u0008\u0087\u0001\u0010ZR\u0016\u0010\u0088\u0001\u001a\u00020\"8\u0002X\u0082D\u00a2\u0006\u0007\n\u0005\u0008\u0088\u0001\u0010]R\u001c\u0010\u0089\u0001\u001a\u0008\u0012\u0004\u0012\u00020\"0T8\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u0089\u0001\u0010VR \u00108\u001a\u0008\u0012\u0004\u0012\u00020\"0W8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00088\u0010X\u001a\u0004\u00088\u0010ZR\u001d\u0010\u008a\u0001\u001a\u0008\u0012\u0004\u0012\u00020\u00190@8\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u008a\u0001\u0010\u008b\u0001R\"\u0010\u008c\u0001\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u00190@0T8\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u008c\u0001\u0010VR)\u0010\u008d\u0001\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u00190@0W8\u0016X\u0096\u0004\u00a2\u0006\u000e\n\u0005\u0008\u008d\u0001\u0010X\u001a\u0005\u0008\u008e\u0001\u0010ZR\u001d\u0010\u008f\u0001\u001a\u0008\u0012\u0004\u0012\u00020\u00190@8\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u008f\u0001\u0010\u008b\u0001R\"\u0010\u0090\u0001\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u00190@0T8\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u0090\u0001\u0010VR)\u0010\u0091\u0001\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u00190@0W8\u0016X\u0096\u0004\u00a2\u0006\u000e\n\u0005\u0008\u0091\u0001\u0010X\u001a\u0005\u0008\u0092\u0001\u0010ZR\u001d\u0010\u0093\u0001\u001a\u0008\u0012\u0004\u0012\u00020\u001d0F8\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u0093\u0001\u0010\u0094\u0001R\"\u0010\u0095\u0001\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u001d0F0T8\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u0095\u0001\u0010VR)\u0010\u0096\u0001\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u001d0F0W8\u0016X\u0096\u0004\u00a2\u0006\u000e\n\u0005\u0008\u0096\u0001\u0010X\u001a\u0005\u0008\u0097\u0001\u0010ZR\u0017\u0010\u0098\u0001\u001a\u0002008\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u0098\u0001\u0010\u0099\u0001R\u001c\u0010\u009a\u0001\u001a\u0008\u0012\u0004\u0012\u0002000T8\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u009a\u0001\u0010VR#\u0010\u009b\u0001\u001a\u0008\u0012\u0004\u0012\u0002000W8\u0016X\u0096\u0004\u00a2\u0006\u000e\n\u0005\u0008\u009b\u0001\u0010X\u001a\u0005\u0008\u009c\u0001\u0010ZR\u0018\u0010\u009d\u0001\u001a\u0004\u0018\u00010h8\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u009d\u0001\u0010jR\u001f\u0010\u009f\u0001\u001a\u000b\u0012\u0007\u0012\u0005\u0018\u00010\u009e\u00010T8\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u009f\u0001\u0010VR&\u0010\u00a0\u0001\u001a\u000b\u0012\u0007\u0012\u0005\u0018\u00010\u009e\u00010W8\u0016X\u0096\u0004\u00a2\u0006\u000e\n\u0005\u0008\u00a0\u0001\u0010X\u001a\u0005\u0008\u00a1\u0001\u0010ZR\u0018\u0010\u00a5\u0001\u001a\u00030\u00a2\u00018VX\u0096\u0004\u00a2\u0006\u0008\u001a\u0006\u0008\u00a3\u0001\u0010\u00a4\u0001R\u001a\u0010\u00a9\u0001\u001a\u0005\u0018\u00010\u00a6\u00018BX\u0082\u0004\u00a2\u0006\u0008\u001a\u0006\u0008\u00a7\u0001\u0010\u00a8\u0001\u00a8\u0006\u00aa\u0001"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;",
        "Landroidx/lifecycle/b1;",
        "Lv61/a;",
        "Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;",
        "Lz71/i;",
        "Lz71/d;",
        "Lx61/b;",
        "screenType",
        "<init>",
        "(Lx61/b;)V",
        "Le81/r;",
        "viewModelController",
        "(Le81/r;)V",
        "Le81/m;",
        "(Le81/m;)V",
        "Llx0/b0;",
        "update$remoteparkassistplugin_release",
        "update",
        "close",
        "()V",
        "startParking",
        "stopParking",
        "stopEngine",
        "startUndoingParkingRoute",
        "stopUndoingParkingRoute",
        "Ls71/k;",
        "newScenario",
        "requestScenarioSelection",
        "(Ls71/k;)V",
        "Ll71/y;",
        "newManeuver",
        "requestTrainedParkingSelection",
        "(Ll71/y;)V",
        "closeRPAModule",
        "",
        "newStatus",
        "driveIsInTargetPositionDidChange",
        "(Z)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "driveErrorDidChange",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V",
        "driveIsUndoActionSupportedDidChange",
        "driveIsUndoActionPossibleDidChange",
        "Lt71/d;",
        "driveMovementStatusDidChange",
        "(Lt71/d;)V",
        "driveIsParkActionPossibleDidChange",
        "driveCurrentScenarioDidChange",
        "Ls71/h;",
        "driveParkingManeuverStatusDidChange",
        "(Ls71/h;)V",
        "Lv71/b;",
        "driveVehicleTrajectoryDidChange",
        "(Lv71/b;)V",
        "scenarioSelection",
        "scenarioSelectionCurrentScenarioDidChange",
        "isSelectionDisabled",
        "scenarioSelectionIsSelectionDisabledDidChange",
        "isStartParkingEnabled",
        "scenarioSelectionStartParkingEnabledDidChange",
        "isWaitingForScenarioConfirmation",
        "scenarioSelectionWaitingForScenarioConfirmationDidChange",
        "isScenarioConfirmationSuccessful",
        "scenarioSelectionConfirmationSuccessfulDidChange",
        "",
        "newSupportedScenarios",
        "scenarioSelectionSupportedScenariosDidChange",
        "(Ljava/util/Set;)V",
        "newEnabledScenarios",
        "scenarioSelectionEnabledScenariosDidChange",
        "",
        "newAvailableTPAManeuvers",
        "scenarioSelectionAvailableTPAManeuversDidChange",
        "(Ljava/util/List;)V",
        "isUndoActionSupported",
        "scenarioSelectionIsUndoActionSupportedChange",
        "newErrorStatus",
        "scenarioSelectionErrorDidChange",
        "resetAllViewModelProperties",
        "provideNewTrajectoryDataWithDelay",
        "scenarioSelectionViewModelController",
        "Le81/r;",
        "driveViewModelController",
        "Le81/m;",
        "Lyy0/j1;",
        "_screenType",
        "Lyy0/j1;",
        "Lyy0/a2;",
        "Lyy0/a2;",
        "getScreenType",
        "()Lyy0/a2;",
        "isClosable",
        "isUndoActionSupportedInit",
        "Z",
        "_isUndoActionSupported",
        "isUndoActionPossibleInit",
        "_isUndoActionPossible",
        "isUndoActionPossible",
        "isParkActionPossibleInit",
        "_isParkActionPossible",
        "isParkActionPossible",
        "isInTargetPositionInit",
        "_isInTargetPosition",
        "isInTargetPosition",
        "",
        "errorInit",
        "Ljava/lang/Void;",
        "_error",
        "error",
        "getError",
        "driveMovementStatusInit",
        "Lt71/d;",
        "_driveMovementStatus",
        "driveMovementStatus",
        "getDriveMovementStatus",
        "isDrivingInit",
        "_isDriving",
        "isDriving",
        "currentScenarioInit",
        "Ls71/k;",
        "_currentScenario",
        "currentScenario",
        "getCurrentScenario",
        "currentScenarioSelection",
        "getCurrentScenarioSelection",
        "getCurrentScenarioSelection$annotations",
        "isScenarioSelectionRequestEnabledInit",
        "_isScenarioSelectionRequestEnabled",
        "isScenarioSelectionRequestEnabled",
        "isScenarioSelectionRequestEnabled$annotations",
        "isWaitingForScenarioSelectionConfirmationInit",
        "_isWaitingForScenarioSelectionConfirmation",
        "isWaitingForScenarioSelectionConfirmation",
        "isScenarioSelectionConfirmationSuccessfulInit",
        "_isScenarioSelectionConfirmationSuccessful",
        "isScenarioSelectionConfirmationSuccessful",
        "isSelectionDisabledInit",
        "_isSelectionDisabled",
        "supportedScenariosInit",
        "Ljava/util/Set;",
        "_supportedScenarios",
        "supportedScenarios",
        "getSupportedScenarios",
        "enabledScenariosInit",
        "_enabledScenarios",
        "enabledScenarios",
        "getEnabledScenarios",
        "availableTPAManeuversInit",
        "Ljava/util/List;",
        "_availableTPAManeuvers",
        "availableTPAManeuvers",
        "getAvailableTPAManeuvers",
        "parkingManeuverStatusInit",
        "Ls71/h;",
        "_parkingManeuverStatus",
        "parkingManeuverStatus",
        "getParkingManeuverStatus",
        "vehicleTrajectoryInit",
        "Lg61/u;",
        "_vehicleTrajectory",
        "vehicleTrajectory",
        "getVehicleTrajectory",
        "",
        "getViewModelControllerHashCode",
        "()I",
        "viewModelControllerHashCode",
        "Le81/t;",
        "getActiveViewModelController",
        "()Le81/t;",
        "activeViewModelController",
        "remoteparkassistplugin_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final $stable:I = 0x8


# instance fields
.field private final _availableTPAManeuvers:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _currentScenario:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _driveMovementStatus:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _enabledScenarios:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _error:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isDriving:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isInTargetPosition:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isParkActionPossible:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isScenarioSelectionConfirmationSuccessful:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isScenarioSelectionRequestEnabled:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isSelectionDisabled:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isUndoActionPossible:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isUndoActionSupported:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isWaitingForScenarioSelectionConfirmation:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _parkingManeuverStatus:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _screenType:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _supportedScenarios:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _vehicleTrajectory:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final availableTPAManeuvers:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final availableTPAManeuversInit:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ll71/y;",
            ">;"
        }
    .end annotation
.end field

.field private final currentScenario:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final currentScenarioInit:Ls71/k;

.field private final currentScenarioSelection:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final driveMovementStatus:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final driveMovementStatusInit:Lt71/d;

.field private driveViewModelController:Le81/m;

.field private final enabledScenarios:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final enabledScenariosInit:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ls71/k;",
            ">;"
        }
    .end annotation
.end field

.field private final error:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final errorInit:Ljava/lang/Void;

.field private final isClosable:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isDriving:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isDrivingInit:Z

.field private final isInTargetPosition:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isInTargetPositionInit:Z

.field private final isParkActionPossible:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isParkActionPossibleInit:Z

.field private final isScenarioSelectionConfirmationSuccessful:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isScenarioSelectionConfirmationSuccessfulInit:Z

.field private final isScenarioSelectionRequestEnabled:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isScenarioSelectionRequestEnabledInit:Z

.field private final isSelectionDisabled:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isSelectionDisabledInit:Z

.field private final isUndoActionPossible:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isUndoActionPossibleInit:Z

.field private final isUndoActionSupported:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isUndoActionSupportedInit:Z

.field private final isWaitingForScenarioSelectionConfirmation:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isWaitingForScenarioSelectionConfirmationInit:Z

.field private final parkingManeuverStatus:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final parkingManeuverStatusInit:Ls71/h;

.field private scenarioSelectionViewModelController:Le81/r;

.field private final screenType:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final supportedScenarios:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final supportedScenariosInit:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ls71/k;",
            ">;"
        }
    .end annotation
.end field

.field private final vehicleTrajectory:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final vehicleTrajectoryInit:Ljava/lang/Void;


# direct methods
.method public constructor <init>(Le81/m;)V
    .locals 2

    const-string v0, "viewModelController"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 69
    sget-object v0, Lx61/b;->d:Lx61/b;

    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;-><init>(Lx61/b;)V

    .line 70
    new-instance v0, Lv61/c;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Lv61/c;-><init>(Le81/m;I)V

    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 71
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->update$remoteparkassistplugin_release(Le81/m;)V

    return-void
.end method

.method public constructor <init>(Le81/r;)V
    .locals 2

    const-string v0, "viewModelController"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    sget-object v0, Lx61/b;->e:Lx61/b;

    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;-><init>(Lx61/b;)V

    .line 67
    new-instance v0, Lv61/b;

    const/4 v1, 0x1

    invoke-direct {v0, p1, v1}, Lv61/b;-><init>(Le81/r;I)V

    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 68
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->update$remoteparkassistplugin_release(Le81/r;)V

    return-void
.end method

.method private constructor <init>(Lx61/b;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_screenType:Lyy0/j1;

    .line 3
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 4
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->screenType:Lyy0/a2;

    .line 5
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    .line 6
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 7
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isClosable:Lyy0/a2;

    .line 8
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isUndoActionSupportedInit:Z

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isUndoActionSupported:Lyy0/j1;

    .line 9
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 10
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isUndoActionSupported:Lyy0/a2;

    .line 11
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isUndoActionPossibleInit:Z

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isUndoActionPossible:Lyy0/j1;

    .line 12
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 13
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isUndoActionPossible:Lyy0/a2;

    .line 14
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isParkActionPossibleInit:Z

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isParkActionPossible:Lyy0/j1;

    .line 15
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 16
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isParkActionPossible:Lyy0/a2;

    .line 17
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isInTargetPositionInit:Z

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isInTargetPosition:Lyy0/j1;

    .line 18
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 19
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isInTargetPosition:Lyy0/a2;

    .line 20
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->errorInit:Ljava/lang/Void;

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_error:Lyy0/j1;

    .line 21
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 22
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->error:Lyy0/a2;

    .line 23
    sget-object p1, Lt71/d;->d:Lt71/d;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveMovementStatusInit:Lt71/d;

    .line 24
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_driveMovementStatus:Lyy0/j1;

    .line 25
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 26
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveMovementStatus:Lyy0/a2;

    .line 27
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isDrivingInit:Z

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isDriving:Lyy0/j1;

    .line 28
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 29
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isDriving:Lyy0/a2;

    .line 30
    sget-object p1, Ls71/k;->e:Ls71/k;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->currentScenarioInit:Ls71/k;

    .line 31
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_currentScenario:Lyy0/j1;

    .line 32
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 33
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->currentScenario:Lyy0/a2;

    .line 34
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->getCurrentScenario()Lyy0/a2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->currentScenarioSelection:Lyy0/a2;

    .line 35
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isScenarioSelectionRequestEnabledInit:Z

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isScenarioSelectionRequestEnabled:Lyy0/j1;

    .line 36
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 37
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isScenarioSelectionRequestEnabled:Lyy0/a2;

    .line 38
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isWaitingForScenarioSelectionConfirmationInit:Z

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isWaitingForScenarioSelectionConfirmation:Lyy0/j1;

    .line 39
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 40
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isWaitingForScenarioSelectionConfirmation:Lyy0/a2;

    .line 41
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isScenarioSelectionConfirmationSuccessfulInit:Z

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isScenarioSelectionConfirmationSuccessful:Lyy0/j1;

    .line 42
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 43
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isScenarioSelectionConfirmationSuccessful:Lyy0/a2;

    .line 44
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isSelectionDisabledInit:Z

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isSelectionDisabled:Lyy0/j1;

    .line 45
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 46
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isSelectionDisabled:Lyy0/a2;

    .line 47
    sget-object p1, Lmx0/u;->d:Lmx0/u;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->supportedScenariosInit:Ljava/util/Set;

    .line 48
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_supportedScenarios:Lyy0/j1;

    .line 49
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 50
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->supportedScenarios:Lyy0/a2;

    .line 51
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->enabledScenariosInit:Ljava/util/Set;

    .line 52
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_enabledScenarios:Lyy0/j1;

    .line 53
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 54
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->enabledScenarios:Lyy0/a2;

    .line 55
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->availableTPAManeuversInit:Ljava/util/List;

    .line 56
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_availableTPAManeuvers:Lyy0/j1;

    .line 57
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 58
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->availableTPAManeuvers:Lyy0/a2;

    .line 59
    sget-object p1, Ls71/h;->d:Ls71/h;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->parkingManeuverStatusInit:Ls71/h;

    .line 60
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_parkingManeuverStatus:Lyy0/j1;

    .line 61
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 62
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->parkingManeuverStatus:Lyy0/a2;

    .line 63
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->vehicleTrajectoryInit:Ljava/lang/Void;

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_vehicleTrajectory:Lyy0/j1;

    .line 64
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 65
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->vehicleTrajectory:Lyy0/a2;

    return-void
.end method

.method private static final _init_$lambda$0(Le81/r;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "init() viewModelController = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final _init_$lambda$1(Le81/m;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "init() viewModelController = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static synthetic a(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->close$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$provideNewTrajectoryDataWithDelay(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;Lv71/b;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->provideNewTrajectoryDataWithDelay(Lv71/b;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Le81/m;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->update$lambda$1(Le81/m;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final close$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;)Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveViewModelController:Le81/m;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->scenarioSelectionViewModelController:Le81/r;

    .line 4
    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "close() driveViewModelController = "

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v0, ", scenarioSelectionViewModelController = "

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method

.method public static synthetic d(Le81/m;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_init_$lambda$1(Le81/m;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Le81/r;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_init_$lambda$0(Le81/r;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Le81/r;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->update$lambda$0(Le81/r;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final getActiveViewModelController()Le81/t;
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->scenarioSelectionViewModelController:Le81/r;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveViewModelController:Le81/m;

    .line 7
    .line 8
    return-object p0
.end method

.method public static synthetic getCurrentScenarioSelection$annotations()V
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic isScenarioSelectionRequestEnabled$annotations()V
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    return-void
.end method

.method private final provideNewTrajectoryDataWithDelay(Lv71/b;)V
    .locals 14

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    goto/16 :goto_5

    .line 5
    .line 6
    :cond_0
    iget-object v1, p1, Lv71/b;->g:Lv71/d;

    .line 7
    .line 8
    iget-object v2, p1, Lv71/b;->a:Lw71/c;

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-static {v2, v3}, Llp/xc;->b(Lw71/c;F)Lsv0/a;

    .line 12
    .line 13
    .line 14
    move-result-object v5

    .line 15
    iget-object v2, p1, Lv71/b;->b:Lw71/c;

    .line 16
    .line 17
    invoke-static {v2, v3}, Llp/xc;->b(Lw71/c;F)Lsv0/a;

    .line 18
    .line 19
    .line 20
    move-result-object v6

    .line 21
    iget-wide v7, p1, Lv71/b;->f:D

    .line 22
    .line 23
    double-to-float v2, v7

    .line 24
    const/16 v4, 0xb4

    .line 25
    .line 26
    int-to-float v4, v4

    .line 27
    mul-float/2addr v2, v4

    .line 28
    float-to-double v7, v2

    .line 29
    const-wide v9, 0x400921fb54442d18L    # Math.PI

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    div-double/2addr v7, v9

    .line 35
    double-to-float v7, v7

    .line 36
    iget-object v2, p1, Lv71/b;->d:Lv71/a;

    .line 37
    .line 38
    if-eqz v2, :cond_2

    .line 39
    .line 40
    iget-object v0, p1, Lv71/b;->e:Ls71/o;

    .line 41
    .line 42
    const-string v8, "trajectoryDirectionStatus"

    .line 43
    .line 44
    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    iget-object v8, v2, Lv71/a;->a:Lw71/b;

    .line 48
    .line 49
    iget-object v11, v8, Lw71/b;->a:Lw71/c;

    .line 50
    .line 51
    invoke-static {v11, v3}, Llp/xc;->b(Lw71/c;F)Lsv0/a;

    .line 52
    .line 53
    .line 54
    move-result-object v11

    .line 55
    iget-wide v12, v8, Lw71/b;->b:D

    .line 56
    .line 57
    double-to-float v8, v12

    .line 58
    mul-float/2addr v8, v4

    .line 59
    float-to-double v12, v8

    .line 60
    div-double/2addr v12, v9

    .line 61
    double-to-float v8, v12

    .line 62
    sget-object v12, Ls71/o;->d:Ls71/o;

    .line 63
    .line 64
    if-ne v0, v12, :cond_1

    .line 65
    .line 66
    const-wide v12, -0x4006de04abbbd2e8L    # -1.5707963267948966

    .line 67
    .line 68
    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_1
    const-wide v12, 0x3ff921fb54442d18L    # 1.5707963267948966

    .line 73
    .line 74
    .line 75
    .line 76
    .line 77
    :goto_0
    double-to-float v12, v12

    .line 78
    mul-float/2addr v12, v4

    .line 79
    float-to-double v12, v12

    .line 80
    div-double/2addr v12, v9

    .line 81
    double-to-float v4, v12

    .line 82
    add-float/2addr v4, v8

    .line 83
    iget-wide v8, v2, Lv71/a;->b:D

    .line 84
    .line 85
    double-to-float v2, v8

    .line 86
    new-instance v8, Lg61/c;

    .line 87
    .line 88
    invoke-direct {v8, v11, v4, v0, v2}, Lg61/c;-><init>(Lsv0/a;FLs71/o;F)V

    .line 89
    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_2
    move-object v8, v0

    .line 93
    :goto_1
    iget-object v0, p1, Lv71/b;->c:Lv71/c;

    .line 94
    .line 95
    iget-object v0, v0, Lv71/c;->a:Ljava/lang/Object;

    .line 96
    .line 97
    new-instance v9, Ljava/util/ArrayList;

    .line 98
    .line 99
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 100
    .line 101
    .line 102
    check-cast v0, Ljava/lang/Iterable;

    .line 103
    .line 104
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 109
    .line 110
    .line 111
    move-result v2

    .line 112
    if-eqz v2, :cond_3

    .line 113
    .line 114
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    check-cast v2, Llx0/r;

    .line 119
    .line 120
    iget-object v4, v2, Llx0/r;->d:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v4, Lw71/c;

    .line 123
    .line 124
    invoke-static {v4, v3}, Llp/xc;->b(Lw71/c;F)Lsv0/a;

    .line 125
    .line 126
    .line 127
    move-result-object v4

    .line 128
    invoke-virtual {v9, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    iget-object v4, v2, Llx0/r;->e:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v4, Lw71/c;

    .line 134
    .line 135
    invoke-static {v4, v3}, Llp/xc;->b(Lw71/c;F)Lsv0/a;

    .line 136
    .line 137
    .line 138
    move-result-object v4

    .line 139
    invoke-virtual {v9, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    iget-object v2, v2, Llx0/r;->f:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v2, Lw71/c;

    .line 145
    .line 146
    invoke-static {v2, v3}, Llp/xc;->b(Lw71/c;F)Lsv0/a;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    invoke-virtual {v9, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    goto :goto_2

    .line 154
    :cond_3
    iget-object v0, v1, Lv71/d;->a:Ljava/util/List;

    .line 155
    .line 156
    check-cast v0, Ljava/lang/Iterable;

    .line 157
    .line 158
    new-instance v10, Ljava/util/ArrayList;

    .line 159
    .line 160
    const/16 v2, 0xa

    .line 161
    .line 162
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 163
    .line 164
    .line 165
    move-result v3

    .line 166
    invoke-direct {v10, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 167
    .line 168
    .line 169
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 174
    .line 175
    .line 176
    move-result v3

    .line 177
    const/high16 v4, 0x3f800000    # 1.0f

    .line 178
    .line 179
    if-eqz v3, :cond_4

    .line 180
    .line 181
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v3

    .line 185
    check-cast v3, Lw71/c;

    .line 186
    .line 187
    invoke-static {v3, v4}, Llp/xc;->b(Lw71/c;F)Lsv0/a;

    .line 188
    .line 189
    .line 190
    move-result-object v3

    .line 191
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 192
    .line 193
    .line 194
    goto :goto_3

    .line 195
    :cond_4
    iget-object v0, v1, Lv71/d;->b:Ljava/util/List;

    .line 196
    .line 197
    check-cast v0, Ljava/lang/Iterable;

    .line 198
    .line 199
    new-instance v11, Ljava/util/ArrayList;

    .line 200
    .line 201
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 202
    .line 203
    .line 204
    move-result v1

    .line 205
    invoke-direct {v11, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 206
    .line 207
    .line 208
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 209
    .line 210
    .line 211
    move-result-object v0

    .line 212
    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 213
    .line 214
    .line 215
    move-result v1

    .line 216
    if-eqz v1, :cond_5

    .line 217
    .line 218
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v1

    .line 222
    check-cast v1, Lw71/c;

    .line 223
    .line 224
    invoke-static {v1, v4}, Llp/xc;->b(Lw71/c;F)Lsv0/a;

    .line 225
    .line 226
    .line 227
    move-result-object v1

    .line 228
    invoke-virtual {v11, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 229
    .line 230
    .line 231
    goto :goto_4

    .line 232
    :cond_5
    iget-object v12, p1, Lv71/b;->e:Ls71/o;

    .line 233
    .line 234
    iget-boolean v13, p1, Lv71/b;->h:Z

    .line 235
    .line 236
    new-instance v4, Lg61/u;

    .line 237
    .line 238
    invoke-direct/range {v4 .. v13}, Lg61/u;-><init>(Lsv0/a;Lsv0/a;FLg61/c;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ls71/o;Z)V

    .line 239
    .line 240
    .line 241
    move-object v0, v4

    .line 242
    :goto_5
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_vehicleTrajectory:Lyy0/j1;

    .line 243
    .line 244
    :cond_6
    move-object p1, p0

    .line 245
    check-cast p1, Lyy0/c2;

    .line 246
    .line 247
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v1

    .line 251
    move-object v2, v1

    .line 252
    check-cast v2, Lg61/u;

    .line 253
    .line 254
    invoke-virtual {p1, v1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 255
    .line 256
    .line 257
    move-result p1

    .line 258
    if-eqz p1, :cond_6

    .line 259
    .line 260
    return-void
.end method

.method private final resetAllViewModelProperties()V
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isUndoActionSupported:Lyy0/j1;

    .line 2
    .line 3
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isUndoActionSupportedInit:Z

    .line 4
    .line 5
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isUndoActionPossible:Lyy0/j1;

    .line 19
    .line 20
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isUndoActionPossibleInit:Z

    .line 21
    .line 22
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v0, Lyy0/c2;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isParkActionPossible:Lyy0/j1;

    .line 35
    .line 36
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isParkActionPossibleInit:Z

    .line 37
    .line 38
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    check-cast v0, Lyy0/c2;

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isInTargetPosition:Lyy0/j1;

    .line 51
    .line 52
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isInTargetPositionInit:Z

    .line 53
    .line 54
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    check-cast v0, Lyy0/c2;

    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_error:Lyy0/j1;

    .line 67
    .line 68
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->errorInit:Ljava/lang/Void;

    .line 69
    .line 70
    check-cast v0, Lyy0/c2;

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_driveMovementStatus:Lyy0/j1;

    .line 76
    .line 77
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveMovementStatusInit:Lt71/d;

    .line 78
    .line 79
    check-cast v0, Lyy0/c2;

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isDriving:Lyy0/j1;

    .line 85
    .line 86
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isDrivingInit:Z

    .line 87
    .line 88
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    check-cast v0, Lyy0/c2;

    .line 93
    .line 94
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_currentScenario:Lyy0/j1;

    .line 101
    .line 102
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->currentScenarioInit:Ls71/k;

    .line 103
    .line 104
    check-cast v0, Lyy0/c2;

    .line 105
    .line 106
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isScenarioSelectionRequestEnabled:Lyy0/j1;

    .line 110
    .line 111
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isScenarioSelectionRequestEnabledInit:Z

    .line 112
    .line 113
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    check-cast v0, Lyy0/c2;

    .line 118
    .line 119
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 120
    .line 121
    .line 122
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isWaitingForScenarioSelectionConfirmation:Lyy0/j1;

    .line 126
    .line 127
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isWaitingForScenarioSelectionConfirmationInit:Z

    .line 128
    .line 129
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    check-cast v0, Lyy0/c2;

    .line 134
    .line 135
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 136
    .line 137
    .line 138
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isScenarioSelectionConfirmationSuccessful:Lyy0/j1;

    .line 142
    .line 143
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isScenarioSelectionConfirmationSuccessfulInit:Z

    .line 144
    .line 145
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 146
    .line 147
    .line 148
    move-result-object v1

    .line 149
    check-cast v0, Lyy0/c2;

    .line 150
    .line 151
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 152
    .line 153
    .line 154
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isSelectionDisabled:Lyy0/j1;

    .line 158
    .line 159
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isSelectionDisabledInit:Z

    .line 160
    .line 161
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    check-cast v0, Lyy0/c2;

    .line 166
    .line 167
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 168
    .line 169
    .line 170
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_supportedScenarios:Lyy0/j1;

    .line 174
    .line 175
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->supportedScenariosInit:Ljava/util/Set;

    .line 176
    .line 177
    check-cast v0, Lyy0/c2;

    .line 178
    .line 179
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 180
    .line 181
    .line 182
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_enabledScenarios:Lyy0/j1;

    .line 183
    .line 184
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->enabledScenariosInit:Ljava/util/Set;

    .line 185
    .line 186
    check-cast v0, Lyy0/c2;

    .line 187
    .line 188
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_availableTPAManeuvers:Lyy0/j1;

    .line 192
    .line 193
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->availableTPAManeuversInit:Ljava/util/List;

    .line 194
    .line 195
    check-cast v0, Lyy0/c2;

    .line 196
    .line 197
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_parkingManeuverStatus:Lyy0/j1;

    .line 201
    .line 202
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->parkingManeuverStatusInit:Ls71/h;

    .line 203
    .line 204
    check-cast v0, Lyy0/c2;

    .line 205
    .line 206
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 207
    .line 208
    .line 209
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_vehicleTrajectory:Lyy0/j1;

    .line 210
    .line 211
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->vehicleTrajectoryInit:Ljava/lang/Void;

    .line 212
    .line 213
    check-cast v0, Lyy0/c2;

    .line 214
    .line 215
    invoke-virtual {v0, p0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    return-void
.end method

.method private static final update$lambda$0(Le81/r;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "update() viewModelController = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final update$lambda$1(Le81/m;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "update() viewModelController = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method


# virtual methods
.method public close()V
    .locals 2

    .line 1
    new-instance v0, Lu2/a;

    .line 2
    .line 3
    const/16 v1, 0xb

    .line 4
    .line 5
    invoke-direct {v0, p0, v1}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveViewModelController:Le81/m;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {v0}, Lz71/h;->onDisappear()V

    .line 16
    .line 17
    .line 18
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveViewModelController:Le81/m;

    .line 19
    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    invoke-interface {v0, p0}, Le81/m;->removeObserver(Lz71/d;)V

    .line 23
    .line 24
    .line 25
    :cond_1
    const/4 v0, 0x0

    .line 26
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveViewModelController:Le81/m;

    .line 27
    .line 28
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->scenarioSelectionViewModelController:Le81/r;

    .line 29
    .line 30
    if-eqz v1, :cond_2

    .line 31
    .line 32
    invoke-interface {v1}, Lz71/h;->onDisappear()V

    .line 33
    .line 34
    .line 35
    :cond_2
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->scenarioSelectionViewModelController:Le81/r;

    .line 36
    .line 37
    if-eqz v1, :cond_3

    .line 38
    .line 39
    invoke-interface {v1, p0}, Le81/r;->removeObserver(Lz71/i;)V

    .line 40
    .line 41
    .line 42
    :cond_3
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->scenarioSelectionViewModelController:Le81/r;

    .line 43
    .line 44
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->resetAllViewModelProperties()V

    .line 45
    .line 46
    .line 47
    return-void
.end method

.method public closeRPAModule()V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveViewModelController:Le81/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Lz71/h;->closeScreen()V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->scenarioSelectionViewModelController:Le81/r;

    .line 9
    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    invoke-interface {p0}, Lz71/h;->closeScreen()V

    .line 13
    .line 14
    .line 15
    :cond_1
    return-void
.end method

.method public driveCurrentScenarioDidChange(Ls71/k;)V
    .locals 3

    .line 1
    const-string v0, "newStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_currentScenario:Lyy0/j1;

    .line 7
    .line 8
    :cond_0
    move-object v0, p0

    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    move-object v2, v1

    .line 16
    check-cast v2, Ls71/k;

    .line 17
    .line 18
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    return-void
.end method

.method public driveErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_error:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 12
    .line 13
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public driveIsInTargetPositionDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isInTargetPosition:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public driveIsParkActionPossibleDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isParkActionPossible:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public driveIsUndoActionPossibleDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isUndoActionPossible:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public driveIsUndoActionSupportedDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isUndoActionSupported:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public driveMovementStatusDidChange(Lt71/d;)V
    .locals 4

    .line 1
    const-string v0, "newStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_driveMovementStatus:Lyy0/j1;

    .line 7
    .line 8
    :cond_0
    move-object v1, v0

    .line 9
    check-cast v1, Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    move-object v3, v2

    .line 16
    check-cast v3, Lt71/d;

    .line 17
    .line 18
    invoke-virtual {v1, v2, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isDriving:Lyy0/j1;

    .line 25
    .line 26
    :cond_1
    move-object p0, v1

    .line 27
    check-cast p0, Lyy0/c2;

    .line 28
    .line 29
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    move-object v2, v0

    .line 34
    check-cast v2, Ljava/lang/Boolean;

    .line 35
    .line 36
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    sget-object v2, Lt71/d;->e:Lt71/d;

    .line 40
    .line 41
    if-eq p1, v2, :cond_3

    .line 42
    .line 43
    sget-object v2, Lt71/d;->f:Lt71/d;

    .line 44
    .line 45
    if-ne p1, v2, :cond_2

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_2
    const/4 v2, 0x0

    .line 49
    goto :goto_1

    .line 50
    :cond_3
    :goto_0
    const/4 v2, 0x1

    .line 51
    :goto_1
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-virtual {p0, v0, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    if-eqz p0, :cond_1

    .line 60
    .line 61
    return-void
.end method

.method public driveParkingManeuverStatusDidChange(Ls71/h;)V
    .locals 3

    .line 1
    const-string v0, "newStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_parkingManeuverStatus:Lyy0/j1;

    .line 7
    .line 8
    :cond_0
    move-object v0, p0

    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    move-object v2, v1

    .line 16
    check-cast v2, Ls71/h;

    .line 17
    .line 18
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    return-void
.end method

.method public driveVehicleTrajectoryDidChange(Lv71/b;)V
    .locals 4

    .line 1
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ls10/a0;

    .line 6
    .line 7
    const/16 v2, 0x10

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-direct {v1, v2, p0, p1, v3}, Ls10/a0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x3

    .line 14
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public getAvailableTPAManeuvers()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->availableTPAManeuvers:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCurrentScenario()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->currentScenario:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCurrentScenarioSelection()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->currentScenarioSelection:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDriveMovementStatus()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveMovementStatus:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEnabledScenarios()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->enabledScenarios:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getError()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->error:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getParkingManeuverStatus()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->parkingManeuverStatus:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getScreenType()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->screenType:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSupportedScenarios()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->supportedScenarios:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getVehicleTrajectory()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->vehicleTrajectory:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getViewModelControllerHashCode()I
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->getActiveViewModelController()Le81/t;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0
.end method

.method public isClosable()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isClosable:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isDriving()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isDriving:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isInTargetPosition()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isInTargetPosition:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isParkActionPossible()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isParkActionPossible:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isScenarioSelectionConfirmationSuccessful()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isScenarioSelectionConfirmationSuccessful:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isScenarioSelectionRequestEnabled()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isScenarioSelectionRequestEnabled:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isSelectionDisabled()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isSelectionDisabled:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isUndoActionPossible()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isUndoActionPossible:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isUndoActionSupported()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isUndoActionSupported:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isWaitingForScenarioSelectionConfirmation()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->isWaitingForScenarioSelectionConfirmation:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public requestScenarioSelection(Ls71/k;)V
    .locals 1

    .line 1
    const-string v0, "newScenario"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->scenarioSelectionViewModelController:Le81/r;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-interface {p0, p1}, Le81/r;->changeScenario(Ls71/k;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public requestTrainedParkingSelection(Ll71/y;)V
    .locals 1

    .line 1
    const-string v0, "newManeuver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->scenarioSelectionViewModelController:Le81/r;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    iget p1, p1, Ll71/y;->b:I

    .line 11
    .line 12
    invoke-interface {p0, p1}, Le81/r;->changeTPAManeuver(I)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method

.method public scenarioSelectionAvailableTPAManeuversDidChange(Ljava/util/List;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ll71/y;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "newAvailableTPAManeuvers"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_availableTPAManeuvers:Lyy0/j1;

    .line 7
    .line 8
    :cond_0
    move-object v0, p0

    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    move-object v2, v1

    .line 16
    check-cast v2, Ljava/util/List;

    .line 17
    .line 18
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    return-void
.end method

.method public scenarioSelectionConfirmationSuccessfulDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isScenarioSelectionConfirmationSuccessful:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public scenarioSelectionCurrentScenarioDidChange(Ls71/k;)V
    .locals 3

    .line 1
    const-string v0, "scenarioSelection"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_currentScenario:Lyy0/j1;

    .line 7
    .line 8
    :cond_0
    move-object v0, p0

    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    move-object v2, v1

    .line 16
    check-cast v2, Ls71/k;

    .line 17
    .line 18
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    return-void
.end method

.method public scenarioSelectionEnabledScenariosDidChange(Ljava/util/Set;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "+",
            "Ls71/k;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "newEnabledScenarios"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_enabledScenarios:Lyy0/j1;

    .line 7
    .line 8
    :cond_0
    move-object v0, p0

    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    move-object v2, v1

    .line 16
    check-cast v2, Ljava/util/Set;

    .line 17
    .line 18
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    return-void
.end method

.method public scenarioSelectionErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_error:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 12
    .line 13
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public scenarioSelectionIsSelectionDisabledDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isSelectionDisabled:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public scenarioSelectionIsUndoActionSupportedChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isUndoActionSupported:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public scenarioSelectionStartParkingEnabledDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isParkActionPossible:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public scenarioSelectionSupportedScenariosDidChange(Ljava/util/Set;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "+",
            "Ls71/k;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "newSupportedScenarios"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_supportedScenarios:Lyy0/j1;

    .line 7
    .line 8
    :cond_0
    move-object v0, p0

    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    move-object v2, v1

    .line 16
    check-cast v2, Ljava/util/Set;

    .line 17
    .line 18
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    return-void
.end method

.method public scenarioSelectionWaitingForScenarioConfirmationDidChange(Z)V
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_isWaitingForScenarioSelectionConfirmation:Lyy0/j1;

    .line 2
    .line 3
    :cond_0
    move-object v0, p0

    .line 4
    check-cast v0, Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v2, p1, v0, v1}, Lp3/m;->y(Ljava/lang/Boolean;ZLyy0/c2;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    return-void
.end method

.method public startParking()V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveViewModelController:Le81/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Le81/m;->startParking()V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->scenarioSelectionViewModelController:Le81/r;

    .line 9
    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    invoke-interface {p0}, Le81/r;->startParking()V

    .line 13
    .line 14
    .line 15
    :cond_1
    return-void
.end method

.method public startUndoingParkingRoute()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveViewModelController:Le81/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Le81/m;->startUndoing()V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public stopEngine()V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveViewModelController:Le81/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Le81/m;->stopEngine()V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->scenarioSelectionViewModelController:Le81/r;

    .line 9
    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    invoke-interface {p0}, Le81/r;->stopEngine()V

    .line 13
    .line 14
    .line 15
    :cond_1
    return-void
.end method

.method public stopParking()V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveViewModelController:Le81/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Le81/m;->stopParking()V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->scenarioSelectionViewModelController:Le81/r;

    .line 9
    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    invoke-interface {p0}, Le81/r;->stopParking()V

    .line 13
    .line 14
    .line 15
    :cond_1
    return-void
.end method

.method public stopUndoingParkingRoute()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveViewModelController:Le81/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Le81/m;->stopUndoing()V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public final update$remoteparkassistplugin_release(Le81/m;)V
    .locals 2

    const-string v0, "viewModelController"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    new-instance v0, Lv61/c;

    const/4 v1, 0x1

    invoke-direct {v0, p1, v1}, Lv61/c;-><init>(Le81/m;I)V

    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->close()V

    .line 11
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->driveViewModelController:Le81/m;

    const/4 v0, 0x1

    .line 12
    invoke-interface {p1, p0, v0}, Le81/m;->addObserver(Lz71/d;Z)V

    .line 13
    invoke-interface {p1}, Lz71/h;->onAppear()V

    .line 14
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_screenType:Lyy0/j1;

    sget-object p1, Lx61/b;->d:Lx61/b;

    check-cast p0, Lyy0/c2;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v0, 0x0

    .line 15
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    return-void
.end method

.method public final update$remoteparkassistplugin_release(Le81/r;)V
    .locals 2

    const-string v0, "viewModelController"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lv61/b;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Lv61/b;-><init>(Le81/r;I)V

    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 2
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->close()V

    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->scenarioSelectionViewModelController:Le81/r;

    const/4 v0, 0x1

    .line 4
    invoke-interface {p1, p0, v0}, Le81/r;->addObserver(Lz71/i;Z)V

    .line 5
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_parkingManeuverStatus:Lyy0/j1;

    invoke-interface {p1}, Le81/r;->getParkingManeuverStatus()Ls71/h;

    move-result-object v1

    check-cast v0, Lyy0/c2;

    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 6
    invoke-interface {p1}, Lz71/h;->onAppear()V

    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->_screenType:Lyy0/j1;

    sget-object p1, Lx61/b;->e:Lx61/b;

    check-cast p0, Lyy0/c2;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v0, 0x0

    .line 8
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    return-void
.end method
