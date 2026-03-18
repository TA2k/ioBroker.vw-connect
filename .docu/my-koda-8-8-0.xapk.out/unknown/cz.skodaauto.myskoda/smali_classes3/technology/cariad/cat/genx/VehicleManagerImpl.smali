.class public final Ltechnology/cariad/cat/genx/VehicleManagerImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/b0;
.implements Ltechnology/cariad/cat/genx/InternalVehicleManager;
.implements Ltechnology/cariad/cat/genx/Referencing;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00fe\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\u0005\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\n\n\u0002\u0008\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0010\u0011\n\u0002\u0008\u0003\n\u0002\u0010\t\n\u0002\u0008\u0018\n\u0002\u0018\u0002\n\u0002\u0008\u0019\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010$\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0008\u0000\u0018\u00002\u00020\u00012\u00020\u00022\u00020\u0003:\u0002\u00ec\u0001B\u007f\u0008\u0000\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u001c\u0010\u000b\u001a\u0018\u0012\u0014\u0012\u0012\u0012\u0004\u0012\u00020\u0008\u0012\u0004\u0012\u00020\t0\u0007j\u0002`\n0\u0006\u0012\u0006\u0010\r\u001a\u00020\u000c\u0012\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u000e\u0012\u0006\u0010\u0011\u001a\u00020\u0010\u0012\u0006\u0010\u0013\u001a\u00020\u0012\u0012\u0006\u0010\u0015\u001a\u00020\u0014\u0012\u0008\u0008\u0002\u0010\u0017\u001a\u00020\u0016\u0012\u0006\u0010\u0018\u001a\u00020\u0008\u0012\u0008\u0008\u0002\u0010\u001a\u001a\u00020\u0019\u0012\u0008\u0008\u0002\u0010\u001c\u001a\u00020\u001b\u00a2\u0006\u0004\u0008\u001d\u0010\u001eJ\u000f\u0010 \u001a\u00020\u001fH\u0016\u00a2\u0006\u0004\u0008 \u0010!J\u001d\u0010&\u001a\u0004\u0018\u00010%2\n\u0010$\u001a\u00060\"j\u0002`#H\u0016\u00a2\u0006\u0004\u0008&\u0010\'J\u0017\u0010+\u001a\u00020*2\u0006\u0010)\u001a\u00020(H\u0016\u00a2\u0006\u0004\u0008+\u0010,J\u0017\u0010-\u001a\u00020*2\u0006\u0010)\u001a\u00020(H\u0016\u00a2\u0006\u0004\u0008-\u0010,J\u000f\u0010.\u001a\u00020*H\u0016\u00a2\u0006\u0004\u0008.\u0010/J$\u00105\u001a\u0008\u0012\u0004\u0012\u00020\u001f022\u000c\u00101\u001a\u0008\u0012\u0004\u0012\u0002000\u0006H\u0096@\u00a2\u0006\u0004\u00083\u00104J\u001e\u00108\u001a\u0008\u0012\u0004\u0012\u00020\u001f022\u0006\u0010$\u001a\u00020\"H\u0096@\u00a2\u0006\u0004\u00086\u00107J\u0016\u0010;\u001a\u0008\u0012\u0004\u0012\u00020\u001f02H\u0096@\u00a2\u0006\u0004\u00089\u0010:J\u0016\u0010>\u001a\u0008\u0012\u0004\u0012\u00020<02H\u0096@\u00a2\u0006\u0004\u0008=\u0010:J\u0017\u0010B\u001a\u00020\u001f2\u0006\u0010?\u001a\u00020<H\u0000\u00a2\u0006\u0004\u0008@\u0010AJ\u001f\u0010G\u001a\u00020\u001f2\u0006\u0010D\u001a\u00020C2\u0006\u0010F\u001a\u00020EH\u0016\u00a2\u0006\u0004\u0008G\u0010HJ/\u0010P\u001a\u00020\u001f2\u0006\u0010J\u001a\u00020I2\u0006\u0010F\u001a\u00020K2\u0006\u0010M\u001a\u00020L2\u0006\u0010O\u001a\u00020NH\u0017\u00a2\u0006\u0004\u0008P\u0010QJ\u0016\u0010S\u001a\u0008\u0012\u0004\u0012\u00020\u001f02H\u0096@\u00a2\u0006\u0004\u0008R\u0010:J\u001f\u0010W\u001a\u00020\u001f2\u0006\u0010U\u001a\u00020T2\u0006\u0010V\u001a\u00020*H\u0016\u00a2\u0006\u0004\u0008W\u0010XJ\u001f\u0010[\u001a\u00020\u001f2\u0006\u0010U\u001a\u00020T2\u0006\u0010Z\u001a\u00020YH\u0016\u00a2\u0006\u0004\u0008[\u0010\\JU\u0010f\u001a\u0004\u0018\u00010Y2\n\u0010$\u001a\u00060\"j\u0002`#2\u0006\u0010O\u001a\u00020T2\u0006\u0010^\u001a\u00020]2\u0006\u0010`\u001a\u00020_2\u0006\u0010a\u001a\u00020\u000c2\u0006\u0010c\u001a\u00020b2\u0006\u0010d\u001a\u00020b2\u0006\u0010e\u001a\u00020\u0010H\u0016\u00a2\u0006\u0004\u0008f\u0010gJ%\u0010h\u001a\u0004\u0018\u00010Y2\n\u0010$\u001a\u00060\"j\u0002`#2\u0006\u0010a\u001a\u00020\u000cH\u0016\u00a2\u0006\u0004\u0008h\u0010iJ#\u0010j\u001a\u00020\u001f2\n\u0010$\u001a\u00060\"j\u0002`#2\u0006\u0010Z\u001a\u00020YH\u0016\u00a2\u0006\u0004\u0008j\u0010kJ)\u0010n\u001a\u0004\u0018\u00010]2\u0006\u0010O\u001a\u00020T2\u0006\u0010l\u001a\u00020]2\u0006\u0010m\u001a\u00020]H\u0016\u00a2\u0006\u0004\u0008n\u0010oJ)\u0010p\u001a\u0004\u0018\u00010]2\u0006\u0010O\u001a\u00020T2\u0006\u0010l\u001a\u00020]2\u0006\u0010m\u001a\u00020]H\u0016\u00a2\u0006\u0004\u0008p\u0010oJ!\u0010t\u001a\u0004\u0018\u00010Y2\u0006\u0010&\u001a\u00020q2\u0006\u0010s\u001a\u00020rH\u0003\u00a2\u0006\u0004\u0008t\u0010uJ\u001d\u0010y\u001a\u0008\u0012\u0004\u0012\u00020q022\u0006\u00101\u001a\u00020vH\u0003\u00a2\u0006\u0004\u0008w\u0010xJ\u001d\u0010z\u001a\u0004\u0018\u00010Y2\n\u0010$\u001a\u00060\"j\u0002`#H\u0003\u00a2\u0006\u0004\u0008z\u0010{J\u0010\u0010|\u001a\u00020\u001fH\u0083 \u00a2\u0006\u0004\u0008|\u0010!J3\u0010\u0082\u0001\u001a\u00030\u0081\u00012\u000c\u0010~\u001a\u0008\u0012\u0004\u0012\u00020\t0}2\u0006\u0010\u007f\u001a\u00020\"2\u0007\u0010\u0080\u0001\u001a\u00020\"H\u0082 \u00a2\u0006\u0006\u0008\u0082\u0001\u0010\u0083\u0001J\u0013\u0010\u0084\u0001\u001a\u00020\u000cH\u0083 \u00a2\u0006\u0006\u0008\u0084\u0001\u0010\u0085\u0001J\u001c\u0010\u0087\u0001\u001a\u00020\u000c2\u0007\u0010\u0086\u0001\u001a\u00020\u0008H\u0083 \u00a2\u0006\u0006\u0008\u0087\u0001\u0010\u0088\u0001J\u001b\u0010\u0089\u0001\u001a\u00020\u000c2\u0006\u0010$\u001a\u00020\"H\u0083 \u00a2\u0006\u0006\u0008\u0089\u0001\u0010\u008a\u0001J\u0013\u0010\u008b\u0001\u001a\u00020\u000cH\u0083 \u00a2\u0006\u0006\u0008\u008b\u0001\u0010\u0085\u0001J\u0013\u0010\u008c\u0001\u001a\u00020\u000cH\u0083 \u00a2\u0006\u0006\u0008\u008c\u0001\u0010\u0085\u0001J\u001b\u0010\u008d\u0001\u001a\u00020\u000c2\u0006\u0010&\u001a\u00020qH\u0083 \u00a2\u0006\u0006\u0008\u008d\u0001\u0010\u008e\u0001J\u001c\u0010\u0090\u0001\u001a\u00020\u001f2\u0007\u0010\u008f\u0001\u001a\u00020\u000cH\u0083 \u00a2\u0006\u0006\u0008\u0090\u0001\u0010\u0091\u0001J\u0013\u0010\u0092\u0001\u001a\u00020\u000cH\u0083 \u00a2\u0006\u0006\u0008\u0092\u0001\u0010\u0085\u0001JG\u0010\u0097\u0001\u001a\u00020\u000c2\u0006\u0010$\u001a\u00020\"2\u0007\u0010\u0093\u0001\u001a\u00020_2\u0006\u0010\u0011\u001a\u00020\u00102\u0007\u0010\u0094\u0001\u001a\u00020b2\u0007\u0010\u0095\u0001\u001a\u00020b2\u0007\u0010\u0096\u0001\u001a\u00020bH\u0083 \u00a2\u0006\u0006\u0008\u0097\u0001\u0010\u0098\u0001J\u0013\u0010\u0099\u0001\u001a\u00020\u000cH\u0083 \u00a2\u0006\u0006\u0008\u0099\u0001\u0010\u0085\u0001J5\u0010\u009c\u0001\u001a\u00020\u000c2\u0008\u0010\u009b\u0001\u001a\u00030\u009a\u00012\u0006\u0010^\u001a\u00020]2\u0006\u0010O\u001a\u00020T2\u0006\u0010\u0011\u001a\u00020\u0010H\u0083 \u00a2\u0006\u0006\u0008\u009c\u0001\u0010\u009d\u0001R\u0015\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u0005\u0010\u009e\u0001R\u0015\u0010\u0011\u001a\u00020\u00108\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u0011\u0010\u009f\u0001R\u0015\u0010\u0013\u001a\u00020\u00128\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u0013\u0010\u00a0\u0001R\u001a\u0010\u0015\u001a\u00020\u00148\u0006\u00a2\u0006\u000f\n\u0005\u0008\u0015\u0010\u00a1\u0001\u001a\u0006\u0008\u00a2\u0001\u0010\u00a3\u0001R\u0015\u0010\u0017\u001a\u00020\u00168\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u0017\u0010\u00a4\u0001R\u001a\u0010\u0018\u001a\u00020\u00088\u0006\u00a2\u0006\u000f\n\u0005\u0008\u0018\u0010\u00a5\u0001\u001a\u0006\u0008\u00a6\u0001\u0010\u00a7\u0001R\u0015\u0010\u001c\u001a\u00020\u001b8\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u001c\u0010\u00a8\u0001R*\u0010\u00a9\u0001\u001a\u00030\u0081\u00018\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0018\n\u0006\u0008\u00a9\u0001\u0010\u00aa\u0001\u001a\u0006\u0008\u00ab\u0001\u0010\u00ac\u0001\"\u0006\u0008\u00ad\u0001\u0010\u00ae\u0001R-\u0010~\u001a\u0008\u0012\u0004\u0012\u00020\t0\u00068\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0017\n\u0005\u0008~\u0010\u00af\u0001\u001a\u0006\u0008\u00b0\u0001\u0010\u00b1\u0001\"\u0006\u0008\u00b2\u0001\u0010\u00b3\u0001R\u0018\u0010\u00b5\u0001\u001a\u00030\u00b4\u00018\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u00b5\u0001\u0010\u00b6\u0001R\u0019\u0010M\u001a\u0004\u0018\u00010L8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0007\n\u0005\u0008M\u0010\u00b7\u0001R \u0010\u00b9\u0001\u001a\u00030\u00b8\u00018\u0016X\u0096\u0004\u00a2\u0006\u0010\n\u0006\u0008\u00b9\u0001\u0010\u00ba\u0001\u001a\u0006\u0008\u00bb\u0001\u0010\u00bc\u0001R\u001e\u0010\u00be\u0001\u001a\t\u0012\u0004\u0012\u00020*0\u00bd\u00018\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u00be\u0001\u0010\u00bf\u0001R&\u0010\u00c1\u0001\u001a\t\u0012\u0004\u0012\u00020*0\u00c0\u00018\u0016X\u0096\u0004\u00a2\u0006\u0010\n\u0006\u0008\u00c1\u0001\u0010\u00c2\u0001\u001a\u0006\u0008\u00c1\u0001\u0010\u00c3\u0001R\u001e\u0010\u00c4\u0001\u001a\t\u0012\u0004\u0012\u00020*0\u00bd\u00018\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u00c4\u0001\u0010\u00bf\u0001R&\u0010\u00c5\u0001\u001a\t\u0012\u0004\u0012\u00020*0\u00c0\u00018\u0016X\u0096\u0004\u00a2\u0006\u0010\n\u0006\u0008\u00c5\u0001\u0010\u00c2\u0001\u001a\u0006\u0008\u00c5\u0001\u0010\u00c3\u0001R\u001e\u0010\u00c6\u0001\u001a\t\u0012\u0004\u0012\u00020*0\u00bd\u00018\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u00c6\u0001\u0010\u00bf\u0001R&\u0010\u00c7\u0001\u001a\t\u0012\u0004\u0012\u00020*0\u00c0\u00018\u0016X\u0096\u0004\u00a2\u0006\u0010\n\u0006\u0008\u00c7\u0001\u0010\u00c2\u0001\u001a\u0006\u0008\u00c7\u0001\u0010\u00c3\u0001R\u001c\u0010\u00c9\u0001\u001a\u0005\u0018\u00010\u00c8\u00018\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0008\n\u0006\u0008\u00c9\u0001\u0010\u00ca\u0001R\u001a\u0010\u00cc\u0001\u001a\u00030\u00cb\u00018\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0008\n\u0006\u0008\u00cc\u0001\u0010\u00cd\u0001R*\u0010\u00cf\u0001\u001a\u0013\u0012\u0008\u0012\u00060\"j\u0002`#\u0012\u0004\u0012\u00020q0\u00ce\u00018\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0008\n\u0006\u0008\u00cf\u0001\u0010\u00d0\u0001R\u001c\u0010\u00d2\u0001\u001a\u00070\u00d1\u0001R\u00020\u00008\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u00d2\u0001\u0010\u00d3\u0001R&\u0010\u00d5\u0001\u001a\t\u0012\u0004\u0012\u00020<0\u00d4\u00018\u0000X\u0080\u0004\u00a2\u0006\u0010\n\u0006\u0008\u00d5\u0001\u0010\u00d6\u0001\u001a\u0006\u0008\u00d7\u0001\u0010\u00d8\u0001R\u0018\u0010\u00da\u0001\u001a\u00030\u00d9\u00018\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u00da\u0001\u0010\u00db\u0001R\u001e\u0010\u00dd\u0001\u001a\t\u0012\u0004\u0012\u00020Y0\u00dc\u00018\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u00dd\u0001\u0010\u00de\u0001R&\u0010\u00e0\u0001\u001a\t\u0012\u0004\u0012\u00020Y0\u00df\u00018\u0016X\u0096\u0004\u00a2\u0006\u0010\n\u0006\u0008\u00e0\u0001\u0010\u00e1\u0001\u001a\u0006\u0008\u00e2\u0001\u0010\u00e3\u0001R,\u0010\u00e4\u0001\u001a\u000f\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020(0\u00060\u00bd\u00018\u0016X\u0096\u0004\u00a2\u0006\u0010\n\u0006\u0008\u00e4\u0001\u0010\u00bf\u0001\u001a\u0006\u0008\u00e5\u0001\u0010\u00e6\u0001R\u001e\u0010\u00e9\u0001\u001a\t\u0012\u0005\u0012\u00030\u00e7\u00010\u00068@X\u0080\u0004\u00a2\u0006\u0008\u001a\u0006\u0008\u00e8\u0001\u0010\u00b1\u0001R\u0016\u0010\u00ea\u0001\u001a\u00020*8VX\u0096\u0004\u00a2\u0006\u0007\u001a\u0005\u0008\u00ea\u0001\u0010/R\u0016\u0010\u00eb\u0001\u001a\u00020*8BX\u0082\u0004\u00a2\u0006\u0007\u001a\u0005\u0008\u00eb\u0001\u0010/\u00a8\u0006\u00ed\u0001"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/VehicleManagerImpl;",
        "Lvy0/b0;",
        "Ltechnology/cariad/cat/genx/InternalVehicleManager;",
        "Ltechnology/cariad/cat/genx/Referencing;",
        "Landroid/content/Context;",
        "context",
        "",
        "Lkotlin/Function1;",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "Ltechnology/cariad/cat/genx/ClientManager;",
        "Ltechnology/cariad/cat/genx/ClientManagerProvider;",
        "clientManagerProvider",
        "",
        "minimumRequiredConnectionTimeout",
        "Lt41/o;",
        "beaconScanner",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "keyPair",
        "Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
        "credentialStore",
        "Ltechnology/cariad/cat/genx/DeviceInformation;",
        "deviceInformation",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
        "linkedParametersForOuterAntennaConnections",
        "genXDispatcher",
        "Lvy0/i1;",
        "supervisorJob",
        "Lvy0/x;",
        "ioDispatcher",
        "<init>",
        "(Landroid/content/Context;Ljava/util/List;ILt41/o;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/CredentialStore;Ltechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/GenXDispatcher;Lvy0/i1;Lvy0/x;)V",
        "Llx0/b0;",
        "close",
        "()V",
        "",
        "Ltechnology/cariad/cat/genx/VIN;",
        "vin",
        "Ltechnology/cariad/cat/genx/Vehicle;",
        "vehicle",
        "(Ljava/lang/String;)Ltechnology/cariad/cat/genx/Vehicle;",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "transportType",
        "",
        "isTransportEnabled",
        "(Ltechnology/cariad/cat/genx/TransportType;)Z",
        "isTransportSupported",
        "isLocationPermissionGranted",
        "()Z",
        "Ltechnology/cariad/cat/genx/Vehicle$Information;",
        "vehicleInformation",
        "Llx0/o;",
        "registerVehicles-gIAlu-s",
        "(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "registerVehicles",
        "unregisterVehicle-gIAlu-s",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "unregisterVehicle",
        "unregisterAllVehicles-IoAF18A",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "unregisterAllVehicles",
        "Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;",
        "startScanningForClients-IoAF18A",
        "startScanningForClients",
        "token",
        "stopScanningForToken$genx_release",
        "(Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;)V",
        "stopScanningForToken",
        "Ltechnology/cariad/cat/genx/QRCode;",
        "qrCode",
        "Ltechnology/cariad/cat/genx/QRKeyExchangeDelegate;",
        "delegate",
        "startKeyExchange",
        "(Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/QRKeyExchangeDelegate;)V",
        "Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;",
        "deviceType",
        "Ltechnology/cariad/cat/genx/EncryptedKeyExchangeDelegate;",
        "Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;",
        "keyExchangeEncryptionCredentials",
        "Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;",
        "encryptionKeyType",
        "startEncryptedKeyExchange",
        "(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/EncryptedKeyExchangeDelegate;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;)V",
        "cancelKeyExchange-IoAF18A",
        "cancelKeyExchange",
        "",
        "cgxTransportType",
        "isEnabled",
        "onStateUpdated",
        "(BZ)V",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "error",
        "onEncounteredError",
        "(BLtechnology/cariad/cat/genx/GenXError;)V",
        "",
        "uuid",
        "Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;",
        "remoteCredentials",
        "cgxAntenna",
        "",
        "beaconMinor",
        "beaconMajor",
        "localKeyPair",
        "onEncryptedKeyExchangeSucceeded",
        "(Ljava/lang/String;B[BLtechnology/cariad/cat/genx/crypto/RemoteCredentials;ISSLtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/GenXError;",
        "onKeyExchangeSucceeded",
        "(Ljava/lang/String;I)Ltechnology/cariad/cat/genx/GenXError;",
        "onKeyExchangeFailed",
        "(Ljava/lang/String;Ltechnology/cariad/cat/genx/GenXError;)V",
        "message",
        "initializationVector",
        "onDecryptMessage",
        "(B[B[B)[B",
        "onEncryptMessage",
        "Ltechnology/cariad/cat/genx/InternalVehicle;",
        "Ltechnology/cariad/cat/genx/Antenna;",
        "antenna",
        "removeAntennaFromVehicle",
        "(Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/GenXError;",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Information;",
        "createOrUpdateVehicleWithNewInnerAntenna-IoAF18A",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ljava/lang/Object;",
        "createOrUpdateVehicleWithNewInnerAntenna",
        "unregisterVehicleNonDispatched",
        "(Ljava/lang/String;)Ltechnology/cariad/cat/genx/GenXError;",
        "destroy",
        "",
        "clientManager",
        "deviceName",
        "appName",
        "",
        "nativeCreate",
        "([Ltechnology/cariad/cat/genx/ClientManager;Ljava/lang/String;Ljava/lang/String;)J",
        "nativeSetDelegate",
        "()I",
        "dispatcher",
        "nativeSetDispatcher",
        "(Ltechnology/cariad/cat/genx/GenXDispatcher;)I",
        "nativeUnregisterVehicle",
        "(Ljava/lang/String;)I",
        "nativeStartScanningForClients",
        "nativeStopScanningForClients",
        "nativeRegisterVehicle",
        "(Ltechnology/cariad/cat/genx/InternalVehicle;)I",
        "timeout",
        "nativeSetConnectionTimeout",
        "(I)V",
        "nativeGetConnectionTimeout",
        "remoteCredential",
        "qrCodeVersionMajor",
        "qrCodeVersionMinor",
        "qrCodeVersionPatch",
        "nativeExchangeKeys",
        "(Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)I",
        "nativeCancelKeyExchange",
        "Ltechnology/cariad/cat/genx/VehicleManager;",
        "vehicleManager",
        "nativeExchangeEncryptedKeys",
        "(Ltechnology/cariad/cat/genx/VehicleManager;[BBLtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)I",
        "Landroid/content/Context;",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
        "Ltechnology/cariad/cat/genx/DeviceInformation;",
        "getDeviceInformation",
        "()Ltechnology/cariad/cat/genx/DeviceInformation;",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "getGenXDispatcher",
        "()Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "Lvy0/x;",
        "reference",
        "J",
        "getReference",
        "()J",
        "setReference",
        "(J)V",
        "Ljava/util/List;",
        "getClientManager",
        "()Ljava/util/List;",
        "setClientManager",
        "(Ljava/util/List;)V",
        "Lvy0/s;",
        "job",
        "Lvy0/s;",
        "Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;",
        "Lpx0/g;",
        "coroutineContext",
        "Lpx0/g;",
        "getCoroutineContext",
        "()Lpx0/g;",
        "Lyy0/j1;",
        "_isBleEnabled",
        "Lyy0/j1;",
        "Lyy0/a2;",
        "isBleEnabled",
        "Lyy0/a2;",
        "()Lyy0/a2;",
        "_isWifiEnabled",
        "isWifiEnabled",
        "_isLocationEnabled",
        "isLocationEnabled",
        "Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;",
        "keyExchangeManager",
        "Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;",
        "Ljava/util/concurrent/locks/ReentrantLock;",
        "vehiclesLock",
        "Ljava/util/concurrent/locks/ReentrantLock;",
        "",
        "vehicles",
        "Ljava/util/Map;",
        "Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;",
        "beaconScannerManager",
        "Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;",
        "Ljava/util/concurrent/CopyOnWriteArrayList;",
        "activeScanningTokens",
        "Ljava/util/concurrent/CopyOnWriteArrayList;",
        "getActiveScanningTokens$genx_release",
        "()Ljava/util/concurrent/CopyOnWriteArrayList;",
        "Lez0/a;",
        "scanningMutex",
        "Lez0/a;",
        "Lyy0/i1;",
        "_vehicleErrors",
        "Lyy0/i1;",
        "Lyy0/i;",
        "vehicleErrors",
        "Lyy0/i;",
        "getVehicleErrors",
        "()Lyy0/i;",
        "enabledTransportTypes",
        "getEnabledTransportTypes",
        "()Lyy0/j1;",
        "Lt41/b;",
        "getAllBeaconsToScanFor$genx_release",
        "allBeaconsToScanFor",
        "isAnyVehicleRegistered",
        "isVehicleManagerClosed",
        "BeaconScannerManager",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final _isBleEnabled:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isLocationEnabled:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isWifiEnabled:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _vehicleErrors:Lyy0/i1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i1;"
        }
    .end annotation
.end field

.field private final activeScanningTokens:Ljava/util/concurrent/CopyOnWriteArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/CopyOnWriteArrayList<",
            "Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;",
            ">;"
        }
    .end annotation
.end field

.field private final beaconScannerManager:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

.field private clientManager:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "+",
            "Ltechnology/cariad/cat/genx/ClientManager;",
            ">;"
        }
    .end annotation
.end field

.field private final context:Landroid/content/Context;

.field private final coroutineContext:Lpx0/g;

.field private final credentialStore:Ltechnology/cariad/cat/genx/crypto/CredentialStore;

.field private final deviceInformation:Ltechnology/cariad/cat/genx/DeviceInformation;

.field private final enabledTransportTypes:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

.field private final ioDispatcher:Lvy0/x;

.field private final isBleEnabled:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isLocationEnabled:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isWifiEnabled:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final job:Lvy0/s;

.field private keyExchangeEncryptionCredentials:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

.field private keyExchangeManager:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

.field private final keyPair:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

.field private final linkedParametersForOuterAntennaConnections:Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

.field private reference:J

.field private final scanningMutex:Lez0/a;

.field private final vehicleErrors:Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i;"
        }
    .end annotation
.end field

.field private vehicles:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "+",
            "Ltechnology/cariad/cat/genx/InternalVehicle;",
            ">;"
        }
    .end annotation
.end field

.field private vehiclesLock:Ljava/util/concurrent/locks/ReentrantLock;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/util/List;ILt41/o;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/CredentialStore;Ltechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/GenXDispatcher;Lvy0/i1;Lvy0/x;)V
    .locals 11
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "Ljava/util/List<",
            "+",
            "Lay0/k;",
            ">;I",
            "Lt41/o;",
            "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
            "Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
            "Ltechnology/cariad/cat/genx/DeviceInformation;",
            "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
            "Ltechnology/cariad/cat/genx/GenXDispatcher;",
            "Lvy0/i1;",
            "Lvy0/x;",
            ")V"
        }
    .end annotation

    move-object/from16 v1, p5

    move-object/from16 v2, p6

    move-object/from16 v3, p7

    move-object/from16 v4, p8

    move-object/from16 v5, p9

    move-object/from16 v6, p10

    move-object/from16 v7, p11

    const-string v8, "context"

    invoke-static {p1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "clientManagerProvider"

    invoke-static {p2, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "beaconScanner"

    invoke-static {p4, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "keyPair"

    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "credentialStore"

    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "deviceInformation"

    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "linkedParametersForOuterAntennaConnections"

    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "genXDispatcher"

    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "supervisorJob"

    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "ioDispatcher"

    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->context:Landroid/content/Context;

    .line 3
    iput-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyPair:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 4
    iput-object v2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->credentialStore:Ltechnology/cariad/cat/genx/crypto/CredentialStore;

    .line 5
    iput-object v3, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->deviceInformation:Ltechnology/cariad/cat/genx/DeviceInformation;

    .line 6
    iput-object v4, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->linkedParametersForOuterAntennaConnections:Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    .line 7
    iput-object v5, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 8
    iput-object v7, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->ioDispatcher:Lvy0/x;

    .line 9
    check-cast p2, Ljava/lang/Iterable;

    .line 10
    new-instance p1, Ljava/util/ArrayList;

    const/16 v1, 0xa

    invoke-static {p2, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v1

    invoke-direct {p1, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 11
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    .line 12
    check-cast v1, Lay0/k;

    .line 13
    iget-object v2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    invoke-interface {v1, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ltechnology/cariad/cat/genx/ClientManager;

    .line 14
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 15
    :cond_0
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->clientManager:Ljava/util/List;

    .line 16
    new-instance p1, Lvy0/k1;

    invoke-direct {p1, v6}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 17
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->job:Lvy0/s;

    .line 18
    iget-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->ioDispatcher:Lvy0/x;

    invoke-virtual {p2, p1}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    move-result-object p1

    new-instance p2, Lvy0/a0;

    const-string v1, "GenX#VehicleManager"

    invoke-direct {p2, v1}, Lvy0/a0;-><init>(Ljava/lang/String;)V

    invoke-interface {p1, p2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    move-result-object p1

    .line 19
    new-instance p2, Ltechnology/cariad/cat/genx/VehicleManagerImpl$special$$inlined$CoroutineExceptionHandler$1;

    sget-object v1, Lvy0/y;->d:Lvy0/y;

    invoke-direct {p2, v1, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$special$$inlined$CoroutineExceptionHandler$1;-><init>(Lvy0/y;Ltechnology/cariad/cat/genx/VehicleManagerImpl;)V

    .line 20
    invoke-interface {p1, p2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->coroutineContext:Lpx0/g;

    .line 21
    sget-object p1, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    iget-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->context:Landroid/content/Context;

    invoke-virtual {p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->isBleEnabled(Landroid/content/Context;)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->_isBleEnabled:Lyy0/j1;

    .line 22
    new-instance p2, Lyy0/l1;

    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 23
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isBleEnabled:Lyy0/a2;

    .line 24
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->_isWifiEnabled:Lyy0/j1;

    .line 25
    new-instance p2, Lyy0/l1;

    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 26
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isWifiEnabled:Lyy0/a2;

    .line 27
    sget-object p1, Ltechnology/cariad/cat/genx/location/Location;->INSTANCE:Ltechnology/cariad/cat/genx/location/Location;

    iget-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->context:Landroid/content/Context;

    invoke-virtual {p1, p2}, Ltechnology/cariad/cat/genx/location/Location;->isEnabled$genx_release(Landroid/content/Context;)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->_isLocationEnabled:Lyy0/j1;

    .line 28
    new-instance p2, Lyy0/l1;

    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 29
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isLocationEnabled:Lyy0/a2;

    .line 30
    iget-object v2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 31
    new-instance v1, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 32
    new-instance v5, Ltechnology/cariad/cat/genx/r0;

    invoke-direct {v5, p0}, Ltechnology/cariad/cat/genx/r0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)V

    .line 33
    new-instance v6, Ltechnology/cariad/cat/genx/a0;

    const/4 p1, 0x4

    invoke-direct {v6, p0, p1}, Ltechnology/cariad/cat/genx/a0;-><init>(Ltechnology/cariad/cat/genx/Referencing;I)V

    .line 34
    new-instance v7, Ltechnology/cariad/cat/genx/v0;

    const/16 p1, 0xa

    invoke-direct {v7, p0, p1}, Ltechnology/cariad/cat/genx/v0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)V

    .line 35
    new-instance v8, Ltechnology/cariad/cat/genx/i0;

    invoke-direct {v8, p0}, Ltechnology/cariad/cat/genx/i0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)V

    .line 36
    new-instance v9, Ltechnology/cariad/cat/genx/v0;

    const/4 p1, 0x2

    invoke-direct {v9, p0, p1}, Ltechnology/cariad/cat/genx/v0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)V

    .line 37
    new-instance v10, Ltechnology/cariad/cat/genx/j0;

    invoke-direct {v10, p0}, Ltechnology/cariad/cat/genx/j0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)V

    move-object v4, p0

    move-object v3, p0

    .line 38
    invoke-direct/range {v1 .. v10}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;-><init>(Ltechnology/cariad/cat/genx/GenXDispatcher;Lvy0/b0;Ltechnology/cariad/cat/genx/ScanningManager;Lay0/n;Lay0/k;Lay0/a;Lay0/r;Lay0/a;Lay0/p;)V

    iput-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 39
    new-instance p1, Ljava/util/concurrent/locks/ReentrantLock;

    const/4 p2, 0x1

    invoke-direct {p1, p2}, Ljava/util/concurrent/locks/ReentrantLock;-><init>(Z)V

    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehiclesLock:Ljava/util/concurrent/locks/ReentrantLock;

    .line 40
    sget-object p1, Lmx0/t;->d:Lmx0/t;

    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 41
    new-instance p1, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    invoke-direct {p1, p0, p4}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lt41/o;)V

    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->beaconScannerManager:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 42
    new-instance p1, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-direct {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->activeScanningTokens:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 43
    invoke-static {}, Lez0/d;->a()Lez0/c;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->scanningMutex:Lez0/a;

    .line 44
    sget-object p1, Lxy0/a;->e:Lxy0/a;

    invoke-static {p2, p2, p1}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->_vehicleErrors:Lyy0/i1;

    .line 45
    new-instance p2, Lyy0/k1;

    invoke-direct {p2, p1}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 46
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicleErrors:Lyy0/i;

    .line 47
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->enabledTransportTypes:Lyy0/j1;

    .line 48
    new-instance p1, Ltechnology/cariad/cat/genx/v0;

    const/4 p2, 0x3

    invoke-direct {p1, p0, p2}, Ltechnology/cariad/cat/genx/v0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)V

    .line 49
    new-instance p2, Lt51/j;

    .line 50
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    .line 51
    const-string v1, "getName(...)"

    .line 52
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 53
    const-string v2, "GenX"

    sget-object v4, Lt51/g;->a:Lt51/g;

    const/4 v5, 0x0

    move-object/from16 p7, p1

    move-object p4, p2

    move-object/from16 p9, v0

    move-object/from16 p10, v1

    move-object/from16 p5, v2

    move-object/from16 p6, v4

    move-object/from16 p8, v5

    invoke-direct/range {p4 .. p10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    move-object p1, p4

    .line 54
    invoke-static {p1}, Lt51/a;->a(Lt51/j;)V

    .line 55
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getClientManager()Ljava/util/List;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    const/4 p2, 0x0

    .line 56
    new-array p2, p2, [Ltechnology/cariad/cat/genx/ClientManager;

    invoke-interface {p1, p2}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Ltechnology/cariad/cat/genx/ClientManager;

    .line 57
    iget-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->deviceInformation:Ltechnology/cariad/cat/genx/DeviceInformation;

    invoke-virtual {p2}, Ltechnology/cariad/cat/genx/DeviceInformation;->getPhoneName()Ljava/lang/String;

    move-result-object p2

    .line 58
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->deviceInformation:Ltechnology/cariad/cat/genx/DeviceInformation;

    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/DeviceInformation;->getAppName()Ljava/lang/String;

    move-result-object v0

    .line 59
    invoke-direct {p0, p1, p2, v0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeCreate([Ltechnology/cariad/cat/genx/ClientManager;Ljava/lang/String;Ljava/lang/String;)J

    move-result-wide p1

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->setReference(J)V

    .line 60
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    new-instance p2, Lba0/h;

    const/16 v0, 0x9

    invoke-direct {p2, p0, p3, v0}, Lba0/h;-><init>(Ljava/lang/Object;II)V

    invoke-interface {p1, p2}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 61
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getClientManager()Ljava/util/List;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    .line 62
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    const/4 p3, 0x0

    if-eqz p2, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    move-object v0, p2

    check-cast v0, Ltechnology/cariad/cat/genx/ClientManager;

    .line 63
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/ClientManager;->getTransportType()Ltechnology/cariad/cat/genx/TransportType;

    move-result-object v0

    sget-object v1, Ltechnology/cariad/cat/genx/TransportType;->BLE:Ltechnology/cariad/cat/genx/TransportType;

    if-ne v0, v1, :cond_1

    goto :goto_1

    :cond_2
    move-object p2, p3

    :goto_1
    instance-of p1, p2, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    if-eqz p1, :cond_3

    check-cast p2, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    goto :goto_2

    :cond_3
    move-object p2, p3

    :goto_2
    if-eqz p2, :cond_4

    invoke-virtual {p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->isBleEnabled$genx_release()Lyy0/j1;

    move-result-object p1

    if-eqz p1, :cond_4

    new-instance p2, Ltechnology/cariad/cat/genx/VehicleManagerImpl$4;

    invoke-direct {p2, p0, p3}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$4;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lkotlin/coroutines/Continuation;)V

    .line 64
    new-instance v0, Lne0/n;

    const/4 v1, 0x5

    invoke-direct {v0, p1, p2, v1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 65
    invoke-static {v0, p0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 66
    :cond_4
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getClientManager()Ljava/util/List;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    .line 67
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_5
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_6

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    move-object v0, p2

    check-cast v0, Ltechnology/cariad/cat/genx/ClientManager;

    .line 68
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/ClientManager;->getTransportType()Ltechnology/cariad/cat/genx/TransportType;

    move-result-object v0

    sget-object v1, Ltechnology/cariad/cat/genx/TransportType;->WiFi:Ltechnology/cariad/cat/genx/TransportType;

    if-ne v0, v1, :cond_5

    goto :goto_3

    :cond_6
    move-object p2, p3

    :goto_3
    instance-of p1, p2, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    if-eqz p1, :cond_7

    check-cast p2, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    goto :goto_4

    :cond_7
    move-object p2, p3

    :goto_4
    if-eqz p2, :cond_8

    invoke-virtual {p2}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->getWifiManager$genx_release()Ltechnology/cariad/cat/genx/wifi/WifiManager;

    move-result-object p1

    if-eqz p1, :cond_8

    invoke-interface {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManager;->getWifiState()Lyy0/a2;

    move-result-object p1

    if-eqz p1, :cond_8

    new-instance p2, Ltechnology/cariad/cat/genx/VehicleManagerImpl$6;

    invoke-direct {p2, p0, p3}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$6;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lkotlin/coroutines/Continuation;)V

    .line 69
    new-instance v0, Lne0/n;

    const/4 v1, 0x5

    invoke-direct {v0, p1, p2, v1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 70
    invoke-static {v0, p0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 71
    :cond_8
    sget-object p1, Ltechnology/cariad/cat/genx/location/Location;->INSTANCE:Ltechnology/cariad/cat/genx/location/Location;

    iget-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->context:Landroid/content/Context;

    invoke-virtual {p1, p2}, Ltechnology/cariad/cat/genx/location/Location;->isLocationEnabled$genx_release(Landroid/content/Context;)Lyy0/i;

    move-result-object p1

    new-instance p2, Ltechnology/cariad/cat/genx/VehicleManagerImpl$7;

    invoke-direct {p2, p0, p3}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$7;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lkotlin/coroutines/Continuation;)V

    .line 72
    new-instance p3, Lne0/n;

    const/4 v0, 0x5

    invoke-direct {p3, p1, p2, v0}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 73
    invoke-static {p3, p0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/util/List;ILt41/o;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/CredentialStore;Ltechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/GenXDispatcher;Lvy0/i1;Lvy0/x;ILkotlin/jvm/internal/g;)V
    .locals 12

    move/from16 v0, p12

    and-int/lit8 v2, v0, 0x8

    if-eqz v2, :cond_0

    .line 77
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    move-result-object v2

    .line 78
    const-string v3, "context"

    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    new-instance v3, Lt41/z;

    sget-object v4, Lvy0/p0;->a:Lcz0/e;

    .line 80
    sget-object v4, Lcz0/d;->e:Lcz0/d;

    .line 81
    invoke-direct {v3, p1, v2, v4}, Lt41/z;-><init>(Landroid/content/Context;Lvy0/i1;Lvy0/x;)V

    move-object v4, v3

    goto :goto_0

    :cond_0
    move-object/from16 v4, p4

    :goto_0
    and-int/lit16 v2, v0, 0x80

    if-eqz v2, :cond_1

    .line 82
    new-instance v5, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    const/16 v10, 0xf

    const/4 v11, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    invoke-direct/range {v5 .. v11}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;-><init>(IIIIILkotlin/jvm/internal/g;)V

    move-object v8, v5

    goto :goto_1

    :cond_1
    move-object/from16 v8, p8

    :goto_1
    and-int/lit16 v2, v0, 0x200

    if-eqz v2, :cond_2

    .line 83
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    move-result-object v2

    move-object v10, v2

    goto :goto_2

    :cond_2
    move-object/from16 v10, p10

    :goto_2
    and-int/lit16 v0, v0, 0x400

    if-eqz v0, :cond_3

    .line 84
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 85
    sget-object v0, Lcz0/d;->e:Lcz0/d;

    move-object v11, v0

    move-object v1, p1

    move-object v2, p2

    move v3, p3

    move-object/from16 v5, p5

    move-object/from16 v6, p6

    move-object/from16 v7, p7

    move-object/from16 v9, p9

    move-object v0, p0

    goto :goto_3

    :cond_3
    move-object/from16 v11, p11

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move v3, p3

    move-object/from16 v5, p5

    move-object/from16 v6, p6

    move-object/from16 v7, p7

    move-object/from16 v9, p9

    .line 86
    :goto_3
    invoke-direct/range {v0 .. v11}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;-><init>(Landroid/content/Context;Ljava/util/List;ILt41/o;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/CredentialStore;Ltechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/GenXDispatcher;Lvy0/i1;Lvy0/x;)V

    return-void
.end method

.method public static synthetic A0(Ltechnology/cariad/cat/genx/ClientManager;)Ljava/lang/CharSequence;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->lambda$0$0(Ltechnology/cariad/cat/genx/ClientManager;)Ljava/lang/CharSequence;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic B()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->lambda$1$5$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic B0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->close$lambda$4(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic C0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startKeyExchange$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic D0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->lambda$1$4(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic E()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startEncryptedKeyExchange$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic E0([B[B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onDecryptMessage$lambda$1([B[B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic F0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/VehicleImpl;)I
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$4(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/VehicleImpl;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic G0(Ltechnology/cariad/cat/genx/ScanningTokenImpl;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startScanningForClients_IoAF18A$lambda$1$0$4(Ltechnology/cariad/cat/genx/ScanningTokenImpl;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic H()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->cancelKeyExchange_IoAF18A$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic H0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onEncryptedKeyExchangeSucceeded$lambda$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic I0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->lambda$1$2$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic J0(Ljava/util/List;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->registerVehicles_gIAlu_s$lambda$1(Ljava/util/List;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic K0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)Ltechnology/cariad/cat/genx/GenXError;
    .locals 0

    .line 1
    invoke-static/range {p0 .. p6}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager$lambda$3(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)Ltechnology/cariad/cat/genx/GenXError;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic L0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->lambda$1$3()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic M0(ZLtechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/ScanningTokenImpl;)Llx0/o;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startScanningForClients_IoAF18A$lambda$1$0(ZLtechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/ScanningTokenImpl;)Llx0/o;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic N0(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$2$0(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic O0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->_init_$lambda$0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic P0(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->unregisterVehicle_gIAlu_s$lambda$1$1$0(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic Q0(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic R0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startScanningForClients_IoAF18A$lambda$1$0$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic S0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onKeyExchangeFailed$lambda$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic T(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;)Llx0/o;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->unregisterVehicle_gIAlu_s$lambda$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;)Llx0/o;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic T0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startEncryptedKeyExchange$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic U([B[B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onEncryptMessage$lambda$2([B[B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic U0([B[B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onEncryptMessage$lambda$1([B[B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic V()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$3()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic V0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startKeyExchange$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic W()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startScanningForClients_IoAF18A$lambda$1$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic W0(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager$lambda$5$0(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic X0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Llx0/o;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->unregisterAllVehicles_IoAF18A$lambda$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Llx0/o;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic Y0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->close$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic Z0(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->removeAntennaFromVehicle$lambda$4$0(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final _init_$lambda$0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/lang/String;
    .locals 7

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getClientManager()Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getClientManager()Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    move-object v1, p0

    .line 14
    check-cast v1, Ljava/lang/Iterable;

    .line 15
    .line 16
    new-instance v5, Ltechnology/cariad/cat/genx/q0;

    .line 17
    .line 18
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 19
    .line 20
    .line 21
    const/16 v6, 0x1f

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    const/4 v3, 0x0

    .line 25
    const/4 v4, 0x0

    .line 26
    invoke-static/range {v1 .. v6}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    new-instance v1, Ljava/lang/StringBuilder;

    .line 31
    .line 32
    const-string v2, "init(): nativeCreate with "

    .line 33
    .line 34
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v0, " ClientManagers = "

    .line 41
    .line 42
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method

.method private static final _init_$lambda$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)Llx0/b0;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v4, Ltechnology/cariad/cat/genx/b0;

    .line 4
    .line 5
    const/16 v1, 0xf

    .line 6
    .line 7
    invoke-direct {v4, v1}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 8
    .line 9
    .line 10
    new-instance v1, Lt51/j;

    .line 11
    .line 12
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v6

    .line 16
    const-string v8, "getName(...)"

    .line 17
    .line 18
    invoke-static {v8}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v7

    .line 22
    const-string v2, "GenX"

    .line 23
    .line 24
    sget-object v11, Lt51/g;->a:Lt51/g;

    .line 25
    .line 26
    const/4 v5, 0x0

    .line 27
    move-object v3, v11

    .line 28
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 32
    .line 33
    .line 34
    new-instance v1, Ltechnology/cariad/cat/genx/v0;

    .line 35
    .line 36
    const/4 v2, 0x4

    .line 37
    invoke-direct {v1, v0, v2}, Ltechnology/cariad/cat/genx/v0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)V

    .line 38
    .line 39
    .line 40
    invoke-static {v1}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 41
    .line 42
    .line 43
    move-result-object v16

    .line 44
    sget-object v14, Lt51/e;->a:Lt51/e;

    .line 45
    .line 46
    if-eqz v16, :cond_0

    .line 47
    .line 48
    new-instance v15, Ltechnology/cariad/cat/genx/b0;

    .line 49
    .line 50
    const/16 v1, 0x10

    .line 51
    .line 52
    invoke-direct {v15, v1}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 53
    .line 54
    .line 55
    new-instance v12, Lt51/j;

    .line 56
    .line 57
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v17

    .line 61
    invoke-static {v8}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v18

    .line 65
    const-string v13, "GenX"

    .line 66
    .line 67
    invoke-direct/range {v12 .. v18}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    move-object v3, v14

    .line 71
    invoke-static {v12}, Lt51/a;->a(Lt51/j;)V

    .line 72
    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_0
    move-object v3, v14

    .line 76
    :goto_0
    new-instance v12, Ltechnology/cariad/cat/genx/b0;

    .line 77
    .line 78
    const/16 v1, 0x11

    .line 79
    .line 80
    invoke-direct {v12, v1}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 81
    .line 82
    .line 83
    new-instance v9, Lt51/j;

    .line 84
    .line 85
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v14

    .line 89
    invoke-static {v8}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v15

    .line 93
    const-string v10, "GenX"

    .line 94
    .line 95
    const/4 v13, 0x0

    .line 96
    invoke-direct/range {v9 .. v15}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    invoke-static {v9}, Lt51/a;->a(Lt51/j;)V

    .line 100
    .line 101
    .line 102
    new-instance v1, Ltechnology/cariad/cat/genx/v0;

    .line 103
    .line 104
    const/4 v2, 0x5

    .line 105
    invoke-direct {v1, v0, v2}, Ltechnology/cariad/cat/genx/v0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)V

    .line 106
    .line 107
    .line 108
    invoke-static {v1}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 109
    .line 110
    .line 111
    move-result-object v5

    .line 112
    if-eqz v5, :cond_1

    .line 113
    .line 114
    new-instance v4, Ltechnology/cariad/cat/genx/b0;

    .line 115
    .line 116
    const/16 v1, 0x12

    .line 117
    .line 118
    invoke-direct {v4, v1}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 119
    .line 120
    .line 121
    new-instance v1, Lt51/j;

    .line 122
    .line 123
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v6

    .line 127
    invoke-static {v8}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v7

    .line 131
    const-string v2, "GenX"

    .line 132
    .line 133
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 137
    .line 138
    .line 139
    :cond_1
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeGetConnectionTimeout()I

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    move/from16 v2, p1

    .line 144
    .line 145
    if-le v2, v1, :cond_2

    .line 146
    .line 147
    new-instance v12, Ltechnology/cariad/cat/genx/b0;

    .line 148
    .line 149
    const/16 v1, 0x13

    .line 150
    .line 151
    invoke-direct {v12, v1}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 152
    .line 153
    .line 154
    new-instance v9, Lt51/j;

    .line 155
    .line 156
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v14

    .line 160
    invoke-static {v8}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v15

    .line 164
    const-string v10, "GenX"

    .line 165
    .line 166
    const/4 v13, 0x0

    .line 167
    invoke-direct/range {v9 .. v15}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    invoke-static {v9}, Lt51/a;->a(Lt51/j;)V

    .line 171
    .line 172
    .line 173
    invoke-direct/range {p0 .. p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeSetConnectionTimeout(I)V

    .line 174
    .line 175
    .line 176
    :cond_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 177
    .line 178
    return-object v0
.end method

.method public static synthetic a(Ltechnology/cariad/cat/genx/TransportType;Z)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onStateUpdated$lambda$0(Ltechnology/cariad/cat/genx/TransportType;Z)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic a1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Llx0/o;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager$lambda$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Llx0/o;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$getContext$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->context:Landroid/content/Context;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getCredentialStore$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ltechnology/cariad/cat/genx/crypto/CredentialStore;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->credentialStore:Ltechnology/cariad/cat/genx/crypto/CredentialStore;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getIoDispatcher$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Lvy0/x;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->ioDispatcher:Lvy0/x;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getLinkedParametersForOuterAntennaConnections$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->linkedParametersForOuterAntennaConnections:Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getScanningMutex$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Lez0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->scanningMutex:Lez0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getVehicles$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getVehiclesLock$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/util/concurrent/locks/ReentrantLock;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehiclesLock:Ljava/util/concurrent/locks/ReentrantLock;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_isBleEnabled$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->_isBleEnabled:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_isLocationEnabled$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->_isLocationEnabled:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_isWifiEnabled$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->_isWifiEnabled:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$nativeRegisterVehicle(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/InternalVehicle;)I
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeRegisterVehicle(Ltechnology/cariad/cat/genx/InternalVehicle;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static final synthetic access$nativeStopScanningForClients(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeStopScanningForClients()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static final synthetic access$setVehicles$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/util/Map;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 2
    .line 3
    return-void
.end method

.method public static final synthetic access$unregisterVehicleNonDispatched(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->unregisterVehicleNonDispatched(Ljava/lang/String;)Ltechnology/cariad/cat/genx/GenXError;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/VehicleImpl;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$5$0(Ltechnology/cariad/cat/genx/VehicleImpl;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b1()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->unregisterAllVehicles_IoAF18A$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic c1()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startEncryptedKeyExchange$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final cancelKeyExchange_IoAF18A$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "cancelKeyExchange(): KeyExchangeManager is not present, therefore no KeyExchange can be running"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final close$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "close()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final close$lambda$4(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Llx0/b0;
    .locals 4

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getReference()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    cmp-long v0, v0, v2

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->destroy()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v2, v3}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->setReference(J)V

    .line 15
    .line 16
    .line 17
    :cond_0
    const-string v0, "close"

    .line 18
    .line 19
    invoke-static {p0, v0}, Lvy0/e0;->l(Lvy0/b0;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/io/Closeable;->close()V

    .line 25
    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0
.end method

.method private final createOrUpdateVehicleWithNewInnerAntenna-IoAF18A(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ljava/lang/Object;
    .locals 24
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation

    .line 1
    move-object/from16 v8, p0

    .line 2
    .line 3
    iget-object v0, v8, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 4
    .line 5
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getVin()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    move-object v1, v0

    .line 18
    check-cast v1, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 19
    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/InternalVehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x0

    .line 28
    :goto_0
    const-string v15, "GenX"

    .line 29
    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    sget-object v0, Ltechnology/cariad/cat/genx/GenXError$VehicleAntennaAlreadyPaired;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$VehicleAntennaAlreadyPaired;

    .line 33
    .line 34
    new-instance v1, Ltechnology/cariad/cat/genx/q;

    .line 35
    .line 36
    const/4 v2, 0x3

    .line 37
    move-object/from16 v3, p1

    .line 38
    .line 39
    invoke-direct {v1, v3, v2}, Ltechnology/cariad/cat/genx/q;-><init>(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;I)V

    .line 40
    .line 41
    .line 42
    invoke-static {v8, v15, v0, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 43
    .line 44
    .line 45
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    return-object v0

    .line 50
    :cond_1
    move-object/from16 v3, p1

    .line 51
    .line 52
    sget-object v18, Lt51/g;->a:Lt51/g;

    .line 53
    .line 54
    const-string v0, "getName(...)"

    .line 55
    .line 56
    if-eqz v1, :cond_3

    .line 57
    .line 58
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/InternalVehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    if-nez v2, :cond_3

    .line 63
    .line 64
    new-instance v2, Ltechnology/cariad/cat/genx/n0;

    .line 65
    .line 66
    const/4 v4, 0x0

    .line 67
    invoke-direct {v2, v1, v4}, Ltechnology/cariad/cat/genx/n0;-><init>(Ltechnology/cariad/cat/genx/InternalVehicle;I)V

    .line 68
    .line 69
    .line 70
    new-instance v16, Lt51/j;

    .line 71
    .line 72
    invoke-static {v8}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v21

    .line 76
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v22

    .line 80
    const-string v17, "GenX"

    .line 81
    .line 82
    const/16 v20, 0x0

    .line 83
    .line 84
    move-object/from16 v19, v2

    .line 85
    .line 86
    invoke-direct/range {v16 .. v22}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-static/range {v16 .. v16}, Lt51/a;->a(Lt51/j;)V

    .line 90
    .line 91
    .line 92
    iget-object v4, v8, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->credentialStore:Ltechnology/cariad/cat/genx/crypto/CredentialStore;

    .line 93
    .line 94
    const/4 v5, 0x2

    .line 95
    const/4 v6, 0x0

    .line 96
    const/4 v3, 0x0

    .line 97
    move-object/from16 v2, p1

    .line 98
    .line 99
    invoke-static/range {v1 .. v6}, Ltechnology/cariad/cat/genx/InternalVehicle;->addAntenna$default(Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/crypto/CredentialStore;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/GenXError;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    if-eqz v0, :cond_2

    .line 104
    .line 105
    new-instance v2, Ltechnology/cariad/cat/genx/n0;

    .line 106
    .line 107
    const/4 v3, 0x1

    .line 108
    invoke-direct {v2, v1, v3}, Ltechnology/cariad/cat/genx/n0;-><init>(Ltechnology/cariad/cat/genx/InternalVehicle;I)V

    .line 109
    .line 110
    .line 111
    invoke-static {v8, v15, v0, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 112
    .line 113
    .line 114
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    return-object v0

    .line 119
    :cond_2
    return-object v1

    .line 120
    :cond_3
    if-nez v1, :cond_5

    .line 121
    .line 122
    new-instance v4, Ltechnology/cariad/cat/genx/b0;

    .line 123
    .line 124
    const/16 v1, 0x1b

    .line 125
    .line 126
    invoke-direct {v4, v1}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 127
    .line 128
    .line 129
    new-instance v1, Lt51/j;

    .line 130
    .line 131
    invoke-static {v8}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v6

    .line 135
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v7

    .line 139
    const-string v2, "GenX"

    .line 140
    .line 141
    const/4 v5, 0x0

    .line 142
    move-object/from16 v3, v18

    .line 143
    .line 144
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 148
    .line 149
    .line 150
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Inner;

    .line 151
    .line 152
    iget-object v1, v8, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->credentialStore:Ltechnology/cariad/cat/genx/crypto/CredentialStore;

    .line 153
    .line 154
    iget-object v2, v8, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->context:Landroid/content/Context;

    .line 155
    .line 156
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 157
    .line 158
    .line 159
    move-result-object v3

    .line 160
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getVin()Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v3

    .line 164
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getLocalKeyPair()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 165
    .line 166
    .line 167
    move-result-object v4

    .line 168
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getRemoteCredentials()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 169
    .line 170
    .line 171
    move-result-object v5

    .line 172
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMajor-Mh2AYeg()S

    .line 173
    .line 174
    .line 175
    move-result v6

    .line 176
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMinor-Mh2AYeg()S

    .line 177
    .line 178
    .line 179
    move-result v7

    .line 180
    iget-object v9, v8, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->deviceInformation:Ltechnology/cariad/cat/genx/DeviceInformation;

    .line 181
    .line 182
    move-object v10, v9

    .line 183
    iget-object v9, v8, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 184
    .line 185
    move-object v11, v10

    .line 186
    new-instance v10, Ljava/lang/ref/WeakReference;

    .line 187
    .line 188
    invoke-direct {v10, v8}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v8}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isBleEnabled()Lyy0/a2;

    .line 192
    .line 193
    .line 194
    move-result-object v12

    .line 195
    invoke-interface {v12}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v12

    .line 199
    check-cast v12, Ljava/lang/Boolean;

    .line 200
    .line 201
    invoke-virtual {v12}, Ljava/lang/Boolean;->booleanValue()Z

    .line 202
    .line 203
    .line 204
    move-result v12

    .line 205
    invoke-virtual {v8}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isWifiEnabled()Lyy0/a2;

    .line 206
    .line 207
    .line 208
    move-result-object v13

    .line 209
    invoke-interface {v13}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v13

    .line 213
    check-cast v13, Ljava/lang/Boolean;

    .line 214
    .line 215
    invoke-virtual {v13}, Ljava/lang/Boolean;->booleanValue()Z

    .line 216
    .line 217
    .line 218
    move-result v13

    .line 219
    const/4 v14, 0x0

    .line 220
    move-object/from16 v23, v11

    .line 221
    .line 222
    move-object v11, v8

    .line 223
    move-object/from16 v8, v23

    .line 224
    .line 225
    invoke-direct/range {v0 .. v14}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Inner;-><init>(Ltechnology/cariad/cat/genx/crypto/CredentialStore;Landroid/content/Context;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SSLtechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/GenXDispatcher;Ljava/lang/ref/WeakReference;Lvy0/b0;ZZLkotlin/jvm/internal/g;)V

    .line 226
    .line 227
    .line 228
    move-object v8, v11

    .line 229
    new-instance v1, Ltechnology/cariad/cat/genx/VehicleImpl;

    .line 230
    .line 231
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 232
    .line 233
    .line 234
    move-result-object v2

    .line 235
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getVin()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v2

    .line 239
    iget-object v4, v8, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 240
    .line 241
    iget-object v5, v8, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->deviceInformation:Ltechnology/cariad/cat/genx/DeviceInformation;

    .line 242
    .line 243
    iget-object v6, v8, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->context:Landroid/content/Context;

    .line 244
    .line 245
    new-instance v7, Ljava/lang/ref/WeakReference;

    .line 246
    .line 247
    invoke-direct {v7, v8}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v8}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isBleEnabled()Lyy0/a2;

    .line 251
    .line 252
    .line 253
    move-result-object v3

    .line 254
    invoke-interface {v3}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v3

    .line 258
    check-cast v3, Ljava/lang/Boolean;

    .line 259
    .line 260
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 261
    .line 262
    .line 263
    move-result v9

    .line 264
    invoke-virtual {v8}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isWifiEnabled()Lyy0/a2;

    .line 265
    .line 266
    .line 267
    move-result-object v3

    .line 268
    invoke-interface {v3}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v3

    .line 272
    check-cast v3, Ljava/lang/Boolean;

    .line 273
    .line 274
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 275
    .line 276
    .line 277
    move-result v10

    .line 278
    const/4 v3, 0x0

    .line 279
    move-object/from16 v23, v2

    .line 280
    .line 281
    move-object v2, v0

    .line 282
    move-object v0, v1

    .line 283
    move-object/from16 v1, v23

    .line 284
    .line 285
    invoke-direct/range {v0 .. v10}, Ltechnology/cariad/cat/genx/VehicleImpl;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;Ltechnology/cariad/cat/genx/GenXDispatcher;Ltechnology/cariad/cat/genx/DeviceInformation;Landroid/content/Context;Ljava/lang/ref/WeakReference;Lvy0/b0;ZZ)V

    .line 286
    .line 287
    .line 288
    new-instance v1, Ltechnology/cariad/cat/genx/u0;

    .line 289
    .line 290
    const/16 v2, 0xd

    .line 291
    .line 292
    invoke-direct {v1, v2, v8, v0}, Ltechnology/cariad/cat/genx/u0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 293
    .line 294
    .line 295
    invoke-static {v1}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 296
    .line 297
    .line 298
    move-result-object v1

    .line 299
    if-eqz v1, :cond_4

    .line 300
    .line 301
    new-instance v2, Ltechnology/cariad/cat/genx/c0;

    .line 302
    .line 303
    const/4 v3, 0x1

    .line 304
    invoke-direct {v2, v0, v3}, Ltechnology/cariad/cat/genx/c0;-><init>(Ltechnology/cariad/cat/genx/VehicleImpl;I)V

    .line 305
    .line 306
    .line 307
    invoke-static {v8, v15, v1, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 308
    .line 309
    .line 310
    invoke-static {v1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    :cond_4
    return-object v0

    .line 315
    :cond_5
    sget-object v5, Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;

    .line 316
    .line 317
    new-instance v4, Ltechnology/cariad/cat/genx/b0;

    .line 318
    .line 319
    const/16 v1, 0x1d

    .line 320
    .line 321
    invoke-direct {v4, v1}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 322
    .line 323
    .line 324
    new-instance v1, Lt51/j;

    .line 325
    .line 326
    invoke-static {v8}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 327
    .line 328
    .line 329
    move-result-object v6

    .line 330
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 331
    .line 332
    .line 333
    move-result-object v7

    .line 334
    const-string v2, "GenX"

    .line 335
    .line 336
    sget-object v3, Lt51/e;->a:Lt51/e;

    .line 337
    .line 338
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 339
    .line 340
    .line 341
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 342
    .line 343
    .line 344
    invoke-static {v5}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 345
    .line 346
    .line 347
    move-result-object v0

    .line 348
    return-object v0
.end method

.method private static final createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getVin()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "createOrUpdateVehicleWithNewInnerAntenna(): Failed to create or update Vehicle for "

    .line 10
    .line 11
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$1(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "createOrUpdateVehicleWithNewInnerAntenna(): Add new antenna to existing Vehicle: "

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

.method private static final createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$2$0(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "createOrUpdateVehicleWithNewInnerAntenna(): Failed to add new Antenna to vehicle "

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

.method private static final createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$3()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "createOrUpdateVehicleWithNewInnerAntenna(): Create new Vehicle with Inner Antenna"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$4(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/VehicleImpl;)I
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeRegisterVehicle(Ltechnology/cariad/cat/genx/InternalVehicle;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$5$0(Ltechnology/cariad/cat/genx/VehicleImpl;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "createOrUpdateVehicleWithNewInnerAntenna(): Failed to register new vehicle "

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

.method private static final createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$6()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "createOrUpdateVehicleWithNewInnerAntenna(): Unreachable code path reached"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->registerVehicles_gIAlu_s$lambda$4$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic d1()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onEncryptMessage$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private final native destroy()V
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public static synthetic e0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->lambda$1$6()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic e1(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->removeAntennaFromVehicle$lambda$0(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$1(Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f1()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onEncounteredError$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic g(B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onEncryptMessage$lambda$3(B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;[BLtechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager$lambda$5(Ltechnology/cariad/cat/genx/VehicleManagerImpl;[BLtechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/GenXError;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)I
    .locals 0

    .line 1
    invoke-static/range {p0 .. p6}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager$lambda$3$0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic h0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;[BLtechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)I
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager$lambda$5$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;[BLtechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic h1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager$lambda$0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/GenXError;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic i1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->_init_$lambda$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final isVehicleManagerClosed()Z
    .locals 4

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getReference()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    cmp-long p0, v0, v2

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public static synthetic j(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/InternalVehicle;)I
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->removeAntennaFromVehicle$lambda$3(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/InternalVehicle;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic j1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager$lambda$4$0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic k([B[B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onDecryptMessage$lambda$2([B[B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k0(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->unregisterAllVehicles_IoAF18A$lambda$1$2$0$0(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k1()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startKeyExchange$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final keyExchangeManager$lambda$0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 1

    .line 1
    const-string v0, "vehicle"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "antenna"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->removeAntennaFromVehicle(Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/GenXError;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final keyExchangeManager$lambda$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Llx0/o;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->createOrUpdateVehicleWithNewInnerAntenna-IoAF18A(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    new-instance p1, Llx0/o;

    .line 11
    .line 12
    invoke-direct {p1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-object p1
.end method

.method private static final keyExchangeManager$lambda$2(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Iterable;

    .line 8
    .line 9
    invoke-static {p0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method private static final keyExchangeManager$lambda$3(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)Ltechnology/cariad/cat/genx/GenXError;
    .locals 9

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "remoteCredentials"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "keyPair"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Ltechnology/cariad/cat/genx/l0;

    .line 17
    .line 18
    move-object v2, p0

    .line 19
    move-object v3, p1

    .line 20
    move-object v4, p2

    .line 21
    move-object v5, p3

    .line 22
    move v6, p4

    .line 23
    move v7, p5

    .line 24
    move v8, p6

    .line 25
    invoke-direct/range {v1 .. v8}, Ltechnology/cariad/cat/genx/l0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)V

    .line 26
    .line 27
    .line 28
    invoke-static {v1}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method private static final keyExchangeManager$lambda$3$0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)I
    .locals 0

    .line 1
    invoke-direct/range {p0 .. p6}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeExchangeKeys(Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final keyExchangeManager$lambda$4(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 2

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/v0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, p0, v1}, Ltechnology/cariad/cat/genx/v0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)V

    .line 5
    .line 6
    .line 7
    invoke-static {v0}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static final keyExchangeManager$lambda$4$0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeCancelKeyExchange()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final keyExchangeManager$lambda$5(Ltechnology/cariad/cat/genx/VehicleManagerImpl;[BLtechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 8

    .line 1
    const-string v0, "uuid"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "keyExchangeEncryptionCredentials"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "encryptionKeyType"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "keyPair"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance v4, Ltechnology/cariad/cat/genx/t0;

    .line 22
    .line 23
    const/4 v0, 0x5

    .line 24
    invoke-direct {v4, p3, v0}, Ltechnology/cariad/cat/genx/t0;-><init>(Ljava/lang/Object;I)V

    .line 25
    .line 26
    .line 27
    new-instance v1, Lt51/j;

    .line 28
    .line 29
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v6

    .line 33
    const-string v0, "getName(...)"

    .line 34
    .line 35
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v7

    .line 39
    const-string v2, "GenX"

    .line 40
    .line 41
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 42
    .line 43
    const/4 v5, 0x0

    .line 44
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 48
    .line 49
    .line 50
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeEncryptionCredentials:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 51
    .line 52
    new-instance v2, Lal/i;

    .line 53
    .line 54
    const/16 v7, 0xa

    .line 55
    .line 56
    move-object v3, p0

    .line 57
    move-object v4, p1

    .line 58
    move-object v5, p3

    .line 59
    move-object v6, p4

    .line 60
    invoke-direct/range {v2 .. v7}, Lal/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 61
    .line 62
    .line 63
    invoke-static {v2}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0
.end method

.method private static final keyExchangeManager$lambda$5$0(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onNativeStartEncryptedKeyExchange(): Set keyExchangeCredentials for "

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

.method private static final keyExchangeManager$lambda$5$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;[BLtechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)I
    .locals 0

    .line 1
    invoke-virtual {p2}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;->getCgxEncryptionKeyType$genx_release()B

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    invoke-direct {p0, p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeExchangeEncryptedKeys(Ltechnology/cariad/cat/genx/VehicleManager;[BBLtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public static synthetic l(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->unregisterVehicle_gIAlu_s$lambda$0(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic l0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startScanningForClients_IoAF18A$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic l1(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->removeAntennaFromVehicle$lambda$2(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final lambda$0$0(Ltechnology/cariad/cat/genx/ClientManager;)Ljava/lang/CharSequence;
    .locals 2

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/Referencing;->getReference()J

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method private static final lambda$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "init(): nativeSetDelegate on dispatcher"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final lambda$1$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeSetDelegate()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final lambda$1$2$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "init(): Could not set delegate"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final lambda$1$3()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "init(): nativeSetDispatcher on dispatcher"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final lambda$1$4(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeSetDispatcher(Ltechnology/cariad/cat/genx/GenXDispatcher;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method private static final lambda$1$5$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "init(): Could not set dispatcher"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final lambda$1$6()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "init(): Timeout for retries is greater than current CoreGenX connection timeout, hence CoreGenX connection timeout is increased"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic m1(Ltechnology/cariad/cat/genx/TransportType;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onEncounteredError$lambda$0(Ltechnology/cariad/cat/genx/TransportType;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic n0(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->removeAntennaFromVehicle$lambda$1(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic n1(B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onDecryptMessage$lambda$3(B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final native nativeCancelKeyExchange()I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeCreate([Ltechnology/cariad/cat/genx/ClientManager;Ljava/lang/String;Ljava/lang/String;)J
.end method

.method private final native nativeExchangeEncryptedKeys(Ltechnology/cariad/cat/genx/VehicleManager;[BBLtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeExchangeKeys(Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeGetConnectionTimeout()I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeRegisterVehicle(Ltechnology/cariad/cat/genx/InternalVehicle;)I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeSetConnectionTimeout(I)V
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeSetDelegate()I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeSetDispatcher(Ltechnology/cariad/cat/genx/GenXDispatcher;)I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeStartScanningForClients()I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeStopScanningForClients()I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeUnregisterVehicle(Ljava/lang/String;)I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public static synthetic o1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->lambda$1$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final onDecryptMessage$lambda$0(B)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyTypeKt;->getEncryptionKeyType(B)Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "onDecryptMessage(): EncryptionCredentials for "

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string p0, " is not present"

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method private static final onDecryptMessage$lambda$1([B[B)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p1}, Lly0/d;->l([B)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, "onDecryptMessage(): Decrypt "

    .line 10
    .line 11
    const-string v1, " with IV "

    .line 12
    .line 13
    invoke-static {v0, p0, v1, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method private static final onDecryptMessage$lambda$2([B[B)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p1}, Lly0/d;->l([B)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, "onDecryptMessage(): Decrypt "

    .line 10
    .line 11
    const-string v1, " with IV "

    .line 12
    .line 13
    invoke-static {v0, p0, v1, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method private static final onDecryptMessage$lambda$3(B)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyTypeKt;->getEncryptionKeyType(B)Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "onDecryptMessage(): EncryptionCredentials for "

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string p0, " is not present"

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method private static final onEncounteredError$lambda$0(Ltechnology/cariad/cat/genx/TransportType;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onEncounteredError(): transportType = "

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

.method private static final onEncounteredError$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onEncounteredError(): Scanning for clients was interrupted or startScanning failed."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onEncryptMessage$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onEncryptMessage(): No EncryptionCredentials present"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onEncryptMessage$lambda$1([B[B)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p1}, Lly0/d;->l([B)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, "onEncryptMessage(): Encrypt "

    .line 10
    .line 11
    const-string v1, " with IV "

    .line 12
    .line 13
    invoke-static {v0, p0, v1, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method private static final onEncryptMessage$lambda$2([B[B)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p1}, Lly0/d;->l([B)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, "onEncryptMessage(): Encrypt "

    .line 10
    .line 11
    const-string v1, " with IV "

    .line 12
    .line 13
    invoke-static {v0, p0, v1, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method private static final onEncryptMessage$lambda$3(B)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyTypeKt;->getEncryptionKeyType(B)Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "onEncryptMessage(): EncryptionCredentials for "

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string p0, " is not present"

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method private static final onEncryptedKeyExchangeSucceeded$lambda$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onKeyExchangeSucceeded(): CoreGenX reported an successful key exchange, but no KeyExchangeManager is present"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onKeyExchangeFailed$lambda$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onKeyExchangeFailed(): CoreGenX reported an failed key exchange, but no KeyExchangeManager is present"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onKeyExchangeSucceeded$lambda$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onKeyExchangeSucceeded(): CoreGenX reported an successful key exchange, but no KeyExchangeManager is present"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onStateUpdated$lambda$0(Ltechnology/cariad/cat/genx/TransportType;Z)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onStateUpdated(): "

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
    const-string p0, " enabled: "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static synthetic p1()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->createOrUpdateVehicleWithNewInnerAntenna_IoAF18A$lambda$6()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic q()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->unregisterAllVehicles_IoAF18A$lambda$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic q0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;)I
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->unregisterVehicleNonDispatched$lambda$0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic q1(B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onDecryptMessage$lambda$0(B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic r0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startScanningForClients_IoAF18A$lambda$1$0$3()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic r1(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->unregisterVehicle_gIAlu_s$lambda$1$0(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final registerVehicles_gIAlu_s$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "registerVehicles(): Failed to register new vehicles"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final registerVehicles_gIAlu_s$lambda$1(Ljava/util/List;)Ljava/lang/String;
    .locals 6

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Ljava/lang/Iterable;

    .line 3
    .line 4
    const/4 v4, 0x0

    .line 5
    const/16 v5, 0x3f

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string v0, "registerVehicles(): "

    .line 15
    .line 16
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method private static final registerVehicles_gIAlu_s$lambda$3(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    const-string v0, "registerVehicles(): Start beacon scanning after registered vehicles have changed ("

    .line 8
    .line 9
    const-string v1, " vehicles registered)"

    .line 10
    .line 11
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final registerVehicles_gIAlu_s$lambda$4$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "registerVehicles(): Beacon scanning started"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final registerVehicles_gIAlu_s$lambda$5$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "registerVehicles(): Beacon scanning could not be started"

    .line 2
    .line 3
    return-object v0
.end method

.method private final removeAntennaFromVehicle(Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 18
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    new-instance v6, Ltechnology/cariad/cat/genx/m0;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-direct {v6, v2, v1, v3}, Ltechnology/cariad/cat/genx/m0;-><init>(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;I)V

    .line 11
    .line 12
    .line 13
    new-instance v3, Lt51/j;

    .line 14
    .line 15
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v8

    .line 19
    const-string v10, "getName(...)"

    .line 20
    .line 21
    invoke-static {v10}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v9

    .line 25
    const-string v4, "GenX"

    .line 26
    .line 27
    sget-object v13, Lt51/g;->a:Lt51/g;

    .line 28
    .line 29
    const/4 v7, 0x0

    .line 30
    move-object v5, v13

    .line 31
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 35
    .line 36
    .line 37
    invoke-interface/range {p1 .. p2}, Ltechnology/cariad/cat/genx/InternalVehicle;->removeAntenna(Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/GenXError;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    const-string v4, "GenX"

    .line 42
    .line 43
    if-eqz v3, :cond_0

    .line 44
    .line 45
    new-instance v5, Ltechnology/cariad/cat/genx/m0;

    .line 46
    .line 47
    const/4 v6, 0x1

    .line 48
    invoke-direct {v5, v2, v1, v6}, Ltechnology/cariad/cat/genx/m0;-><init>(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;I)V

    .line 49
    .line 50
    .line 51
    invoke-static {v0, v4, v3, v5}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 52
    .line 53
    .line 54
    return-object v3

    .line 55
    :cond_0
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/InternalVehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    if-nez v3, :cond_1

    .line 60
    .line 61
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/InternalVehicle;->getOuterAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    if-nez v3, :cond_1

    .line 66
    .line 67
    new-instance v14, Ltechnology/cariad/cat/genx/m0;

    .line 68
    .line 69
    const/4 v3, 0x2

    .line 70
    invoke-direct {v14, v2, v1, v3}, Ltechnology/cariad/cat/genx/m0;-><init>(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;I)V

    .line 71
    .line 72
    .line 73
    new-instance v11, Lt51/j;

    .line 74
    .line 75
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v16

    .line 79
    invoke-static {v10}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v17

    .line 83
    const-string v12, "GenX"

    .line 84
    .line 85
    const/4 v15, 0x0

    .line 86
    invoke-direct/range {v11 .. v17}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-static {v11}, Lt51/a;->a(Lt51/j;)V

    .line 90
    .line 91
    .line 92
    new-instance v3, Ltechnology/cariad/cat/genx/u0;

    .line 93
    .line 94
    const/16 v5, 0xc

    .line 95
    .line 96
    invoke-direct {v3, v5, v0, v1}, Ltechnology/cariad/cat/genx/u0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    invoke-static {v3}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    if-eqz v3, :cond_1

    .line 104
    .line 105
    new-instance v5, Ltechnology/cariad/cat/genx/m0;

    .line 106
    .line 107
    const/4 v6, 0x3

    .line 108
    invoke-direct {v5, v2, v1, v6}, Ltechnology/cariad/cat/genx/m0;-><init>(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;I)V

    .line 109
    .line 110
    .line 111
    invoke-static {v0, v4, v3, v5}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 112
    .line 113
    .line 114
    :cond_1
    const/4 v0, 0x0

    .line 115
    return-object v0
.end method

.method private static final removeAntennaFromVehicle$lambda$0(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/Vehicle;->getVin()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "removeAntennaFromVehicle(): Remove Antenna "

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string p0, " from vehicle "

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method

.method private static final removeAntennaFromVehicle$lambda$1(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "removeAntennaFromVehicle(): Failed to remove antenna "

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
    const-string p0, " from vehicle for "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method private static final removeAntennaFromVehicle$lambda$2(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/Vehicle;->getVin()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "removeAntennaFromVehicle(): After "

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string p0, " was removed, vehicle for "

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, " has no registered antennas and vehicle is unregistered"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method private static final removeAntennaFromVehicle$lambda$3(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/InternalVehicle;)I
    .locals 0

    .line 1
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/Vehicle;->getVin()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeUnregisterVehicle(Ljava/lang/String;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method private static final removeAntennaFromVehicle$lambda$4$0(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/InternalVehicle;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "removeAntennaFromVehicle(): "

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
    const-string p0, " was removed, but unregistering "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string p0, " failed"

    .line 20
    .line 21
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method

.method public static synthetic s1()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->registerVehicles_gIAlu_s$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final startEncryptedKeyExchange$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startEncryptedKeyExchange(): Cannot start Key Exchange"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startEncryptedKeyExchange$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startEncryptedKeyExchange(): Location permission is not granted"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startEncryptedKeyExchange$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startEncryptedKeyExchange(): Location is not enabled"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startKeyExchange$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startKeyExchange(): Cannot start Key Exchange"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startKeyExchange$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startKeyExchange(): Location permission is not granted"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startKeyExchange$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startKeyExchange(): Location is not enabled"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients_IoAF18A$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): Scanning could not be started"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients_IoAF18A$lambda$1$0(ZLtechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/ScanningTokenImpl;)Llx0/o;
    .locals 8

    .line 1
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 2
    .line 3
    const-string v7, "getName(...)"

    .line 4
    .line 5
    if-nez p0, :cond_1

    .line 6
    .line 7
    new-instance v3, Ltechnology/cariad/cat/genx/o0;

    .line 8
    .line 9
    const/4 p0, 0x5

    .line 10
    invoke-direct {v3, p0}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lt51/j;

    .line 14
    .line 15
    invoke-static {p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v5

    .line 19
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v6

    .line 23
    const-string v1, "GenX"

    .line 24
    .line 25
    const/4 v4, 0x0

    .line 26
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 30
    .line 31
    .line 32
    new-instance p0, Ltechnology/cariad/cat/genx/v0;

    .line 33
    .line 34
    const/16 v0, 0x8

    .line 35
    .line 36
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/genx/v0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)V

    .line 37
    .line 38
    .line 39
    invoke-static {p0}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    if-nez p0, :cond_0

    .line 44
    .line 45
    new-instance v3, Ltechnology/cariad/cat/genx/l;

    .line 46
    .line 47
    const/4 p0, 0x1

    .line 48
    invoke-direct {v3, p2, p0}, Ltechnology/cariad/cat/genx/l;-><init>(Ltechnology/cariad/cat/genx/ScanningTokenImpl;I)V

    .line 49
    .line 50
    .line 51
    new-instance v0, Lt51/j;

    .line 52
    .line 53
    invoke-static {p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    const-string v1, "GenX"

    .line 62
    .line 63
    const/4 v4, 0x0

    .line 64
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 68
    .line 69
    .line 70
    iget-object p0, p1, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->activeScanningTokens:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 71
    .line 72
    invoke-virtual {p0, p2}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/o0;

    .line 77
    .line 78
    const/4 v1, 0x6

    .line 79
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

    .line 80
    .line 81
    .line 82
    const-string v1, "GenX"

    .line 83
    .line 84
    invoke-static {p1, v1, p0, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {p2}, Ltechnology/cariad/cat/genx/ScanningTokenImpl;->close()V

    .line 88
    .line 89
    .line 90
    iget-object p1, p1, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->activeScanningTokens:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 91
    .line 92
    invoke-virtual {p1, p2}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 96
    .line 97
    .line 98
    move-result-object p2

    .line 99
    goto :goto_0

    .line 100
    :cond_1
    new-instance v3, Ltechnology/cariad/cat/genx/l;

    .line 101
    .line 102
    const/4 p0, 0x2

    .line 103
    invoke-direct {v3, p2, p0}, Ltechnology/cariad/cat/genx/l;-><init>(Ltechnology/cariad/cat/genx/ScanningTokenImpl;I)V

    .line 104
    .line 105
    .line 106
    new-instance v0, Lt51/j;

    .line 107
    .line 108
    invoke-static {p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v5

    .line 112
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v6

    .line 116
    const-string v1, "GenX"

    .line 117
    .line 118
    const/4 v4, 0x0

    .line 119
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 123
    .line 124
    .line 125
    iget-object p0, p1, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->activeScanningTokens:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 126
    .line 127
    invoke-virtual {p0, p2}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    :goto_0
    new-instance p0, Llx0/o;

    .line 131
    .line 132
    invoke-direct {p0, p2}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    return-object p0
.end method

.method private static final startScanningForClients_IoAF18A$lambda$1$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): starting scanning"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients_IoAF18A$lambda$1$0$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeStartScanningForClients()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final startScanningForClients_IoAF18A$lambda$1$0$2(Ltechnology/cariad/cat/genx/ScanningTokenImpl;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "startScanningForClients(): Successfully started scanning - newToken = "

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

.method private static final startScanningForClients_IoAF18A$lambda$1$0$3()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): Scanning could not be started"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients_IoAF18A$lambda$1$0$4(Ltechnology/cariad/cat/genx/ScanningTokenImpl;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "startScanningForClients(): Scanning is already running - newToken = "

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

.method public static synthetic t1()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->onKeyExchangeSucceeded$lambda$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic u1(Ltechnology/cariad/cat/genx/ScanningTokenImpl;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startScanningForClients_IoAF18A$lambda$1$0$2(Ltechnology/cariad/cat/genx/ScanningTokenImpl;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final unregisterAllVehicles_IoAF18A$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "unregisterAllVehicles(): Failed to unregister all vehicles"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final unregisterAllVehicles_IoAF18A$lambda$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Llx0/o;
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/b0;

    .line 2
    .line 3
    const/16 v0, 0x19

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v1, "getName(...)"

    .line 15
    .line 16
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "GenX"

    .line 21
    .line 22
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehiclesLock:Ljava/util/concurrent/locks/ReentrantLock;

    .line 32
    .line 33
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 34
    .line 35
    .line 36
    :try_start_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 37
    .line 38
    invoke-static {v0}, Lmx0/x;->u(Ljava/util/Map;)Ljava/util/Map;

    .line 39
    .line 40
    .line 41
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 43
    .line 44
    .line 45
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    check-cast v0, Ljava/lang/Iterable;

    .line 50
    .line 51
    invoke-static {v0}, Lmx0/q;->z(Ljava/lang/Iterable;)Lky0/m;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    iget-object v0, v0, Lky0/m;->b:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v0, Ljava/lang/Iterable;

    .line 58
    .line 59
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    if-eqz v1, :cond_1

    .line 68
    .line 69
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    check-cast v1, Ljava/util/Map$Entry;

    .line 74
    .line 75
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    check-cast v1, Ljava/lang/String;

    .line 80
    .line 81
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->unregisterVehicleNonDispatched(Ljava/lang/String;)Ltechnology/cariad/cat/genx/GenXError;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    if-eqz v2, :cond_0

    .line 86
    .line 87
    new-instance v0, Ltechnology/cariad/cat/genx/k;

    .line 88
    .line 89
    const/4 v3, 0x3

    .line 90
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/genx/k;-><init>(Ljava/lang/String;I)V

    .line 91
    .line 92
    .line 93
    const-string v1, "GenX"

    .line 94
    .line 95
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 96
    .line 97
    .line 98
    invoke-static {v2}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    new-instance v0, Llx0/o;

    .line 103
    .line 104
    invoke-direct {v0, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    return-object v0

    .line 108
    :cond_1
    new-instance p0, Llx0/o;

    .line 109
    .line 110
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 111
    .line 112
    invoke-direct {p0, v0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    return-object p0

    .line 116
    :catchall_0
    move-exception v0

    .line 117
    move-object p0, v0

    .line 118
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 119
    .line 120
    .line 121
    throw p0
.end method

.method private static final unregisterAllVehicles_IoAF18A$lambda$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "unregisterAllVehicles()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final unregisterAllVehicles_IoAF18A$lambda$1$2$0$0(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "unregisterAllVehicles(): Failed to unregister vehicle with identifier = "

    .line 2
    .line 3
    const-string v1, "."

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private final unregisterVehicleNonDispatched(Ljava/lang/String;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 4
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/k0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, p1, v1}, Ltechnology/cariad/cat/genx/k0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;I)V

    .line 5
    .line 6
    .line 7
    invoke-static {v0}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehiclesLock:Ljava/util/concurrent/locks/ReentrantLock;

    .line 12
    .line 13
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 14
    .line 15
    .line 16
    :try_start_0
    iget-object v2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 17
    .line 18
    invoke-interface {v2, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    check-cast v2, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 23
    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    invoke-interface {v2}, Ljava/io/Closeable;->close()V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :catchall_0
    move-exception p0

    .line 31
    goto :goto_1

    .line 32
    :cond_0
    :goto_0
    iget-object v2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 33
    .line 34
    const-string v3, "<this>"

    .line 35
    .line 36
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-static {v2}, Lmx0/x;->w(Ljava/util/Map;)Ljava/util/LinkedHashMap;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    invoke-interface {v2, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    invoke-static {v2}, Lmx0/x;->o(Ljava/util/LinkedHashMap;)Ljava/util/Map;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 51
    .line 52
    invoke-interface {p1}, Ljava/util/Map;->isEmpty()Z

    .line 53
    .line 54
    .line 55
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 56
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 57
    .line 58
    .line 59
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->beaconScannerManager:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 60
    .line 61
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->reloadBeacons$genx_release()V

    .line 62
    .line 63
    .line 64
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->beaconScannerManager:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->stopScanning$genx_release(Z)V

    .line 67
    .line 68
    .line 69
    return-object v0

    .line 70
    :goto_1
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 71
    .line 72
    .line 73
    throw p0
.end method

.method private static final unregisterVehicleNonDispatched$lambda$0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;)I
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->nativeUnregisterVehicle(Ljava/lang/String;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final unregisterVehicle_gIAlu_s$lambda$0(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "unregisterVehicle(): Failed to unregister vehicle with identifier = "

    .line 2
    .line 3
    const-string v1, "."

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static final unregisterVehicle_gIAlu_s$lambda$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;)Llx0/o;
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/k;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-direct {v3, p1, v0}, Ltechnology/cariad/cat/genx/k;-><init>(Ljava/lang/String;I)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lt51/j;

    .line 8
    .line 9
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v5

    .line 13
    const-string v1, "getName(...)"

    .line 14
    .line 15
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string v1, "GenX"

    .line 20
    .line 21
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 28
    .line 29
    .line 30
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->unregisterVehicleNonDispatched(Ljava/lang/String;)Ltechnology/cariad/cat/genx/GenXError;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    if-eqz v0, :cond_0

    .line 35
    .line 36
    new-instance v1, Ltechnology/cariad/cat/genx/k;

    .line 37
    .line 38
    const/4 v2, 0x2

    .line 39
    invoke-direct {v1, p1, v2}, Ltechnology/cariad/cat/genx/k;-><init>(Ljava/lang/String;I)V

    .line 40
    .line 41
    .line 42
    const-string p1, "GenX"

    .line 43
    .line 44
    invoke-static {p0, p1, v0, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 45
    .line 46
    .line 47
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    goto :goto_0

    .line 52
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    :goto_0
    new-instance p1, Llx0/o;

    .line 55
    .line 56
    invoke-direct {p1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    return-object p1
.end method

.method private static final unregisterVehicle_gIAlu_s$lambda$1$0(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "unregisterVehicle(): vin = "

    .line 2
    .line 3
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private static final unregisterVehicle_gIAlu_s$lambda$1$1$0(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "unregisterVehicle(): Failed to unregister vehicle with identifier = "

    .line 2
    .line 3
    const-string v1, "."

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static synthetic v1()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->lambda$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic w1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->registerVehicles_gIAlu_s$lambda$3(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic x0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->registerVehicles_gIAlu_s$lambda$5$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic y0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager$lambda$4(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ltechnology/cariad/cat/genx/GenXError;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic z0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager$lambda$2(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public cancelKeyExchange-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    instance-of v0, p1, Ltechnology/cariad/cat/genx/VehicleManagerImpl$cancelKeyExchange$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$cancelKeyExchange$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$cancelKeyExchange$1;->label:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$cancelKeyExchange$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$cancelKeyExchange$1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$cancelKeyExchange$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$cancelKeyExchange$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$cancelKeyExchange$1;->label:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$cancelKeyExchange$1;->L$0:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    check-cast p1, Llx0/o;

    .line 44
    .line 45
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 46
    .line 47
    return-object p0

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 60
    .line 61
    const/4 v2, 0x0

    .line 62
    if-eqz p1, :cond_5

    .line 63
    .line 64
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isVehicleManagerClosed()Z

    .line 65
    .line 66
    .line 67
    move-result v4

    .line 68
    if-eqz v4, :cond_3

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_3
    iput-object v2, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$cancelKeyExchange$1;->L$0:Ljava/lang/Object;

    .line 72
    .line 73
    iput v3, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$cancelKeyExchange$1;->label:I

    .line 74
    .line 75
    invoke-virtual {p1, v0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->cancelKeyExchange-IoAF18A$genx_release(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    if-ne p0, v1, :cond_4

    .line 80
    .line 81
    return-object v1

    .line 82
    :cond_4
    return-object p0

    .line 83
    :cond_5
    :goto_1
    new-instance p1, Ltechnology/cariad/cat/genx/o0;

    .line 84
    .line 85
    const/16 v0, 0x8

    .line 86
    .line 87
    invoke-direct {p1, v0}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

    .line 88
    .line 89
    .line 90
    const-string v0, "GenX"

    .line 91
    .line 92
    invoke-static {p0, v0, v2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 93
    .line 94
    .line 95
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 96
    .line 97
    return-object p0
.end method

.method public close()V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/b0;

    .line 2
    .line 3
    const/16 v0, 0x15

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v1, "getName(...)"

    .line 15
    .line 16
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "GenX"

    .line 21
    .line 22
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->activeScanningTokens:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 32
    .line 33
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_0

    .line 42
    .line 43
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    check-cast v1, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 48
    .line 49
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;->close()V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->activeScanningTokens:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;->clear()V

    .line 56
    .line 57
    .line 58
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->beaconScannerManager:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 59
    .line 60
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->close$genx_release()V

    .line 61
    .line 62
    .line 63
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehiclesLock:Ljava/util/concurrent/locks/ReentrantLock;

    .line 64
    .line 65
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 66
    .line 67
    .line 68
    :try_start_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 69
    .line 70
    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    check-cast v0, Ljava/lang/Iterable;

    .line 75
    .line 76
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    if-eqz v2, :cond_1

    .line 85
    .line 86
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    check-cast v2, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 91
    .line 92
    invoke-interface {v2}, Ljava/io/Closeable;->close()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :catchall_0
    move-exception v0

    .line 97
    move-object p0, v0

    .line 98
    goto :goto_3

    .line 99
    :cond_1
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getClientManager()Ljava/util/List;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    check-cast v0, Ljava/lang/Iterable;

    .line 107
    .line 108
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    if-eqz v1, :cond_2

    .line 117
    .line 118
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    check-cast v1, Ltechnology/cariad/cat/genx/ClientManager;

    .line 123
    .line 124
    invoke-interface {v1}, Ljava/io/Closeable;->close()V

    .line 125
    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_2
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 129
    .line 130
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->setClientManager(Ljava/util/List;)V

    .line 131
    .line 132
    .line 133
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 134
    .line 135
    if-eqz v0, :cond_3

    .line 136
    .line 137
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->close()V

    .line 138
    .line 139
    .line 140
    :cond_3
    const/4 v0, 0x0

    .line 141
    iput-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 142
    .line 143
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 144
    .line 145
    new-instance v1, Ltechnology/cariad/cat/genx/v0;

    .line 146
    .line 147
    const/4 v2, 0x7

    .line 148
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/v0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)V

    .line 149
    .line 150
    .line 151
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 152
    .line 153
    .line 154
    return-void

    .line 155
    :goto_3
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 156
    .line 157
    .line 158
    throw p0
.end method

.method public final getActiveScanningTokens$genx_release()Ljava/util/concurrent/CopyOnWriteArrayList;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/concurrent/CopyOnWriteArrayList<",
            "Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->activeScanningTokens:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAllBeaconsToScanFor$genx_release()Ljava/util/List;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lt41/b;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Iterable;

    .line 8
    .line 9
    new-instance v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_4

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 29
    .line 30
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/InternalVehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    const/4 v3, 0x0

    .line 35
    if-eqz v2, :cond_0

    .line 36
    .line 37
    invoke-interface {v2}, Ltechnology/cariad/cat/genx/InternalVehicleAntenna;->getBeaconsToSearch()Lyy0/a2;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    if-eqz v2, :cond_0

    .line 42
    .line 43
    invoke-interface {v2}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    check-cast v2, Ljava/util/List;

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_0
    move-object v2, v3

    .line 51
    :goto_1
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 52
    .line 53
    if-nez v2, :cond_1

    .line 54
    .line 55
    move-object v2, v4

    .line 56
    :cond_1
    check-cast v2, Ljava/util/Collection;

    .line 57
    .line 58
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/InternalVehicle;->getOuterAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    if-eqz v1, :cond_2

    .line 63
    .line 64
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/InternalVehicleAntenna;->getBeaconsToSearch()Lyy0/a2;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    if-eqz v1, :cond_2

    .line 69
    .line 70
    invoke-interface {v1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    move-object v3, v1

    .line 75
    check-cast v3, Ljava/util/List;

    .line 76
    .line 77
    :cond_2
    if-nez v3, :cond_3

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_3
    move-object v4, v3

    .line 81
    :goto_2
    check-cast v4, Ljava/lang/Iterable;

    .line 82
    .line 83
    invoke-static {v4, v2}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    new-instance v2, Lt41/b;

    .line 88
    .line 89
    sget-object v3, Ltechnology/cariad/cat/genx/VehicleManager;->Companion:Ltechnology/cariad/cat/genx/VehicleManager$Companion;

    .line 90
    .line 91
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->getPairingBeaconUUID()Ljava/util/UUID;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    const/16 v4, 0x51

    .line 96
    .line 97
    const/16 v5, 0x4d

    .line 98
    .line 99
    invoke-direct {v2, v3, v4, v5}, Lt41/b;-><init>(Ljava/util/UUID;SS)V

    .line 100
    .line 101
    .line 102
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    check-cast v2, Ljava/lang/Iterable;

    .line 107
    .line 108
    invoke-static {v2, v1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    invoke-static {v1, v0}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 113
    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_4
    return-object v0
.end method

.method public getClientManager()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ltechnology/cariad/cat/genx/ClientManager;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->clientManager:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->coroutineContext:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDeviceInformation()Ltechnology/cariad/cat/genx/DeviceInformation;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->deviceInformation:Ltechnology/cariad/cat/genx/DeviceInformation;

    .line 2
    .line 3
    return-object p0
.end method

.method public bridge synthetic getEnabledTransportTypes()Lyy0/a2;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getEnabledTransportTypes()Lyy0/j1;

    move-result-object p0

    return-object p0
.end method

.method public getEnabledTransportTypes()Lyy0/j1;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/j1;"
        }
    .end annotation

    .line 2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->enabledTransportTypes:Lyy0/j1;

    return-object p0
.end method

.method public final getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReference()J
    .locals 2

    .line 1
    iget-wide v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->reference:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getVehicleErrors()Lyy0/i;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicleErrors:Lyy0/i;

    .line 2
    .line 3
    return-object p0
.end method

.method public isAnyVehicleRegistered()Z
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehiclesLock:Ljava/util/concurrent/locks/ReentrantLock;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    xor-int/lit8 p0, p0, 0x1

    .line 13
    .line 14
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 15
    .line 16
    .line 17
    return p0

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 20
    .line 21
    .line 22
    throw p0
.end method

.method public isBleEnabled()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isBleEnabled:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isLocationEnabled()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isLocationEnabled:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isLocationPermissionGranted()Z
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/location/Location;->INSTANCE:Ltechnology/cariad/cat/genx/location/Location;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->context:Landroid/content/Context;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/genx/location/Location;->isPermissionGranted$genx_release(Landroid/content/Context;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isTransportEnabled(Ltechnology/cariad/cat/genx/TransportType;)Z
    .locals 2

    .line 1
    const-string v0, "transportType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getClientManager()Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Ljava/lang/Iterable;

    .line 11
    .line 12
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    move-object v1, v0

    .line 27
    check-cast v1, Ltechnology/cariad/cat/genx/ClientManager;

    .line 28
    .line 29
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/ClientManager;->getTransportType()Ltechnology/cariad/cat/genx/TransportType;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    if-ne v1, p1, :cond_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    const/4 v0, 0x0

    .line 37
    :goto_0
    check-cast v0, Ltechnology/cariad/cat/genx/ClientManager;

    .line 38
    .line 39
    const/4 p0, 0x0

    .line 40
    if-eqz v0, :cond_2

    .line 41
    .line 42
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/ClientManager;->isEnabled()Z

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    const/4 v0, 0x1

    .line 47
    if-ne p1, v0, :cond_2

    .line 48
    .line 49
    return v0

    .line 50
    :cond_2
    return p0
.end method

.method public isTransportSupported(Ltechnology/cariad/cat/genx/TransportType;)Z
    .locals 2

    .line 1
    const-string v0, "transportType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getClientManager()Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Ljava/lang/Iterable;

    .line 11
    .line 12
    instance-of v0, p0, Ljava/util/Collection;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    move-object v0, p0

    .line 18
    check-cast v0, Ljava/util/Collection;

    .line 19
    .line 20
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    return v1

    .line 27
    :cond_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    check-cast v0, Ltechnology/cariad/cat/genx/ClientManager;

    .line 42
    .line 43
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/ClientManager;->getTransportType()Ltechnology/cariad/cat/genx/TransportType;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    if-ne v0, p1, :cond_1

    .line 48
    .line 49
    const/4 p0, 0x1

    .line 50
    return p0

    .line 51
    :cond_2
    return v1
.end method

.method public isWifiEnabled()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isWifiEnabled:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public onDecryptMessage(B[B[B)[B
    .locals 12

    .line 1
    const-string v0, "message"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "initializationVector"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeEncryptionCredentials:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 12
    .line 13
    const-string v1, "GenX"

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    new-instance p2, Ltechnology/cariad/cat/genx/e;

    .line 19
    .line 20
    const/4 p3, 0x2

    .line 21
    invoke-direct {p2, p1, p3}, Ltechnology/cariad/cat/genx/e;-><init>(BI)V

    .line 22
    .line 23
    .line 24
    invoke-static {p0, v1, v2, p2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 25
    .line 26
    .line 27
    return-object v2

    .line 28
    :cond_0
    invoke-static {p1}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyTypeKt;->getEncryptionKeyType(B)Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sget-object v3, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;->VKMS:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 33
    .line 34
    const-string v4, "getName(...)"

    .line 35
    .line 36
    sget-object v7, Lt51/g;->a:Lt51/g;

    .line 37
    .line 38
    if-ne v0, v3, :cond_2

    .line 39
    .line 40
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeEncryptionCredentials:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 41
    .line 42
    instance-of v0, v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials$VKMS;

    .line 43
    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    new-instance v8, Ltechnology/cariad/cat/genx/p0;

    .line 47
    .line 48
    const/4 p1, 0x2

    .line 49
    invoke-direct {v8, p2, p1, p3}, Ltechnology/cariad/cat/genx/p0;-><init>([BI[B)V

    .line 50
    .line 51
    .line 52
    new-instance v5, Lt51/j;

    .line 53
    .line 54
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v10

    .line 58
    invoke-static {v4}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v11

    .line 62
    const-string v6, "GenX"

    .line 63
    .line 64
    const/4 v9, 0x0

    .line 65
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 69
    .line 70
    .line 71
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeEncryptionCredentials:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 72
    .line 73
    if-eqz p0, :cond_4

    .line 74
    .line 75
    invoke-interface {p0, p2, p3}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;->decrypt-gIAlu-s([B[B)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    instance-of p1, p0, Llx0/n;

    .line 80
    .line 81
    if-eqz p1, :cond_1

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_1
    move-object v2, p0

    .line 85
    :goto_0
    check-cast v2, [B

    .line 86
    .line 87
    return-object v2

    .line 88
    :cond_2
    invoke-static {p1}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyTypeKt;->getEncryptionKeyType(B)Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    sget-object v3, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;->RSE_DIAGNOSIS:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 93
    .line 94
    if-ne v0, v3, :cond_5

    .line 95
    .line 96
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeEncryptionCredentials:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 97
    .line 98
    instance-of v0, v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials$RSE_DIAGNOSIS;

    .line 99
    .line 100
    if-eqz v0, :cond_5

    .line 101
    .line 102
    new-instance v8, Ltechnology/cariad/cat/genx/p0;

    .line 103
    .line 104
    const/4 p1, 0x3

    .line 105
    invoke-direct {v8, p2, p1, p3}, Ltechnology/cariad/cat/genx/p0;-><init>([BI[B)V

    .line 106
    .line 107
    .line 108
    new-instance v5, Lt51/j;

    .line 109
    .line 110
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v10

    .line 114
    invoke-static {v4}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v11

    .line 118
    const-string v6, "GenX"

    .line 119
    .line 120
    const/4 v9, 0x0

    .line 121
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 125
    .line 126
    .line 127
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeEncryptionCredentials:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 128
    .line 129
    if-eqz p0, :cond_4

    .line 130
    .line 131
    invoke-interface {p0, p2, p3}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;->decrypt-gIAlu-s([B[B)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    instance-of p1, p0, Llx0/n;

    .line 136
    .line 137
    if-eqz p1, :cond_3

    .line 138
    .line 139
    goto :goto_1

    .line 140
    :cond_3
    move-object v2, p0

    .line 141
    :goto_1
    check-cast v2, [B

    .line 142
    .line 143
    :cond_4
    return-object v2

    .line 144
    :cond_5
    new-instance p2, Ltechnology/cariad/cat/genx/e;

    .line 145
    .line 146
    const/4 p3, 0x3

    .line 147
    invoke-direct {p2, p1, p3}, Ltechnology/cariad/cat/genx/e;-><init>(BI)V

    .line 148
    .line 149
    .line 150
    invoke-static {p0, v1, v2, p2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 151
    .line 152
    .line 153
    return-object v2
.end method

.method public onEncounteredError(BLtechnology/cariad/cat/genx/GenXError;)V
    .locals 2

    .line 1
    const-string v0, "error"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ltechnology/cariad/cat/genx/TransportTypeKt;->getTransportType(B)Ltechnology/cariad/cat/genx/TransportType;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    new-instance v0, Ltechnology/cariad/cat/genx/s;

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    invoke-direct {v0, p1, v1}, Ltechnology/cariad/cat/genx/s;-><init>(Ltechnology/cariad/cat/genx/TransportType;I)V

    .line 14
    .line 15
    .line 16
    const-string p1, "GenX"

    .line 17
    .line 18
    invoke-static {p0, p1, p2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 19
    .line 20
    .line 21
    invoke-static {p2}, Ltechnology/cariad/cat/genx/GenXErrorKt;->getCgxStatusValue(Ltechnology/cariad/cat/genx/GenXError;)Ljava/lang/Integer;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sget-object v1, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 26
    .line 27
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getClientScanFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-nez v0, :cond_0

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-ne v0, v1, :cond_1

    .line 43
    .line 44
    new-instance v0, Ltechnology/cariad/cat/genx/o0;

    .line 45
    .line 46
    const/4 v1, 0x7

    .line 47
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

    .line 48
    .line 49
    .line 50
    invoke-static {p0, p1, p2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->activeScanningTokens:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 54
    .line 55
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_1

    .line 64
    .line 65
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    check-cast v0, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 70
    .line 71
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;->close()V

    .line 72
    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_1
    :goto_1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->_vehicleErrors:Lyy0/i1;

    .line 76
    .line 77
    invoke-interface {p0, p2}, Lyy0/i1;->a(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    return-void
.end method

.method public onEncryptMessage(B[B[B)[B
    .locals 12

    .line 1
    const-string v0, "message"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "initializationVector"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeEncryptionCredentials:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 12
    .line 13
    const-string v1, "GenX"

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    new-instance p1, Ltechnology/cariad/cat/genx/o0;

    .line 19
    .line 20
    const/4 p2, 0x3

    .line 21
    invoke-direct {p1, p2}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

    .line 22
    .line 23
    .line 24
    invoke-static {p0, v1, v2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 25
    .line 26
    .line 27
    return-object v2

    .line 28
    :cond_0
    invoke-static {p1}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyTypeKt;->getEncryptionKeyType(B)Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sget-object v3, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;->VKMS:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 33
    .line 34
    const-string v4, "getName(...)"

    .line 35
    .line 36
    sget-object v7, Lt51/g;->a:Lt51/g;

    .line 37
    .line 38
    if-ne v0, v3, :cond_2

    .line 39
    .line 40
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeEncryptionCredentials:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 41
    .line 42
    instance-of v0, v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials$VKMS;

    .line 43
    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    new-instance v8, Ltechnology/cariad/cat/genx/p0;

    .line 47
    .line 48
    const/4 p1, 0x0

    .line 49
    invoke-direct {v8, p2, p1, p3}, Ltechnology/cariad/cat/genx/p0;-><init>([BI[B)V

    .line 50
    .line 51
    .line 52
    new-instance v5, Lt51/j;

    .line 53
    .line 54
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v10

    .line 58
    invoke-static {v4}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v11

    .line 62
    const-string v6, "GenX"

    .line 63
    .line 64
    const/4 v9, 0x0

    .line 65
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 69
    .line 70
    .line 71
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeEncryptionCredentials:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 72
    .line 73
    if-eqz p0, :cond_4

    .line 74
    .line 75
    invoke-interface {p0, p2, p3}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;->encrypt-gIAlu-s([B[B)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    instance-of p1, p0, Llx0/n;

    .line 80
    .line 81
    if-eqz p1, :cond_1

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_1
    move-object v2, p0

    .line 85
    :goto_0
    check-cast v2, [B

    .line 86
    .line 87
    return-object v2

    .line 88
    :cond_2
    invoke-static {p1}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyTypeKt;->getEncryptionKeyType(B)Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    sget-object v3, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;->RSE_DIAGNOSIS:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 93
    .line 94
    if-ne v0, v3, :cond_5

    .line 95
    .line 96
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeEncryptionCredentials:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 97
    .line 98
    instance-of v0, v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials$RSE_DIAGNOSIS;

    .line 99
    .line 100
    if-eqz v0, :cond_5

    .line 101
    .line 102
    new-instance v8, Ltechnology/cariad/cat/genx/p0;

    .line 103
    .line 104
    const/4 p1, 0x1

    .line 105
    invoke-direct {v8, p2, p1, p3}, Ltechnology/cariad/cat/genx/p0;-><init>([BI[B)V

    .line 106
    .line 107
    .line 108
    new-instance v5, Lt51/j;

    .line 109
    .line 110
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v10

    .line 114
    invoke-static {v4}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v11

    .line 118
    const-string v6, "GenX"

    .line 119
    .line 120
    const/4 v9, 0x0

    .line 121
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 125
    .line 126
    .line 127
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeEncryptionCredentials:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 128
    .line 129
    if-eqz p0, :cond_4

    .line 130
    .line 131
    invoke-interface {p0, p2, p3}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;->encrypt-gIAlu-s([B[B)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    instance-of p1, p0, Llx0/n;

    .line 136
    .line 137
    if-eqz p1, :cond_3

    .line 138
    .line 139
    goto :goto_1

    .line 140
    :cond_3
    move-object v2, p0

    .line 141
    :goto_1
    check-cast v2, [B

    .line 142
    .line 143
    :cond_4
    return-object v2

    .line 144
    :cond_5
    new-instance p2, Ltechnology/cariad/cat/genx/e;

    .line 145
    .line 146
    const/4 p3, 0x1

    .line 147
    invoke-direct {p2, p1, p3}, Ltechnology/cariad/cat/genx/e;-><init>(BI)V

    .line 148
    .line 149
    .line 150
    invoke-static {p0, v1, v2, p2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 151
    .line 152
    .line 153
    return-object v2
.end method

.method public onEncryptedKeyExchangeSucceeded(Ljava/lang/String;B[BLtechnology/cariad/cat/genx/crypto/RemoteCredentials;ISSLtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 10

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "uuid"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "remoteCredentials"

    .line 12
    .line 13
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "localKeyPair"

    .line 17
    .line 18
    move-object/from16 v9, p8

    .line 19
    .line 20
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 24
    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    move-object v2, p1

    .line 28
    move v3, p2

    .line 29
    move-object v4, p3

    .line 30
    move-object v5, p4

    .line 31
    move v6, p5

    .line 32
    move/from16 v7, p6

    .line 33
    .line 34
    move/from16 v8, p7

    .line 35
    .line 36
    invoke-virtual/range {v1 .. v9}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->onEncryptedKeyExchangeSucceeded$genx_release(Ljava/lang/String;B[BLtechnology/cariad/cat/genx/crypto/RemoteCredentials;ISSLtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/GenXError;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_0
    new-instance p1, Ltechnology/cariad/cat/genx/b0;

    .line 42
    .line 43
    const/16 p2, 0xe

    .line 44
    .line 45
    invoke-direct {p1, p2}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 46
    .line 47
    .line 48
    const/4 p2, 0x0

    .line 49
    const-string p3, "GenX"

    .line 50
    .line 51
    invoke-static {p0, p3, p2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 52
    .line 53
    .line 54
    sget-object p0, Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;

    .line 55
    .line 56
    return-object p0
.end method

.method public onKeyExchangeFailed(Ljava/lang/String;Ltechnology/cariad/cat/genx/GenXError;)V
    .locals 1

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "error"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-virtual {v0, p1, p2}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->onCGXKeyExchangeFailed$genx_release(Ljava/lang/String;Ltechnology/cariad/cat/genx/GenXError;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    new-instance p1, Ltechnology/cariad/cat/genx/b0;

    .line 20
    .line 21
    const/16 p2, 0x1a

    .line 22
    .line 23
    invoke-direct {p1, p2}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 24
    .line 25
    .line 26
    const/4 p2, 0x0

    .line 27
    const-string v0, "GenX"

    .line 28
    .line 29
    invoke-static {p0, v0, p2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public onKeyExchangeSucceeded(Ljava/lang/String;I)Ltechnology/cariad/cat/genx/GenXError;
    .locals 1

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {v0, p1, p2}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->onCGXKeyExchangeSucceeded$genx_release(Ljava/lang/String;I)Ltechnology/cariad/cat/genx/GenXError;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :cond_0
    new-instance p1, Ltechnology/cariad/cat/genx/b0;

    .line 16
    .line 17
    const/16 p2, 0x1c

    .line 18
    .line 19
    invoke-direct {p1, p2}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 20
    .line 21
    .line 22
    const/4 p2, 0x0

    .line 23
    const-string v0, "GenX"

    .line 24
    .line 25
    invoke-static {p0, v0, p2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;

    .line 29
    .line 30
    return-object p0
.end method

.method public onStateUpdated(BZ)V
    .locals 7

    .line 1
    invoke-static {p1}, Ltechnology/cariad/cat/genx/TransportTypeKt;->getTransportType(B)Ltechnology/cariad/cat/genx/TransportType;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    new-instance v3, Ltechnology/cariad/cat/genx/d;

    .line 6
    .line 7
    invoke-direct {v3, p1, p2}, Ltechnology/cariad/cat/genx/d;-><init>(Ltechnology/cariad/cat/genx/TransportType;Z)V

    .line 8
    .line 9
    .line 10
    new-instance v0, Lt51/j;

    .line 11
    .line 12
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v5

    .line 16
    const-string v1, "getName(...)"

    .line 17
    .line 18
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    const-string v1, "GenX"

    .line 23
    .line 24
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 25
    .line 26
    const/4 v4, 0x0

    .line 27
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 34
    .line 35
    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast v0, Ljava/lang/Iterable;

    .line 40
    .line 41
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-eqz v1, :cond_0

    .line 50
    .line 51
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    check-cast v1, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 56
    .line 57
    invoke-interface {v1, p1, p2}, Ltechnology/cariad/cat/genx/InternalVehicle;->setClientManagerState(Ltechnology/cariad/cat/genx/TransportType;Z)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getEnabledTransportTypes()Lyy0/j1;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    :cond_1
    move-object v0, p0

    .line 66
    check-cast v0, Lyy0/c2;

    .line 67
    .line 68
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    move-object v2, v1

    .line 73
    check-cast v2, Ljava/util/List;

    .line 74
    .line 75
    if-eqz p2, :cond_2

    .line 76
    .line 77
    check-cast v2, Ljava/util/Collection;

    .line 78
    .line 79
    invoke-static {v2, p1}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    goto :goto_1

    .line 84
    :cond_2
    check-cast v2, Ljava/lang/Iterable;

    .line 85
    .line 86
    invoke-static {v2, p1}, Lmx0/q;->W(Ljava/lang/Iterable;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    :goto_1
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v0

    .line 94
    if-eqz v0, :cond_1

    .line 95
    .line 96
    return-void
.end method

.method public registerVehicles-gIAlu-s(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 17
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ltechnology/cariad/cat/genx/Vehicle$Information;",
            ">;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    instance-of v3, v2, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;

    .line 13
    .line 14
    iget v4, v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;->label:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;->label:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;->result:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;->label:I

    .line 36
    .line 37
    sget-object v8, Lt51/g;->a:Lt51/g;

    .line 38
    .line 39
    const-string v13, "GenX"

    .line 40
    .line 41
    const/4 v14, 0x2

    .line 42
    const/4 v15, 0x1

    .line 43
    const-string v16, "getName(...)"

    .line 44
    .line 45
    if-eqz v5, :cond_3

    .line 46
    .line 47
    if-eq v5, v15, :cond_2

    .line 48
    .line 49
    if-ne v5, v14, :cond_1

    .line 50
    .line 51
    iget-object v1, v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;->L$1:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v1, Ljava/util/List;

    .line 54
    .line 55
    iget-object v3, v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;->L$0:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v3, Ljava/util/List;

    .line 58
    .line 59
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto/16 :goto_3

    .line 63
    .line 64
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 65
    .line 66
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 67
    .line 68
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw v0

    .line 72
    :cond_2
    iget-object v1, v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;->L$0:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v1, Ljava/util/List;

    .line 75
    .line 76
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isVehicleManagerClosed()Z

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    if-eqz v2, :cond_4

    .line 88
    .line 89
    sget-object v1, Ltechnology/cariad/cat/genx/GenXError$VehicleManagerAlreadyClosed;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$VehicleManagerAlreadyClosed;

    .line 90
    .line 91
    new-instance v2, Ltechnology/cariad/cat/genx/b0;

    .line 92
    .line 93
    const/16 v3, 0x14

    .line 94
    .line 95
    invoke-direct {v2, v3}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 96
    .line 97
    .line 98
    invoke-static {v0, v13, v1, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 99
    .line 100
    .line 101
    invoke-static {v1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    return-object v0

    .line 106
    :cond_4
    new-instance v9, Ltechnology/cariad/cat/genx/p;

    .line 107
    .line 108
    const/4 v2, 0x1

    .line 109
    invoke-direct {v9, v1, v2}, Ltechnology/cariad/cat/genx/p;-><init>(Ljava/util/List;I)V

    .line 110
    .line 111
    .line 112
    new-instance v6, Lt51/j;

    .line 113
    .line 114
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v11

    .line 118
    invoke-static/range {v16 .. v16}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v12

    .line 122
    const-string v7, "GenX"

    .line 123
    .line 124
    const/4 v10, 0x0

    .line 125
    invoke-direct/range {v6 .. v12}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    invoke-static {v6}, Lt51/a;->a(Lt51/j;)V

    .line 129
    .line 130
    .line 131
    iput-object v1, v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;->L$0:Ljava/lang/Object;

    .line 132
    .line 133
    iput v15, v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;->label:I

    .line 134
    .line 135
    new-instance v2, Lpx0/i;

    .line 136
    .line 137
    invoke-static {v3}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 138
    .line 139
    .line 140
    move-result-object v5

    .line 141
    invoke-direct {v2, v5}, Lpx0/i;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 142
    .line 143
    .line 144
    iget-object v5, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 145
    .line 146
    new-instance v6, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;

    .line 147
    .line 148
    invoke-direct {v6, v0, v1, v2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$errorsDuringRegistration$1$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/util/List;Lkotlin/coroutines/Continuation;)V

    .line 149
    .line 150
    .line 151
    invoke-interface {v5, v6}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v2}, Lpx0/i;->a()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    if-ne v2, v4, :cond_5

    .line 159
    .line 160
    goto :goto_2

    .line 161
    :cond_5
    :goto_1
    move-object v1, v2

    .line 162
    check-cast v1, Ljava/util/List;

    .line 163
    .line 164
    new-instance v9, Ltechnology/cariad/cat/genx/v0;

    .line 165
    .line 166
    const/4 v2, 0x6

    .line 167
    invoke-direct {v9, v0, v2}, Ltechnology/cariad/cat/genx/v0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)V

    .line 168
    .line 169
    .line 170
    new-instance v6, Lt51/j;

    .line 171
    .line 172
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object v11

    .line 176
    invoke-static/range {v16 .. v16}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v12

    .line 180
    const-string v7, "GenX"

    .line 181
    .line 182
    const/4 v10, 0x0

    .line 183
    invoke-direct/range {v6 .. v12}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    invoke-static {v6}, Lt51/a;->a(Lt51/j;)V

    .line 187
    .line 188
    .line 189
    iget-object v2, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->beaconScannerManager:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 190
    .line 191
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->startScanning$genx_release()Lvy0/h0;

    .line 192
    .line 193
    .line 194
    move-result-object v2

    .line 195
    const/4 v5, 0x0

    .line 196
    iput-object v5, v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;->L$0:Ljava/lang/Object;

    .line 197
    .line 198
    iput-object v1, v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;->L$1:Ljava/lang/Object;

    .line 199
    .line 200
    iput v14, v3, Ltechnology/cariad/cat/genx/VehicleManagerImpl$registerVehicles$1;->label:I

    .line 201
    .line 202
    invoke-interface {v2, v3}, Lvy0/h0;->B(Lrx0/c;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v2

    .line 206
    if-ne v2, v4, :cond_6

    .line 207
    .line 208
    :goto_2
    return-object v4

    .line 209
    :cond_6
    :goto_3
    check-cast v2, Llx0/o;

    .line 210
    .line 211
    iget-object v2, v2, Llx0/o;->d:Ljava/lang/Object;

    .line 212
    .line 213
    invoke-static {v2}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 214
    .line 215
    .line 216
    move-result-object v3

    .line 217
    if-nez v3, :cond_7

    .line 218
    .line 219
    check-cast v2, Llx0/b0;

    .line 220
    .line 221
    new-instance v6, Ltechnology/cariad/cat/genx/b0;

    .line 222
    .line 223
    const/16 v2, 0x16

    .line 224
    .line 225
    invoke-direct {v6, v2}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 226
    .line 227
    .line 228
    new-instance v3, Lt51/j;

    .line 229
    .line 230
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object v8

    .line 234
    invoke-static/range {v16 .. v16}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object v9

    .line 238
    const-string v4, "GenX"

    .line 239
    .line 240
    sget-object v5, Lt51/f;->a:Lt51/f;

    .line 241
    .line 242
    const/4 v7, 0x0

    .line 243
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 247
    .line 248
    .line 249
    goto :goto_4

    .line 250
    :cond_7
    new-instance v2, Ltechnology/cariad/cat/genx/b0;

    .line 251
    .line 252
    const/16 v4, 0x17

    .line 253
    .line 254
    invoke-direct {v2, v4}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 255
    .line 256
    .line 257
    invoke-static {v0, v13, v3, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 258
    .line 259
    .line 260
    :goto_4
    move-object v0, v1

    .line 261
    check-cast v0, Ljava/util/Collection;

    .line 262
    .line 263
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 264
    .line 265
    .line 266
    move-result v0

    .line 267
    if-nez v0, :cond_8

    .line 268
    .line 269
    invoke-static {v1}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v0

    .line 273
    const-string v1, "first(...)"

    .line 274
    .line 275
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 276
    .line 277
    .line 278
    check-cast v0, Ljava/lang/Throwable;

    .line 279
    .line 280
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    return-object v0

    .line 285
    :cond_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 286
    .line 287
    return-object v0
.end method

.method public setClientManager(Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "+",
            "Ltechnology/cariad/cat/genx/ClientManager;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->clientManager:Ljava/util/List;

    .line 7
    .line 8
    return-void
.end method

.method public setReference(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->reference:J

    .line 2
    .line 3
    return-void
.end method

.method public startEncryptedKeyExchange(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/EncryptedKeyExchangeDelegate;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;)V
    .locals 7
    .annotation build Ltechnology/cariad/cat/genx/ExperimentalAPI;
    .end annotation

    .line 1
    const-string v0, "deviceType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "delegate"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "keyExchangeEncryptionCredentials"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "encryptionKeyType"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 22
    .line 23
    const-string v0, "GenX"

    .line 24
    .line 25
    if-nez v1, :cond_0

    .line 26
    .line 27
    sget-object p3, Ltechnology/cariad/cat/genx/GenXError$VehicleManagerAlreadyClosed;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$VehicleManagerAlreadyClosed;

    .line 28
    .line 29
    new-instance p4, Ltechnology/cariad/cat/genx/o0;

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    invoke-direct {p4, v1}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

    .line 33
    .line 34
    .line 35
    invoke-static {p0, v0, p3, p4}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 36
    .line 37
    .line 38
    invoke-interface {p2, p1, p3}, Ltechnology/cariad/cat/genx/EncryptedKeyExchangeDelegate;->onEncryptedKeyExchangeFailed(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/GenXError;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isLocationPermissionGranted()Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-nez v2, :cond_1

    .line 47
    .line 48
    sget-object p3, Ltechnology/cariad/cat/genx/GenXError$LocationPermissionNotGranted;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$LocationPermissionNotGranted;

    .line 49
    .line 50
    new-instance p4, Ltechnology/cariad/cat/genx/o0;

    .line 51
    .line 52
    const/4 v1, 0x1

    .line 53
    invoke-direct {p4, v1}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

    .line 54
    .line 55
    .line 56
    invoke-static {p0, v0, p3, p4}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 57
    .line 58
    .line 59
    invoke-interface {p2, p1, p3}, Ltechnology/cariad/cat/genx/EncryptedKeyExchangeDelegate;->onEncryptedKeyExchangeFailed(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/GenXError;)V

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :cond_1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isLocationEnabled()Lyy0/a2;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    invoke-interface {v2}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    check-cast v2, Ljava/lang/Boolean;

    .line 72
    .line 73
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 74
    .line 75
    .line 76
    move-result v2

    .line 77
    if-nez v2, :cond_2

    .line 78
    .line 79
    sget-object p3, Ltechnology/cariad/cat/genx/GenXError$LocationNotEnabled;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$LocationNotEnabled;

    .line 80
    .line 81
    new-instance p4, Ltechnology/cariad/cat/genx/o0;

    .line 82
    .line 83
    const/4 v1, 0x2

    .line 84
    invoke-direct {p4, v1}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

    .line 85
    .line 86
    .line 87
    invoke-static {p0, v0, p3, p4}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 88
    .line 89
    .line 90
    invoke-interface {p2, p1, p3}, Ltechnology/cariad/cat/genx/EncryptedKeyExchangeDelegate;->onEncryptedKeyExchangeFailed(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/GenXError;)V

    .line 91
    .line 92
    .line 93
    return-void

    .line 94
    :cond_2
    iget-object v6, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyPair:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 95
    .line 96
    move-object v2, p1

    .line 97
    move-object v5, p2

    .line 98
    move-object v3, p3

    .line 99
    move-object v4, p4

    .line 100
    invoke-virtual/range {v1 .. v6}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->startEncryptedKeyExchange(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;Ltechnology/cariad/cat/genx/EncryptedKeyExchangeDelegate;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)V

    .line 101
    .line 102
    .line 103
    return-void
.end method

.method public startKeyExchange(Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/QRKeyExchangeDelegate;)V
    .locals 4

    .line 1
    const-string v0, "qrCode"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "delegate"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyExchangeManager:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 12
    .line 13
    const-string v1, "GenX"

    .line 14
    .line 15
    if-eqz v0, :cond_3

    .line 16
    .line 17
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isVehicleManagerClosed()Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isLocationPermissionGranted()Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-nez v2, :cond_1

    .line 29
    .line 30
    sget-object v0, Ltechnology/cariad/cat/genx/GenXError$LocationPermissionNotGranted;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$LocationPermissionNotGranted;

    .line 31
    .line 32
    new-instance v2, Ltechnology/cariad/cat/genx/b0;

    .line 33
    .line 34
    const/16 v3, 0xc

    .line 35
    .line 36
    invoke-direct {v2, v3}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 37
    .line 38
    .line 39
    invoke-static {p0, v1, v0, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/QRCode;->getVin()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-interface {p2, p0, v0}, Ltechnology/cariad/cat/genx/QRKeyExchangeDelegate;->onKeyExchangeFailed(Ljava/lang/String;Ltechnology/cariad/cat/genx/GenXError;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isLocationEnabled()Lyy0/a2;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    invoke-interface {v2}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    check-cast v2, Ljava/lang/Boolean;

    .line 59
    .line 60
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    if-nez v2, :cond_2

    .line 65
    .line 66
    sget-object v0, Ltechnology/cariad/cat/genx/GenXError$LocationNotEnabled;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$LocationNotEnabled;

    .line 67
    .line 68
    new-instance v2, Ltechnology/cariad/cat/genx/b0;

    .line 69
    .line 70
    const/16 v3, 0xd

    .line 71
    .line 72
    invoke-direct {v2, v3}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 73
    .line 74
    .line 75
    invoke-static {p0, v1, v0, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/QRCode;->getVin()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-interface {p2, p0, v0}, Ltechnology/cariad/cat/genx/QRKeyExchangeDelegate;->onKeyExchangeFailed(Ljava/lang/String;Ltechnology/cariad/cat/genx/GenXError;)V

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    :cond_2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->keyPair:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 87
    .line 88
    invoke-virtual {v0, p1, p0, p2}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->startKeyExchange$genx_release(Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/QRKeyExchangeDelegate;)V

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :cond_3
    :goto_0
    sget-object v0, Ltechnology/cariad/cat/genx/GenXError$VehicleManagerAlreadyClosed;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$VehicleManagerAlreadyClosed;

    .line 93
    .line 94
    new-instance v2, Ltechnology/cariad/cat/genx/b0;

    .line 95
    .line 96
    const/16 v3, 0xb

    .line 97
    .line 98
    invoke-direct {v2, v3}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 99
    .line 100
    .line 101
    invoke-static {p0, v1, v0, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/QRCode;->getVin()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    invoke-interface {p2, p0, v0}, Ltechnology/cariad/cat/genx/QRKeyExchangeDelegate;->onKeyExchangeFailed(Ljava/lang/String;Ltechnology/cariad/cat/genx/GenXError;)V

    .line 109
    .line 110
    .line 111
    return-void
.end method

.method public startScanningForClients-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    instance-of v0, p1, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->label:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->label:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    const/4 v6, 0x0

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    iget-object p0, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->L$1:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Ltechnology/cariad/cat/genx/ScanningTokenImpl;

    .line 44
    .line 45
    iget-object p0, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->L$0:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, Lez0/a;

    .line 48
    .line 49
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    check-cast p1, Llx0/o;

    .line 53
    .line 54
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 55
    .line 56
    goto/16 :goto_3

    .line 57
    .line 58
    :catchall_0
    move-exception p1

    .line 59
    goto/16 :goto_4

    .line 60
    .line 61
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_2
    iget v2, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->I$0:I

    .line 70
    .line 71
    iget-object v7, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->L$0:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v7, Lez0/a;

    .line 74
    .line 75
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    move-object p1, v7

    .line 79
    goto :goto_1

    .line 80
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isVehicleManagerClosed()Z

    .line 84
    .line 85
    .line 86
    move-result p1

    .line 87
    if-eqz p1, :cond_4

    .line 88
    .line 89
    sget-object p1, Ltechnology/cariad/cat/genx/GenXError$VehicleManagerAlreadyClosed;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$VehicleManagerAlreadyClosed;

    .line 90
    .line 91
    new-instance v0, Ltechnology/cariad/cat/genx/b0;

    .line 92
    .line 93
    const/16 v1, 0x18

    .line 94
    .line 95
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/b0;-><init>(I)V

    .line 96
    .line 97
    .line 98
    const-string v1, "GenX"

    .line 99
    .line 100
    invoke-static {p0, v1, p1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 101
    .line 102
    .line 103
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0

    .line 108
    :cond_4
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->scanningMutex:Lez0/a;

    .line 109
    .line 110
    iput-object p1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->L$0:Ljava/lang/Object;

    .line 111
    .line 112
    iput v3, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->I$0:I

    .line 113
    .line 114
    iput v5, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->label:I

    .line 115
    .line 116
    invoke-interface {p1, v0}, Lez0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    if-ne v2, v1, :cond_5

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_5
    move v2, v3

    .line 124
    :goto_1
    :try_start_1
    new-instance v7, Ltechnology/cariad/cat/genx/ScanningTokenImpl;

    .line 125
    .line 126
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 127
    .line 128
    .line 129
    move-result-object v8

    .line 130
    const-string v9, "randomUUID(...)"

    .line 131
    .line 132
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    new-instance v9, Ljava/lang/ref/WeakReference;

    .line 136
    .line 137
    invoke-direct {v9, p0}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    invoke-direct {v7, v8, v9}, Ltechnology/cariad/cat/genx/ScanningTokenImpl;-><init>(Ljava/util/UUID;Ljava/lang/ref/WeakReference;)V

    .line 141
    .line 142
    .line 143
    iget-object v8, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->activeScanningTokens:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 144
    .line 145
    invoke-interface {v8}, Ljava/util/Collection;->isEmpty()Z

    .line 146
    .line 147
    .line 148
    move-result v8

    .line 149
    xor-int/2addr v5, v8

    .line 150
    iget-object v8, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 151
    .line 152
    new-instance v9, Lb71/o;

    .line 153
    .line 154
    const/4 v10, 0x5

    .line 155
    invoke-direct {v9, v5, p0, v7, v10}, Lb71/o;-><init>(ZLjava/lang/Object;Ljava/lang/Object;I)V

    .line 156
    .line 157
    .line 158
    iput-object p1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->L$0:Ljava/lang/Object;

    .line 159
    .line 160
    iput-object v6, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->L$1:Ljava/lang/Object;

    .line 161
    .line 162
    iput v2, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->I$0:I

    .line 163
    .line 164
    iput v3, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->I$1:I

    .line 165
    .line 166
    iput v5, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->I$2:I

    .line 167
    .line 168
    iput v4, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->label:I

    .line 169
    .line 170
    invoke-static {v8, v9, v0}, Ltechnology/cariad/cat/genx/GenXDispatcherKt;->dispatchSuspendedWithResult(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 174
    if-ne p0, v1, :cond_6

    .line 175
    .line 176
    :goto_2
    return-object v1

    .line 177
    :cond_6
    move-object v11, p1

    .line 178
    move-object p1, p0

    .line 179
    move-object p0, v11

    .line 180
    :goto_3
    invoke-interface {p0, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    return-object p1

    .line 184
    :catchall_1
    move-exception p0

    .line 185
    move-object v11, p1

    .line 186
    move-object p1, p0

    .line 187
    move-object p0, v11

    .line 188
    :goto_4
    invoke-interface {p0, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    throw p1
.end method

.method public final stopScanningForToken$genx_release(Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;)V
    .locals 2

    .line 1
    const-string v0, "token"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v0, p0, p1, v1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    const/4 p1, 0x3

    .line 13
    invoke-static {p0, v1, v1, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public unregisterAllVehicles-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    instance-of v0, p1, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterAllVehicles$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterAllVehicles$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterAllVehicles$1;->label:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterAllVehicles$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterAllVehicles$1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterAllVehicles$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterAllVehicles$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterAllVehicles$1;->label:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    check-cast p1, Llx0/o;

    .line 40
    .line 41
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isVehicleManagerClosed()Z

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    if-eqz p1, :cond_3

    .line 60
    .line 61
    sget-object p1, Ltechnology/cariad/cat/genx/GenXError$VehicleManagerAlreadyClosed;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$VehicleManagerAlreadyClosed;

    .line 62
    .line 63
    new-instance v0, Ltechnology/cariad/cat/genx/o0;

    .line 64
    .line 65
    const/4 v1, 0x4

    .line 66
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/o0;-><init>(I)V

    .line 67
    .line 68
    .line 69
    const-string v1, "GenX"

    .line 70
    .line 71
    invoke-static {p0, v1, p1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 72
    .line 73
    .line 74
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0

    .line 79
    :cond_3
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 80
    .line 81
    new-instance v2, Ltechnology/cariad/cat/genx/v0;

    .line 82
    .line 83
    const/16 v4, 0x9

    .line 84
    .line 85
    invoke-direct {v2, p0, v4}, Ltechnology/cariad/cat/genx/v0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)V

    .line 86
    .line 87
    .line 88
    iput v3, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterAllVehicles$1;->label:I

    .line 89
    .line 90
    invoke-static {p1, v2, v0}, Ltechnology/cariad/cat/genx/GenXDispatcherKt;->dispatchSuspendedWithResult(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    if-ne p0, v1, :cond_4

    .line 95
    .line 96
    return-object v1

    .line 97
    :cond_4
    return-object p0
.end method

.method public unregisterVehicle-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    instance-of v0, p2, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterVehicle$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterVehicle$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterVehicle$1;->label:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterVehicle$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterVehicle$1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterVehicle$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterVehicle$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterVehicle$1;->label:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterVehicle$1;->L$0:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Ljava/lang/String;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    check-cast p2, Llx0/o;

    .line 44
    .line 45
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 46
    .line 47
    return-object p0

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->isVehicleManagerClosed()Z

    .line 60
    .line 61
    .line 62
    move-result p2

    .line 63
    if-eqz p2, :cond_3

    .line 64
    .line 65
    sget-object p2, Ltechnology/cariad/cat/genx/GenXError$VehicleManagerAlreadyClosed;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$VehicleManagerAlreadyClosed;

    .line 66
    .line 67
    new-instance v0, Ltechnology/cariad/cat/genx/k;

    .line 68
    .line 69
    const/4 v1, 0x4

    .line 70
    invoke-direct {v0, p1, v1}, Ltechnology/cariad/cat/genx/k;-><init>(Ljava/lang/String;I)V

    .line 71
    .line 72
    .line 73
    const-string p1, "GenX"

    .line 74
    .line 75
    invoke-static {p0, p1, p2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 76
    .line 77
    .line 78
    invoke-static {p2}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0

    .line 83
    :cond_3
    iget-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 84
    .line 85
    new-instance v2, Ltechnology/cariad/cat/genx/k0;

    .line 86
    .line 87
    const/4 v4, 0x1

    .line 88
    invoke-direct {v2, p0, p1, v4}, Ltechnology/cariad/cat/genx/k0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;I)V

    .line 89
    .line 90
    .line 91
    const/4 p0, 0x0

    .line 92
    iput-object p0, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterVehicle$1;->L$0:Ljava/lang/Object;

    .line 93
    .line 94
    iput v3, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$unregisterVehicle$1;->label:I

    .line 95
    .line 96
    invoke-static {p2, v2, v0}, Ltechnology/cariad/cat/genx/GenXDispatcherKt;->dispatchSuspendedWithResult(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    if-ne p0, v1, :cond_4

    .line 101
    .line 102
    return-object v1

    .line 103
    :cond_4
    return-object p0
.end method

.method public vehicle(Ljava/lang/String;)Ltechnology/cariad/cat/genx/Vehicle;
    .locals 1

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehiclesLock:Ljava/util/concurrent/locks/ReentrantLock;

    .line 7
    .line 8
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 9
    .line 10
    .line 11
    :try_start_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->vehicles:Ljava/util/Map;

    .line 12
    .line 13
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Ltechnology/cariad/cat/genx/InternalVehicle;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    .line 19
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 20
    .line 21
    .line 22
    return-object p0

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 25
    .line 26
    .line 27
    throw p0
.end method
