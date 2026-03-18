.class public final Landroidx/datastore/core/NativeSharedCounter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0010\t\n\u0002\u0008\u0007\u0008\u0000\u0018\u00002\u00020\u0001J\u0018\u0010\u0004\u001a\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0002H\u0086 \u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u0018\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u0002H\u0086 \u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u0018\u0010\n\u001a\u00020\u00022\u0006\u0010\t\u001a\u00020\u0006H\u0086 \u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u0018\u0010\u000c\u001a\u00020\u00022\u0006\u0010\t\u001a\u00020\u0006H\u0086 \u00a2\u0006\u0004\u0008\u000c\u0010\u000b\u00a8\u0006\r"
    }
    d2 = {
        "Landroidx/datastore/core/NativeSharedCounter;",
        "",
        "",
        "fd",
        "nativeTruncateFile",
        "(I)I",
        "",
        "nativeCreateSharedCounter",
        "(I)J",
        "address",
        "nativeGetCounterValue",
        "(J)I",
        "nativeIncrementAndGetCounterValue",
        "datastore-core_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# virtual methods
.method public final native nativeCreateSharedCounter(I)J
.end method

.method public final native nativeGetCounterValue(J)I
.end method

.method public final native nativeIncrementAndGetCounterValue(J)I
.end method

.method public final native nativeTruncateFile(I)I
.end method
