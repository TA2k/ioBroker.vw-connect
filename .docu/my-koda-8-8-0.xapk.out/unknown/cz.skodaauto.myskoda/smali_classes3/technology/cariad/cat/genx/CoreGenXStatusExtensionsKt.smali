.class public final Ltechnology/cariad/cat/genx/CoreGenXStatusExtensionsKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0000\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\u001a\u000c\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0000\u001a\u0011\u0010\u0003\u001a\u00020\u00012\u0006\u0010\u0004\u001a\u00020\u0005H\u0082 \u00a8\u0006\u0006"
    }
    d2 = {
        "loadLastStatusMessage",
        "",
        "Ltechnology/cariad/cat/genx/CoreGenXStatus;",
        "nativeGetLastStatusMessage",
        "cgxStatus",
        "",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final loadLastStatusMessage(Ltechnology/cariad/cat/genx/CoreGenXStatus;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatusExtensionsKt;->nativeGetLastStatusMessage(I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method private static final native nativeGetLastStatusMessage(I)Ljava/lang/String;
.end method
