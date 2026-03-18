.class public final Ltechnology/cariad/cat/genx/protocol/AddressKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001a\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0000\u001a\u000c\u0010\u0004\u001a\u00020\u0005*\u00020\u0006H\u0000\u001a\u000c\u0010\u0007\u001a\u00020\u0008*\u00020\u0006H\u0000\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0082T\u00a2\u0006\u0002\n\u0000\"\u000e\u0010\u0002\u001a\u00020\u0001X\u0082T\u00a2\u0006\u0002\n\u0000\"\u000e\u0010\u0003\u001a\u00020\u0001X\u0082T\u00a2\u0006\u0002\n\u0000\u00a8\u0006\t"
    }
    d2 = {
        "GLOBAL_SERVICE_ID_SHIFT",
        "",
        "GLOBAL_MESSAGE_ID_SHIFT",
        "METADATA_SHIFT",
        "toHexString",
        "",
        "",
        "toAddress",
        "Ltechnology/cariad/cat/genx/protocol/Address;",
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


# static fields
.field private static final GLOBAL_MESSAGE_ID_SHIFT:I = 0x20

.field private static final GLOBAL_SERVICE_ID_SHIFT:I = 0x28

.field private static final METADATA_SHIFT:I = 0x18


# direct methods
.method public static final toAddress(J)Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 7

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 2
    .line 3
    const/16 v1, 0x38

    .line 4
    .line 5
    shr-long v1, p0, v1

    .line 6
    .line 7
    const-wide/16 v3, 0xff

    .line 8
    .line 9
    and-long/2addr v1, v3

    .line 10
    long-to-int v1, v1

    .line 11
    int-to-byte v1, v1

    .line 12
    const/16 v2, 0x30

    .line 13
    .line 14
    shr-long v5, p0, v2

    .line 15
    .line 16
    and-long/2addr v5, v3

    .line 17
    long-to-int v2, v5

    .line 18
    int-to-byte v2, v2

    .line 19
    const/16 v5, 0x28

    .line 20
    .line 21
    shr-long v5, p0, v5

    .line 22
    .line 23
    and-long/2addr v5, v3

    .line 24
    long-to-int v5, v5

    .line 25
    int-to-byte v5, v5

    .line 26
    const/4 v6, 0x0

    .line 27
    invoke-direct {v0, v1, v2, v5, v6}, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;-><init>(BBBLkotlin/jvm/internal/g;)V

    .line 28
    .line 29
    .line 30
    const/16 v1, 0x20

    .line 31
    .line 32
    shr-long v1, p0, v1

    .line 33
    .line 34
    and-long/2addr v1, v3

    .line 35
    long-to-int v1, v1

    .line 36
    int-to-byte v1, v1

    .line 37
    sget-object v2, Ltechnology/cariad/cat/genx/protocol/AddressDirection;->Companion:Ltechnology/cariad/cat/genx/protocol/AddressDirection$Companion;

    .line 38
    .line 39
    const/16 v5, 0x18

    .line 40
    .line 41
    shr-long/2addr p0, v5

    .line 42
    and-long/2addr p0, v3

    .line 43
    long-to-int p0, p0

    .line 44
    int-to-byte p0, p0

    .line 45
    invoke-virtual {v2, p0}, Ltechnology/cariad/cat/genx/protocol/AddressDirection$Companion;->asAddressDirection-7apg3OU(B)Ltechnology/cariad/cat/genx/protocol/AddressDirection;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    new-instance p1, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 50
    .line 51
    invoke-direct {p1, v0, v1, p0, v6}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 52
    .line 53
    .line 54
    return-object p1
.end method

.method public static final toHexString(J)Ljava/lang/String;
    .locals 1

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    invoke-static {v0}, Lry/a;->a(I)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1, v0}, Ljava/lang/Long;->toString(JI)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    const-string p1, "toString(...)"

    .line 11
    .line 12
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string p1, "0x"

    .line 16
    .line 17
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
