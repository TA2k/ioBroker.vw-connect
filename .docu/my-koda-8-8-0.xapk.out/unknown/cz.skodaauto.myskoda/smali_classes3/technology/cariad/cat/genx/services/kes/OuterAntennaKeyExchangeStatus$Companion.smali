.class public final Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0012\n\u0000\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0010\u0010\u0006\u001a\u0004\u0018\u00010\u00072\u0006\u0010\u0008\u001a\u00020\tR\u000e\u0010\u0004\u001a\u00020\u0005X\u0086T\u00a2\u0006\u0002\n\u0000\u00a8\u0006\n"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus$Companion;",
        "",
        "<init>",
        "()V",
        "EXPECTED_SIZE",
        "",
        "fromBytes",
        "Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;",
        "byteArray",
        "",
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


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final fromBytes([B)Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;
    .locals 4

    .line 1
    const-string p0, "byteArray"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->getEntries()Lsx0/a;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    const/4 v1, 0x0

    .line 19
    if-eqz v0, :cond_2

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    move-object v2, v0

    .line 26
    check-cast v2, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 27
    .line 28
    array-length v3, p1

    .line 29
    if-nez v3, :cond_1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    const/4 v1, 0x0

    .line 33
    aget-byte v1, p1, v1

    .line 34
    .line 35
    invoke-static {v1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    :goto_0
    if-eqz v1, :cond_0

    .line 40
    .line 41
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->getByte()B

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    invoke-virtual {v1}, Ljava/lang/Byte;->byteValue()B

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-ne v2, v1, :cond_0

    .line 50
    .line 51
    move-object v1, v0

    .line 52
    :cond_2
    check-cast v1, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 53
    .line 54
    return-object v1
.end method
