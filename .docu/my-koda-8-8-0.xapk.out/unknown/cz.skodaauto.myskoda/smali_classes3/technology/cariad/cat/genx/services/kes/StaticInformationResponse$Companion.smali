.class public final Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;
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
        "Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse$Companion;",
        "",
        "<init>",
        "()V",
        "EXPECTED_SIZE",
        "",
        "fromBytes",
        "Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final fromBytes([B)Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;
    .locals 3

    .line 1
    const-string p0, "byteArray"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length p0, p1

    .line 7
    const/4 v0, 0x5

    .line 8
    if-ge p0, v0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;

    .line 13
    .line 14
    const/4 v0, 0x3

    .line 15
    invoke-static {v0, p1}, Lmx0/n;->U(I[B)Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Ljava/util/Collection;

    .line 20
    .line 21
    invoke-static {v1}, Lmx0/q;->t0(Ljava/util/Collection;)[B

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    aget-byte v0, p1, v0

    .line 26
    .line 27
    const/4 v2, 0x4

    .line 28
    aget-byte p1, p1, v2

    .line 29
    .line 30
    const/4 v2, 0x1

    .line 31
    if-ne p1, v2, :cond_1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    const/4 v2, 0x0

    .line 35
    :goto_0
    invoke-direct {p0, v1, v0, v2}, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;-><init>([BBZ)V

    .line 36
    .line 37
    .line 38
    return-object p0
.end method
