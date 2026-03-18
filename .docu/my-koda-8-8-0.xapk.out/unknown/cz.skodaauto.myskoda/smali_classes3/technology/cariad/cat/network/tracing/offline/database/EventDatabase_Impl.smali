.class public final Ltechnology/cariad/cat/network/tracing/offline/database/EventDatabase_Impl;
.super Ltechnology/cariad/cat/network/tracing/offline/database/EventDatabase;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\u0004"
    }
    d2 = {
        "Ltechnology/cariad/cat/network/tracing/offline/database/EventDatabase_Impl;",
        "Ltechnology/cariad/cat/network/tracing/offline/database/EventDatabase;",
        "<init>",
        "()V",
        "network_release"
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
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/network/tracing/offline/database/EventDatabase;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lay/b;

    .line 5
    .line 6
    invoke-direct {v0, p0}, Lay/b;-><init>(Ltechnology/cariad/cat/network/tracing/offline/database/EventDatabase_Impl;)V

    .line 7
    .line 8
    .line 9
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final d(Ljava/util/LinkedHashMap;)Ljava/util/List;
    .locals 0

    .line 1
    new-instance p0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final e()Lla/h;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/util/LinkedHashMap;

    .line 7
    .line 8
    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 9
    .line 10
    .line 11
    new-instance v2, Lla/h;

    .line 12
    .line 13
    const-string v3, "event"

    .line 14
    .line 15
    filled-new-array {v3}, [Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    invoke-direct {v2, p0, v0, v1, v3}, Lla/h;-><init>(Lla/u;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;[Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    return-object v2
.end method

.method public final f()Lka/u;
    .locals 1

    .line 1
    new-instance v0, Lb61/a;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lb61/a;-><init>(Ltechnology/cariad/cat/network/tracing/offline/database/EventDatabase_Impl;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final j()Ljava/util/Set;
    .locals 0

    .line 1
    new-instance p0, Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final k()Ljava/util/LinkedHashMap;
    .locals 2

    .line 1
    new-instance p0, Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    const-class v0, La61/a;

    .line 7
    .line 8
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 9
    .line 10
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 15
    .line 16
    invoke-interface {p0, v0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    return-object p0
.end method
