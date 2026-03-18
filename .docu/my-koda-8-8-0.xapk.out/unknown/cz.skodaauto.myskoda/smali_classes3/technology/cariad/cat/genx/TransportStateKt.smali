.class public final Ltechnology/cariad/cat/genx/TransportStateKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0000\u001a\n\u0010\u0005\u001a\u00020\u0006*\u00020\u0001\"\u0018\u0010\u0000\u001a\u00020\u0001*\u00020\u00028@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0003\u0010\u0004\u00a8\u0006\u0007"
    }
    d2 = {
        "transportState",
        "Ltechnology/cariad/cat/genx/TransportState;",
        "",
        "getTransportState",
        "(I)Ltechnology/cariad/cat/genx/TransportState;",
        "isConnectAllowed",
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
.method public static final getTransportState(I)Ltechnology/cariad/cat/genx/TransportState;
    .locals 3

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/TransportState;->getEntries()Lsx0/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Ltechnology/cariad/cat/genx/TransportState;

    .line 20
    .line 21
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/TransportState;->getCgxValue$genx_release()I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-ne v2, p0, :cond_0

    .line 26
    .line 27
    return-object v1

    .line 28
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 29
    .line 30
    const-string v0, "Collection contains no element matching the predicate."

    .line 31
    .line 32
    invoke-direct {p0, v0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw p0
.end method

.method public static final isConnectAllowed(Ltechnology/cariad/cat/genx/TransportState;)Z
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ltechnology/cariad/cat/genx/TransportState;->DISCONNECTED:Ltechnology/cariad/cat/genx/TransportState;

    .line 7
    .line 8
    sget-object v1, Ltechnology/cariad/cat/genx/TransportState;->CONNECTED:Ltechnology/cariad/cat/genx/TransportState;

    .line 9
    .line 10
    sget-object v2, Ltechnology/cariad/cat/genx/TransportState;->CONNECTING:Ltechnology/cariad/cat/genx/TransportState;

    .line 11
    .line 12
    filled-new-array {v0, v1, v2}, [Ltechnology/cariad/cat/genx/TransportState;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-interface {v0, p0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0
.end method
