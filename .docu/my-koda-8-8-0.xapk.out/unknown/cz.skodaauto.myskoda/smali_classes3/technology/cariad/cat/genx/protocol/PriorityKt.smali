.class public final Ltechnology/cariad/cat/genx/protocol/PriorityKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0005\n\u0000\u001a\u000c\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0000\u00a8\u0006\u0003"
    }
    d2 = {
        "toPriority",
        "Ltechnology/cariad/cat/genx/protocol/Priority;",
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
.method public static final toPriority(B)Ltechnology/cariad/cat/genx/protocol/Priority;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, v0, :cond_0

    .line 3
    .line 4
    sget-object p0, Ltechnology/cariad/cat/genx/protocol/Priority;->MIDDLE:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 5
    .line 6
    return-object p0

    .line 7
    :cond_0
    const/4 v0, 0x2

    .line 8
    if-ne p0, v0, :cond_1

    .line 9
    .line 10
    sget-object p0, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_1
    const/4 v0, 0x3

    .line 14
    if-ne p0, v0, :cond_2

    .line 15
    .line 16
    sget-object p0, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGHEST:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_2
    sget-object p0, Ltechnology/cariad/cat/genx/protocol/Priority;->LOW:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 20
    .line 21
    return-object p0
.end method
