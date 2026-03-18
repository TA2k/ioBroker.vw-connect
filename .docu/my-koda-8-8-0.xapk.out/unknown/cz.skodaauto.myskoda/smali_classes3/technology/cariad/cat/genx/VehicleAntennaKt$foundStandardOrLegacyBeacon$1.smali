.class final Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getFoundStandardOrLegacyBeacon(Ltechnology/cariad/cat/genx/VehicleAntenna;)Lyy0/i;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lrx0/i;",
        "Lay0/o;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0010\u0003\u001a\u0004\u0018\u00010\u00002\u0008\u0010\u0001\u001a\u0004\u0018\u00010\u00002\u0008\u0010\u0002\u001a\u0004\u0018\u00010\u0000H\n\u00a2\u0006\u0004\u0008\u0003\u0010\u0004"
    }
    d2 = {
        "Lt41/g;",
        "legacy",
        "standard",
        "<anonymous>",
        "(Lt41/g;Lt41/g;)Lt41/g;"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.VehicleAntennaKt$foundStandardOrLegacyBeacon$1"
    f = "VehicleAntenna.kt"
    l = {}
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;",
            ">;)V"
        }
    .end annotation

    .line 1
    const/4 v0, 0x3

    .line 2
    invoke-direct {p0, v0, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lt41/g;

    check-cast p2, Lt41/g;

    check-cast p3, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;->invoke(Lt41/g;Lt41/g;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Lt41/g;Lt41/g;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lt41/g;",
            "Lt41/g;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lt41/g;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    new-instance p0, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;

    invoke-direct {p0, p3}, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;-><init>(Lkotlin/coroutines/Continuation;)V

    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;->L$0:Ljava/lang/Object;

    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;->L$1:Ljava/lang/Object;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lt41/g;

    .line 4
    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;->L$1:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lt41/g;

    .line 8
    .line 9
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 10
    .line 11
    iget p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaKt$foundStandardOrLegacyBeacon$1;->label:I

    .line 12
    .line 13
    if-nez p0, :cond_1

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    if-nez v1, :cond_0

    .line 19
    .line 20
    return-object v0

    .line 21
    :cond_0
    return-object v1

    .line 22
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0
.end method
