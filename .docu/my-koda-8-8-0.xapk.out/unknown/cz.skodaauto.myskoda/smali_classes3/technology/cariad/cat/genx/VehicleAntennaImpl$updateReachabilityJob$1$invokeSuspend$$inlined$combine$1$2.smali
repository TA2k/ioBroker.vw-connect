.class public final Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lay0/a;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field final synthetic $flowArray:[Lyy0/i;


# direct methods
.method public constructor <init>([Lyy0/i;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$2;->$flowArray:[Lyy0/i;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$2;->invoke()[Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke()[Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()[",
            "Ltechnology/cariad/cat/genx/Reachability;"
        }
    .end annotation

    .line 2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$2;->$flowArray:[Lyy0/i;

    array-length p0, p0

    new-array p0, p0, [Ltechnology/cariad/cat/genx/Reachability;

    return-object p0
.end method
