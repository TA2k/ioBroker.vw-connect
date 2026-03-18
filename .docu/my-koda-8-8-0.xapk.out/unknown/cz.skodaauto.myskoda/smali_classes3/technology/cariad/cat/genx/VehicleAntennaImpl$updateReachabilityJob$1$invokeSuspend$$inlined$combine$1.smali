.class public final Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lyy0/i;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0017\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003*\u0001\u0000\u0008\n\u0018\u00002\u0008\u0012\u0004\u0012\u00028\u00000\u0001J\u001e\u0010\u0005\u001a\u00020\u00042\u000c\u0010\u0003\u001a\u0008\u0012\u0004\u0012\u00028\u00000\u0002H\u0096@\u00a2\u0006\u0004\u0008\u0005\u0010\u0006\u00a8\u0006\u0007"
    }
    d2 = {
        "kotlinx/coroutines/flow/internal/SafeCollector_commonKt$unsafeFlow$1",
        "Lyy0/i;",
        "Lyy0/j;",
        "collector",
        "Llx0/b0;",
        "collect",
        "(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "kotlinx-coroutines-core"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field final synthetic $flowArray$inlined:[Lyy0/i;

.field final synthetic this$0:Ltechnology/cariad/cat/genx/VehicleAntennaImpl;


# direct methods
.method public constructor <init>([Lyy0/i;Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1;->$flowArray$inlined:[Lyy0/i;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaImpl;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1;->$flowArray$inlined:[Lyy0/i;

    .line 2
    .line 3
    new-instance v1, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$2;

    .line 4
    .line 5
    invoke-direct {v1, v0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$2;-><init>([Lyy0/i;)V

    .line 6
    .line 7
    .line 8
    new-instance v2, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaImpl;

    .line 12
    .line 13
    invoke-direct {v2, v3, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;-><init>(Lkotlin/coroutines/Continuation;Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)V

    .line 14
    .line 15
    .line 16
    invoke-static {v1, v2, p2, p1, v0}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    if-ne p0, p1, :cond_0

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0
.end method
