.class public final Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


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
        "Lrx0/i;",
        "Lay0/o;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0011\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0006\u001a\u00020\u0005\"\u0004\u0008\u0000\u0010\u0000\"\u0006\u0008\u0001\u0010\u0001\u0018\u0001*\u0008\u0012\u0004\u0012\u00028\u00000\u00022\u000c\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00028\u00010\u0003H\n\u00a2\u0006\u0004\u0008\u0006\u0010\u0007"
    }
    d2 = {
        "R",
        "T",
        "Lyy0/j;",
        "",
        "it",
        "Llx0/b0;",
        "<anonymous>",
        "(Lyy0/j;Lkotlin/Array;)V"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3"
    f = "VehicleAntennaImpl.kt"
    l = {
        0x120
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field private synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/VehicleAntennaImpl;


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)V
    .locals 0

    .line 1
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaImpl;

    .line 2
    .line 3
    const/4 p2, 0x3

    .line 4
    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lyy0/j;

    check-cast p2, [Ljava/lang/Object;

    check-cast p3, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->invoke(Lyy0/j;[Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Lyy0/j;[Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lyy0/j;",
            "[",
            "Ltechnology/cariad/cat/genx/Reachability;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;

    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaImpl;

    invoke-direct {v0, p3, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;-><init>(Lkotlin/coroutines/Continuation;Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)V

    iput-object p1, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->L$1:Ljava/lang/Object;

    sget-object p0, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->label:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    if-ne v1, v3, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->L$1:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v0, [Ljava/lang/Object;

    .line 15
    .line 16
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->L$0:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lyy0/j;

    .line 19
    .line 20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    goto :goto_2

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->L$0:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p1, Lyy0/j;

    .line 38
    .line 39
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->L$1:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v1, [Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v1, [Ltechnology/cariad/cat/genx/Reachability;

    .line 44
    .line 45
    array-length v4, v1

    .line 46
    const/4 v5, 0x0

    .line 47
    :goto_0
    if-ge v5, v4, :cond_4

    .line 48
    .line 49
    aget-object v6, v1, v5

    .line 50
    .line 51
    sget-object v7, Ltechnology/cariad/cat/genx/Reachability;->REACHABLE:Ltechnology/cariad/cat/genx/Reachability;

    .line 52
    .line 53
    if-ne v6, v7, :cond_3

    .line 54
    .line 55
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaImpl;

    .line 56
    .line 57
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getReachability()Lyy0/j1;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    :cond_2
    move-object v1, v6

    .line 62
    check-cast v1, Lyy0/c2;

    .line 63
    .line 64
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    move-object v5, v4

    .line 69
    check-cast v5, Ltechnology/cariad/cat/genx/Reachability;

    .line 70
    .line 71
    sget-object v5, Ltechnology/cariad/cat/genx/Reachability;->REACHABLE:Ltechnology/cariad/cat/genx/Reachability;

    .line 72
    .line 73
    invoke-virtual {v1, v4, v5}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    if-eqz v1, :cond_2

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_3
    add-int/lit8 v5, v5, 0x1

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_4
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaImpl;

    .line 84
    .line 85
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getReachability()Lyy0/j1;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    :cond_5
    move-object v4, v1

    .line 90
    check-cast v4, Lyy0/c2;

    .line 91
    .line 92
    invoke-virtual {v4}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v5

    .line 96
    move-object v6, v5

    .line 97
    check-cast v6, Ltechnology/cariad/cat/genx/Reachability;

    .line 98
    .line 99
    sget-object v6, Ltechnology/cariad/cat/genx/Reachability;->UNREACHABLE:Ltechnology/cariad/cat/genx/Reachability;

    .line 100
    .line 101
    invoke-virtual {v4, v5, v6}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v4

    .line 105
    if-eqz v4, :cond_5

    .line 106
    .line 107
    :goto_1
    const/4 v1, 0x0

    .line 108
    iput-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->L$0:Ljava/lang/Object;

    .line 109
    .line 110
    iput-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->L$1:Ljava/lang/Object;

    .line 111
    .line 112
    iput v3, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1$invokeSuspend$$inlined$combine$1$3;->label:I

    .line 113
    .line 114
    invoke-interface {p1, v2, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    if-ne p0, v0, :cond_6

    .line 119
    .line 120
    return-object v0

    .line 121
    :cond_6
    :goto_2
    return-object v2
.end method
