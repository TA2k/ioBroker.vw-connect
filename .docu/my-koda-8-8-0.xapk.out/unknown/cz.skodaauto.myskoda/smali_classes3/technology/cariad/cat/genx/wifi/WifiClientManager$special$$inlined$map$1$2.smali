.class public final Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lyy0/j;"
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
.field final synthetic $this_unsafeFlow:Lyy0/j;

.field final synthetic this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;


# direct methods
.method public constructor <init>(Lyy0/j;Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2;->$this_unsafeFlow:Lyy0/j;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p2, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;->label:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;->label:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;->L$3:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Lyy0/j;

    .line 39
    .line 40
    iget-object p0, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;->L$1:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;

    .line 43
    .line 44
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2;->$this_unsafeFlow:Lyy0/j;

    .line 60
    .line 61
    check-cast p1, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 62
    .line 63
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 64
    .line 65
    new-instance v7, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$2$1;

    .line 66
    .line 67
    invoke-direct {v7, p1}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$2$1;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;)V

    .line 68
    .line 69
    .line 70
    new-instance v4, Lt51/j;

    .line 71
    .line 72
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v9

    .line 76
    const-string p0, "getName(...)"

    .line 77
    .line 78
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v10

    .line 82
    const-string v5, "GenX"

    .line 83
    .line 84
    sget-object v6, Lt51/g;->a:Lt51/g;

    .line 85
    .line 86
    const/4 v8, 0x0

    .line 87
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 91
    .line 92
    .line 93
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->ENABLED:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 94
    .line 95
    const/4 v2, 0x0

    .line 96
    if-ne p1, p0, :cond_3

    .line 97
    .line 98
    move p0, v3

    .line 99
    goto :goto_1

    .line 100
    :cond_3
    move p0, v2

    .line 101
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    const/4 p1, 0x0

    .line 106
    iput-object p1, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;->L$0:Ljava/lang/Object;

    .line 107
    .line 108
    iput-object p1, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;->L$1:Ljava/lang/Object;

    .line 109
    .line 110
    iput-object p1, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;->L$2:Ljava/lang/Object;

    .line 111
    .line 112
    iput-object p1, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;->L$3:Ljava/lang/Object;

    .line 113
    .line 114
    iput v2, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;->I$0:I

    .line 115
    .line 116
    iput v3, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1$2$1;->label:I

    .line 117
    .line 118
    invoke-interface {p2, p0, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    if-ne p0, v1, :cond_4

    .line 123
    .line 124
    return-object v1

    .line 125
    :cond_4
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 126
    .line 127
    return-object p0
.end method
