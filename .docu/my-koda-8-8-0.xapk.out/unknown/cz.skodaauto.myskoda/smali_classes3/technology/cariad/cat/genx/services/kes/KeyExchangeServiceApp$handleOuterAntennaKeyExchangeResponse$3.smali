.class final Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleOuterAntennaKeyExchangeResponse([BLjava/lang/String;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lrx0/i;",
        "Lay0/n;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0002\u0010\u0003"
    }
    d2 = {
        "Lvy0/b0;",
        "Llx0/b0;",
        "<anonymous>",
        "(Lvy0/b0;)V"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.services.kes.KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3"
    f = "KeyExchangeServiceApp.kt"
    l = {
        0x142
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $response:Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;",
            "Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->$response:Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->invokeSuspend$lambda$0(Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->invokeSuspend$lambda$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final invokeSuspend$lambda$0(Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;->getOuterAntennaLAMSecret()[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "handleOuterAntennaKeyExchangeResponse(): \'outerAntennaVehicleKeysInfoResponse\': QPM1 required, creating QPM1 with TransceiverSecret: "

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method private static final invokeSuspend$lambda$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "handleOuterAntennaKeyExchangeResponse(): Cannot calculate QPM1 therefore fail KES"

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Object;",
            "Lkotlin/coroutines/Continuation<",
            "*>;)",
            "Lkotlin/coroutines/Continuation<",
            "Llx0/b0;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 4
    .line 5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->$response:Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->L$0:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lvy0/b0;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->label:I

    .line 8
    .line 9
    const/4 v3, 0x1

    .line 10
    const/4 v4, 0x0

    .line 11
    if-eqz v2, :cond_1

    .line 12
    .line 13
    if-ne v2, v3, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->$response:Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;

    .line 31
    .line 32
    new-instance v8, Ltechnology/cariad/cat/genx/services/kes/e;

    .line 33
    .line 34
    const/4 v2, 0x0

    .line 35
    invoke-direct {v8, p1, v2}, Ltechnology/cariad/cat/genx/services/kes/e;-><init>(Ljava/lang/Object;I)V

    .line 36
    .line 37
    .line 38
    new-instance v5, Lt51/j;

    .line 39
    .line 40
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v10

    .line 44
    const-string p1, "getName(...)"

    .line 45
    .line 46
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v11

    .line 50
    const-string v6, "GenX"

    .line 51
    .line 52
    sget-object v7, Lt51/d;->a:Lt51/d;

    .line 53
    .line 54
    const/4 v9, 0x0

    .line 55
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 59
    .line 60
    .line 61
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 62
    .line 63
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->getVehicle()Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/InternalVehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    if-eqz p1, :cond_3

    .line 72
    .line 73
    iget-object v2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->$response:Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;

    .line 74
    .line 75
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;->getOuterAntennaLAMSecret()[B

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    iput-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->L$0:Ljava/lang/Object;

    .line 80
    .line 81
    iput v3, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->label:I

    .line 82
    .line 83
    invoke-interface {p1, v2, p0}, Ltechnology/cariad/cat/genx/InternalVehicleAntenna;->calculateQPM1([BLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    if-ne p1, v1, :cond_2

    .line 88
    .line 89
    return-object v1

    .line 90
    :cond_2
    :goto_0
    check-cast p1, [B

    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_3
    move-object p1, v4

    .line 94
    :goto_1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 95
    .line 96
    if-eqz p1, :cond_4

    .line 97
    .line 98
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$sendQPM1(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;[B)V

    .line 99
    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_4
    new-instance p1, Ltechnology/cariad/cat/genx/services/kes/f;

    .line 103
    .line 104
    const/4 v1, 0x0

    .line 105
    invoke-direct {p1, v1}, Ltechnology/cariad/cat/genx/services/kes/f;-><init>(I)V

    .line 106
    .line 107
    .line 108
    const-string v1, "GenX"

    .line 109
    .line 110
    invoke-static {v0, v1, v4, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 111
    .line 112
    .line 113
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$get_result$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Lyy0/j1;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    new-instance p1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;

    .line 118
    .line 119
    sget-object v0, Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;

    .line 120
    .line 121
    invoke-direct {p1, v0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;-><init>(Ltechnology/cariad/cat/genx/GenXError;)V

    .line 122
    .line 123
    .line 124
    check-cast p0, Lyy0/c2;

    .line 125
    .line 126
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 127
    .line 128
    .line 129
    invoke-virtual {p0, v4, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 133
    .line 134
    return-object p0
.end method
