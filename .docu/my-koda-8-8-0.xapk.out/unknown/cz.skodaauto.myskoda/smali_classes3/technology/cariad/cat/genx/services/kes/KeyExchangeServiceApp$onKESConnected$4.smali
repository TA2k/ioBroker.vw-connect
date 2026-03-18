.class final Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->onKESConnected(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)V
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
    c = "technology.cariad.cat.genx.services.kes.KeyExchangeServiceApp$onKESConnected$4"
    f = "KeyExchangeServiceApp.kt"
    l = {
        0xdc
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $connection:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

.field final synthetic $transport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleAntennaTransport;",
            "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;",
            "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->$transport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->$connection:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->invokeSuspend$lambda$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->invokeSuspend$lambda$1(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final invokeSuspend$lambda$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->getVehicle()Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/Vehicle;->getVin()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "onKESConnected(): KeyExchangeService is available on vehicle "

    .line 10
    .line 11
    const-string v1, " -> Request \'StaticInformation\'"

    .line 12
    .line 13
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method private static final invokeSuspend$lambda$1(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->getVehicle()Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/Vehicle;->getVin()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "onKESConnected(): KeyExchangeService is not available on vehicle "

    .line 10
    .line 11
    const-string v1, " -> close connection and notify KES completed"

    .line 12
    .line 13
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3
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
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->$transport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->$connection:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 8
    .line 9
    invoke-direct {v0, v1, v2, p0, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->L$0:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->label:I

    .line 8
    .line 9
    const/4 v3, 0x1

    .line 10
    if-eqz v2, :cond_1

    .line 11
    .line 12
    if-ne v2, v3, :cond_0

    .line 13
    .line 14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 21
    .line 22
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->$transport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 30
    .line 31
    sget-object v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->Companion:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;

    .line 32
    .line 33
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;->getSTATIC_INFO_REQUEST()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    iput-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->L$0:Ljava/lang/Object;

    .line 38
    .line 39
    iput v3, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->label:I

    .line 40
    .line 41
    invoke-interface {p1, v2, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->isAddressRegistered(Ltechnology/cariad/cat/genx/protocol/Address;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    if-ne p1, v1, :cond_2

    .line 46
    .line 47
    return-object v1

    .line 48
    :cond_2
    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    .line 49
    .line 50
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    const-string v1, "getName(...)"

    .line 55
    .line 56
    sget-object v4, Lt51/g;->a:Lt51/g;

    .line 57
    .line 58
    if-eqz p1, :cond_3

    .line 59
    .line 60
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 61
    .line 62
    new-instance v5, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 63
    .line 64
    const/4 v2, 0x0

    .line 65
    invoke-direct {v5, p1, v2}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 66
    .line 67
    .line 68
    new-instance v2, Lt51/j;

    .line 69
    .line 70
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v8

    .line 78
    const-string v3, "GenX"

    .line 79
    .line 80
    const/4 v6, 0x0

    .line 81
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 85
    .line 86
    .line 87
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 88
    .line 89
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$sendStaticInformationRequest(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)V

    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_3
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 94
    .line 95
    new-instance v5, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 96
    .line 97
    const/4 v2, 0x1

    .line 98
    invoke-direct {v5, p1, v2}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 99
    .line 100
    .line 101
    new-instance v2, Lt51/j;

    .line 102
    .line 103
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v7

    .line 107
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v8

    .line 111
    const-string v3, "GenX"

    .line 112
    .line 113
    const/4 v6, 0x0

    .line 114
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 118
    .line 119
    .line 120
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 121
    .line 122
    invoke-static {p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$get_result$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Lyy0/j1;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$NoOuterPairingRequired;->INSTANCE:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$NoOuterPairingRequired;

    .line 127
    .line 128
    check-cast p1, Lyy0/c2;

    .line 129
    .line 130
    invoke-virtual {p1, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;->$connection:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 134
    .line 135
    invoke-interface {p0}, Ljava/io/Closeable;->close()V

    .line 136
    .line 137
    .line 138
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 139
    .line 140
    return-object p0
.end method
