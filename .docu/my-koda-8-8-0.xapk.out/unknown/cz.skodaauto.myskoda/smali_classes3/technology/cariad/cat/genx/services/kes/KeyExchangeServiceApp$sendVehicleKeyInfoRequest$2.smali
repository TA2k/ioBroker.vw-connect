.class final Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendVehicleKeyInfoRequest()V
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
    c = "technology.cariad.cat.genx.services.kes.KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2"
    f = "KeyExchangeServiceApp.kt"
    l = {
        0x20a
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field I$0:I

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->invokeSuspend$lambda$0$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final invokeSuspend$lambda$0$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getVin$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "sendVehicleKeyInfoRequest(): Failed to send message - "

    .line 6
    .line 7
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1
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
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iput-object p1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->L$0:Ljava/lang/Object;

    .line 9
    .line 10
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->label:I

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x1

    .line 11
    if-eqz v2, :cond_1

    .line 12
    .line 13
    if-ne v2, v4, :cond_0

    .line 14
    .line 15
    iget-object v1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->L$2:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 18
    .line 19
    iget-object v1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->L$1:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 22
    .line 23
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    check-cast p1, Llx0/o;

    .line 27
    .line 28
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 43
    .line 44
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 45
    .line 46
    sget-object v5, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->Companion:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;

    .line 47
    .line 48
    invoke-virtual {v5}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;->getOUTER_ANTENNA_VEHICLE_KEYS_INFO_REQUEST()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    sget-object v6, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 53
    .line 54
    sget-object v7, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoRequest;->INSTANCE:Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoRequest;

    .line 55
    .line 56
    invoke-virtual {v7}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoRequest;->getByteArray()[B

    .line 57
    .line 58
    .line 59
    move-result-object v7

    .line 60
    invoke-direct {v2, v5, v6, v4, v7}, Ltechnology/cariad/cat/genx/protocol/Message;-><init>(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V

    .line 61
    .line 62
    .line 63
    invoke-static {p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getConnection$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Llx0/l;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    if-eqz p1, :cond_2

    .line 68
    .line 69
    iget-object p1, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast p1, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 72
    .line 73
    if-eqz p1, :cond_2

    .line 74
    .line 75
    iput-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->L$0:Ljava/lang/Object;

    .line 76
    .line 77
    iput-object v3, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->L$1:Ljava/lang/Object;

    .line 78
    .line 79
    iput-object v3, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->L$2:Ljava/lang/Object;

    .line 80
    .line 81
    const/4 v5, 0x0

    .line 82
    iput v5, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->I$0:I

    .line 83
    .line 84
    iput v4, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->label:I

    .line 85
    .line 86
    invoke-interface {p1, v2, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;->send-gIAlu-s(Ltechnology/cariad/cat/genx/protocol/Message;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    if-ne p1, v1, :cond_3

    .line 91
    .line 92
    return-object v1

    .line 93
    :cond_2
    sget-object p1, Ltechnology/cariad/cat/genx/GenXError$InvalidConnection;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$InvalidConnection;

    .line 94
    .line 95
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    :cond_3
    :goto_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 100
    .line 101
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 102
    .line 103
    .line 104
    move-result-object v8

    .line 105
    if-eqz v8, :cond_4

    .line 106
    .line 107
    new-instance v7, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 108
    .line 109
    const/4 p1, 0x4

    .line 110
    invoke-direct {v7, p0, p1}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 111
    .line 112
    .line 113
    new-instance v4, Lt51/j;

    .line 114
    .line 115
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v9

    .line 119
    const-string p1, "getName(...)"

    .line 120
    .line 121
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v10

    .line 125
    const-string v5, "GenX"

    .line 126
    .line 127
    sget-object v6, Lt51/e;->a:Lt51/e;

    .line 128
    .line 129
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 133
    .line 134
    .line 135
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$get_result$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Lyy0/j1;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    new-instance p1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;

    .line 140
    .line 141
    check-cast v8, Ltechnology/cariad/cat/genx/GenXError;

    .line 142
    .line 143
    invoke-direct {p1, v8}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;-><init>(Ltechnology/cariad/cat/genx/GenXError;)V

    .line 144
    .line 145
    .line 146
    check-cast p0, Lyy0/c2;

    .line 147
    .line 148
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 149
    .line 150
    .line 151
    invoke-virtual {p0, v3, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 155
    .line 156
    return-object p0
.end method
