.class final Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendStaticInformationRequest()V
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
    c = "technology.cariad.cat.genx.services.kes.KeyExchangeServiceApp$sendStaticInformationRequest$3"
    f = "KeyExchangeServiceApp.kt"
    l = {
        0x20a
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $hasOuterVehicleKeys:Z

.field I$0:I

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;ZLkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;",
            "Z",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 2
    .line 3
    iput-boolean p2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->$hasOuterVehicleKeys:Z

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

.method public static synthetic b(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->invokeSuspend$lambda$0$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

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
    const-string v0, "sendStaticInformationRequest(): Failed to send message - "

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
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 4
    .line 5
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->$hasOuterVehicleKeys:Z

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;ZLkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->L$0:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->label:I

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
    iget-object v1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->L$2:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 18
    .line 19
    iget-object v1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->L$1:Ljava/lang/Object;

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
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 43
    .line 44
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 45
    .line 46
    sget-object v5, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->Companion:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;

    .line 47
    .line 48
    invoke-virtual {v5}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;->getSTATIC_INFO_REQUEST()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    sget-object v6, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 53
    .line 54
    iget-boolean v7, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->$hasOuterVehicleKeys:Z

    .line 55
    .line 56
    invoke-static {v7}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeMessageKt;->toByte(Z)B

    .line 57
    .line 58
    .line 59
    move-result v7

    .line 60
    new-array v8, v4, [B

    .line 61
    .line 62
    const/4 v9, 0x0

    .line 63
    aput-byte v7, v8, v9

    .line 64
    .line 65
    invoke-direct {v2, v5, v6, v4, v8}, Ltechnology/cariad/cat/genx/protocol/Message;-><init>(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V

    .line 66
    .line 67
    .line 68
    invoke-static {p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getConnection$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Llx0/l;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    if-eqz p1, :cond_2

    .line 73
    .line 74
    iget-object p1, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p1, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 77
    .line 78
    if-eqz p1, :cond_2

    .line 79
    .line 80
    iput-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->L$0:Ljava/lang/Object;

    .line 81
    .line 82
    iput-object v3, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->L$1:Ljava/lang/Object;

    .line 83
    .line 84
    iput-object v3, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->L$2:Ljava/lang/Object;

    .line 85
    .line 86
    iput v9, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->I$0:I

    .line 87
    .line 88
    iput v4, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->label:I

    .line 89
    .line 90
    invoke-interface {p1, v2, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;->send-gIAlu-s(Ltechnology/cariad/cat/genx/protocol/Message;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    if-ne p1, v1, :cond_3

    .line 95
    .line 96
    return-object v1

    .line 97
    :cond_2
    sget-object p1, Ltechnology/cariad/cat/genx/GenXError$InvalidConnection;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$InvalidConnection;

    .line 98
    .line 99
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    :cond_3
    :goto_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 104
    .line 105
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 106
    .line 107
    .line 108
    move-result-object v8

    .line 109
    if-eqz v8, :cond_4

    .line 110
    .line 111
    new-instance v7, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 112
    .line 113
    const/4 p1, 0x3

    .line 114
    invoke-direct {v7, p0, p1}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 115
    .line 116
    .line 117
    new-instance v4, Lt51/j;

    .line 118
    .line 119
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v9

    .line 123
    const-string p1, "getName(...)"

    .line 124
    .line 125
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v10

    .line 129
    const-string v5, "GenX"

    .line 130
    .line 131
    sget-object v6, Lt51/e;->a:Lt51/e;

    .line 132
    .line 133
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 137
    .line 138
    .line 139
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$get_result$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Lyy0/j1;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    new-instance p1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;

    .line 144
    .line 145
    check-cast v8, Ltechnology/cariad/cat/genx/GenXError;

    .line 146
    .line 147
    invoke-direct {p1, v8}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;-><init>(Ltechnology/cariad/cat/genx/GenXError;)V

    .line 148
    .line 149
    .line 150
    check-cast p0, Lyy0/c2;

    .line 151
    .line 152
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 153
    .line 154
    .line 155
    invoke-virtual {p0, v3, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 159
    .line 160
    return-object p0
.end method
