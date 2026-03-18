.class final Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->onCGXKeyExchangeSucceeded$genx_release(Ljava/lang/String;I)Ltechnology/cariad/cat/genx/GenXError;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6$WhenMappings;
    }
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
    c = "technology.cariad.cat.genx.keyexchange.KeyExchangeManager$onCGXKeyExchangeSucceeded$6"
    f = "KeyExchangeManager.kt"
    l = {
        0x102
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $cgxAntenna:I

.field final synthetic $localKeyPairOfActiveKeyExchange:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

.field final synthetic $qrCodeOfActiveKeyExchange:Ltechnology/cariad/cat/genx/QRCode;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;


# direct methods
.method public constructor <init>(ILtechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I",
            "Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;",
            "Ltechnology/cariad/cat/genx/QRCode;",
            "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput p1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$cgxAntenna:I

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$qrCodeOfActiveKeyExchange:Ltechnology/cariad/cat/genx/QRCode;

    .line 6
    .line 7
    iput-object p4, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$localKeyPairOfActiveKeyExchange:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6
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
    new-instance v0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$cgxAntenna:I

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 6
    .line 7
    iget-object v3, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$qrCodeOfActiveKeyExchange:Ltechnology/cariad/cat/genx/QRCode;

    .line 8
    .line 9
    iget-object v4, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$localKeyPairOfActiveKeyExchange:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 10
    .line 11
    move-object v5, p2

    .line 12
    invoke-direct/range {v0 .. v5}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;-><init>(ILtechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->label:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 15
    .line 16
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iget p1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$cgxAntenna:I

    .line 26
    .line 27
    invoke-static {p1}, Ltechnology/cariad/cat/genx/AntennaKt;->getAntenna(I)Ltechnology/cariad/cat/genx/Antenna;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    sget-object v1, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 32
    .line 33
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    aget p1, v1, p1

    .line 38
    .line 39
    if-eq p1, v2, :cond_3

    .line 40
    .line 41
    const/4 v1, 0x2

    .line 42
    if-ne p1, v1, :cond_2

    .line 43
    .line 44
    iget-object p1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 45
    .line 46
    new-instance v1, Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;

    .line 47
    .line 48
    iget-object v3, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$qrCodeOfActiveKeyExchange:Ltechnology/cariad/cat/genx/QRCode;

    .line 49
    .line 50
    iget v4, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$cgxAntenna:I

    .line 51
    .line 52
    invoke-static {v4}, Ltechnology/cariad/cat/genx/AntennaKt;->getAntenna(I)Ltechnology/cariad/cat/genx/Antenna;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    iget-object v5, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$localKeyPairOfActiveKeyExchange:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 57
    .line 58
    invoke-direct {v1, v3, v4, v5}, Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;-><init>(Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)V

    .line 59
    .line 60
    .line 61
    iput v2, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->label:I

    .line 62
    .line 63
    invoke-static {p1, v1, p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->access$innerCGXKeyExchangeDidSucceeded(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    if-ne p0, v0, :cond_4

    .line 68
    .line 69
    return-object v0

    .line 70
    :cond_2
    new-instance p0, La8/r0;

    .line 71
    .line 72
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 73
    .line 74
    .line 75
    throw p0

    .line 76
    :cond_3
    iget-object p1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 77
    .line 78
    new-instance v0, Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;

    .line 79
    .line 80
    iget-object v1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$qrCodeOfActiveKeyExchange:Ltechnology/cariad/cat/genx/QRCode;

    .line 81
    .line 82
    iget v2, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$cgxAntenna:I

    .line 83
    .line 84
    invoke-static {v2}, Ltechnology/cariad/cat/genx/AntennaKt;->getAntenna(I)Ltechnology/cariad/cat/genx/Antenna;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    iget-object p0, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$onCGXKeyExchangeSucceeded$6;->$localKeyPairOfActiveKeyExchange:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 89
    .line 90
    invoke-direct {v0, v1, v2, p0}, Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;-><init>(Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)V

    .line 91
    .line 92
    .line 93
    invoke-static {p1, v0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->access$outerCGXKeyExchangeDidSucceeded(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/KeyExchangeInformation;)V

    .line 94
    .line 95
    .line 96
    :cond_4
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    return-object p0
.end method
