.class final Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connect(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
        "\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0002\u0010\u0005\u001a\u00020\u00042\u0014\u0010\u0003\u001a\u0010\u0012\u0004\u0012\u00020\u0001\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0005\u0010\u0006"
    }
    d2 = {
        "Llx0/l;",
        "Ltechnology/cariad/cat/genx/Reachability;",
        "Ltechnology/cariad/cat/genx/Car2PhoneMode;",
        "<destruct>",
        "",
        "<anonymous>",
        "(Llx0/l;)Z"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.services.kes.KeyExchangeServiceApp$connect$3$3"
    f = "KeyExchangeServiceApp.kt"
    l = {}
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;",
            ">;)V"
        }
    .end annotation

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-direct {p0, v0, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 0
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
    new-instance p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;->L$0:Ljava/lang/Object;

    .line 7
    .line 8
    return-object p0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/l;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;->invoke(Llx0/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Llx0/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llx0/l;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ljava/lang/Boolean;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Llx0/l;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;->label:I

    .line 8
    .line 9
    if-nez p0, :cond_1

    .line 10
    .line 11
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Ltechnology/cariad/cat/genx/Reachability;

    .line 17
    .line 18
    iget-object p1, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p1, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 21
    .line 22
    sget-object v0, Ltechnology/cariad/cat/genx/Reachability;->REACHABLE:Ltechnology/cariad/cat/genx/Reachability;

    .line 23
    .line 24
    if-ne p0, v0, :cond_0

    .line 25
    .line 26
    if-eqz p1, :cond_0

    .line 27
    .line 28
    sget-object p0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->Companion:Ltechnology/cariad/cat/genx/Car2PhoneMode$Companion;

    .line 29
    .line 30
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/Car2PhoneMode$Companion;->getPairingActive()Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {p1, p0}, Ltechnology/cariad/cat/genx/Car2PhoneMode;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-nez p0, :cond_0

    .line 39
    .line 40
    const/4 p0, 0x1

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 p0, 0x0

    .line 43
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

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
.end method
