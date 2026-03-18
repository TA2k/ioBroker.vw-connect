.class final Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


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
        "Lay0/o;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0005\u001a\u0010\u0012\u0004\u0012\u00020\u0000\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u00042\u0006\u0010\u0001\u001a\u00020\u00002\u0008\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\n\u00a2\u0006\u0004\u0008\u0005\u0010\u0006"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/Reachability;",
        "reachability",
        "Ltechnology/cariad/cat/genx/Car2PhoneMode;",
        "car2PhoneMode",
        "Llx0/l;",
        "<anonymous>",
        "(Ltechnology/cariad/cat/genx/Reachability;Ltechnology/cariad/cat/genx/Car2PhoneMode;)Llx0/l;"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.services.kes.KeyExchangeServiceApp$connect$3$2"
    f = "KeyExchangeServiceApp.kt"
    l = {}
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

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
            "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 2
    .line 3
    const/4 p1, 0x3

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/Reachability;Ltechnology/cariad/cat/genx/Car2PhoneMode;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;->invokeSuspend$lambda$0(Ltechnology/cariad/cat/genx/Reachability;Ltechnology/cariad/cat/genx/Car2PhoneMode;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final invokeSuspend$lambda$0(Ltechnology/cariad/cat/genx/Reachability;Ltechnology/cariad/cat/genx/Car2PhoneMode;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "connect(): Observed reachability = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, ", mode = "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method


# virtual methods
.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ltechnology/cariad/cat/genx/Reachability;

    check-cast p2, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    check-cast p3, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;->invoke(Ltechnology/cariad/cat/genx/Reachability;Ltechnology/cariad/cat/genx/Car2PhoneMode;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Ltechnology/cariad/cat/genx/Reachability;Ltechnology/cariad/cat/genx/Car2PhoneMode;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/Reachability;",
            "Ltechnology/cariad/cat/genx/Car2PhoneMode;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/l;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;

    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    invoke-direct {v0, p0, p3}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V

    iput-object p1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;->L$1:Ljava/lang/Object;

    sget-object p0, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ltechnology/cariad/cat/genx/Reachability;

    .line 4
    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;->L$1:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 8
    .line 9
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 10
    .line 11
    iget v2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;->label:I

    .line 12
    .line 13
    if-nez v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;->this$0:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 19
    .line 20
    new-instance v5, Ltechnology/cariad/cat/genx/services/kes/d;

    .line 21
    .line 22
    const/4 p1, 0x0

    .line 23
    invoke-direct {v5, p1, v0, v1}, Ltechnology/cariad/cat/genx/services/kes/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    new-instance v2, Lt51/j;

    .line 27
    .line 28
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v7

    .line 32
    const-string p0, "getName(...)"

    .line 33
    .line 34
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v8

    .line 38
    const-string v3, "GenX"

    .line 39
    .line 40
    sget-object v4, Lt51/d;->a:Lt51/d;

    .line 41
    .line 42
    const/4 v6, 0x0

    .line 43
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 47
    .line 48
    .line 49
    new-instance p0, Llx0/l;

    .line 50
    .line 51
    invoke-direct {p0, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    return-object p0

    .line 55
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 56
    .line 57
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0
.end method
