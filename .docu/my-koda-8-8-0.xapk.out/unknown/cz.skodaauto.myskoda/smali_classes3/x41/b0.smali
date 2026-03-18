.class public final Lx41/b0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public synthetic d:Ljava/lang/Object;

.field public final synthetic e:Lx41/u0;


# direct methods
.method public constructor <init>(Lx41/u0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx41/b0;->e:Lx41/u0;

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


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    new-instance v0, Lx41/b0;

    .line 2
    .line 3
    iget-object p0, p0, Lx41/b0;->e:Lx41/u0;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Lx41/b0;-><init>(Lx41/u0;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iput-object p1, v0, Lx41/b0;->d:Ljava/lang/Object;

    .line 9
    .line 10
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ltechnology/cariad/cat/genx/GenXError;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lx41/b0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lx41/b0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lx41/b0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lx41/b0;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ltechnology/cariad/cat/genx/GenXError;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    new-instance p1, Lx41/y;

    .line 11
    .line 12
    const/16 v1, 0xb

    .line 13
    .line 14
    invoke-direct {p1, v1}, Lx41/y;-><init>(I)V

    .line 15
    .line 16
    .line 17
    const-string v1, "Car2PhonePairing"

    .line 18
    .line 19
    iget-object p0, p0, Lx41/b0;->e:Lx41/u0;

    .line 20
    .line 21
    invoke-static {p0, v1, v0, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 22
    .line 23
    .line 24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    return-object p0
.end method
