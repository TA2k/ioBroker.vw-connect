.class public final Lx41/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/QRKeyExchangeDelegate;


# instance fields
.field public final synthetic a:Lx41/u0;


# direct methods
.method public constructor <init>(Lx41/u0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lx41/m0;->a:Lx41/u0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onKeyExchangeFailed(Ljava/lang/String;Ltechnology/cariad/cat/genx/GenXError;)V
    .locals 6

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "error"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lq61/c;

    .line 12
    .line 13
    const/16 v1, 0xd

    .line 14
    .line 15
    invoke-direct {v0, p1, v1}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 16
    .line 17
    .line 18
    const-string p1, "Car2PhonePairing"

    .line 19
    .line 20
    invoke-static {p0, p1, p2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lx41/m0;->a:Lx41/u0;

    .line 24
    .line 25
    iget-object p1, p0, Lx41/u0;->l:Lyy0/c2;

    .line 26
    .line 27
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 28
    .line 29
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    invoke-virtual {p1, v1, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    iget-object v2, p0, Lx41/u0;->k:Lss/b;

    .line 37
    .line 38
    if-eqz v2, :cond_0

    .line 39
    .line 40
    iget-object v3, p0, Lx41/u0;->i:Lvy0/x;

    .line 41
    .line 42
    new-instance v4, Lwa0/c;

    .line 43
    .line 44
    const/4 v5, 0x5

    .line 45
    invoke-direct {v4, v5, v2, p2, v1}, Lwa0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 46
    .line 47
    .line 48
    const/4 p2, 0x2

    .line 49
    invoke-static {p0, v3, v1, v4, p2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 50
    .line 51
    .line 52
    :cond_0
    iput-object v1, p0, Lx41/u0;->k:Lss/b;

    .line 53
    .line 54
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1, v1, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method public final onKeyExchangeStarted()V
    .locals 7

    .line 1
    new-instance v3, Lx41/y;

    .line 2
    .line 3
    const/16 v0, 0xc

    .line 4
    .line 5
    invoke-direct {v3, v0}, Lx41/y;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v1, "getName(...)"

    .line 15
    .line 16
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "Car2PhonePairing"

    .line 21
    .line 22
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    iget-object p0, p0, Lx41/m0;->a:Lx41/u0;

    .line 32
    .line 33
    iget-object v0, p0, Lx41/u0;->k:Lss/b;

    .line 34
    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    iget-object v1, p0, Lx41/u0;->i:Lvy0/x;

    .line 38
    .line 39
    new-instance v2, Lx41/i0;

    .line 40
    .line 41
    const/4 v3, 0x1

    .line 42
    const/4 v4, 0x0

    .line 43
    invoke-direct {v2, v0, v4, v3}, Lx41/i0;-><init>(Lss/b;Lkotlin/coroutines/Continuation;I)V

    .line 44
    .line 45
    .line 46
    const/4 v0, 0x2

    .line 47
    invoke-static {p0, v1, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 48
    .line 49
    .line 50
    :cond_0
    return-void
.end method

.method public final onKeyExchangeSucceeded(Ljava/util/List;)V
    .locals 8

    .line 1
    const-string v0, "keyExchangeInformation"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ld01/v;

    .line 7
    .line 8
    const/16 v0, 0xe

    .line 9
    .line 10
    invoke-direct {v4, p1, v0}, Ld01/v;-><init>(Ljava/util/List;I)V

    .line 11
    .line 12
    .line 13
    new-instance v1, Lt51/j;

    .line 14
    .line 15
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string v0, "getName(...)"

    .line 20
    .line 21
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v7

    .line 25
    const-string v2, "Car2PhonePairing"

    .line 26
    .line 27
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 28
    .line 29
    const/4 v5, 0x0

    .line 30
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lx41/m0;->a:Lx41/u0;

    .line 37
    .line 38
    iget-object v0, p0, Lx41/u0;->l:Lyy0/c2;

    .line 39
    .line 40
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    const/4 v2, 0x0

    .line 46
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    iget-object v0, p0, Lx41/u0;->k:Lss/b;

    .line 50
    .line 51
    iput-object v2, p0, Lx41/u0;->k:Lss/b;

    .line 52
    .line 53
    iget-object v1, p0, Lx41/u0;->j:Lpx0/g;

    .line 54
    .line 55
    new-instance v3, Lk90/b;

    .line 56
    .line 57
    invoke-direct {v3, p1, v0, p0, v2}, Lk90/b;-><init>(Ljava/util/List;Lss/b;Lx41/u0;Lkotlin/coroutines/Continuation;)V

    .line 58
    .line 59
    .line 60
    const/4 p1, 0x2

    .line 61
    invoke-static {p0, v1, v2, v3, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 62
    .line 63
    .line 64
    return-void
.end method
