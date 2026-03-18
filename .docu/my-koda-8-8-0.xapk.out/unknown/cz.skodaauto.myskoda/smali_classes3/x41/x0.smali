.class public final Lx41/x0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lx41/z0;

.field public final synthetic g:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;


# direct methods
.method public constructor <init>(Lx41/z0;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx41/x0;->f:Lx41/z0;

    .line 2
    .line 3
    iput-object p2, p0, Lx41/x0;->g:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

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


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Lx41/x0;

    .line 2
    .line 3
    iget-object v1, p0, Lx41/x0;->f:Lx41/z0;

    .line 4
    .line 5
    iget-object p0, p0, Lx41/x0;->g:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Lx41/x0;-><init>(Lx41/z0;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Lx41/x0;->e:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lx41/x0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lx41/x0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lx41/x0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lx41/x0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Lx41/x0;->d:I

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
    check-cast p1, Llx0/o;

    .line 18
    .line 19
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iget-object p1, p0, Lx41/x0;->f:Lx41/z0;

    .line 34
    .line 35
    iget-object v2, p1, Lx41/z0;->a:Lv51/f;

    .line 36
    .line 37
    iget-object p1, p1, Lx41/z0;->g:Ljava/lang/String;

    .line 38
    .line 39
    const-class v4, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 40
    .line 41
    invoke-static {v4}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    iput-object v0, p0, Lx41/x0;->e:Ljava/lang/Object;

    .line 46
    .line 47
    iput v3, p0, Lx41/x0;->d:I

    .line 48
    .line 49
    iget-object v3, p0, Lx41/x0;->g:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 50
    .line 51
    invoke-virtual {v2, p1, v3, v4, p0}, Lv51/f;->d(Ljava/lang/String;Ljava/lang/Object;Lhy0/a0;Lrx0/c;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    if-ne p0, v1, :cond_2

    .line 56
    .line 57
    return-object v1

    .line 58
    :cond_2
    :goto_0
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    if-eqz p0, :cond_3

    .line 63
    .line 64
    new-instance p1, Lx41/y;

    .line 65
    .line 66
    const/16 v1, 0x17

    .line 67
    .line 68
    invoke-direct {p1, v1}, Lx41/y;-><init>(I)V

    .line 69
    .line 70
    .line 71
    const-string v1, "Car2PhonePairing"

    .line 72
    .line 73
    invoke-static {v0, v1, p0, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 74
    .line 75
    .line 76
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 77
    .line 78
    return-object p0
.end method
