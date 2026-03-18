.class public final La7/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lpx0/e;


# instance fields
.field public final synthetic d:Ljava/util/concurrent/atomic/AtomicReference;

.field public final synthetic e:Lxy0/x;


# direct methods
.method public constructor <init>(Ljava/util/concurrent/atomic/AtomicReference;Lxy0/x;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La7/q;->d:Ljava/util/concurrent/atomic/AtomicReference;

    .line 5
    .line 6
    iput-object p2, p0, La7/q;->e:Lxy0/x;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final c(Lay0/n;Lrx0/c;)V
    .locals 4

    .line 1
    instance-of v0, p2, La7/p;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, La7/p;

    .line 7
    .line 8
    iget v1, v0, La7/p;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, La7/p;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, La7/p;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, La7/p;-><init>(La7/q;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, La7/p;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, La7/p;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-eq v2, v3, :cond_1

    .line 35
    .line 36
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput-object p1, v0, La7/p;->d:Lay0/n;

    .line 52
    .line 53
    iput v3, v0, La7/p;->g:I

    .line 54
    .line 55
    new-instance p2, Lvy0/l;

    .line 56
    .line 57
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    invoke-direct {p2, v3, v0}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p2}, Lvy0/l;->q()V

    .line 65
    .line 66
    .line 67
    new-instance v0, La3/f;

    .line 68
    .line 69
    const/4 v2, 0x1

    .line 70
    iget-object v3, p0, La7/q;->e:Lxy0/x;

    .line 71
    .line 72
    invoke-direct {v0, v3, v2}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p2, v0}, Lvy0/l;->s(Lay0/k;)V

    .line 76
    .line 77
    .line 78
    iget-object p0, p0, La7/q;->d:Ljava/util/concurrent/atomic/AtomicReference;

    .line 79
    .line 80
    invoke-virtual {p0, p2}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    check-cast p0, Lvy0/k;

    .line 85
    .line 86
    if-eqz p0, :cond_3

    .line 87
    .line 88
    const/4 v0, 0x0

    .line 89
    invoke-interface {p0, v0}, Lvy0/k;->c(Ljava/lang/Throwable;)Z

    .line 90
    .line 91
    .line 92
    :cond_3
    check-cast v3, Lxy0/w;

    .line 93
    .line 94
    invoke-virtual {v3, p1}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    invoke-virtual {p2}, Lvy0/l;->p()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    if-ne p0, v1, :cond_4

    .line 102
    .line 103
    return-void

    .line 104
    :cond_4
    :goto_1
    new-instance p0, La8/r0;

    .line 105
    .line 106
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 107
    .line 108
    .line 109
    throw p0
.end method

.method public final fold(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-interface {p2, p1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final get(Lpx0/f;)Lpx0/e;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ljp/de;->b(Lpx0/e;Lpx0/f;)Lpx0/e;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getKey()Lpx0/f;
    .locals 0

    .line 1
    sget-object p0, La7/a0;->d:La7/a0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final minusKey(Lpx0/f;)Lpx0/g;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ljp/de;->c(Lpx0/e;Lpx0/f;)Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final plus(Lpx0/g;)Lpx0/g;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ljp/de;->d(Lpx0/e;Lpx0/g;)Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
