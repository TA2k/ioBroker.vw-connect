.class public final Lw3/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/b0;


# instance fields
.field public final d:Landroid/view/View;

.field public final e:Ll4/w;

.field public final f:Lvy0/b0;

.field public final g:Ljava/util/concurrent/atomic/AtomicReference;


# direct methods
.method public constructor <init>(Landroid/view/View;Ll4/w;Lvy0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw3/m0;->d:Landroid/view/View;

    .line 5
    .line 6
    iput-object p2, p0, Lw3/m0;->e:Ll4/w;

    .line 7
    .line 8
    iput-object p3, p0, Lw3/m0;->f:Lvy0/b0;

    .line 9
    .line 10
    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 11
    .line 12
    const/4 p2, 0x0

    .line 13
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lw3/m0;->g:Ljava/util/concurrent/atomic/AtomicReference;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a(Lc2/p;Lrx0/c;)V
    .locals 5

    .line 1
    instance-of v0, p2, Lw3/l0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lw3/l0;

    .line 7
    .line 8
    iget v1, v0, Lw3/l0;->f:I

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
    iput v1, v0, Lw3/l0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lw3/l0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lw3/l0;-><init>(Lw3/m0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lw3/l0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lw3/l0;->f:I

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
    new-instance p2, Lb1/e;

    .line 52
    .line 53
    const/16 v2, 0xe

    .line 54
    .line 55
    invoke-direct {p2, v2, p1, p0}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    new-instance p1, Lvu/j;

    .line 59
    .line 60
    const/4 v2, 0x6

    .line 61
    const/4 v4, 0x0

    .line 62
    invoke-direct {p1, p0, v4, v2}, Lvu/j;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 63
    .line 64
    .line 65
    iput v3, v0, Lw3/l0;->f:I

    .line 66
    .line 67
    new-instance v2, Lvh/j;

    .line 68
    .line 69
    iget-object p0, p0, Lw3/m0;->g:Ljava/util/concurrent/atomic/AtomicReference;

    .line 70
    .line 71
    invoke-direct {v2, p2, p0, p1, v4}, Lvh/j;-><init>(Lay0/k;Ljava/util/concurrent/atomic/AtomicReference;Lay0/n;Lkotlin/coroutines/Continuation;)V

    .line 72
    .line 73
    .line 74
    invoke-static {v2, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    if-ne p0, v1, :cond_3

    .line 79
    .line 80
    return-void

    .line 81
    :cond_3
    :goto_1
    new-instance p0, La8/r0;

    .line 82
    .line 83
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 84
    .line 85
    .line 86
    throw p0
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/m0;->f:Lvy0/b0;

    .line 2
    .line 3
    invoke-interface {p0}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
