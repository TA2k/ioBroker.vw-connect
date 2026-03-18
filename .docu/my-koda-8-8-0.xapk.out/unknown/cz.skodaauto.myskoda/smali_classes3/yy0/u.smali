.class public abstract synthetic Lyy0/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lym0/b;

.field public static final b:Lj51/i;

.field public static final c:Lj51/i;

.field public static final d:Lj51/i;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lym0/b;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lym0/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lyy0/u;->a:Lym0/b;

    .line 9
    .line 10
    new-instance v0, Lj51/i;

    .line 11
    .line 12
    const-string v1, "NO_VALUE"

    .line 13
    .line 14
    const/4 v2, 0x1

    .line 15
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 16
    .line 17
    .line 18
    sput-object v0, Lyy0/u;->b:Lj51/i;

    .line 19
    .line 20
    new-instance v0, Lj51/i;

    .line 21
    .line 22
    const-string v1, "NONE"

    .line 23
    .line 24
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    sput-object v0, Lyy0/u;->c:Lj51/i;

    .line 28
    .line 29
    new-instance v0, Lj51/i;

    .line 30
    .line 31
    const-string v1, "PENDING"

    .line 32
    .line 33
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 34
    .line 35
    .line 36
    sput-object v0, Lyy0/u;->d:Lj51/i;

    .line 37
    .line 38
    return-void
.end method

.method public static final A(Lyy0/i;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lyy0/a1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lyy0/a1;

    .line 7
    .line 8
    iget v1, v0, Lyy0/a1;->f:I

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
    iput v1, v0, Lyy0/a1;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyy0/a1;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lyy0/a1;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyy0/a1;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Lyy0/a1;->d:Lkotlin/jvm/internal/f0;

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance p1, Lkotlin/jvm/internal/f0;

    .line 54
    .line 55
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 56
    .line 57
    .line 58
    new-instance v2, Lyy0/r0;

    .line 59
    .line 60
    const/4 v4, 0x3

    .line 61
    invoke-direct {v2, p1, v4}, Lyy0/r0;-><init>(Lkotlin/jvm/internal/f0;I)V

    .line 62
    .line 63
    .line 64
    iput-object p1, v0, Lyy0/a1;->d:Lkotlin/jvm/internal/f0;

    .line 65
    .line 66
    iput v3, v0, Lyy0/a1;->f:I

    .line 67
    .line 68
    invoke-interface {p0, v2, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    if-ne p0, v1, :cond_3

    .line 73
    .line 74
    return-object v1

    .line 75
    :cond_3
    move-object p0, p1

    .line 76
    :goto_1
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 77
    .line 78
    return-object p0
.end method

.method public static final B(Lyy0/i;Lvy0/b0;)Lvy0/x1;
    .locals 3

    .line 1
    new-instance v0, Lru0/i0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, p0, v2, v1}, Lru0/i0;-><init>(Lyy0/i;Lkotlin/coroutines/Continuation;I)V

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x3

    .line 9
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public static final C(Lay0/n;Lyy0/i;)Lzy0/j;
    .locals 3

    .line 1
    sget v0, Lyy0/q0;->a:I

    .line 2
    .line 3
    new-instance v0, Lqa0/a;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/16 v2, 0x1c

    .line 7
    .line 8
    invoke-direct {v0, p0, v1, v2}, Lqa0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static final varargs D([Lyy0/i;)Lyy0/e;
    .locals 4

    .line 1
    sget v0, Lyy0/q0;->a:I

    .line 2
    .line 3
    invoke-static {p0}, Lmx0/n;->a([Ljava/lang/Object;)Ljava/lang/Iterable;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    new-instance v0, Lyy0/e;

    .line 8
    .line 9
    const/4 v1, -0x2

    .line 10
    sget-object v2, Lxy0/a;->d:Lxy0/a;

    .line 11
    .line 12
    sget-object v3, Lpx0/h;->d:Lpx0/h;

    .line 13
    .line 14
    invoke-direct {v0, p0, v3, v1, v2}, Lyy0/e;-><init>(Ljava/lang/Iterable;Lpx0/g;ILxy0/a;)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public static final E(Lce/s;Lpw0/a;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lyy0/b1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lyy0/b1;

    .line 7
    .line 8
    iget v1, v0, Lyy0/b1;->e:I

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
    iput v1, v0, Lyy0/b1;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyy0/b1;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lyy0/b1;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyy0/b1;->e:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    invoke-static {p0}, Lyy0/u;->n(Lyy0/i;)Lyy0/t1;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    iget-object p2, p1, Lpw0/a;->e:Lpx0/g;

    .line 56
    .line 57
    sget-object v2, Lvy0/h1;->d:Lvy0/h1;

    .line 58
    .line 59
    invoke-interface {p2, v2}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    check-cast p2, Lvy0/i1;

    .line 64
    .line 65
    new-instance v2, Lvy0/r;

    .line 66
    .line 67
    invoke-direct {v2, v3}, Lvy0/p1;-><init>(Z)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v2, p2}, Lvy0/p1;->S(Lvy0/i1;)V

    .line 71
    .line 72
    .line 73
    iget-object p2, p0, Lyy0/t1;->b:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast p2, Lpx0/g;

    .line 76
    .line 77
    iget-object p0, p0, Lyy0/t1;->a:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Lyy0/i;

    .line 80
    .line 81
    new-instance v4, Lws/b;

    .line 82
    .line 83
    const/16 v5, 0xf

    .line 84
    .line 85
    const/4 v6, 0x0

    .line 86
    invoke-direct {v4, v5, p0, v2, v6}, Lws/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 87
    .line 88
    .line 89
    const/4 p0, 0x2

    .line 90
    invoke-static {p1, p2, v6, v4, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 91
    .line 92
    .line 93
    iput v3, v0, Lyy0/b1;->e:I

    .line 94
    .line 95
    invoke-virtual {v2, v0}, Lvy0/p1;->y(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p2

    .line 99
    if-ne p2, v1, :cond_3

    .line 100
    .line 101
    return-object v1

    .line 102
    :cond_3
    :goto_1
    check-cast p2, Llx0/o;

    .line 103
    .line 104
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 105
    .line 106
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    return-object p0
.end method

.method public static final F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;
    .locals 8

    .line 1
    invoke-static {p0}, Lyy0/u;->n(Lyy0/i;)Lyy0/t1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p3}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 6
    .line 7
    .line 8
    move-result-object v3

    .line 9
    iget-object v0, p0, Lyy0/t1;->b:Ljava/lang/Object;

    .line 10
    .line 11
    move-object v7, v0

    .line 12
    check-cast v7, Lpx0/g;

    .line 13
    .line 14
    iget-object p0, p0, Lyy0/t1;->a:Ljava/lang/Object;

    .line 15
    .line 16
    move-object v2, p0

    .line 17
    check-cast v2, Lyy0/i;

    .line 18
    .line 19
    sget-object p0, Lyy0/u1;->a:Lyy0/w1;

    .line 20
    .line 21
    invoke-virtual {p2, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    sget-object p0, Lvy0/c0;->d:Lvy0/c0;

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    sget-object p0, Lvy0/c0;->g:Lvy0/c0;

    .line 31
    .line 32
    :goto_0
    new-instance v0, Lvh/j;

    .line 33
    .line 34
    const/4 v5, 0x0

    .line 35
    const/16 v6, 0x8

    .line 36
    .line 37
    move-object v1, p2

    .line 38
    move-object v4, p3

    .line 39
    invoke-direct/range {v0 .. v6}, Lvh/j;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    invoke-static {p1, v7, p0, v0}, Lvy0/e0;->D(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;)Lvy0/x1;

    .line 43
    .line 44
    .line 45
    new-instance p0, Lyy0/l1;

    .line 46
    .line 47
    invoke-direct {p0, v3}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 48
    .line 49
    .line 50
    return-object p0
.end method

.method public static final G(Lyy0/i;I)Lyy0/d0;
    .locals 2

    .line 1
    if-lez p1, :cond_0

    .line 2
    .line 3
    new-instance v0, Lyy0/d0;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-direct {v0, p0, p1, v1}, Lyy0/d0;-><init>(Lyy0/i;II)V

    .line 7
    .line 8
    .line 9
    return-object v0

    .line 10
    :cond_0
    const-string p0, "Requested element count "

    .line 11
    .line 12
    const-string v0, " should be positive"

    .line 13
    .line 14
    invoke-static {p0, p1, v0}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p1
.end method

.method public static final H(Lyy0/i;Lay0/o;)Lzy0/j;
    .locals 7

    .line 1
    sget v0, Lyy0/q0;->a:I

    .line 2
    .line 3
    new-instance v1, Lzy0/j;

    .line 4
    .line 5
    const/4 v5, -0x2

    .line 6
    sget-object v6, Lxy0/a;->d:Lxy0/a;

    .line 7
    .line 8
    sget-object v4, Lpx0/h;->d:Lpx0/h;

    .line 9
    .line 10
    move-object v3, p0

    .line 11
    move-object v2, p1

    .line 12
    invoke-direct/range {v1 .. v6}, Lzy0/j;-><init>(Lay0/o;Lyy0/i;Lpx0/g;ILxy0/a;)V

    .line 13
    .line 14
    .line 15
    return-object v1
.end method

.method public static final a(IILxy0/a;)Lyy0/q1;
    .locals 1

    .line 1
    if-ltz p0, :cond_4

    .line 2
    .line 3
    if-ltz p1, :cond_3

    .line 4
    .line 5
    if-gtz p0, :cond_1

    .line 6
    .line 7
    if-gtz p1, :cond_1

    .line 8
    .line 9
    sget-object v0, Lxy0/a;->d:Lxy0/a;

    .line 10
    .line 11
    if-ne p2, v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string p1, "replay or extraBufferCapacity must be positive with non-default onBufferOverflow strategy "

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p1

    .line 38
    :cond_1
    :goto_0
    add-int/2addr p1, p0

    .line 39
    if-gez p1, :cond_2

    .line 40
    .line 41
    const p1, 0x7fffffff

    .line 42
    .line 43
    .line 44
    :cond_2
    new-instance v0, Lyy0/q1;

    .line 45
    .line 46
    invoke-direct {v0, p0, p1, p2}, Lyy0/q1;-><init>(IILxy0/a;)V

    .line 47
    .line 48
    .line 49
    return-object v0

    .line 50
    :cond_3
    const-string p0, "extraBufferCapacity cannot be negative, but was "

    .line 51
    .line 52
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 57
    .line 58
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p1

    .line 66
    :cond_4
    const-string p1, "replay cannot be negative, but was "

    .line 67
    .line 68
    invoke-static {p0, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 73
    .line 74
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p1
.end method

.method public static synthetic b(IILxy0/a;)Lyy0/q1;
    .locals 3

    .line 1
    and-int/lit8 v0, p1, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 v0, 0x1

    .line 9
    :goto_0
    and-int/lit8 v2, p1, 0x2

    .line 10
    .line 11
    if-eqz v2, :cond_1

    .line 12
    .line 13
    move p0, v1

    .line 14
    :cond_1
    and-int/lit8 p1, p1, 0x4

    .line 15
    .line 16
    if-eqz p1, :cond_2

    .line 17
    .line 18
    sget-object p2, Lxy0/a;->d:Lxy0/a;

    .line 19
    .line 20
    :cond_2
    invoke-static {v0, p0, p2}, Lyy0/u;->a(IILxy0/a;)Lyy0/q1;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public static final c(Ljava/lang/Object;)Lyy0/c2;
    .locals 1

    .line 1
    new-instance v0, Lyy0/c2;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lzy0/c;->b:Lj51/i;

    .line 6
    .line 7
    :cond_0
    invoke-direct {v0, p0}, Lyy0/c2;-><init>(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public static final d(Lyy0/j;Ljava/lang/Object;Ljava/lang/Object;Lrx0/c;)V
    .locals 4

    .line 1
    instance-of v0, p3, Lyy0/g0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lyy0/g0;

    .line 7
    .line 8
    iget v1, v0, Lyy0/g0;->f:I

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
    iput v1, v0, Lyy0/g0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyy0/g0;

    .line 21
    .line 22
    invoke-direct {v0, p3}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lyy0/g0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyy0/g0;->f:I

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
    iget-object p2, v0, Lyy0/g0;->d:Ljava/lang/Object;

    .line 45
    .line 46
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object p2, v0, Lyy0/g0;->d:Ljava/lang/Object;

    .line 54
    .line 55
    iput v3, v0, Lyy0/g0;->f:I

    .line 56
    .line 57
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    if-ne p0, v1, :cond_3

    .line 62
    .line 63
    return-void

    .line 64
    :cond_3
    :goto_1
    new-instance p0, Lzy0/a;

    .line 65
    .line 66
    invoke-direct {p0, p2}, Lzy0/a;-><init>(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    throw p0
.end method

.method public static final e(Lyy0/i2;Lay0/o;Ljava/lang/Throwable;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p3, Lyy0/v;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lyy0/v;

    .line 7
    .line 8
    iget v1, v0, Lyy0/v;->f:I

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
    iput v1, v0, Lyy0/v;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyy0/v;

    .line 21
    .line 22
    invoke-direct {v0, p3}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lyy0/v;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyy0/v;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p2, v0, Lyy0/v;->d:Ljava/lang/Throwable;

    .line 37
    .line 38
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :catchall_0
    move-exception p0

    .line 43
    goto :goto_2

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    :try_start_1
    iput-object p2, v0, Lyy0/v;->d:Ljava/lang/Throwable;

    .line 56
    .line 57
    iput v3, v0, Lyy0/v;->f:I

    .line 58
    .line 59
    invoke-interface {p1, p0, p2, v0}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 63
    if-ne p0, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    return-object p0

    .line 69
    :goto_2
    if-eqz p2, :cond_4

    .line 70
    .line 71
    if-eq p2, p0, :cond_4

    .line 72
    .line 73
    invoke-static {p0, p2}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 74
    .line 75
    .line 76
    :cond_4
    throw p0
.end method

.method public static final f([Ljava/lang/Object;JLjava/lang/Object;)V
    .locals 0

    .line 1
    long-to-int p1, p1

    .line 2
    array-length p2, p0

    .line 3
    add-int/lit8 p2, p2, -0x1

    .line 4
    .line 5
    and-int/2addr p1, p2

    .line 6
    aput-object p3, p0, p1

    .line 7
    .line 8
    return-void
.end method

.method public static g(Lyy0/i;I)Lyy0/i;
    .locals 7

    .line 1
    sget-object v0, Lxy0/a;->d:Lxy0/a;

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-gez p1, :cond_1

    .line 5
    .line 6
    const/4 v2, -0x2

    .line 7
    if-eq p1, v2, :cond_1

    .line 8
    .line 9
    if-ne p1, v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const-string p0, "Buffer size should be non-negative, BUFFERED, or CONFLATED, but was "

    .line 13
    .line 14
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p1

    .line 28
    :cond_1
    :goto_0
    if-ne p1, v1, :cond_2

    .line 29
    .line 30
    sget-object v0, Lxy0/a;->e:Lxy0/a;

    .line 31
    .line 32
    const/4 p1, 0x0

    .line 33
    :cond_2
    move v4, p1

    .line 34
    move-object v5, v0

    .line 35
    instance-of p1, p0, Lzy0/o;

    .line 36
    .line 37
    if-eqz p1, :cond_3

    .line 38
    .line 39
    check-cast p0, Lzy0/o;

    .line 40
    .line 41
    const/4 p1, 0x0

    .line 42
    const/4 v0, 0x1

    .line 43
    invoke-static {p0, p1, v4, v5, v0}, Lzy0/c;->b(Lzy0/o;Lpx0/g;ILxy0/a;I)Lyy0/i;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :cond_3
    new-instance v1, Lzy0/g;

    .line 49
    .line 50
    const/4 v3, 0x0

    .line 51
    const/4 v6, 0x2

    .line 52
    move-object v2, p0

    .line 53
    invoke-direct/range {v1 .. v6}, Lzy0/g;-><init>(Lyy0/i;Lpx0/g;ILxy0/a;I)V

    .line 54
    .line 55
    .line 56
    return-object v1
.end method

.method public static final h(Lay0/n;)Lyy0/c;
    .locals 4

    .line 1
    new-instance v0, Lyy0/c;

    .line 2
    .line 3
    const/4 v1, -0x2

    .line 4
    sget-object v2, Lxy0/a;->d:Lxy0/a;

    .line 5
    .line 6
    sget-object v3, Lpx0/h;->d:Lpx0/h;

    .line 7
    .line 8
    invoke-direct {v0, p0, v3, v1, v2}, Lyy0/c;-><init>(Lay0/n;Lpx0/g;ILxy0/a;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public static final i(Lyy0/i;Lyy0/j;Lrx0/c;)Ljava/io/Serializable;
    .locals 5

    .line 1
    instance-of v0, p2, Lyy0/a0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lyy0/a0;

    .line 7
    .line 8
    iget v1, v0, Lyy0/a0;->f:I

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
    iput v1, v0, Lyy0/a0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyy0/a0;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lyy0/a0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyy0/a0;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Lyy0/a0;->d:Lkotlin/jvm/internal/f0;

    .line 37
    .line 38
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :catchall_0
    move-exception p1

    .line 43
    goto :goto_2

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    new-instance p2, Lkotlin/jvm/internal/f0;

    .line 56
    .line 57
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 58
    .line 59
    .line 60
    :try_start_1
    new-instance v2, Ly70/c0;

    .line 61
    .line 62
    const/4 v4, 0x2

    .line 63
    invoke-direct {v2, v4, p1, p2}, Ly70/c0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iput-object p2, v0, Lyy0/a0;->d:Lkotlin/jvm/internal/f0;

    .line 67
    .line 68
    iput v3, v0, Lyy0/a0;->f:I

    .line 69
    .line 70
    invoke-interface {p0, v2, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 74
    if-ne p0, v1, :cond_3

    .line 75
    .line 76
    return-object v1

    .line 77
    :cond_3
    :goto_1
    const/4 p0, 0x0

    .line 78
    return-object p0

    .line 79
    :catchall_1
    move-exception p1

    .line 80
    move-object p0, p2

    .line 81
    :goto_2
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p0, Ljava/lang/Throwable;

    .line 84
    .line 85
    if-eqz p0, :cond_4

    .line 86
    .line 87
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result p2

    .line 91
    if-nez p2, :cond_6

    .line 92
    .line 93
    :cond_4
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    sget-object v0, Lvy0/h1;->d:Lvy0/h1;

    .line 98
    .line 99
    invoke-interface {p2, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 100
    .line 101
    .line 102
    move-result-object p2

    .line 103
    check-cast p2, Lvy0/i1;

    .line 104
    .line 105
    if-eqz p2, :cond_7

    .line 106
    .line 107
    invoke-interface {p2}, Lvy0/i1;->isCancelled()Z

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    if-nez v0, :cond_5

    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_5
    invoke-interface {p2}, Lvy0/i1;->j()Ljava/util/concurrent/CancellationException;

    .line 115
    .line 116
    .line 117
    move-result-object p2

    .line 118
    if-eqz p2, :cond_7

    .line 119
    .line 120
    invoke-virtual {p2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result p2

    .line 124
    if-nez p2, :cond_6

    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_6
    throw p1

    .line 128
    :cond_7
    :goto_3
    if-nez p0, :cond_8

    .line 129
    .line 130
    return-object p1

    .line 131
    :cond_8
    instance-of p2, p1, Ljava/util/concurrent/CancellationException;

    .line 132
    .line 133
    if-eqz p2, :cond_9

    .line 134
    .line 135
    invoke-static {p0, p1}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 136
    .line 137
    .line 138
    throw p0

    .line 139
    :cond_9
    invoke-static {p1, p0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 140
    .line 141
    .line 142
    throw p1
.end method

.method public static final j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Lzy0/q;->d:Lzy0/q;

    .line 2
    .line 3
    invoke-interface {p0, v0, p1}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    if-ne p0, p1, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method public static final k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p0, p2}, Lyy0/u;->C(Lay0/n;Lyy0/i;)Lzy0/j;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 p2, 0x0

    .line 6
    invoke-static {p0, p2}, Lyy0/u;->g(Lyy0/i;I)Lyy0/i;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-static {p0, p1}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    if-ne p0, p1, :cond_0

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method

.method public static final l(Lyy0/i;Lyy0/i;Lyy0/i;Lyy0/i;Lay0/q;)Llb0/y;
    .locals 2

    .line 1
    const/4 v0, 0x4

    .line 2
    new-array v0, v0, [Lyy0/i;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    aput-object p0, v0, v1

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    aput-object p1, v0, p0

    .line 9
    .line 10
    const/4 p0, 0x2

    .line 11
    aput-object p2, v0, p0

    .line 12
    .line 13
    const/4 p0, 0x3

    .line 14
    aput-object p3, v0, p0

    .line 15
    .line 16
    new-instance p0, Llb0/y;

    .line 17
    .line 18
    const/16 p1, 0x16

    .line 19
    .line 20
    invoke-direct {p0, p1, v0, p4}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    return-object p0
.end method

.method public static final m(Lyy0/i;Lyy0/i;Lyy0/i;Lay0/p;)Lyy0/f1;
    .locals 2

    .line 1
    const/4 v0, 0x3

    .line 2
    new-array v0, v0, [Lyy0/i;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    aput-object p0, v0, v1

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    aput-object p1, v0, p0

    .line 9
    .line 10
    const/4 p0, 0x2

    .line 11
    aput-object p2, v0, p0

    .line 12
    .line 13
    new-instance p0, Lyy0/f1;

    .line 14
    .line 15
    invoke-direct {p0, v0, p3}, Lyy0/f1;-><init>([Lyy0/i;Lay0/p;)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method

.method public static final n(Lyy0/i;)Lyy0/t1;
    .locals 4

    .line 1
    sget-object v0, Lxy0/n;->p1:Lxy0/m;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    sget-object v0, Lxy0/m;->a:Lxy0/m;

    .line 7
    .line 8
    instance-of v0, p0, Lzy0/e;

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    move-object v0, p0

    .line 13
    check-cast v0, Lzy0/e;

    .line 14
    .line 15
    invoke-virtual {v0}, Lzy0/e;->g()Lyy0/i;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    new-instance p0, Lyy0/t1;

    .line 22
    .line 23
    iget v2, v0, Lzy0/e;->e:I

    .line 24
    .line 25
    const/4 v3, -0x3

    .line 26
    if-eq v2, v3, :cond_0

    .line 27
    .line 28
    const/4 v3, -0x2

    .line 29
    if-eq v2, v3, :cond_0

    .line 30
    .line 31
    if-eqz v2, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    sget-object v2, Lxy0/a;->d:Lxy0/a;

    .line 35
    .line 36
    :goto_0
    iget-object v0, v0, Lzy0/e;->d:Lpx0/g;

    .line 37
    .line 38
    invoke-direct {p0, v1, v0}, Lyy0/t1;-><init>(Lyy0/i;Lpx0/g;)V

    .line 39
    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_1
    new-instance v0, Lyy0/t1;

    .line 43
    .line 44
    sget-object v1, Lxy0/a;->d:Lxy0/a;

    .line 45
    .line 46
    sget-object v1, Lpx0/h;->d:Lpx0/h;

    .line 47
    .line 48
    invoke-direct {v0, p0, v1}, Lyy0/t1;-><init>(Lyy0/i;Lpx0/g;)V

    .line 49
    .line 50
    .line 51
    return-object v0
.end method

.method public static final o(Lyy0/i;J)Lyy0/i;
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-ltz v0, :cond_1

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance v0, Le81/e;

    .line 11
    .line 12
    const/16 v1, 0xf

    .line 13
    .line 14
    invoke-direct {v0, p1, p2, v1}, Le81/e;-><init>(JI)V

    .line 15
    .line 16
    .line 17
    new-instance p1, Le71/e;

    .line 18
    .line 19
    const/4 p2, 0x0

    .line 20
    invoke-direct {p1, v0, p0, p2}, Le71/e;-><init>(Lay0/k;Lyy0/i;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    new-instance p0, Lyy0/m1;

    .line 24
    .line 25
    invoke-direct {p0, p1}, Lyy0/m1;-><init>(Lay0/o;)V

    .line 26
    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 30
    .line 31
    const-string p1, "Debounce timeout should not be negative"

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0
.end method

.method public static final p(Lyy0/i;)Lyy0/i;
    .locals 3

    .line 1
    instance-of v0, p0, Lyy0/a2;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    instance-of v0, p0, Lyy0/g;

    .line 7
    .line 8
    sget-object v1, Lyy0/u;->a:Lym0/b;

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    move-object v0, p0

    .line 13
    check-cast v0, Lyy0/g;

    .line 14
    .line 15
    iget-object v2, v0, Lyy0/g;->e:Lay0/n;

    .line 16
    .line 17
    if-ne v2, v1, :cond_1

    .line 18
    .line 19
    return-object v0

    .line 20
    :cond_1
    new-instance v0, Lyy0/g;

    .line 21
    .line 22
    invoke-direct {v0, v1, p0}, Lyy0/g;-><init>(Lay0/n;Lyy0/i;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method

.method public static final q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p0}, Lyy0/u;->s(Lyy0/j;)V

    .line 2
    .line 3
    .line 4
    invoke-interface {p1, p0, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    if-ne p0, p1, :cond_0

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method public static final r(Lyy0/j;Lxy0/z;ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lyy0/n;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lyy0/n;

    .line 7
    .line 8
    iget v1, v0, Lyy0/n;->i:I

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
    iput v1, v0, Lyy0/n;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyy0/n;

    .line 21
    .line 22
    invoke-direct {v0, p3}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lyy0/n;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyy0/n;->i:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_4

    .line 34
    .line 35
    if-eq v2, v4, :cond_3

    .line 36
    .line 37
    if-ne v2, v3, :cond_2

    .line 38
    .line 39
    iget-boolean p2, v0, Lyy0/n;->g:Z

    .line 40
    .line 41
    iget-object p0, v0, Lyy0/n;->f:Lxy0/c;

    .line 42
    .line 43
    iget-object p1, v0, Lyy0/n;->e:Lxy0/z;

    .line 44
    .line 45
    iget-object v2, v0, Lyy0/n;->d:Lyy0/j;

    .line 46
    .line 47
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    .line 50
    :cond_1
    move-object p3, p0

    .line 51
    move-object p0, v2

    .line 52
    goto :goto_1

    .line 53
    :catchall_0
    move-exception p0

    .line 54
    goto :goto_4

    .line 55
    :cond_2
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

    .line 63
    :cond_3
    iget-boolean p2, v0, Lyy0/n;->g:Z

    .line 64
    .line 65
    iget-object p0, v0, Lyy0/n;->f:Lxy0/c;

    .line 66
    .line 67
    iget-object p1, v0, Lyy0/n;->e:Lxy0/z;

    .line 68
    .line 69
    iget-object v2, v0, Lyy0/n;->d:Lyy0/j;

    .line 70
    .line 71
    :try_start_1
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_4
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    invoke-static {p0}, Lyy0/u;->s(Lyy0/j;)V

    .line 79
    .line 80
    .line 81
    :try_start_2
    invoke-interface {p1}, Lxy0/z;->iterator()Lxy0/c;

    .line 82
    .line 83
    .line 84
    move-result-object p3

    .line 85
    :goto_1
    iput-object p0, v0, Lyy0/n;->d:Lyy0/j;

    .line 86
    .line 87
    iput-object p1, v0, Lyy0/n;->e:Lxy0/z;

    .line 88
    .line 89
    iput-object p3, v0, Lyy0/n;->f:Lxy0/c;

    .line 90
    .line 91
    iput-boolean p2, v0, Lyy0/n;->g:Z

    .line 92
    .line 93
    iput v4, v0, Lyy0/n;->i:I

    .line 94
    .line 95
    invoke-virtual {p3, v0}, Lxy0/c;->a(Lrx0/c;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    if-ne v2, v1, :cond_5

    .line 100
    .line 101
    goto :goto_3

    .line 102
    :cond_5
    move-object v5, v2

    .line 103
    move-object v2, p0

    .line 104
    move-object p0, p3

    .line 105
    move-object p3, v5

    .line 106
    :goto_2
    check-cast p3, Ljava/lang/Boolean;

    .line 107
    .line 108
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 109
    .line 110
    .line 111
    move-result p3

    .line 112
    if-eqz p3, :cond_6

    .line 113
    .line 114
    invoke-virtual {p0}, Lxy0/c;->c()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p3

    .line 118
    iput-object v2, v0, Lyy0/n;->d:Lyy0/j;

    .line 119
    .line 120
    iput-object p1, v0, Lyy0/n;->e:Lxy0/z;

    .line 121
    .line 122
    iput-object p0, v0, Lyy0/n;->f:Lxy0/c;

    .line 123
    .line 124
    iput-boolean p2, v0, Lyy0/n;->g:Z

    .line 125
    .line 126
    iput v3, v0, Lyy0/n;->i:I

    .line 127
    .line 128
    invoke-interface {v2, p3, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 132
    if-ne p3, v1, :cond_1

    .line 133
    .line 134
    :goto_3
    return-object v1

    .line 135
    :cond_6
    if-eqz p2, :cond_7

    .line 136
    .line 137
    const/4 p0, 0x0

    .line 138
    invoke-interface {p1, p0}, Lxy0/z;->d(Ljava/util/concurrent/CancellationException;)V

    .line 139
    .line 140
    .line 141
    :cond_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 142
    .line 143
    return-object p0

    .line 144
    :goto_4
    :try_start_3
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 145
    :catchall_1
    move-exception p3

    .line 146
    if-eqz p2, :cond_8

    .line 147
    .line 148
    invoke-static {p1, p0}, Llp/kf;->d(Lxy0/z;Ljava/lang/Throwable;)V

    .line 149
    .line 150
    .line 151
    :cond_8
    throw p3
.end method

.method public static final s(Lyy0/j;)V
    .locals 1

    .line 1
    instance-of v0, p0, Lyy0/i2;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    check-cast p0, Lyy0/i2;

    .line 7
    .line 8
    iget-object p0, p0, Lyy0/i2;->d:Ljava/lang/Throwable;

    .line 9
    .line 10
    throw p0
.end method

.method public static final t(Lyy0/i;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    sget-object v0, Lzy0/c;->b:Lj51/i;

    .line 2
    .line 3
    instance-of v1, p2, Lyy0/v0;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p2

    .line 8
    check-cast v1, Lyy0/v0;

    .line 9
    .line 10
    iget v2, v1, Lyy0/v0;->g:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lyy0/v0;->g:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lyy0/v0;

    .line 23
    .line 24
    invoke-direct {v1, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p2, v1, Lyy0/v0;->f:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lyy0/v0;->g:I

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    if-ne v3, v4, :cond_1

    .line 37
    .line 38
    iget-object p0, v1, Lyy0/v0;->e:Lyy0/t0;

    .line 39
    .line 40
    iget-object p1, v1, Lyy0/v0;->d:Lkotlin/jvm/internal/f0;

    .line 41
    .line 42
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lzy0/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 43
    .line 44
    .line 45
    goto :goto_2

    .line 46
    :catch_0
    move-exception p2

    .line 47
    goto :goto_1

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

    .line 56
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    new-instance p2, Lkotlin/jvm/internal/f0;

    .line 60
    .line 61
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 62
    .line 63
    .line 64
    iput-object v0, p2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 65
    .line 66
    new-instance v3, Lyy0/t0;

    .line 67
    .line 68
    const/4 v5, 0x0

    .line 69
    invoke-direct {v3, p1, p2, v5}, Lyy0/t0;-><init>(Lay0/n;Lkotlin/jvm/internal/f0;I)V

    .line 70
    .line 71
    .line 72
    :try_start_1
    iput-object p2, v1, Lyy0/v0;->d:Lkotlin/jvm/internal/f0;

    .line 73
    .line 74
    iput-object v3, v1, Lyy0/v0;->e:Lyy0/t0;

    .line 75
    .line 76
    iput v4, v1, Lyy0/v0;->g:I

    .line 77
    .line 78
    invoke-interface {p0, v3, v1}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0
    :try_end_1
    .catch Lzy0/a; {:try_start_1 .. :try_end_1} :catch_1

    .line 82
    if-ne p0, v2, :cond_3

    .line 83
    .line 84
    return-object v2

    .line 85
    :cond_3
    move-object p1, p2

    .line 86
    goto :goto_2

    .line 87
    :catch_1
    move-exception p0

    .line 88
    move-object p1, p2

    .line 89
    move-object p2, p0

    .line 90
    move-object p0, v3

    .line 91
    :goto_1
    iget-object v2, p2, Lzy0/a;->d:Ljava/lang/Object;

    .line 92
    .line 93
    if-ne v2, p0, :cond_5

    .line 94
    .line 95
    invoke-interface {v1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    invoke-static {p0}, Lvy0/e0;->r(Lpx0/g;)V

    .line 100
    .line 101
    .line 102
    :goto_2
    iget-object p0, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 103
    .line 104
    if-eq p0, v0, :cond_4

    .line 105
    .line 106
    return-object p0

    .line 107
    :cond_4
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 108
    .line 109
    const-string p1, "Expected at least one element matching the predicate"

    .line 110
    .line 111
    invoke-direct {p0, p1}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw p0

    .line 115
    :cond_5
    throw p2
.end method

.method public static final u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    sget-object v0, Lzy0/c;->b:Lj51/i;

    .line 2
    .line 3
    instance-of v1, p1, Lyy0/u0;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p1

    .line 8
    check-cast v1, Lyy0/u0;

    .line 9
    .line 10
    iget v2, v1, Lyy0/u0;->g:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lyy0/u0;->g:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lyy0/u0;

    .line 23
    .line 24
    invoke-direct {v1, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v1, Lyy0/u0;->f:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lyy0/u0;->g:I

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    if-ne v3, v4, :cond_1

    .line 37
    .line 38
    iget-object p0, v1, Lyy0/u0;->e:Lyy0/r0;

    .line 39
    .line 40
    iget-object v2, v1, Lyy0/u0;->d:Lkotlin/jvm/internal/f0;

    .line 41
    .line 42
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lzy0/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 43
    .line 44
    .line 45
    goto :goto_2

    .line 46
    :catch_0
    move-exception p1

    .line 47
    goto :goto_1

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

    .line 56
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    new-instance p1, Lkotlin/jvm/internal/f0;

    .line 60
    .line 61
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 62
    .line 63
    .line 64
    iput-object v0, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 65
    .line 66
    new-instance v3, Lyy0/r0;

    .line 67
    .line 68
    const/4 v5, 0x0

    .line 69
    invoke-direct {v3, p1, v5}, Lyy0/r0;-><init>(Lkotlin/jvm/internal/f0;I)V

    .line 70
    .line 71
    .line 72
    :try_start_1
    iput-object p1, v1, Lyy0/u0;->d:Lkotlin/jvm/internal/f0;

    .line 73
    .line 74
    iput-object v3, v1, Lyy0/u0;->e:Lyy0/r0;

    .line 75
    .line 76
    iput v4, v1, Lyy0/u0;->g:I

    .line 77
    .line 78
    invoke-interface {p0, v3, v1}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0
    :try_end_1
    .catch Lzy0/a; {:try_start_1 .. :try_end_1} :catch_1

    .line 82
    if-ne p0, v2, :cond_3

    .line 83
    .line 84
    return-object v2

    .line 85
    :cond_3
    move-object v2, p1

    .line 86
    goto :goto_2

    .line 87
    :catch_1
    move-exception p0

    .line 88
    move-object v2, p1

    .line 89
    move-object p1, p0

    .line 90
    move-object p0, v3

    .line 91
    :goto_1
    iget-object v3, p1, Lzy0/a;->d:Ljava/lang/Object;

    .line 92
    .line 93
    if-ne v3, p0, :cond_5

    .line 94
    .line 95
    invoke-interface {v1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    invoke-static {p0}, Lvy0/e0;->r(Lpx0/g;)V

    .line 100
    .line 101
    .line 102
    :goto_2
    iget-object p0, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 103
    .line 104
    if-eq p0, v0, :cond_4

    .line 105
    .line 106
    return-object p0

    .line 107
    :cond_4
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 108
    .line 109
    const-string p1, "Expected at least one element"

    .line 110
    .line 111
    invoke-direct {p0, p1}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw p0

    .line 115
    :cond_5
    throw p1
.end method

.method public static final v(Lyy0/i;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lyy0/y0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lyy0/y0;

    .line 7
    .line 8
    iget v1, v0, Lyy0/y0;->g:I

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
    iput v1, v0, Lyy0/y0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyy0/y0;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lyy0/y0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyy0/y0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Lyy0/y0;->e:Lyy0/t0;

    .line 37
    .line 38
    iget-object p1, v0, Lyy0/y0;->d:Lkotlin/jvm/internal/f0;

    .line 39
    .line 40
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lzy0/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 41
    .line 42
    .line 43
    goto :goto_2

    .line 44
    :catch_0
    move-exception p2

    .line 45
    goto :goto_1

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    new-instance p2, Lkotlin/jvm/internal/f0;

    .line 58
    .line 59
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 60
    .line 61
    .line 62
    new-instance v2, Lyy0/t0;

    .line 63
    .line 64
    const/4 v4, 0x1

    .line 65
    invoke-direct {v2, p1, p2, v4}, Lyy0/t0;-><init>(Lay0/n;Lkotlin/jvm/internal/f0;I)V

    .line 66
    .line 67
    .line 68
    :try_start_1
    iput-object p2, v0, Lyy0/y0;->d:Lkotlin/jvm/internal/f0;

    .line 69
    .line 70
    iput-object v2, v0, Lyy0/y0;->e:Lyy0/t0;

    .line 71
    .line 72
    iput v3, v0, Lyy0/y0;->g:I

    .line 73
    .line 74
    invoke-interface {p0, v2, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0
    :try_end_1
    .catch Lzy0/a; {:try_start_1 .. :try_end_1} :catch_1

    .line 78
    if-ne p0, v1, :cond_3

    .line 79
    .line 80
    return-object v1

    .line 81
    :cond_3
    move-object p1, p2

    .line 82
    goto :goto_2

    .line 83
    :catch_1
    move-exception p0

    .line 84
    move-object p1, p2

    .line 85
    move-object p2, p0

    .line 86
    move-object p0, v2

    .line 87
    :goto_1
    iget-object v1, p2, Lzy0/a;->d:Ljava/lang/Object;

    .line 88
    .line 89
    if-ne v1, p0, :cond_4

    .line 90
    .line 91
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    invoke-static {p0}, Lvy0/e0;->r(Lpx0/g;)V

    .line 96
    .line 97
    .line 98
    :goto_2
    iget-object p0, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 99
    .line 100
    return-object p0

    .line 101
    :cond_4
    throw p2
.end method

.method public static final w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lyy0/x0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lyy0/x0;

    .line 7
    .line 8
    iget v1, v0, Lyy0/x0;->g:I

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
    iput v1, v0, Lyy0/x0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyy0/x0;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lyy0/x0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyy0/x0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Lyy0/x0;->e:Lyy0/r0;

    .line 37
    .line 38
    iget-object v1, v0, Lyy0/x0;->d:Lkotlin/jvm/internal/f0;

    .line 39
    .line 40
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lzy0/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 41
    .line 42
    .line 43
    goto :goto_2

    .line 44
    :catch_0
    move-exception p1

    .line 45
    goto :goto_1

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    new-instance p1, Lkotlin/jvm/internal/f0;

    .line 58
    .line 59
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 60
    .line 61
    .line 62
    new-instance v2, Lyy0/r0;

    .line 63
    .line 64
    const/4 v4, 0x1

    .line 65
    invoke-direct {v2, p1, v4}, Lyy0/r0;-><init>(Lkotlin/jvm/internal/f0;I)V

    .line 66
    .line 67
    .line 68
    :try_start_1
    iput-object p1, v0, Lyy0/x0;->d:Lkotlin/jvm/internal/f0;

    .line 69
    .line 70
    iput-object v2, v0, Lyy0/x0;->e:Lyy0/r0;

    .line 71
    .line 72
    iput v3, v0, Lyy0/x0;->g:I

    .line 73
    .line 74
    invoke-interface {p0, v2, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0
    :try_end_1
    .catch Lzy0/a; {:try_start_1 .. :try_end_1} :catch_1

    .line 78
    if-ne p0, v1, :cond_3

    .line 79
    .line 80
    return-object v1

    .line 81
    :cond_3
    move-object v1, p1

    .line 82
    goto :goto_2

    .line 83
    :catch_1
    move-exception p0

    .line 84
    move-object v1, p1

    .line 85
    move-object p1, p0

    .line 86
    move-object p0, v2

    .line 87
    :goto_1
    iget-object v2, p1, Lzy0/a;->d:Ljava/lang/Object;

    .line 88
    .line 89
    if-ne v2, p0, :cond_4

    .line 90
    .line 91
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    invoke-static {p0}, Lvy0/e0;->r(Lpx0/g;)V

    .line 96
    .line 97
    .line 98
    :goto_2
    iget-object p0, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 99
    .line 100
    return-object p0

    .line 101
    :cond_4
    throw p1
.end method

.method public static final x(Lay0/n;Lyy0/i;)Lyy0/m;
    .locals 2

    .line 1
    sget v0, Lyy0/q0;->a:I

    .line 2
    .line 3
    new-instance v0, Lne0/n;

    .line 4
    .line 5
    const/4 v1, 0x4

    .line 6
    invoke-direct {v0, p1, p0, v1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 7
    .line 8
    .line 9
    new-instance p0, Lyy0/m;

    .line 10
    .line 11
    const/4 p1, 0x1

    .line 12
    invoke-direct {p0, v0, p1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public static final y(Lyy0/n1;Lpx0/g;ILxy0/a;)Lyy0/i;
    .locals 1

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    const/4 v0, -0x3

    .line 4
    if-ne p2, v0, :cond_1

    .line 5
    .line 6
    :cond_0
    sget-object v0, Lxy0/a;->d:Lxy0/a;

    .line 7
    .line 8
    if-ne p3, v0, :cond_1

    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_1
    new-instance v0, Lzy0/g;

    .line 12
    .line 13
    invoke-direct {v0, p0, p1, p2, p3}, Lzy0/f;-><init>(Lyy0/i;Lpx0/g;ILxy0/a;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public static final z(Lyy0/i;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    sget-object v0, Lzy0/c;->b:Lj51/i;

    .line 2
    .line 3
    instance-of v1, p1, Lyy0/z0;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p1

    .line 8
    check-cast v1, Lyy0/z0;

    .line 9
    .line 10
    iget v2, v1, Lyy0/z0;->f:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lyy0/z0;->f:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lyy0/z0;

    .line 23
    .line 24
    invoke-direct {v1, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v1, Lyy0/z0;->e:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lyy0/z0;->f:I

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    if-ne v3, v4, :cond_1

    .line 37
    .line 38
    iget-object p0, v1, Lyy0/z0;->d:Lkotlin/jvm/internal/f0;

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    new-instance p1, Lkotlin/jvm/internal/f0;

    .line 56
    .line 57
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 58
    .line 59
    .line 60
    iput-object v0, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 61
    .line 62
    new-instance v3, Lyy0/r0;

    .line 63
    .line 64
    const/4 v5, 0x2

    .line 65
    invoke-direct {v3, p1, v5}, Lyy0/r0;-><init>(Lkotlin/jvm/internal/f0;I)V

    .line 66
    .line 67
    .line 68
    iput-object p1, v1, Lyy0/z0;->d:Lkotlin/jvm/internal/f0;

    .line 69
    .line 70
    iput v4, v1, Lyy0/z0;->f:I

    .line 71
    .line 72
    invoke-interface {p0, v3, v1}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    if-ne p0, v2, :cond_3

    .line 77
    .line 78
    return-object v2

    .line 79
    :cond_3
    move-object p0, p1

    .line 80
    :goto_1
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 81
    .line 82
    if-eq p0, v0, :cond_4

    .line 83
    .line 84
    return-object p0

    .line 85
    :cond_4
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 86
    .line 87
    const-string p1, "Expected at least one element"

    .line 88
    .line 89
    invoke-direct {p0, p1}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0
.end method
