.class public abstract Lg1/g3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lg1/e1;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lg1/e1;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x2

    .line 5
    const/4 v3, 0x0

    .line 6
    invoke-direct {v0, v1, v3, v2}, Lg1/e1;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lg1/g3;->a:Lg1/e1;

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Lp3/i0;Lrx0/a;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Lg1/x2;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lg1/x2;

    .line 7
    .line 8
    iget v1, v0, Lg1/x2;->f:I

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
    iput v1, v0, Lg1/x2;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/x2;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lg1/x2;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/x2;->f:I

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
    iget-object p0, v0, Lg1/x2;->d:Lp3/i0;

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_2

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
    :goto_1
    iput-object p0, v0, Lg1/x2;->d:Lp3/i0;

    .line 54
    .line 55
    iput v3, v0, Lg1/x2;->f:I

    .line 56
    .line 57
    sget-object p1, Lp3/l;->e:Lp3/l;

    .line 58
    .line 59
    invoke-virtual {p0, p1, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    if-ne p1, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_2
    check-cast p1, Lp3/k;

    .line 67
    .line 68
    iget-object v2, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 69
    .line 70
    move-object v4, v2

    .line 71
    check-cast v4, Ljava/util/Collection;

    .line 72
    .line 73
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    const/4 v5, 0x0

    .line 78
    move v6, v5

    .line 79
    :goto_3
    if-ge v6, v4, :cond_4

    .line 80
    .line 81
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    check-cast v7, Lp3/t;

    .line 86
    .line 87
    invoke-virtual {v7}, Lp3/t;->a()V

    .line 88
    .line 89
    .line 90
    add-int/lit8 v6, v6, 0x1

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_4
    iget-object p1, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 94
    .line 95
    move-object v2, p1

    .line 96
    check-cast v2, Ljava/util/Collection;

    .line 97
    .line 98
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    :goto_4
    if-ge v5, v2, :cond_6

    .line 103
    .line 104
    invoke-interface {p1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v4

    .line 108
    check-cast v4, Lp3/t;

    .line 109
    .line 110
    iget-boolean v4, v4, Lp3/t;->d:Z

    .line 111
    .line 112
    if-eqz v4, :cond_5

    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_5
    add-int/lit8 v5, v5, 0x1

    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    return-object p0
.end method

.method public static final b(Lp3/i0;ZLp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Lg1/v2;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lg1/v2;

    .line 7
    .line 8
    iget v1, v0, Lg1/v2;->h:I

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
    iput v1, v0, Lg1/v2;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/v2;

    .line 21
    .line 22
    invoke-direct {v0, p3}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lg1/v2;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/v2;->h:I

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
    iget-boolean p0, v0, Lg1/v2;->f:Z

    .line 37
    .line 38
    iget-object p1, v0, Lg1/v2;->e:Lp3/l;

    .line 39
    .line 40
    iget-object p2, v0, Lg1/v2;->d:Lp3/i0;

    .line 41
    .line 42
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    move-object v4, p1

    .line 46
    move p1, p0

    .line 47
    move-object p0, p2

    .line 48
    move-object p2, v4

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    :cond_3
    iput-object p0, v0, Lg1/v2;->d:Lp3/i0;

    .line 62
    .line 63
    iput-object p2, v0, Lg1/v2;->e:Lp3/l;

    .line 64
    .line 65
    iput-boolean p1, v0, Lg1/v2;->f:Z

    .line 66
    .line 67
    iput v3, v0, Lg1/v2;->h:I

    .line 68
    .line 69
    invoke-virtual {p0, p2, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p3

    .line 73
    if-ne p3, v1, :cond_4

    .line 74
    .line 75
    return-object v1

    .line 76
    :cond_4
    :goto_1
    check-cast p3, Lp3/k;

    .line 77
    .line 78
    invoke-static {p3, p1}, Lg1/g3;->f(Lp3/k;Z)Z

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    if-eqz v2, :cond_3

    .line 83
    .line 84
    iget-object p0, p3, Lp3/k;->a:Ljava/lang/Object;

    .line 85
    .line 86
    const/4 p1, 0x0

    .line 87
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    return-object p0
.end method

.method public static synthetic c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Lp3/l;->d:Lp3/l;

    .line 2
    .line 3
    and-int/lit8 v1, p2, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 v1, 0x0

    .line 10
    :goto_0
    and-int/lit8 p2, p2, 0x2

    .line 11
    .line 12
    if-eqz p2, :cond_1

    .line 13
    .line 14
    sget-object v0, Lp3/l;->e:Lp3/l;

    .line 15
    .line 16
    :cond_1
    invoke-static {p0, v1, v0, p1}, Lg1/g3;->b(Lp3/i0;ZLp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static final d(Lp3/x;Lay0/k;Lay0/k;Lay0/o;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    new-instance v0, La7/k0;

    .line 2
    .line 3
    const/4 v6, 0x0

    .line 4
    const/4 v7, 0x4

    .line 5
    move-object v1, p0

    .line 6
    move-object v4, p1

    .line 7
    move-object v3, p2

    .line 8
    move-object v2, p3

    .line 9
    move-object v5, p4

    .line 10
    invoke-direct/range {v0 .. v7}, La7/k0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    invoke-static {v0, p5}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 18
    .line 19
    if-ne p0, p1, :cond_0

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method

.method public static synthetic e(Lp3/x;Lay0/o;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;
    .locals 8

    .line 1
    and-int/lit8 v0, p4, 0x2

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object v4, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    sget-object v0, Ljn/f;->f:Ljn/f;

    .line 9
    .line 10
    move-object v4, v0

    .line 11
    :goto_0
    and-int/lit8 v0, p4, 0x4

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    sget-object p1, Lg1/g3;->a:Lg1/e1;

    .line 16
    .line 17
    :cond_1
    move-object v5, p1

    .line 18
    and-int/lit8 p1, p4, 0x8

    .line 19
    .line 20
    if-eqz p1, :cond_2

    .line 21
    .line 22
    move-object v6, v1

    .line 23
    goto :goto_1

    .line 24
    :cond_2
    move-object v6, p2

    .line 25
    :goto_1
    const/4 v3, 0x0

    .line 26
    move-object v2, p0

    .line 27
    move-object v7, p3

    .line 28
    invoke-static/range {v2 .. v7}, Lg1/g3;->d(Lp3/x;Lay0/k;Lay0/k;Lay0/o;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method public static f(Lp3/k;Z)Z
    .locals 4

    .line 1
    iget-object p0, p0, Lp3/k;->a:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    check-cast v0, Ljava/util/Collection;

    .line 5
    .line 6
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x0

    .line 11
    move v2, v1

    .line 12
    :goto_0
    if-ge v2, v0, :cond_2

    .line 13
    .line 14
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    check-cast v3, Lp3/t;

    .line 19
    .line 20
    if-eqz p1, :cond_0

    .line 21
    .line 22
    invoke-static {v3}, Lp3/s;->a(Lp3/t;)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    goto :goto_1

    .line 27
    :cond_0
    invoke-static {v3}, Lp3/s;->b(Lp3/t;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    :goto_1
    if-nez v3, :cond_1

    .line 32
    .line 33
    return v1

    .line 34
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_2
    const/4 p0, 0x1

    .line 38
    return p0
.end method

.method public static g(Lvy0/b0;Lvy0/i1;Lay0/n;)Lvy0/x1;
    .locals 4

    .line 1
    sget-object v0, Lvy0/c0;->g:Lvy0/c0;

    .line 2
    .line 3
    new-instance v1, Lg1/d3;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v1, p1, p2, v3, v2}, Lg1/d3;-><init>(Lvy0/i1;Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 8
    .line 9
    .line 10
    const/4 p1, 0x1

    .line 11
    invoke-static {p0, v3, v0, v1, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static final h(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lg1/e3;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lg1/e3;

    .line 7
    .line 8
    iget v1, v0, Lg1/e3;->f:I

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
    iput v1, v0, Lg1/e3;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/e3;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lg1/e3;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/e3;->f:I

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
    iget-object p0, v0, Lg1/e3;->d:Lkotlin/jvm/internal/f0;

    .line 37
    .line 38
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lp3/n; {:try_start_0 .. :try_end_0} :catch_0

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance p2, Lkotlin/jvm/internal/f0;

    .line 54
    .line 55
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 56
    .line 57
    .line 58
    sget-object v2, Lg1/m1;->a:Lg1/m1;

    .line 59
    .line 60
    iput-object v2, p2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 61
    .line 62
    :try_start_1
    invoke-virtual {p0}, Lp3/i0;->f()Lw3/h2;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    invoke-interface {v2}, Lw3/h2;->b()J

    .line 67
    .line 68
    .line 69
    move-result-wide v4

    .line 70
    new-instance v2, Lg1/l1;

    .line 71
    .line 72
    const/4 v6, 0x0

    .line 73
    const/4 v7, 0x2

    .line 74
    invoke-direct {v2, v7, p1, p2, v6}, Lg1/l1;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 75
    .line 76
    .line 77
    iput-object p2, v0, Lg1/e3;->d:Lkotlin/jvm/internal/f0;

    .line 78
    .line 79
    iput v3, v0, Lg1/e3;->f:I

    .line 80
    .line 81
    invoke-virtual {p0, v4, v5, v2, v0}, Lp3/i0;->g(JLay0/n;Lrx0/a;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0
    :try_end_1
    .catch Lp3/n; {:try_start_1 .. :try_end_1} :catch_0

    .line 85
    if-ne p0, v1, :cond_3

    .line 86
    .line 87
    return-object v1

    .line 88
    :cond_3
    move-object p0, p2

    .line 89
    :goto_1
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 90
    .line 91
    return-object p0

    .line 92
    :catch_0
    sget-object p0, Lg1/o1;->a:Lg1/o1;

    .line 93
    .line 94
    return-object p0
.end method

.method public static final i(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p2, Lg1/f3;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lg1/f3;

    .line 7
    .line 8
    iget v1, v0, Lg1/f3;->g:I

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
    iput v1, v0, Lg1/f3;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/f3;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lg1/f3;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/f3;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x0

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_4

    .line 35
    .line 36
    if-eq v2, v5, :cond_3

    .line 37
    .line 38
    if-ne v2, v3, :cond_2

    .line 39
    .line 40
    iget-object p0, v0, Lg1/f3;->e:Lp3/l;

    .line 41
    .line 42
    iget-object p1, v0, Lg1/f3;->d:Lp3/i0;

    .line 43
    .line 44
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    :cond_1
    move-object v12, p1

    .line 48
    move-object p1, p0

    .line 49
    move-object p0, v12

    .line 50
    goto/16 :goto_5

    .line 51
    .line 52
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_3
    iget-object p0, v0, Lg1/f3;->e:Lp3/l;

    .line 61
    .line 62
    iget-object p1, v0, Lg1/f3;->d:Lp3/i0;

    .line 63
    .line 64
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    :cond_5
    iput-object p0, v0, Lg1/f3;->d:Lp3/i0;

    .line 72
    .line 73
    iput-object p1, v0, Lg1/f3;->e:Lp3/l;

    .line 74
    .line 75
    iput v5, v0, Lg1/f3;->g:I

    .line 76
    .line 77
    invoke-virtual {p0, p1, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    if-ne p2, v1, :cond_6

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_6
    move-object v12, p1

    .line 85
    move-object p1, p0

    .line 86
    move-object p0, v12

    .line 87
    :goto_1
    check-cast p2, Lp3/k;

    .line 88
    .line 89
    iget-object p2, p2, Lp3/k;->a:Ljava/lang/Object;

    .line 90
    .line 91
    move-object v2, p2

    .line 92
    check-cast v2, Ljava/util/Collection;

    .line 93
    .line 94
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    move v6, v4

    .line 99
    :goto_2
    if-ge v6, v2, :cond_c

    .line 100
    .line 101
    invoke-interface {p2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v7

    .line 105
    check-cast v7, Lp3/t;

    .line 106
    .line 107
    invoke-static {v7}, Lp3/s;->c(Lp3/t;)Z

    .line 108
    .line 109
    .line 110
    move-result v7

    .line 111
    if-nez v7, :cond_b

    .line 112
    .line 113
    move-object v2, p2

    .line 114
    check-cast v2, Ljava/util/Collection;

    .line 115
    .line 116
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 117
    .line 118
    .line 119
    move-result v2

    .line 120
    move v6, v4

    .line 121
    :goto_3
    if-ge v6, v2, :cond_8

    .line 122
    .line 123
    invoke-interface {p2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v7

    .line 127
    check-cast v7, Lp3/t;

    .line 128
    .line 129
    invoke-virtual {v7}, Lp3/t;->b()Z

    .line 130
    .line 131
    .line 132
    move-result v8

    .line 133
    if-nez v8, :cond_9

    .line 134
    .line 135
    iget-object v8, p1, Lp3/i0;->i:Lp3/j0;

    .line 136
    .line 137
    iget-wide v8, v8, Lp3/j0;->B:J

    .line 138
    .line 139
    invoke-virtual {p1}, Lp3/i0;->d()J

    .line 140
    .line 141
    .line 142
    move-result-wide v10

    .line 143
    invoke-static {v7, v8, v9, v10, v11}, Lp3/s;->f(Lp3/t;JJ)Z

    .line 144
    .line 145
    .line 146
    move-result v7

    .line 147
    if-eqz v7, :cond_7

    .line 148
    .line 149
    goto :goto_7

    .line 150
    :cond_7
    add-int/lit8 v6, v6, 0x1

    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_8
    sget-object p2, Lp3/l;->f:Lp3/l;

    .line 154
    .line 155
    iput-object p1, v0, Lg1/f3;->d:Lp3/i0;

    .line 156
    .line 157
    iput-object p0, v0, Lg1/f3;->e:Lp3/l;

    .line 158
    .line 159
    iput v3, v0, Lg1/f3;->g:I

    .line 160
    .line 161
    invoke-virtual {p1, p2, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object p2

    .line 165
    if-ne p2, v1, :cond_1

    .line 166
    .line 167
    :goto_4
    return-object v1

    .line 168
    :goto_5
    check-cast p2, Lp3/k;

    .line 169
    .line 170
    iget-object p2, p2, Lp3/k;->a:Ljava/lang/Object;

    .line 171
    .line 172
    move-object v2, p2

    .line 173
    check-cast v2, Ljava/util/Collection;

    .line 174
    .line 175
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 176
    .line 177
    .line 178
    move-result v2

    .line 179
    move v6, v4

    .line 180
    :goto_6
    if-ge v6, v2, :cond_5

    .line 181
    .line 182
    invoke-interface {p2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v7

    .line 186
    check-cast v7, Lp3/t;

    .line 187
    .line 188
    invoke-virtual {v7}, Lp3/t;->b()Z

    .line 189
    .line 190
    .line 191
    move-result v7

    .line 192
    if-eqz v7, :cond_a

    .line 193
    .line 194
    :cond_9
    :goto_7
    const/4 p0, 0x0

    .line 195
    return-object p0

    .line 196
    :cond_a
    add-int/lit8 v6, v6, 0x1

    .line 197
    .line 198
    goto :goto_6

    .line 199
    :cond_b
    add-int/lit8 v6, v6, 0x1

    .line 200
    .line 201
    goto :goto_2

    .line 202
    :cond_c
    invoke-interface {p2, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    return-object p0
.end method
