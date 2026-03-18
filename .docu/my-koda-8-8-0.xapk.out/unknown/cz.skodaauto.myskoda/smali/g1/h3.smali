.class public abstract Lg1/h3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lfw0/i0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfw0/i0;

    .line 2
    .line 3
    const/16 v1, 0x9

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lfw0/i0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lg1/h3;->a:Lfw0/i0;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lg1/q2;FLc1/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Lg1/a2;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lg1/a2;

    .line 7
    .line 8
    iget v1, v0, Lg1/a2;->f:I

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
    iput v1, v0, Lg1/a2;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/a2;

    .line 21
    .line 22
    invoke-direct {v0, p3}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lg1/a2;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/a2;->f:I

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
    iget-object p0, v0, Lg1/a2;->d:Lkotlin/jvm/internal/c0;

    .line 37
    .line 38
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance p3, Lkotlin/jvm/internal/c0;

    .line 54
    .line 55
    invoke-direct {p3}, Ljava/lang/Object;-><init>()V

    .line 56
    .line 57
    .line 58
    new-instance v2, Lf2/o;

    .line 59
    .line 60
    const/4 v4, 0x0

    .line 61
    invoke-direct {v2, p1, p2, p3, v4}, Lf2/o;-><init>(FLc1/j;Lkotlin/jvm/internal/c0;Lkotlin/coroutines/Continuation;)V

    .line 62
    .line 63
    .line 64
    iput-object p3, v0, Lg1/a2;->d:Lkotlin/jvm/internal/c0;

    .line 65
    .line 66
    iput v3, v0, Lg1/a2;->f:I

    .line 67
    .line 68
    sget-object p1, Le1/w0;->d:Le1/w0;

    .line 69
    .line 70
    invoke-interface {p0, p1, v2, v0}, Lg1/q2;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    if-ne p0, v1, :cond_3

    .line 75
    .line 76
    return-object v1

    .line 77
    :cond_3
    move-object p0, p3

    .line 78
    :goto_1
    iget p0, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 79
    .line 80
    new-instance p1, Ljava/lang/Float;

    .line 81
    .line 82
    invoke-direct {p1, p0}, Ljava/lang/Float;-><init>(F)V

    .line 83
    .line 84
    .line 85
    return-object p1
.end method

.method public static final b(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lg1/k1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lg1/k1;

    .line 7
    .line 8
    iget v1, v0, Lg1/k1;->g:I

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
    iput v1, v0, Lg1/k1;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/k1;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lg1/k1;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/k1;->g:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v4, :cond_1

    .line 36
    .line 37
    iget-object p0, v0, Lg1/k1;->e:Lp3/l;

    .line 38
    .line 39
    iget-object p1, v0, Lg1/k1;->d:Lp3/i0;

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    move-object v7, p1

    .line 45
    move-object p1, p0

    .line 46
    move-object p0, v7

    .line 47
    goto :goto_3

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
    iget-object p2, p0, Lp3/i0;->i:Lp3/j0;

    .line 60
    .line 61
    iget-object p2, p2, Lp3/j0;->w:Lp3/k;

    .line 62
    .line 63
    iget-object p2, p2, Lp3/k;->a:Ljava/lang/Object;

    .line 64
    .line 65
    move-object v2, p2

    .line 66
    check-cast v2, Ljava/util/Collection;

    .line 67
    .line 68
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    move v5, v3

    .line 73
    :goto_1
    if-ge v5, v2, :cond_6

    .line 74
    .line 75
    invoke-interface {p2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v6

    .line 79
    check-cast v6, Lp3/t;

    .line 80
    .line 81
    iget-boolean v6, v6, Lp3/t;->d:Z

    .line 82
    .line 83
    if-eqz v6, :cond_5

    .line 84
    .line 85
    :goto_2
    iput-object p0, v0, Lg1/k1;->d:Lp3/i0;

    .line 86
    .line 87
    iput-object p1, v0, Lg1/k1;->e:Lp3/l;

    .line 88
    .line 89
    iput v4, v0, Lg1/k1;->g:I

    .line 90
    .line 91
    invoke-virtual {p0, p1, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p2

    .line 95
    if-ne p2, v1, :cond_3

    .line 96
    .line 97
    return-object v1

    .line 98
    :cond_3
    :goto_3
    check-cast p2, Lp3/k;

    .line 99
    .line 100
    iget-object p2, p2, Lp3/k;->a:Ljava/lang/Object;

    .line 101
    .line 102
    move-object v2, p2

    .line 103
    check-cast v2, Ljava/util/Collection;

    .line 104
    .line 105
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    move v5, v3

    .line 110
    :goto_4
    if-ge v5, v2, :cond_6

    .line 111
    .line 112
    invoke-interface {p2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v6

    .line 116
    check-cast v6, Lp3/t;

    .line 117
    .line 118
    iget-boolean v6, v6, Lp3/t;->d:Z

    .line 119
    .line 120
    if-eqz v6, :cond_4

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_4
    add-int/lit8 v5, v5, 0x1

    .line 124
    .line 125
    goto :goto_4

    .line 126
    :cond_5
    add-int/lit8 v5, v5, 0x1

    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 130
    .line 131
    return-object p0
.end method

.method public static final c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-interface {p2}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lg1/l1;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-direct {v1, v0, p1, v2}, Lg1/l1;-><init>(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    check-cast p0, Lp3/j0;

    .line 12
    .line 13
    invoke-virtual {p0, v1, p2}, Lp3/j0;->X0(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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

.method public static final d(Lp3/k;Z)J
    .locals 7

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
    const-wide/16 v1, 0x0

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    move v4, v3

    .line 14
    :goto_0
    if-ge v3, v0, :cond_2

    .line 15
    .line 16
    invoke-interface {p0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v5

    .line 20
    check-cast v5, Lp3/t;

    .line 21
    .line 22
    iget-boolean v6, v5, Lp3/t;->d:Z

    .line 23
    .line 24
    if-eqz v6, :cond_1

    .line 25
    .line 26
    iget-boolean v6, v5, Lp3/t;->h:Z

    .line 27
    .line 28
    if-eqz v6, :cond_1

    .line 29
    .line 30
    if-eqz p1, :cond_0

    .line 31
    .line 32
    iget-wide v5, v5, Lp3/t;->c:J

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_0
    iget-wide v5, v5, Lp3/t;->g:J

    .line 36
    .line 37
    :goto_1
    invoke-static {v1, v2, v5, v6}, Ld3/b;->h(JJ)J

    .line 38
    .line 39
    .line 40
    move-result-wide v1

    .line 41
    add-int/lit8 v4, v4, 0x1

    .line 42
    .line 43
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    if-nez v4, :cond_3

    .line 47
    .line 48
    const-wide p0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    return-wide p0

    .line 54
    :cond_3
    int-to-float p0, v4

    .line 55
    invoke-static {v1, v2, p0}, Ld3/b;->b(JF)J

    .line 56
    .line 57
    .line 58
    move-result-wide p0

    .line 59
    return-wide p0
.end method

.method public static final e(Lp3/k;Z)F
    .locals 8

    .line 1
    invoke-static {p0, p1}, Lg1/h3;->d(Lp3/k;Z)J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-wide v2, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    invoke-static {v0, v1, v2, v3}, Ld3/b;->c(JJ)Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    const/4 v3, 0x0

    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    return v3

    .line 18
    :cond_0
    iget-object p0, p0, Lp3/k;->a:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v2, p0

    .line 21
    check-cast v2, Ljava/util/Collection;

    .line 22
    .line 23
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    const/4 v4, 0x0

    .line 28
    move v5, v4

    .line 29
    :goto_0
    if-ge v4, v2, :cond_3

    .line 30
    .line 31
    invoke-interface {p0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v6

    .line 35
    check-cast v6, Lp3/t;

    .line 36
    .line 37
    iget-boolean v7, v6, Lp3/t;->d:Z

    .line 38
    .line 39
    if-eqz v7, :cond_2

    .line 40
    .line 41
    iget-boolean v7, v6, Lp3/t;->h:Z

    .line 42
    .line 43
    if-eqz v7, :cond_2

    .line 44
    .line 45
    if-eqz p1, :cond_1

    .line 46
    .line 47
    iget-wide v6, v6, Lp3/t;->c:J

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    iget-wide v6, v6, Lp3/t;->g:J

    .line 51
    .line 52
    :goto_1
    invoke-static {v6, v7, v0, v1}, Ld3/b;->g(JJ)J

    .line 53
    .line 54
    .line 55
    move-result-wide v6

    .line 56
    invoke-static {v6, v7}, Ld3/b;->d(J)F

    .line 57
    .line 58
    .line 59
    move-result v6

    .line 60
    add-float/2addr v6, v3

    .line 61
    add-int/lit8 v5, v5, 0x1

    .line 62
    .line 63
    move v3, v6

    .line 64
    :cond_2
    add-int/lit8 v4, v4, 0x1

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_3
    int-to-float p0, v5

    .line 68
    div-float/2addr v3, p0

    .line 69
    return v3
.end method

.method public static final f(Lg1/f0;FLrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lg1/b2;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lg1/b2;

    .line 7
    .line 8
    iget v1, v0, Lg1/b2;->f:I

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
    iput v1, v0, Lg1/b2;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/b2;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lg1/b2;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/b2;->f:I

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
    iget-object p0, v0, Lg1/b2;->d:Lkotlin/jvm/internal/c0;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    new-instance p2, Lkotlin/jvm/internal/c0;

    .line 54
    .line 55
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 56
    .line 57
    .line 58
    new-instance v2, Lg1/c2;

    .line 59
    .line 60
    const/4 v4, 0x0

    .line 61
    invoke-direct {v2, p2, p1, v4}, Lg1/c2;-><init>(Lkotlin/jvm/internal/c0;FLkotlin/coroutines/Continuation;)V

    .line 62
    .line 63
    .line 64
    iput-object p2, v0, Lg1/b2;->d:Lkotlin/jvm/internal/c0;

    .line 65
    .line 66
    iput v3, v0, Lg1/b2;->f:I

    .line 67
    .line 68
    sget-object p1, Le1/w0;->d:Le1/w0;

    .line 69
    .line 70
    invoke-virtual {p0, p1, v2, v0}, Lg1/f0;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    if-ne p0, v1, :cond_3

    .line 75
    .line 76
    return-object v1

    .line 77
    :cond_3
    move-object p0, p2

    .line 78
    :goto_1
    iget p0, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 79
    .line 80
    new-instance p1, Ljava/lang/Float;

    .line 81
    .line 82
    invoke-direct {p1, p0}, Ljava/lang/Float;-><init>(F)V

    .line 83
    .line 84
    .line 85
    return-object p1
.end method
