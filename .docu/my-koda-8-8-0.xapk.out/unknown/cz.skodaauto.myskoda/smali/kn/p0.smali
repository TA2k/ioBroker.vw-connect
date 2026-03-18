.class public final Lkn/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo3/a;


# instance fields
.field public final d:Lkn/c0;

.field public final e:Lvy0/b0;

.field public f:Lkn/f0;


# direct methods
.method public constructor <init>(Lkn/c0;Lvy0/b0;)V
    .locals 1

    .line 1
    const-string v0, "state"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lkn/p0;->d:Lkn/c0;

    .line 10
    .line 11
    iput-object p2, p0, Lkn/p0;->e:Lvy0/b0;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final P(IJJ)J
    .locals 0

    .line 1
    const/4 p2, 0x1

    .line 2
    if-ne p1, p2, :cond_0

    .line 3
    .line 4
    invoke-static {p4, p5}, Ld3/b;->f(J)F

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    const/4 p2, 0x0

    .line 9
    cmpl-float p1, p1, p2

    .line 10
    .line 11
    if-lez p1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0, p4, p5}, Lkn/p0;->a(J)J

    .line 14
    .line 15
    .line 16
    move-result-wide p0

    .line 17
    return-wide p0

    .line 18
    :cond_0
    const-wide/16 p0, 0x0

    .line 19
    .line 20
    return-wide p0
.end method

.method public final a(J)J
    .locals 8

    .line 1
    iget-object v0, p0, Lkn/p0;->d:Lkn/c0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lkn/c0;->g()F

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-static {p1, p2}, Ld3/b;->f(J)F

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    add-float/2addr v1, v0

    .line 12
    const/4 v0, 0x0

    .line 13
    cmpl-float v1, v1, v0

    .line 14
    .line 15
    if-ltz v1, :cond_0

    .line 16
    .line 17
    new-instance v2, Le2/f0;

    .line 18
    .line 19
    const/4 v7, 0x3

    .line 20
    const/4 v6, 0x0

    .line 21
    move-object v3, p0

    .line 22
    move-wide v4, p1

    .line 23
    invoke-direct/range {v2 .. v7}, Le2/f0;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    const/4 p0, 0x3

    .line 27
    iget-object p1, v3, Lkn/p0;->e:Lvy0/b0;

    .line 28
    .line 29
    invoke-static {p1, v6, v6, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 30
    .line 31
    .line 32
    invoke-static {v4, v5}, Ld3/b;->f(J)F

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    invoke-static {v0, p0}, Ljp/bf;->a(FF)J

    .line 37
    .line 38
    .line 39
    move-result-wide p0

    .line 40
    return-wide p0

    .line 41
    :cond_0
    const-wide/16 p0, 0x0

    .line 42
    .line 43
    return-wide p0
.end method

.method public final y0(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Lkn/o0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lkn/o0;

    .line 7
    .line 8
    iget v1, v0, Lkn/o0;->h:I

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
    iput v1, v0, Lkn/o0;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkn/o0;

    .line 21
    .line 22
    check-cast p3, Lrx0/c;

    .line 23
    .line 24
    invoke-direct {v0, p0, p3}, Lkn/o0;-><init>(Lkn/p0;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p3, v0, Lkn/o0;->f:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, v0, Lkn/o0;->h:I

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v3, :cond_1

    .line 37
    .line 38
    iget-wide p1, v0, Lkn/o0;->e:J

    .line 39
    .line 40
    iget-object p0, v0, Lkn/o0;->d:Lkn/p0;

    .line 41
    .line 42
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_2

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
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-object p3, p0, Lkn/p0;->d:Lkn/c0;

    .line 58
    .line 59
    iget-object v2, p3, Lkn/c0;->f:Lc1/c;

    .line 60
    .line 61
    invoke-virtual {v2}, Lc1/c;->e()Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-nez v2, :cond_6

    .line 66
    .line 67
    iget-boolean v2, p3, Lkn/c0;->n:Z

    .line 68
    .line 69
    if-eqz v2, :cond_3

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_3
    invoke-virtual {p3}, Lkn/c0;->g()F

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    const/4 v4, 0x0

    .line 77
    cmpg-float v2, v2, v4

    .line 78
    .line 79
    if-nez v2, :cond_4

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_4
    iput-object p0, v0, Lkn/o0;->d:Lkn/p0;

    .line 83
    .line 84
    iput-wide p1, v0, Lkn/o0;->e:J

    .line 85
    .line 86
    iput v3, v0, Lkn/o0;->h:I

    .line 87
    .line 88
    new-instance v2, Li50/p;

    .line 89
    .line 90
    const/4 v3, 0x0

    .line 91
    const/16 v4, 0x12

    .line 92
    .line 93
    invoke-direct {v2, p3, v3, v4}, Li50/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 94
    .line 95
    .line 96
    invoke-static {v2, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p3

    .line 100
    if-ne p3, v1, :cond_5

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_5
    sget-object p3, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    :goto_1
    if-ne p3, v1, :cond_6

    .line 106
    .line 107
    return-object v1

    .line 108
    :cond_6
    :goto_2
    iget-object p3, p0, Lkn/p0;->f:Lkn/f0;

    .line 109
    .line 110
    sget-object v0, Lkn/f0;->d:Lkn/f0;

    .line 111
    .line 112
    if-ne p3, v0, :cond_8

    .line 113
    .line 114
    iget-object p0, p0, Lkn/p0;->d:Lkn/c0;

    .line 115
    .line 116
    invoke-virtual {p0}, Lkn/c0;->i()Lkn/f0;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    sget-object p3, Lkn/f0;->e:Lkn/f0;

    .line 121
    .line 122
    if-ne p0, p3, :cond_7

    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_7
    const-wide/16 p1, 0x0

    .line 126
    .line 127
    :cond_8
    :goto_3
    new-instance p0, Lt4/q;

    .line 128
    .line 129
    invoke-direct {p0, p1, p2}, Lt4/q;-><init>(J)V

    .line 130
    .line 131
    .line 132
    return-object p0
.end method

.method public final z(IJ)J
    .locals 1

    .line 1
    iget-object v0, p0, Lkn/p0;->d:Lkn/c0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lkn/c0;->i()Lkn/f0;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iput-object v0, p0, Lkn/p0;->f:Lkn/f0;

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    if-ne p1, v0, :cond_0

    .line 11
    .line 12
    invoke-static {p2, p3}, Ld3/b;->f(J)F

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    const/4 v0, 0x0

    .line 17
    cmpg-float p1, p1, v0

    .line 18
    .line 19
    if-gez p1, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0, p2, p3}, Lkn/p0;->a(J)J

    .line 22
    .line 23
    .line 24
    move-result-wide p0

    .line 25
    return-wide p0

    .line 26
    :cond_0
    const-wide/16 p0, 0x0

    .line 27
    .line 28
    return-wide p0
.end method
