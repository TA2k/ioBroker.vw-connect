.class public final Lo3/g;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/c2;
.implements Lo3/a;


# instance fields
.field public r:Lo3/a;

.field public s:Lo3/d;

.field public t:Lo3/g;

.field public final u:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lo3/a;Lo3/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo3/g;->r:Lo3/a;

    .line 5
    .line 6
    if-nez p2, :cond_0

    .line 7
    .line 8
    new-instance p2, Lo3/d;

    .line 9
    .line 10
    invoke-direct {p2}, Lo3/d;-><init>()V

    .line 11
    .line 12
    .line 13
    :cond_0
    iput-object p2, p0, Lo3/g;->s:Lo3/d;

    .line 14
    .line 15
    const-string p1, "androidx.compose.ui.input.nestedscroll.NestedScrollNode"

    .line 16
    .line 17
    iput-object p1, p0, Lo3/g;->u:Ljava/lang/String;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final P(IJJ)J
    .locals 6

    .line 1
    iget-object v0, p0, Lo3/g;->r:Lo3/a;

    .line 2
    .line 3
    move v1, p1

    .line 4
    move-wide v2, p2

    .line 5
    move-wide v4, p4

    .line 6
    invoke-interface/range {v0 .. v5}, Lo3/a;->P(IJJ)J

    .line 7
    .line 8
    .line 9
    move-result-wide p1

    .line 10
    iget-boolean p3, p0, Lx2/r;->q:Z

    .line 11
    .line 12
    const/4 p4, 0x0

    .line 13
    if-eqz p3, :cond_0

    .line 14
    .line 15
    if-eqz p3, :cond_0

    .line 16
    .line 17
    invoke-static {p0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    move-object p4, p0

    .line 22
    check-cast p4, Lo3/g;

    .line 23
    .line 24
    :cond_0
    move-object v0, p4

    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    invoke-static {v2, v3, p1, p2}, Ld3/b;->h(JJ)J

    .line 28
    .line 29
    .line 30
    move-result-wide v2

    .line 31
    invoke-static {v4, v5, p1, p2}, Ld3/b;->g(JJ)J

    .line 32
    .line 33
    .line 34
    move-result-wide v4

    .line 35
    invoke-virtual/range {v0 .. v5}, Lo3/g;->P(IJJ)J

    .line 36
    .line 37
    .line 38
    move-result-wide p3

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    const-wide/16 p3, 0x0

    .line 41
    .line 42
    :goto_0
    invoke-static {p1, p2, p3, p4}, Ld3/b;->h(JJ)J

    .line 43
    .line 44
    .line 45
    move-result-wide p0

    .line 46
    return-wide p0
.end method

.method public final P0()V
    .locals 3

    .line 1
    iget-object v0, p0, Lo3/g;->s:Lo3/d;

    .line 2
    .line 3
    iput-object p0, v0, Lo3/d;->a:Lo3/g;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    iput-object v1, v0, Lo3/d;->b:Lo3/g;

    .line 7
    .line 8
    iput-object v1, p0, Lo3/g;->t:Lo3/g;

    .line 9
    .line 10
    new-instance v1, La7/j;

    .line 11
    .line 12
    const/16 v2, 0x11

    .line 13
    .line 14
    invoke-direct {v1, p0, v2}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    iput-object v1, v0, Lo3/d;->c:Lkotlin/jvm/internal/n;

    .line 18
    .line 19
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    iput-object p0, v0, Lo3/d;->d:Lvy0/b0;

    .line 24
    .line 25
    return-void
.end method

.method public final Q0()V
    .locals 3

    .line 1
    new-instance v0, Lkotlin/jvm/internal/f0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lo3/h;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-direct {v1, v0, v2}, Lo3/h;-><init>(Lkotlin/jvm/internal/f0;I)V

    .line 10
    .line 11
    .line 12
    invoke-static {p0, v1}, Lv3/f;->B(Lv3/c2;Lay0/k;)V

    .line 13
    .line 14
    .line 15
    iget-object v0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lv3/c2;

    .line 18
    .line 19
    check-cast v0, Lo3/g;

    .line 20
    .line 21
    iput-object v0, p0, Lo3/g;->t:Lo3/g;

    .line 22
    .line 23
    iget-object v1, p0, Lo3/g;->s:Lo3/d;

    .line 24
    .line 25
    iput-object v0, v1, Lo3/d;->b:Lo3/g;

    .line 26
    .line 27
    iget-object v0, v1, Lo3/d;->a:Lo3/g;

    .line 28
    .line 29
    if-ne v0, p0, :cond_0

    .line 30
    .line 31
    const/4 p0, 0x0

    .line 32
    iput-object p0, v1, Lo3/d;->a:Lo3/g;

    .line 33
    .line 34
    :cond_0
    return-void
.end method

.method public final X0()Lvy0/b0;
    .locals 3

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-static {p0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Lo3/g;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-object v0, v1

    .line 14
    :goto_0
    if-eqz v0, :cond_1

    .line 15
    .line 16
    invoke-virtual {v0}, Lo3/g;->X0()Lvy0/b0;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    :cond_1
    if-eqz v1, :cond_2

    .line 21
    .line 22
    invoke-static {v1}, Lvy0/e0;->B(Lvy0/b0;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    const/4 v2, 0x1

    .line 27
    if-ne v0, v2, :cond_2

    .line 28
    .line 29
    return-object v1

    .line 30
    :cond_2
    iget-object p0, p0, Lo3/g;->s:Lo3/d;

    .line 31
    .line 32
    iget-object p0, p0, Lo3/d;->d:Lvy0/b0;

    .line 33
    .line 34
    if-eqz p0, :cond_3

    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    const-string v0, "in order to access nested coroutine scope you need to attach dispatcher to the `Modifier.nestedScroll` first."

    .line 40
    .line 41
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method

.method public final g()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lo3/g;->u:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final i(JJLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p5, Lo3/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p5

    .line 6
    check-cast v0, Lo3/e;

    .line 7
    .line 8
    iget v1, v0, Lo3/e;->h:I

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
    iput v1, v0, Lo3/e;->h:I

    .line 18
    .line 19
    :goto_0
    move-object v6, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v0, Lo3/e;

    .line 22
    .line 23
    check-cast p5, Lrx0/c;

    .line 24
    .line 25
    invoke-direct {v0, p0, p5}, Lo3/e;-><init>(Lo3/g;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :goto_1
    iget-object p5, v6, Lo3/e;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v1, v6, Lo3/e;->h:I

    .line 34
    .line 35
    const/4 v7, 0x2

    .line 36
    const/4 v2, 0x1

    .line 37
    if-eqz v1, :cond_3

    .line 38
    .line 39
    if-eq v1, v2, :cond_2

    .line 40
    .line 41
    if-ne v1, v7, :cond_1

    .line 42
    .line 43
    iget-wide p0, v6, Lo3/e;->d:J

    .line 44
    .line 45
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_5

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget-wide p3, v6, Lo3/e;->e:J

    .line 58
    .line 59
    iget-wide p1, v6, Lo3/e;->d:J

    .line 60
    .line 61
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_3
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lo3/g;->r:Lo3/a;

    .line 69
    .line 70
    iput-wide p1, v6, Lo3/e;->d:J

    .line 71
    .line 72
    iput-wide p3, v6, Lo3/e;->e:J

    .line 73
    .line 74
    iput v2, v6, Lo3/e;->h:I

    .line 75
    .line 76
    move-wide v2, p1

    .line 77
    move-wide v4, p3

    .line 78
    invoke-interface/range {v1 .. v6}, Lo3/a;->i(JJLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p5

    .line 82
    if-ne p5, v0, :cond_4

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_4
    move-wide p1, v2

    .line 86
    move-wide p3, v4

    .line 87
    :goto_2
    check-cast p5, Lt4/q;

    .line 88
    .line 89
    iget-wide v8, p5, Lt4/q;->a:J

    .line 90
    .line 91
    iget-boolean p5, p0, Lx2/r;->q:Z

    .line 92
    .line 93
    if-eqz p5, :cond_5

    .line 94
    .line 95
    const/4 v1, 0x0

    .line 96
    if-eqz p5, :cond_6

    .line 97
    .line 98
    if-eqz p5, :cond_6

    .line 99
    .line 100
    invoke-static {p0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    move-object v1, p0

    .line 105
    check-cast v1, Lo3/g;

    .line 106
    .line 107
    goto :goto_3

    .line 108
    :cond_5
    iget-object v1, p0, Lo3/g;->t:Lo3/g;

    .line 109
    .line 110
    :cond_6
    :goto_3
    if-eqz v1, :cond_8

    .line 111
    .line 112
    invoke-static {p1, p2, v8, v9}, Lt4/q;->e(JJ)J

    .line 113
    .line 114
    .line 115
    move-result-wide v2

    .line 116
    invoke-static {p3, p4, v8, v9}, Lt4/q;->d(JJ)J

    .line 117
    .line 118
    .line 119
    move-result-wide v4

    .line 120
    iput-wide v8, v6, Lo3/e;->d:J

    .line 121
    .line 122
    iput v7, v6, Lo3/e;->h:I

    .line 123
    .line 124
    invoke-virtual/range {v1 .. v6}, Lo3/g;->i(JJLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object p5

    .line 128
    if-ne p5, v0, :cond_7

    .line 129
    .line 130
    :goto_4
    return-object v0

    .line 131
    :cond_7
    move-wide p0, v8

    .line 132
    :goto_5
    check-cast p5, Lt4/q;

    .line 133
    .line 134
    iget-wide p2, p5, Lt4/q;->a:J

    .line 135
    .line 136
    move-wide v8, p0

    .line 137
    goto :goto_6

    .line 138
    :cond_8
    const-wide/16 p2, 0x0

    .line 139
    .line 140
    :goto_6
    invoke-static {v8, v9, p2, p3}, Lt4/q;->e(JJ)J

    .line 141
    .line 142
    .line 143
    move-result-wide p0

    .line 144
    new-instance p2, Lt4/q;

    .line 145
    .line 146
    invoke-direct {p2, p0, p1}, Lt4/q;-><init>(J)V

    .line 147
    .line 148
    .line 149
    return-object p2
.end method

.method public final y0(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lo3/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lo3/f;

    .line 7
    .line 8
    iget v1, v0, Lo3/f;->g:I

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
    iput v1, v0, Lo3/f;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lo3/f;

    .line 21
    .line 22
    check-cast p3, Lrx0/c;

    .line 23
    .line 24
    invoke-direct {v0, p0, p3}, Lo3/f;-><init>(Lo3/g;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p3, v0, Lo3/f;->e:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, v0, Lo3/f;->g:I

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v4, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    iget-wide p0, v0, Lo3/f;->d:J

    .line 42
    .line 43
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_4

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    iget-wide p1, v0, Lo3/f;->d:J

    .line 56
    .line 57
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iget-boolean p3, p0, Lx2/r;->q:Z

    .line 65
    .line 66
    const/4 v2, 0x0

    .line 67
    if-eqz p3, :cond_4

    .line 68
    .line 69
    if-eqz p3, :cond_4

    .line 70
    .line 71
    invoke-static {p0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 72
    .line 73
    .line 74
    move-result-object p3

    .line 75
    move-object v2, p3

    .line 76
    check-cast v2, Lo3/g;

    .line 77
    .line 78
    :cond_4
    if-eqz v2, :cond_6

    .line 79
    .line 80
    iput-wide p1, v0, Lo3/f;->d:J

    .line 81
    .line 82
    iput v4, v0, Lo3/f;->g:I

    .line 83
    .line 84
    invoke-virtual {v2, p1, p2, v0}, Lo3/g;->y0(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p3

    .line 88
    if-ne p3, v1, :cond_5

    .line 89
    .line 90
    goto :goto_3

    .line 91
    :cond_5
    :goto_1
    check-cast p3, Lt4/q;

    .line 92
    .line 93
    iget-wide v4, p3, Lt4/q;->a:J

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_6
    const-wide/16 v4, 0x0

    .line 97
    .line 98
    :goto_2
    iget-object p0, p0, Lo3/g;->r:Lo3/a;

    .line 99
    .line 100
    invoke-static {p1, p2, v4, v5}, Lt4/q;->d(JJ)J

    .line 101
    .line 102
    .line 103
    move-result-wide p1

    .line 104
    iput-wide v4, v0, Lo3/f;->d:J

    .line 105
    .line 106
    iput v3, v0, Lo3/f;->g:I

    .line 107
    .line 108
    invoke-interface {p0, p1, p2, v0}, Lo3/a;->y0(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p3

    .line 112
    if-ne p3, v1, :cond_7

    .line 113
    .line 114
    :goto_3
    return-object v1

    .line 115
    :cond_7
    move-wide p0, v4

    .line 116
    :goto_4
    check-cast p3, Lt4/q;

    .line 117
    .line 118
    iget-wide p2, p3, Lt4/q;->a:J

    .line 119
    .line 120
    invoke-static {p0, p1, p2, p3}, Lt4/q;->e(JJ)J

    .line 121
    .line 122
    .line 123
    move-result-wide p0

    .line 124
    new-instance p2, Lt4/q;

    .line 125
    .line 126
    invoke-direct {p2, p0, p1}, Lt4/q;-><init>(J)V

    .line 127
    .line 128
    .line 129
    return-object p2
.end method

.method public final z(IJ)J
    .locals 2

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-static {p0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    move-object v1, v0

    .line 13
    check-cast v1, Lo3/g;

    .line 14
    .line 15
    :cond_0
    if-eqz v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {v1, p1, p2, p3}, Lo3/g;->z(IJ)J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    goto :goto_0

    .line 22
    :cond_1
    const-wide/16 v0, 0x0

    .line 23
    .line 24
    :goto_0
    iget-object p0, p0, Lo3/g;->r:Lo3/a;

    .line 25
    .line 26
    invoke-static {p2, p3, v0, v1}, Ld3/b;->g(JJ)J

    .line 27
    .line 28
    .line 29
    move-result-wide p2

    .line 30
    invoke-interface {p0, p1, p2, p3}, Lo3/a;->z(IJ)J

    .line 31
    .line 32
    .line 33
    move-result-wide p0

    .line 34
    invoke-static {v0, v1, p0, p1}, Ld3/b;->h(JJ)J

    .line 35
    .line 36
    .line 37
    move-result-wide p0

    .line 38
    return-wide p0
.end method
