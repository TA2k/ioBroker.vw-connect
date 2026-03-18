.class public final Lg1/u2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Lg1/q2;

.field public b:Le1/j;

.field public c:Lg1/j1;

.field public d:Lg1/w1;

.field public e:Z

.field public f:Lo3/d;

.field public final g:Lg1/p2;

.field public final h:Ld2/g;

.field public i:Z

.field public j:I

.field public k:Lg1/e2;

.field public final l:Lg1/t2;

.field public final m:Le81/w;


# direct methods
.method public constructor <init>(Lg1/q2;Le1/j;Lg1/j1;Lg1/w1;ZLo3/d;Lg1/p2;Ld2/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lg1/u2;->a:Lg1/q2;

    .line 5
    .line 6
    iput-object p2, p0, Lg1/u2;->b:Le1/j;

    .line 7
    .line 8
    iput-object p3, p0, Lg1/u2;->c:Lg1/j1;

    .line 9
    .line 10
    iput-object p4, p0, Lg1/u2;->d:Lg1/w1;

    .line 11
    .line 12
    iput-boolean p5, p0, Lg1/u2;->e:Z

    .line 13
    .line 14
    iput-object p6, p0, Lg1/u2;->f:Lo3/d;

    .line 15
    .line 16
    iput-object p7, p0, Lg1/u2;->g:Lg1/p2;

    .line 17
    .line 18
    iput-object p8, p0, Lg1/u2;->h:Ld2/g;

    .line 19
    .line 20
    const/4 p1, 0x1

    .line 21
    iput p1, p0, Lg1/u2;->j:I

    .line 22
    .line 23
    sget-object p1, Landroidx/compose/foundation/gestures/b;->b:Lg1/h2;

    .line 24
    .line 25
    iput-object p1, p0, Lg1/u2;->k:Lg1/e2;

    .line 26
    .line 27
    new-instance p1, Lg1/t2;

    .line 28
    .line 29
    invoke-direct {p1, p0}, Lg1/t2;-><init>(Lg1/u2;)V

    .line 30
    .line 31
    .line 32
    iput-object p1, p0, Lg1/u2;->l:Lg1/t2;

    .line 33
    .line 34
    new-instance p1, Le81/w;

    .line 35
    .line 36
    const/16 p2, 0xe

    .line 37
    .line 38
    invoke-direct {p1, p0, p2}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 39
    .line 40
    .line 41
    iput-object p1, p0, Lg1/u2;->m:Le81/w;

    .line 42
    .line 43
    return-void
.end method


# virtual methods
.method public final a(JLrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p3, Lg1/r2;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lg1/r2;

    .line 7
    .line 8
    iget v1, v0, Lg1/r2;->g:I

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
    iput v1, v0, Lg1/r2;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/r2;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lg1/r2;-><init>(Lg1/u2;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lg1/r2;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/r2;->g:I

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
    iget-object p1, v0, Lg1/r2;->d:Lkotlin/jvm/internal/e0;

    .line 38
    .line 39
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    .line 41
    .line 42
    move-object v6, p0

    .line 43
    goto :goto_1

    .line 44
    :catchall_0
    move-exception v0

    .line 45
    move-object p1, v0

    .line 46
    move-object v6, p0

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
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    new-instance v7, Lkotlin/jvm/internal/e0;

    .line 60
    .line 61
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 62
    .line 63
    .line 64
    iput-wide p1, v7, Lkotlin/jvm/internal/e0;->d:J

    .line 65
    .line 66
    iput-boolean v4, p0, Lg1/u2;->i:Z

    .line 67
    .line 68
    :try_start_1
    sget-object p3, Le1/w0;->d:Le1/w0;

    .line 69
    .line 70
    new-instance v5, Lg1/s2;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 71
    .line 72
    const/4 v10, 0x0

    .line 73
    move-object v6, p0

    .line 74
    move-wide v8, p1

    .line 75
    :try_start_2
    invoke-direct/range {v5 .. v10}, Lg1/s2;-><init>(Lg1/u2;Lkotlin/jvm/internal/e0;JLkotlin/coroutines/Continuation;)V

    .line 76
    .line 77
    .line 78
    iput-object v7, v0, Lg1/r2;->d:Lkotlin/jvm/internal/e0;

    .line 79
    .line 80
    iput v4, v0, Lg1/r2;->g:I

    .line 81
    .line 82
    invoke-virtual {v6, p3, v5, v0}, Lg1/u2;->f(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 86
    if-ne p0, v1, :cond_3

    .line 87
    .line 88
    return-object v1

    .line 89
    :cond_3
    move-object p1, v7

    .line 90
    :goto_1
    iput-boolean v3, v6, Lg1/u2;->i:Z

    .line 91
    .line 92
    iget-wide p0, p1, Lkotlin/jvm/internal/e0;->d:J

    .line 93
    .line 94
    new-instance p2, Lt4/q;

    .line 95
    .line 96
    invoke-direct {p2, p0, p1}, Lt4/q;-><init>(J)V

    .line 97
    .line 98
    .line 99
    return-object p2

    .line 100
    :catchall_1
    move-exception v0

    .line 101
    :goto_2
    move-object p1, v0

    .line 102
    goto :goto_3

    .line 103
    :catchall_2
    move-exception v0

    .line 104
    move-object v6, p0

    .line 105
    goto :goto_2

    .line 106
    :goto_3
    iput-boolean v3, v6, Lg1/u2;->i:Z

    .line 107
    .line 108
    throw p1
.end method

.method public final b(JZLrx0/i;)Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    iget-object p3, p0, Lg1/u2;->c:Lg1/j1;

    .line 6
    .line 7
    sget-object v1, Landroidx/compose/foundation/gestures/b;->a:Lfw0/i0;

    .line 8
    .line 9
    instance-of p3, p3, Lg1/d0;

    .line 10
    .line 11
    if-eqz p3, :cond_0

    .line 12
    .line 13
    goto :goto_2

    .line 14
    :cond_0
    iget-object p3, p0, Lg1/u2;->d:Lg1/w1;

    .line 15
    .line 16
    sget-object v1, Lg1/w1;->e:Lg1/w1;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    if-ne p3, v1, :cond_1

    .line 20
    .line 21
    const/4 p3, 0x1

    .line 22
    :goto_0
    invoke-static {p1, p2, p3, v2, v2}, Lt4/q;->a(JIFF)J

    .line 23
    .line 24
    .line 25
    move-result-wide p1

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const/4 p3, 0x2

    .line 28
    goto :goto_0

    .line 29
    :goto_1
    new-instance p3, Lc80/s;

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    invoke-direct {p3, p0, v1}, Lc80/s;-><init>(Lg1/u2;Lkotlin/coroutines/Continuation;)V

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lg1/u2;->b:Le1/j;

    .line 36
    .line 37
    if-eqz v1, :cond_3

    .line 38
    .line 39
    iget-object v2, p0, Lg1/u2;->a:Lg1/q2;

    .line 40
    .line 41
    invoke-interface {v2}, Lg1/q2;->d()Z

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    if-nez v2, :cond_2

    .line 46
    .line 47
    iget-object v2, p0, Lg1/u2;->a:Lg1/q2;

    .line 48
    .line 49
    invoke-interface {v2}, Lg1/q2;->b()Z

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    if-eqz v2, :cond_3

    .line 54
    .line 55
    :cond_2
    invoke-virtual {v1, p1, p2, p3, p4}, Le1/j;->b(JLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 60
    .line 61
    if-ne p0, p1, :cond_4

    .line 62
    .line 63
    return-object p0

    .line 64
    :cond_3
    new-instance p3, Lc80/s;

    .line 65
    .line 66
    invoke-direct {p3, p0, p4}, Lc80/s;-><init>(Lg1/u2;Lkotlin/coroutines/Continuation;)V

    .line 67
    .line 68
    .line 69
    iput-wide p1, p3, Lc80/s;->g:J

    .line 70
    .line 71
    invoke-virtual {p3, v0}, Lc80/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 76
    .line 77
    if-ne p0, p1, :cond_4

    .line 78
    .line 79
    return-object p0

    .line 80
    :cond_4
    :goto_2
    return-object v0
.end method

.method public final c(Lg1/e2;JI)J
    .locals 14

    .line 1
    move-wide/from16 v0, p2

    .line 2
    .line 3
    iget-object v2, p0, Lg1/u2;->f:Lo3/d;

    .line 4
    .line 5
    iget-object v2, v2, Lo3/d;->a:Lo3/g;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    iget-boolean v4, v2, Lx2/r;->q:Z

    .line 11
    .line 12
    if-eqz v4, :cond_0

    .line 13
    .line 14
    invoke-static {v2}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    check-cast v2, Lo3/g;

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move-object v2, v3

    .line 22
    :goto_0
    const-wide/16 v4, 0x0

    .line 23
    .line 24
    move/from16 v7, p4

    .line 25
    .line 26
    if-eqz v2, :cond_1

    .line 27
    .line 28
    invoke-virtual {v2, v7, v0, v1}, Lo3/g;->z(IJ)J

    .line 29
    .line 30
    .line 31
    move-result-wide v8

    .line 32
    move-wide v12, v8

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move-wide v12, v4

    .line 35
    :goto_1
    invoke-static {v0, v1, v12, v13}, Ld3/b;->g(JJ)J

    .line 36
    .line 37
    .line 38
    move-result-wide v0

    .line 39
    iget-object v2, p0, Lg1/u2;->d:Lg1/w1;

    .line 40
    .line 41
    sget-object v6, Lg1/w1;->e:Lg1/w1;

    .line 42
    .line 43
    const/4 v8, 0x1

    .line 44
    const/4 v9, 0x0

    .line 45
    if-ne v2, v6, :cond_2

    .line 46
    .line 47
    invoke-static {v0, v1, v8, v9}, Ld3/b;->a(JIF)J

    .line 48
    .line 49
    .line 50
    move-result-wide v9

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/4 v2, 0x2

    .line 53
    invoke-static {v0, v1, v2, v9}, Ld3/b;->a(JIF)J

    .line 54
    .line 55
    .line 56
    move-result-wide v9

    .line 57
    :goto_2
    invoke-virtual {p0, v9, v10}, Lg1/u2;->e(J)J

    .line 58
    .line 59
    .line 60
    move-result-wide v9

    .line 61
    invoke-virtual {p0, v9, v10}, Lg1/u2;->g(J)F

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    invoke-interface {p1, v2}, Lg1/e2;->a(F)F

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    invoke-virtual {p0, v2}, Lg1/u2;->h(F)J

    .line 70
    .line 71
    .line 72
    move-result-wide v9

    .line 73
    invoke-virtual {p0, v9, v10}, Lg1/u2;->e(J)J

    .line 74
    .line 75
    .line 76
    move-result-wide v9

    .line 77
    iget-object v2, p0, Lg1/u2;->g:Lg1/p2;

    .line 78
    .line 79
    iget-boolean v6, v2, Lx2/r;->q:Z

    .line 80
    .line 81
    if-nez v6, :cond_3

    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_3
    invoke-static {v2}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    check-cast v2, Lw3/t;

    .line 89
    .line 90
    invoke-virtual {v2}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    :try_start_0
    sget-object v6, Lw3/t;->Y1:Ljava/lang/reflect/Method;

    .line 95
    .line 96
    if-nez v6, :cond_4

    .line 97
    .line 98
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 99
    .line 100
    .line 101
    move-result-object v6

    .line 102
    const-string v11, "dispatchOnScrollChanged"

    .line 103
    .line 104
    invoke-virtual {v6, v11, v3}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    invoke-virtual {v6, v8}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 109
    .line 110
    .line 111
    sput-object v6, Lw3/t;->Y1:Ljava/lang/reflect/Method;

    .line 112
    .line 113
    :cond_4
    sget-object v6, Lw3/t;->Y1:Ljava/lang/reflect/Method;

    .line 114
    .line 115
    if-eqz v6, :cond_5

    .line 116
    .line 117
    invoke-virtual {v6, v2, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 118
    .line 119
    .line 120
    :catch_0
    :cond_5
    :goto_3
    invoke-static {v0, v1, v9, v10}, Ld3/b;->g(JJ)J

    .line 121
    .line 122
    .line 123
    move-result-wide v0

    .line 124
    iget-object p0, p0, Lg1/u2;->f:Lo3/d;

    .line 125
    .line 126
    iget-object p0, p0, Lo3/d;->a:Lo3/g;

    .line 127
    .line 128
    if-eqz p0, :cond_6

    .line 129
    .line 130
    iget-boolean v2, p0, Lx2/r;->q:Z

    .line 131
    .line 132
    if-eqz v2, :cond_6

    .line 133
    .line 134
    invoke-static {p0}, Lv3/f;->j(Lv3/c2;)Lv3/c2;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    move-object v3, p0

    .line 139
    check-cast v3, Lo3/g;

    .line 140
    .line 141
    :cond_6
    move-object v6, v3

    .line 142
    move-wide v8, v9

    .line 143
    if-eqz v6, :cond_7

    .line 144
    .line 145
    move-wide v10, v0

    .line 146
    invoke-virtual/range {v6 .. v11}, Lo3/g;->P(IJJ)J

    .line 147
    .line 148
    .line 149
    move-result-wide v4

    .line 150
    :cond_7
    invoke-static {v12, v13, v8, v9}, Ld3/b;->h(JJ)J

    .line 151
    .line 152
    .line 153
    move-result-wide v0

    .line 154
    invoke-static {v0, v1, v4, v5}, Ld3/b;->h(JJ)J

    .line 155
    .line 156
    .line 157
    move-result-wide v0

    .line 158
    return-wide v0
.end method

.method public final d(F)F
    .locals 0

    .line 1
    iget-boolean p0, p0, Lg1/u2;->e:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, -0x1

    .line 6
    int-to-float p0, p0

    .line 7
    mul-float/2addr p1, p0

    .line 8
    :cond_0
    return p1
.end method

.method public final e(J)J
    .locals 0

    .line 1
    iget-boolean p0, p0, Lg1/u2;->e:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/high16 p0, -0x40800000    # -1.0f

    .line 6
    .line 7
    invoke-static {p1, p2, p0}, Ld3/b;->i(JF)J

    .line 8
    .line 9
    .line 10
    move-result-wide p0

    .line 11
    return-wide p0

    .line 12
    :cond_0
    return-wide p1
.end method

.method public final f(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lg1/u2;->a:Lg1/q2;

    .line 2
    .line 3
    new-instance v1, Le1/e;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/16 v3, 0x1d

    .line 7
    .line 8
    invoke-direct {v1, v3, p0, p2, v2}, Le1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {v0, p1, v1, p3}, Lg1/q2;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    if-ne p0, p1, :cond_0

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0
.end method

.method public final g(J)F
    .locals 2

    .line 1
    iget-object p0, p0, Lg1/u2;->d:Lg1/w1;

    .line 2
    .line 3
    sget-object v0, Lg1/w1;->e:Lg1/w1;

    .line 4
    .line 5
    if-ne p0, v0, :cond_0

    .line 6
    .line 7
    const/16 p0, 0x20

    .line 8
    .line 9
    shr-long p0, p1, p0

    .line 10
    .line 11
    :goto_0
    long-to-int p0, p0

    .line 12
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0

    .line 17
    :cond_0
    const-wide v0, 0xffffffffL

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    and-long p0, p1, v0

    .line 23
    .line 24
    goto :goto_0
.end method

.method public final h(F)J
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    cmpg-float v1, p1, v0

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    const-wide/16 p0, 0x0

    .line 7
    .line 8
    return-wide p0

    .line 9
    :cond_0
    iget-object p0, p0, Lg1/u2;->d:Lg1/w1;

    .line 10
    .line 11
    sget-object v1, Lg1/w1;->e:Lg1/w1;

    .line 12
    .line 13
    const-wide v2, 0xffffffffL

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    const/16 v4, 0x20

    .line 19
    .line 20
    if-ne p0, v1, :cond_1

    .line 21
    .line 22
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    int-to-long p0, p0

    .line 27
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    int-to-long v0, v0

    .line 32
    shl-long/2addr p0, v4

    .line 33
    and-long/2addr v0, v2

    .line 34
    or-long/2addr p0, v0

    .line 35
    return-wide p0

    .line 36
    :cond_1
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    int-to-long v0, p0

    .line 41
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    int-to-long p0, p0

    .line 46
    shl-long/2addr v0, v4

    .line 47
    and-long/2addr p0, v2

    .line 48
    or-long/2addr p0, v0

    .line 49
    return-wide p0
.end method
