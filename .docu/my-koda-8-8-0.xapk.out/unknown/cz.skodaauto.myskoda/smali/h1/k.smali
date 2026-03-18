.class public abstract Lh1/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x190

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lh1/k;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Lg1/e2;FLc1/k;Lc1/u;Lay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p5, Lh1/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p5

    .line 6
    check-cast v0, Lh1/i;

    .line 7
    .line 8
    iget v1, v0, Lh1/i;->h:I

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
    iput v1, v0, Lh1/i;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lh1/i;

    .line 21
    .line 22
    invoke-direct {v0, p5}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p5, v0, Lh1/i;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lh1/i;->h:I

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
    iget p1, v0, Lh1/i;->d:F

    .line 37
    .line 38
    iget-object p0, v0, Lh1/i;->f:Lkotlin/jvm/internal/c0;

    .line 39
    .line 40
    iget-object p2, v0, Lh1/i;->e:Lc1/k;

    .line 41
    .line 42
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p5}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    new-instance v6, Lkotlin/jvm/internal/c0;

    .line 58
    .line 59
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p2}, Lc1/k;->a()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p5

    .line 66
    check-cast p5, Ljava/lang/Number;

    .line 67
    .line 68
    invoke-virtual {p5}, Ljava/lang/Number;->floatValue()F

    .line 69
    .line 70
    .line 71
    move-result p5

    .line 72
    const/4 v2, 0x0

    .line 73
    cmpg-float p5, p5, v2

    .line 74
    .line 75
    if-nez p5, :cond_3

    .line 76
    .line 77
    move p5, v3

    .line 78
    goto :goto_1

    .line 79
    :cond_3
    const/4 p5, 0x0

    .line 80
    :goto_1
    xor-int/2addr p5, v3

    .line 81
    new-instance v4, Lh1/h;

    .line 82
    .line 83
    const/4 v9, 0x0

    .line 84
    move-object v7, p0

    .line 85
    move v5, p1

    .line 86
    move-object v8, p4

    .line 87
    invoke-direct/range {v4 .. v9}, Lh1/h;-><init>(FLkotlin/jvm/internal/c0;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 88
    .line 89
    .line 90
    iput-object p2, v0, Lh1/i;->e:Lc1/k;

    .line 91
    .line 92
    iput-object v6, v0, Lh1/i;->f:Lkotlin/jvm/internal/c0;

    .line 93
    .line 94
    iput v5, v0, Lh1/i;->d:F

    .line 95
    .line 96
    iput v3, v0, Lh1/i;->h:I

    .line 97
    .line 98
    invoke-static {p2, p3, p5, v4, v0}, Lc1/d;->f(Lc1/k;Lc1/u;ZLay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    if-ne p0, v1, :cond_4

    .line 103
    .line 104
    return-object v1

    .line 105
    :cond_4
    move p1, v5

    .line 106
    move-object p0, v6

    .line 107
    :goto_2
    new-instance p3, Lh1/a;

    .line 108
    .line 109
    iget p0, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 110
    .line 111
    sub-float/2addr p1, p0

    .line 112
    new-instance p0, Ljava/lang/Float;

    .line 113
    .line 114
    invoke-direct {p0, p1}, Ljava/lang/Float;-><init>(F)V

    .line 115
    .line 116
    .line 117
    invoke-direct {p3, p0, p2}, Lh1/a;-><init>(Ljava/lang/Float;Lc1/k;)V

    .line 118
    .line 119
    .line 120
    return-object p3
.end method

.method public static final b(Lg1/e2;FFLc1/k;Lc1/j;Lay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p6

    .line 4
    .line 5
    instance-of v2, v1, Lh1/j;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lh1/j;

    .line 11
    .line 12
    iget v3, v2, Lh1/j;->i:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lh1/j;->i:I

    .line 22
    .line 23
    :goto_0
    move-object v8, v2

    .line 24
    goto :goto_1

    .line 25
    :cond_0
    new-instance v2, Lh1/j;

    .line 26
    .line 27
    invoke-direct {v2, v1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :goto_1
    iget-object v1, v8, Lh1/j;->h:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v3, v8, Lh1/j;->i:I

    .line 36
    .line 37
    const/4 v9, 0x0

    .line 38
    const/4 v4, 0x1

    .line 39
    if-eqz v3, :cond_2

    .line 40
    .line 41
    if-ne v3, v4, :cond_1

    .line 42
    .line 43
    iget v0, v8, Lh1/j;->e:F

    .line 44
    .line 45
    iget v2, v8, Lh1/j;->d:F

    .line 46
    .line 47
    iget-object v3, v8, Lh1/j;->g:Lkotlin/jvm/internal/c0;

    .line 48
    .line 49
    iget-object v4, v8, Lh1/j;->f:Lc1/k;

    .line 50
    .line 51
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    move v1, v0

    .line 55
    move v0, v2

    .line 56
    goto :goto_3

    .line 57
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    new-instance v12, Lkotlin/jvm/internal/c0;

    .line 69
    .line 70
    invoke-direct {v12}, Ljava/lang/Object;-><init>()V

    .line 71
    .line 72
    .line 73
    invoke-virtual/range {p3 .. p3}, Lc1/k;->a()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    check-cast v1, Ljava/lang/Number;

    .line 78
    .line 79
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    new-instance v3, Ljava/lang/Float;

    .line 84
    .line 85
    invoke-direct {v3, v0}, Ljava/lang/Float;-><init>(F)V

    .line 86
    .line 87
    .line 88
    invoke-virtual/range {p3 .. p3}, Lc1/k;->a()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v5

    .line 92
    check-cast v5, Ljava/lang/Number;

    .line 93
    .line 94
    invoke-virtual {v5}, Ljava/lang/Number;->floatValue()F

    .line 95
    .line 96
    .line 97
    move-result v5

    .line 98
    cmpg-float v5, v5, v9

    .line 99
    .line 100
    if-nez v5, :cond_3

    .line 101
    .line 102
    move v5, v4

    .line 103
    goto :goto_2

    .line 104
    :cond_3
    const/4 v5, 0x0

    .line 105
    :goto_2
    xor-int/lit8 v6, v5, 0x1

    .line 106
    .line 107
    new-instance v10, Lh1/h;

    .line 108
    .line 109
    const/4 v15, 0x1

    .line 110
    move-object/from16 v13, p0

    .line 111
    .line 112
    move/from16 v11, p2

    .line 113
    .line 114
    move-object/from16 v14, p5

    .line 115
    .line 116
    invoke-direct/range {v10 .. v15}, Lh1/h;-><init>(FLkotlin/jvm/internal/c0;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 117
    .line 118
    .line 119
    move-object v5, v3

    .line 120
    move-object/from16 v3, p3

    .line 121
    .line 122
    iput-object v3, v8, Lh1/j;->f:Lc1/k;

    .line 123
    .line 124
    iput-object v12, v8, Lh1/j;->g:Lkotlin/jvm/internal/c0;

    .line 125
    .line 126
    iput v0, v8, Lh1/j;->d:F

    .line 127
    .line 128
    iput v1, v8, Lh1/j;->e:F

    .line 129
    .line 130
    iput v4, v8, Lh1/j;->i:I

    .line 131
    .line 132
    move-object v4, v5

    .line 133
    move-object v7, v10

    .line 134
    move-object/from16 v5, p4

    .line 135
    .line 136
    invoke-static/range {v3 .. v8}, Lc1/d;->h(Lc1/k;Ljava/lang/Float;Lc1/j;ZLay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v4

    .line 140
    if-ne v4, v2, :cond_4

    .line 141
    .line 142
    return-object v2

    .line 143
    :cond_4
    move-object/from16 v4, p3

    .line 144
    .line 145
    move-object v3, v12

    .line 146
    :goto_3
    invoke-virtual {v4}, Lc1/k;->a()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    check-cast v2, Ljava/lang/Number;

    .line 151
    .line 152
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 153
    .line 154
    .line 155
    move-result v2

    .line 156
    invoke-static {v2, v1}, Lh1/k;->d(FF)F

    .line 157
    .line 158
    .line 159
    move-result v1

    .line 160
    new-instance v2, Lh1/a;

    .line 161
    .line 162
    iget v3, v3, Lkotlin/jvm/internal/c0;->d:F

    .line 163
    .line 164
    sub-float/2addr v0, v3

    .line 165
    new-instance v3, Ljava/lang/Float;

    .line 166
    .line 167
    invoke-direct {v3, v0}, Ljava/lang/Float;-><init>(F)V

    .line 168
    .line 169
    .line 170
    const/16 v0, 0x1d

    .line 171
    .line 172
    invoke-static {v4, v9, v1, v0}, Lc1/d;->m(Lc1/k;FFI)Lc1/k;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    invoke-direct {v2, v3, v0}, Lh1/a;-><init>(Ljava/lang/Float;Lc1/k;)V

    .line 177
    .line 178
    .line 179
    return-object v2
.end method

.method public static final c(Lc1/i;Lg1/e2;Lay0/k;F)V
    .locals 1

    .line 1
    :try_start_0
    invoke-interface {p1, p3}, Lg1/e2;->a(F)F

    .line 2
    .line 3
    .line 4
    move-result p1
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    goto :goto_0

    .line 6
    :catch_0
    invoke-virtual {p0}, Lc1/i;->a()V

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    :goto_0
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-interface {p2, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    sub-float/2addr p3, p1

    .line 18
    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    const/high16 p2, 0x3f000000    # 0.5f

    .line 23
    .line 24
    cmpl-float p1, p1, p2

    .line 25
    .line 26
    if-lez p1, :cond_0

    .line 27
    .line 28
    invoke-virtual {p0}, Lc1/i;->a()V

    .line 29
    .line 30
    .line 31
    :cond_0
    return-void
.end method

.method public static final d(FF)F
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    cmpg-float v1, p1, v0

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    return v0

    .line 7
    :cond_0
    cmpl-float v0, p1, v0

    .line 8
    .line 9
    if-lez v0, :cond_1

    .line 10
    .line 11
    cmpl-float v0, p0, p1

    .line 12
    .line 13
    if-lez v0, :cond_2

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_1
    cmpg-float v0, p0, p1

    .line 17
    .line 18
    if-gez v0, :cond_2

    .line 19
    .line 20
    :goto_0
    return p1

    .line 21
    :cond_2
    return p0
.end method
