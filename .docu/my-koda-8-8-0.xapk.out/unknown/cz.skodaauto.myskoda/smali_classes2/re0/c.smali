.class public final Lre0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lte0/c;


# instance fields
.field public final a:Lez0/c;

.field public final b:Llx0/q;


# direct methods
.method public constructor <init>(Lve0/v;Lve0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iput-object p1, p0, Lre0/c;->a:Lez0/c;

    .line 9
    .line 10
    new-instance p1, Lqf0/d;

    .line 11
    .line 12
    const/16 p2, 0x8

    .line 13
    .line 14
    invoke-direct {p1, p2}, Lqf0/d;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iput-object p1, p0, Lre0/c;->b:Llx0/q;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p1, Lre0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lre0/a;

    .line 7
    .line 8
    iget v1, v0, Lre0/a;->h:I

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
    iput v1, v0, Lre0/a;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lre0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lre0/a;-><init>(Lre0/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lre0/a;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lre0/a;->h:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v5, 0x0

    .line 34
    const/4 v6, 0x0

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
    iget-object p0, v0, Lre0/a;->d:Lez0/a;

    .line 42
    .line 43
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    .line 45
    .line 46
    goto :goto_3

    .line 47
    :catchall_0
    move-exception p1

    .line 48
    goto :goto_4

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
    iget v2, v0, Lre0/a;->e:I

    .line 58
    .line 59
    iget-object v4, v0, Lre0/a;->d:Lez0/a;

    .line 60
    .line 61
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    move-object p1, v4

    .line 65
    goto :goto_1

    .line 66
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iget-object p1, p0, Lre0/c;->a:Lez0/c;

    .line 70
    .line 71
    iput-object p1, v0, Lre0/a;->d:Lez0/a;

    .line 72
    .line 73
    iput v5, v0, Lre0/a;->e:I

    .line 74
    .line 75
    iput v4, v0, Lre0/a;->h:I

    .line 76
    .line 77
    invoke-virtual {p1, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    if-ne v2, v1, :cond_4

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_4
    move v2, v5

    .line 85
    :goto_1
    :try_start_1
    new-instance v4, Lr1/b;

    .line 86
    .line 87
    const/16 v7, 0x9

    .line 88
    .line 89
    invoke-direct {v4, p0, v7}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 90
    .line 91
    .line 92
    new-instance v7, Llk/c;

    .line 93
    .line 94
    const/16 v8, 0x14

    .line 95
    .line 96
    invoke-direct {v7, p0, v8}, Llk/c;-><init>(Ljava/lang/Object;I)V

    .line 97
    .line 98
    .line 99
    iput-object p1, v0, Lre0/a;->d:Lez0/a;

    .line 100
    .line 101
    iput v2, v0, Lre0/a;->e:I

    .line 102
    .line 103
    iput v3, v0, Lre0/a;->h:I

    .line 104
    .line 105
    invoke-virtual {p0, v4, v7, v5, v0}, Lre0/c;->b(Lay0/a;Lay0/n;ILrx0/c;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 109
    if-ne p0, v1, :cond_5

    .line 110
    .line 111
    :goto_2
    return-object v1

    .line 112
    :cond_5
    move-object v9, p1

    .line 113
    move-object p1, p0

    .line 114
    move-object p0, v9

    .line 115
    :goto_3
    invoke-interface {p0, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    return-object p1

    .line 119
    :catchall_1
    move-exception p0

    .line 120
    move-object v9, p1

    .line 121
    move-object p1, p0

    .line 122
    move-object p0, v9

    .line 123
    :goto_4
    invoke-interface {p0, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    throw p1
.end method

.method public final b(Lay0/a;Lay0/n;ILrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p2

    .line 4
    .line 5
    move/from16 v3, p3

    .line 6
    .line 7
    move-object/from16 v0, p4

    .line 8
    .line 9
    instance-of v4, v0, Lre0/b;

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    move-object v4, v0

    .line 14
    check-cast v4, Lre0/b;

    .line 15
    .line 16
    iget v5, v4, Lre0/b;->k:I

    .line 17
    .line 18
    const/high16 v6, -0x80000000

    .line 19
    .line 20
    and-int v7, v5, v6

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    sub-int/2addr v5, v6

    .line 25
    iput v5, v4, Lre0/b;->k:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v4, Lre0/b;

    .line 29
    .line 30
    invoke-direct {v4, v1, v0}, Lre0/b;-><init>(Lre0/c;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v0, v4, Lre0/b;->i:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v6, v4, Lre0/b;->k:I

    .line 38
    .line 39
    const/4 v7, 0x2

    .line 40
    const/4 v8, 0x1

    .line 41
    if-eqz v6, :cond_3

    .line 42
    .line 43
    if-eq v6, v8, :cond_2

    .line 44
    .line 45
    if-ne v6, v7, :cond_1

    .line 46
    .line 47
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    return-object v0

    .line 51
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v0

    .line 59
    :cond_2
    iget-wide v2, v4, Lre0/b;->h:J

    .line 60
    .line 61
    iget v6, v4, Lre0/b;->g:I

    .line 62
    .line 63
    iget v8, v4, Lre0/b;->f:I

    .line 64
    .line 65
    iget-object v9, v4, Lre0/b;->e:Lay0/n;

    .line 66
    .line 67
    iget-object v10, v4, Lre0/b;->d:Lay0/a;

    .line 68
    .line 69
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    move v0, v6

    .line 73
    move-object v6, v10

    .line 74
    move-wide v15, v2

    .line 75
    move v3, v8

    .line 76
    move-object v2, v9

    .line 77
    move-wide v9, v15

    .line 78
    goto :goto_1

    .line 79
    :cond_3
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    :try_start_0
    invoke-interface/range {p1 .. p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 86
    return-object v0

    .line 87
    :catchall_0
    move-exception v0

    .line 88
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 93
    .line 94
    .line 95
    move-result-object v6

    .line 96
    if-eqz v6, :cond_7

    .line 97
    .line 98
    new-instance v0, Ljava/lang/Integer;

    .line 99
    .line 100
    invoke-direct {v0, v3}, Ljava/lang/Integer;-><init>(I)V

    .line 101
    .line 102
    .line 103
    invoke-interface {v2, v6, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    const/4 v0, 0x3

    .line 107
    if-ge v3, v0, :cond_6

    .line 108
    .line 109
    const/16 v0, 0x3e8

    .line 110
    .line 111
    int-to-long v9, v0

    .line 112
    const-wide/high16 v11, 0x4000000000000000L    # 2.0

    .line 113
    .line 114
    int-to-double v13, v3

    .line 115
    invoke-static {v11, v12, v13, v14}, Ljava/lang/Math;->pow(DD)D

    .line 116
    .line 117
    .line 118
    move-result-wide v11

    .line 119
    double-to-long v11, v11

    .line 120
    mul-long/2addr v9, v11

    .line 121
    move-object/from16 v6, p1

    .line 122
    .line 123
    iput-object v6, v4, Lre0/b;->d:Lay0/a;

    .line 124
    .line 125
    iput-object v2, v4, Lre0/b;->e:Lay0/n;

    .line 126
    .line 127
    iput v3, v4, Lre0/b;->f:I

    .line 128
    .line 129
    const/4 v0, 0x0

    .line 130
    iput v0, v4, Lre0/b;->g:I

    .line 131
    .line 132
    iput-wide v9, v4, Lre0/b;->h:J

    .line 133
    .line 134
    iput v8, v4, Lre0/b;->k:I

    .line 135
    .line 136
    invoke-static {v9, v10, v4}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v8

    .line 140
    if-ne v8, v5, :cond_4

    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_4
    :goto_1
    add-int/lit8 v8, v3, 0x1

    .line 144
    .line 145
    const/4 v11, 0x0

    .line 146
    iput-object v11, v4, Lre0/b;->d:Lay0/a;

    .line 147
    .line 148
    iput-object v11, v4, Lre0/b;->e:Lay0/n;

    .line 149
    .line 150
    iput v3, v4, Lre0/b;->f:I

    .line 151
    .line 152
    iput v0, v4, Lre0/b;->g:I

    .line 153
    .line 154
    iput-wide v9, v4, Lre0/b;->h:J

    .line 155
    .line 156
    iput v7, v4, Lre0/b;->k:I

    .line 157
    .line 158
    invoke-virtual {v1, v6, v2, v8, v4}, Lre0/c;->b(Lay0/a;Lay0/n;ILrx0/c;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    if-ne v0, v5, :cond_5

    .line 163
    .line 164
    :goto_2
    return-object v5

    .line 165
    :cond_5
    return-object v0

    .line 166
    :cond_6
    new-instance v0, Ljava/security/KeyStoreException;

    .line 167
    .line 168
    const-string v1, "Unable to get or create key with retry"

    .line 169
    .line 170
    invoke-direct {v0, v1, v6}, Ljava/security/KeyStoreException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 171
    .line 172
    .line 173
    throw v0

    .line 174
    :cond_7
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    new-instance v0, La8/r0;

    .line 178
    .line 179
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 180
    .line 181
    .line 182
    throw v0
.end method
