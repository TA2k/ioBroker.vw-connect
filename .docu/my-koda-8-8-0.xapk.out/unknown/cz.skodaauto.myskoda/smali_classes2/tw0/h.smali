.class public final Ltw0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lvz0/d;

.field public final b:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lvz0/d;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltw0/h;->a:Lvz0/d;

    .line 5
    .line 6
    sget-object v0, Ltw0/a;->a:Ljava/util/List;

    .line 7
    .line 8
    check-cast v0, Ljava/lang/Iterable;

    .line 9
    .line 10
    new-instance v1, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 13
    .line 14
    .line 15
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    check-cast v2, Luw0/c;

    .line 30
    .line 31
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    new-instance v2, Luw0/h;

    .line 35
    .line 36
    invoke-direct {v2, p1}, Luw0/h;-><init>(Lvz0/d;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    iput-object v1, p0, Ltw0/h;->b:Ljava/util/ArrayList;

    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public final a(Ljava/nio/charset/Charset;Lzw0/a;Lio/ktor/utils/io/t;Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    move-object/from16 v0, p4

    .line 2
    .line 3
    instance-of v1, v0, Ltw0/c;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Ltw0/c;

    .line 9
    .line 10
    iget v2, v1, Ltw0/c;->j:I

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
    iput v2, v1, Ltw0/c;->j:I

    .line 20
    .line 21
    :goto_0
    move-object v6, v1

    .line 22
    goto :goto_1

    .line 23
    :cond_0
    new-instance v1, Ltw0/c;

    .line 24
    .line 25
    invoke-direct {v1, p0, v0}, Ltw0/c;-><init>(Ltw0/h;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :goto_1
    iget-object v0, v6, Ltw0/c;->h:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v1, v6, Ltw0/c;->j:I

    .line 34
    .line 35
    iget-object v8, p0, Ltw0/h;->b:Ljava/util/ArrayList;

    .line 36
    .line 37
    const/4 v9, 0x1

    .line 38
    iget-object p0, p0, Ltw0/h;->a:Lvz0/d;

    .line 39
    .line 40
    const/4 v10, 0x2

    .line 41
    const/4 v11, 0x0

    .line 42
    if-eqz v1, :cond_3

    .line 43
    .line 44
    if-eq v1, v9, :cond_2

    .line 45
    .line 46
    if-ne v1, v10, :cond_1

    .line 47
    .line 48
    iget-object p1, v6, Ltw0/c;->g:Lqz0/a;

    .line 49
    .line 50
    check-cast p1, Lqz0/a;

    .line 51
    .line 52
    iget-object v1, v6, Ltw0/c;->d:Ljava/nio/charset/Charset;

    .line 53
    .line 54
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto/16 :goto_4

    .line 58
    .line 59
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 62
    .line 63
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw p0

    .line 67
    :cond_2
    iget-object p1, v6, Ltw0/c;->f:Lio/ktor/utils/io/t;

    .line 68
    .line 69
    iget-object v1, v6, Ltw0/c;->e:Lzw0/a;

    .line 70
    .line 71
    iget-object v2, v6, Ltw0/c;->d:Ljava/nio/charset/Charset;

    .line 72
    .line 73
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    move-object v4, p1

    .line 77
    move-object p1, v2

    .line 78
    goto :goto_2

    .line 79
    :cond_3
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    new-instance v1, Lam0/i;

    .line 83
    .line 84
    const/16 v0, 0x1c

    .line 85
    .line 86
    invoke-direct {v1, v8, v0}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 87
    .line 88
    .line 89
    new-instance v0, Lsw0/c;

    .line 90
    .line 91
    const/4 v5, 0x1

    .line 92
    move-object v2, p1

    .line 93
    move-object v3, p2

    .line 94
    move-object/from16 v4, p3

    .line 95
    .line 96
    invoke-direct/range {v0 .. v5}, Lsw0/c;-><init>(Lyy0/i;Ljava/lang/Comparable;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 97
    .line 98
    .line 99
    new-instance v1, Lsw0/e;

    .line 100
    .line 101
    const/4 v3, 0x1

    .line 102
    invoke-direct {v1, v4, v11, v3}, Lsw0/e;-><init>(Lio/ktor/utils/io/t;Lkotlin/coroutines/Continuation;I)V

    .line 103
    .line 104
    .line 105
    iput-object p1, v6, Ltw0/c;->d:Ljava/nio/charset/Charset;

    .line 106
    .line 107
    iput-object p2, v6, Ltw0/c;->e:Lzw0/a;

    .line 108
    .line 109
    iput-object v4, v6, Ltw0/c;->f:Lio/ktor/utils/io/t;

    .line 110
    .line 111
    iput v9, v6, Ltw0/c;->j:I

    .line 112
    .line 113
    invoke-static {v0, v1, v6}, Lyy0/u;->v(Lyy0/i;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    if-ne v0, v7, :cond_4

    .line 118
    .line 119
    goto :goto_3

    .line 120
    :cond_4
    move-object v1, p2

    .line 121
    :goto_2
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    if-nez v2, :cond_6

    .line 126
    .line 127
    if-nez v0, :cond_5

    .line 128
    .line 129
    invoke-interface {v4}, Lio/ktor/utils/io/t;->g()Z

    .line 130
    .line 131
    .line 132
    move-result v2

    .line 133
    if-eqz v2, :cond_6

    .line 134
    .line 135
    :cond_5
    return-object v0

    .line 136
    :cond_6
    iget-object v0, p0, Lvz0/d;->b:Lwq/f;

    .line 137
    .line 138
    invoke-static {v0, v1}, Llp/n0;->d(Lwq/f;Lzw0/a;)Lqz0/a;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    iput-object p1, v6, Ltw0/c;->d:Ljava/nio/charset/Charset;

    .line 143
    .line 144
    iput-object v11, v6, Ltw0/c;->e:Lzw0/a;

    .line 145
    .line 146
    iput-object v11, v6, Ltw0/c;->f:Lio/ktor/utils/io/t;

    .line 147
    .line 148
    move-object v1, v0

    .line 149
    check-cast v1, Lqz0/a;

    .line 150
    .line 151
    iput-object v1, v6, Ltw0/c;->g:Lqz0/a;

    .line 152
    .line 153
    iput v10, v6, Ltw0/c;->j:I

    .line 154
    .line 155
    invoke-static {v4, v6}, Lio/ktor/utils/io/h0;->i(Lio/ktor/utils/io/t;Lrx0/c;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    if-ne v1, v7, :cond_7

    .line 160
    .line 161
    :goto_3
    return-object v7

    .line 162
    :cond_7
    move-object v12, v1

    .line 163
    move-object v1, p1

    .line 164
    move-object p1, v0

    .line 165
    move-object v0, v12

    .line 166
    :goto_4
    check-cast v0, Lnz0/i;

    .line 167
    .line 168
    :try_start_0
    check-cast p1, Lqz0/a;

    .line 169
    .line 170
    invoke-static {v0, v1, v10}, Ljp/ib;->b(Lnz0/i;Ljava/nio/charset/Charset;I)Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    invoke-virtual {p0, v0, p1}, Lvz0/d;->b(Ljava/lang/String;Lqz0/a;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 178
    return-object p0

    .line 179
    :catchall_0
    move-exception v0

    .line 180
    move-object p0, v0

    .line 181
    new-instance p1, Lsw0/f;

    .line 182
    .line 183
    new-instance v0, Ljava/lang/StringBuilder;

    .line 184
    .line 185
    const-string v1, "Illegal input: "

    .line 186
    .line 187
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 195
    .line 196
    .line 197
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    invoke-direct {p1, v0, p0}, Lsw0/f;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 202
    .line 203
    .line 204
    throw p1
.end method

.method public final b(Low0/e;Ljava/nio/charset/Charset;Lzw0/a;Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    move-object/from16 v0, p5

    .line 2
    .line 3
    iget-object v1, p0, Ltw0/h;->a:Lvz0/d;

    .line 4
    .line 5
    iget-object v2, v1, Lvz0/d;->b:Lwq/f;

    .line 6
    .line 7
    instance-of v3, v0, Ltw0/g;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v0

    .line 12
    check-cast v3, Ltw0/g;

    .line 13
    .line 14
    iget v4, v3, Ltw0/g;->j:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Ltw0/g;->j:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Ltw0/g;

    .line 27
    .line 28
    invoke-direct {v3, p0, v0}, Ltw0/g;-><init>(Ltw0/h;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v0, v3, Ltw0/g;->h:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Ltw0/g;->j:I

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    if-eqz v5, :cond_2

    .line 39
    .line 40
    if-ne v5, v6, :cond_1

    .line 41
    .line 42
    iget-object p0, v3, Ltw0/g;->g:Ljava/lang/Object;

    .line 43
    .line 44
    iget-object p1, v3, Ltw0/g;->f:Lzw0/a;

    .line 45
    .line 46
    iget-object v4, v3, Ltw0/g;->e:Ljava/nio/charset/Charset;

    .line 47
    .line 48
    iget-object v3, v3, Ltw0/g;->d:Low0/e;

    .line 49
    .line 50
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    move-object v11, p1

    .line 54
    move-object p1, v3

    .line 55
    move-object v10, v4

    .line 56
    goto :goto_1

    .line 57
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    new-instance v8, Lam0/i;

    .line 69
    .line 70
    const/16 v0, 0x1c

    .line 71
    .line 72
    iget-object p0, p0, Ltw0/h;->b:Ljava/util/ArrayList;

    .line 73
    .line 74
    invoke-direct {v8, p0, v0}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 75
    .line 76
    .line 77
    new-instance v7, Ltw0/f;

    .line 78
    .line 79
    move-object v9, p1

    .line 80
    move-object v10, p2

    .line 81
    move-object/from16 v11, p3

    .line 82
    .line 83
    move-object/from16 v12, p4

    .line 84
    .line 85
    invoke-direct/range {v7 .. v12}, Ltw0/f;-><init>(Lam0/i;Low0/e;Ljava/nio/charset/Charset;Lzw0/a;Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    new-instance p0, Lb40/a;

    .line 89
    .line 90
    const/4 v0, 0x2

    .line 91
    const/16 v5, 0xd

    .line 92
    .line 93
    const/4 v8, 0x0

    .line 94
    invoke-direct {p0, v0, v8, v5}, Lb40/a;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 95
    .line 96
    .line 97
    iput-object p1, v3, Ltw0/g;->d:Low0/e;

    .line 98
    .line 99
    iput-object p2, v3, Ltw0/g;->e:Ljava/nio/charset/Charset;

    .line 100
    .line 101
    iput-object v11, v3, Ltw0/g;->f:Lzw0/a;

    .line 102
    .line 103
    iput-object v12, v3, Ltw0/g;->g:Ljava/lang/Object;

    .line 104
    .line 105
    iput v6, v3, Ltw0/g;->j:I

    .line 106
    .line 107
    invoke-static {v7, p0, v3}, Lyy0/u;->v(Lyy0/i;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    if-ne v0, v4, :cond_3

    .line 112
    .line 113
    return-object v4

    .line 114
    :cond_3
    move-object v10, p2

    .line 115
    move-object p0, v12

    .line 116
    :goto_1
    check-cast v0, Lrw0/d;

    .line 117
    .line 118
    if-eqz v0, :cond_4

    .line 119
    .line 120
    return-object v0

    .line 121
    :cond_4
    :try_start_0
    invoke-static {v2, v11}, Llp/n0;->d(Lwq/f;Lzw0/a;)Lqz0/a;

    .line 122
    .line 123
    .line 124
    move-result-object v0
    :try_end_0
    .catch Lqz0/h; {:try_start_0 .. :try_end_0} :catch_0

    .line 125
    goto :goto_2

    .line 126
    :catch_0
    invoke-static {p0, v2}, Llp/n0;->c(Ljava/lang/Object;Lwq/f;)Lqz0/a;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    :goto_2
    check-cast v0, Lqz0/a;

    .line 131
    .line 132
    invoke-virtual {v1, v0, p0}, Lvz0/d;->d(Lqz0/a;Ljava/lang/Object;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    new-instance v0, Lrw0/e;

    .line 137
    .line 138
    invoke-static {p1, v10}, Ljp/ic;->k(Low0/e;Ljava/nio/charset/Charset;)Low0/e;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-direct {v0, p0, p1}, Lrw0/e;-><init>(Ljava/lang/String;Low0/e;)V

    .line 143
    .line 144
    .line 145
    return-object v0
.end method
