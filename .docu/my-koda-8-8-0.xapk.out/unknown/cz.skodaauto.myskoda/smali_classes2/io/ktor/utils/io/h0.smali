.class public abstract Lio/ktor/utils/io/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lio/ktor/utils/io/f0;

.field public static final b:Lio/ktor/utils/io/j0;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lio/ktor/utils/io/f0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/ktor/utils/io/h0;->a:Lio/ktor/utils/io/f0;

    .line 7
    .line 8
    new-instance v0, Lio/ktor/utils/io/j0;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, v1}, Lio/ktor/utils/io/j0;-><init>(Ljava/lang/Throwable;)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lio/ktor/utils/io/h0;->b:Lio/ktor/utils/io/j0;

    .line 15
    .line 16
    return-void
.end method

.method public static final a(Lio/ktor/utils/io/t;)V
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/io/IOException;

    .line 7
    .line 8
    const-string v1, "Channel was cancelled"

    .line 9
    .line 10
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p0, v0}, Lio/ktor/utils/io/t;->c(Ljava/lang/Throwable;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public static final b(Lio/ktor/utils/io/d0;Ljava/lang/Throwable;)V
    .locals 9

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-nez p1, :cond_0

    .line 7
    .line 8
    new-instance v1, Lio/ktor/utils/io/g0;

    .line 9
    .line 10
    const/4 v7, 0x0

    .line 11
    const/4 v8, 0x0

    .line 12
    const/4 v2, 0x1

    .line 13
    const-class v4, Lio/ktor/utils/io/d0;

    .line 14
    .line 15
    const-string v5, "flushAndClose"

    .line 16
    .line 17
    const-string v6, "flushAndClose(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 18
    .line 19
    move-object v3, p0

    .line 20
    invoke-direct/range {v1 .. v8}, Lio/ktor/utils/io/g0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 21
    .line 22
    .line 23
    sget-object p0, Lio/ktor/utils/io/h0;->a:Lio/ktor/utils/io/f0;

    .line 24
    .line 25
    :try_start_0
    new-instance p1, Lqx0/b;

    .line 26
    .line 27
    invoke-direct {p1, v1}, Lqx0/b;-><init>(Lio/ktor/utils/io/g0;)V

    .line 28
    .line 29
    .line 30
    invoke-static {p1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    invoke-static {v0, p1}, Laz0/b;->h(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :catchall_0
    move-exception v0

    .line 41
    move-object p1, v0

    .line 42
    invoke-static {p1, p0}, Ljp/qb;->a(Ljava/lang/Throwable;Lkotlin/coroutines/Continuation;)V

    .line 43
    .line 44
    .line 45
    const/4 p0, 0x0

    .line 46
    throw p0

    .line 47
    :cond_0
    move-object v3, p0

    .line 48
    move-object p0, v3

    .line 49
    check-cast p0, Lio/ktor/utils/io/m;

    .line 50
    .line 51
    invoke-virtual {p0, p1}, Lio/ktor/utils/io/m;->c(Ljava/lang/Throwable;)V

    .line 52
    .line 53
    .line 54
    return-void
.end method

.method public static final c(Lio/ktor/utils/io/t;Lio/ktor/utils/io/d0;JLrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p4

    .line 2
    .line 3
    instance-of v1, v0, Lio/ktor/utils/io/u;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lio/ktor/utils/io/u;

    .line 9
    .line 10
    iget v2, v1, Lio/ktor/utils/io/u;->j:I

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
    iput v2, v1, Lio/ktor/utils/io/u;->j:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lio/ktor/utils/io/u;

    .line 23
    .line 24
    invoke-direct {v1, v0}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object v0, v1, Lio/ktor/utils/io/u;->i:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lio/ktor/utils/io/u;->j:I

    .line 32
    .line 33
    const/4 v4, 0x4

    .line 34
    const/4 v5, 0x3

    .line 35
    const/4 v6, 0x2

    .line 36
    const/4 v7, 0x1

    .line 37
    const/4 v8, 0x0

    .line 38
    if-eqz v3, :cond_5

    .line 39
    .line 40
    if-eq v3, v7, :cond_4

    .line 41
    .line 42
    if-eq v3, v6, :cond_3

    .line 43
    .line 44
    if-eq v3, v5, :cond_2

    .line 45
    .line 46
    if-eq v3, v4, :cond_1

    .line 47
    .line 48
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw v0

    .line 56
    :cond_1
    iget-object v1, v1, Lio/ktor/utils/io/u;->f:Ljava/lang/Throwable;

    .line 57
    .line 58
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto/16 :goto_7

    .line 62
    .line 63
    :cond_2
    iget-wide v2, v1, Lio/ktor/utils/io/u;->h:J

    .line 64
    .line 65
    iget-wide v4, v1, Lio/ktor/utils/io/u;->g:J

    .line 66
    .line 67
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto/16 :goto_4

    .line 71
    .line 72
    :cond_3
    iget-wide v9, v1, Lio/ktor/utils/io/u;->h:J

    .line 73
    .line 74
    iget-wide v11, v1, Lio/ktor/utils/io/u;->g:J

    .line 75
    .line 76
    iget-object v3, v1, Lio/ktor/utils/io/u;->e:Lio/ktor/utils/io/d0;

    .line 77
    .line 78
    iget-object v13, v1, Lio/ktor/utils/io/u;->d:Lio/ktor/utils/io/t;

    .line 79
    .line 80
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 81
    .line 82
    .line 83
    move-object/from16 v16, v13

    .line 84
    .line 85
    move-object v13, v1

    .line 86
    move-object/from16 v1, v16

    .line 87
    .line 88
    goto/16 :goto_3

    .line 89
    .line 90
    :catchall_0
    move-exception v0

    .line 91
    goto/16 :goto_5

    .line 92
    .line 93
    :cond_4
    iget-wide v9, v1, Lio/ktor/utils/io/u;->h:J

    .line 94
    .line 95
    iget-wide v11, v1, Lio/ktor/utils/io/u;->g:J

    .line 96
    .line 97
    iget-object v3, v1, Lio/ktor/utils/io/u;->e:Lio/ktor/utils/io/d0;

    .line 98
    .line 99
    iget-object v13, v1, Lio/ktor/utils/io/u;->d:Lio/ktor/utils/io/t;

    .line 100
    .line 101
    :try_start_1
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 102
    .line 103
    .line 104
    goto :goto_2

    .line 105
    :cond_5
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    move-object/from16 v3, p1

    .line 109
    .line 110
    move-wide/from16 v9, p2

    .line 111
    .line 112
    move-wide v11, v9

    .line 113
    move-object v13, v1

    .line 114
    move-object/from16 v1, p0

    .line 115
    .line 116
    :goto_1
    :try_start_2
    invoke-interface {v1}, Lio/ktor/utils/io/t;->g()Z

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    if-nez v0, :cond_8

    .line 121
    .line 122
    const-wide/16 v14, 0x0

    .line 123
    .line 124
    cmp-long v0, v9, v14

    .line 125
    .line 126
    if-lez v0, :cond_8

    .line 127
    .line 128
    invoke-interface {v1}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    invoke-virtual {v0}, Lnz0/a;->Z()Z

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    if-eqz v0, :cond_6

    .line 137
    .line 138
    iput-object v1, v13, Lio/ktor/utils/io/u;->d:Lio/ktor/utils/io/t;

    .line 139
    .line 140
    iput-object v3, v13, Lio/ktor/utils/io/u;->e:Lio/ktor/utils/io/d0;

    .line 141
    .line 142
    iput-wide v11, v13, Lio/ktor/utils/io/u;->g:J

    .line 143
    .line 144
    iput-wide v9, v13, Lio/ktor/utils/io/u;->h:J

    .line 145
    .line 146
    iput v7, v13, Lio/ktor/utils/io/u;->j:I

    .line 147
    .line 148
    invoke-interface {v1, v7, v13}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 152
    if-ne v0, v2, :cond_6

    .line 153
    .line 154
    goto/16 :goto_6

    .line 155
    .line 156
    :catchall_1
    move-exception v0

    .line 157
    move-object/from16 v16, v13

    .line 158
    .line 159
    move-object v13, v1

    .line 160
    move-object/from16 v1, v16

    .line 161
    .line 162
    goto :goto_5

    .line 163
    :cond_6
    move-object/from16 v16, v13

    .line 164
    .line 165
    move-object v13, v1

    .line 166
    move-object/from16 v1, v16

    .line 167
    .line 168
    :goto_2
    :try_start_3
    invoke-interface {v13}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 169
    .line 170
    .line 171
    move-result-object v0

    .line 172
    invoke-static {v0}, Ljp/hb;->c(Lnz0/i;)J

    .line 173
    .line 174
    .line 175
    move-result-wide v14

    .line 176
    invoke-static {v9, v10, v14, v15}, Ljava/lang/Math;->min(JJ)J

    .line 177
    .line 178
    .line 179
    move-result-wide v14

    .line 180
    invoke-interface {v13}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    move-object v7, v3

    .line 185
    check-cast v7, Lio/ktor/utils/io/m;

    .line 186
    .line 187
    invoke-virtual {v7}, Lio/ktor/utils/io/m;->j()Lnz0/a;

    .line 188
    .line 189
    .line 190
    move-result-object v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 191
    :try_start_4
    invoke-virtual {v0, v3, v14, v15}, Lnz0/a;->b(Lnz0/a;J)V

    .line 192
    .line 193
    .line 194
    sub-long/2addr v9, v14

    .line 195
    iput-object v13, v1, Lio/ktor/utils/io/u;->d:Lio/ktor/utils/io/t;

    .line 196
    .line 197
    iput-object v7, v1, Lio/ktor/utils/io/u;->e:Lio/ktor/utils/io/d0;

    .line 198
    .line 199
    iput-wide v11, v1, Lio/ktor/utils/io/u;->g:J

    .line 200
    .line 201
    iput-wide v9, v1, Lio/ktor/utils/io/u;->h:J

    .line 202
    .line 203
    iput v6, v1, Lio/ktor/utils/io/u;->j:I

    .line 204
    .line 205
    invoke-virtual {v7, v1}, Lio/ktor/utils/io/m;->b(Lrx0/c;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 209
    if-ne v0, v2, :cond_7

    .line 210
    .line 211
    goto :goto_6

    .line 212
    :cond_7
    move-object v3, v13

    .line 213
    move-object v13, v1

    .line 214
    move-object v1, v3

    .line 215
    move-object v3, v7

    .line 216
    :goto_3
    const/4 v7, 0x1

    .line 217
    goto :goto_1

    .line 218
    :catchall_2
    move-exception v0

    .line 219
    move-object v3, v7

    .line 220
    goto :goto_5

    .line 221
    :cond_8
    iput-object v8, v13, Lio/ktor/utils/io/u;->d:Lio/ktor/utils/io/t;

    .line 222
    .line 223
    iput-object v8, v13, Lio/ktor/utils/io/u;->e:Lio/ktor/utils/io/d0;

    .line 224
    .line 225
    iput-wide v11, v13, Lio/ktor/utils/io/u;->g:J

    .line 226
    .line 227
    iput-wide v9, v13, Lio/ktor/utils/io/u;->h:J

    .line 228
    .line 229
    iput v5, v13, Lio/ktor/utils/io/u;->j:I

    .line 230
    .line 231
    check-cast v3, Lio/ktor/utils/io/m;

    .line 232
    .line 233
    invoke-virtual {v3, v13}, Lio/ktor/utils/io/m;->b(Lrx0/c;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    if-ne v0, v2, :cond_9

    .line 238
    .line 239
    goto :goto_6

    .line 240
    :cond_9
    move-wide v2, v9

    .line 241
    move-wide v4, v11

    .line 242
    :goto_4
    sub-long/2addr v4, v2

    .line 243
    new-instance v0, Ljava/lang/Long;

    .line 244
    .line 245
    invoke-direct {v0, v4, v5}, Ljava/lang/Long;-><init>(J)V

    .line 246
    .line 247
    .line 248
    return-object v0

    .line 249
    :goto_5
    :try_start_5
    invoke-interface {v13, v0}, Lio/ktor/utils/io/t;->c(Ljava/lang/Throwable;)V

    .line 250
    .line 251
    .line 252
    invoke-static {v3, v0}, Lio/ktor/utils/io/h0;->b(Lio/ktor/utils/io/d0;Ljava/lang/Throwable;)V

    .line 253
    .line 254
    .line 255
    throw v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 256
    :catchall_3
    move-exception v0

    .line 257
    iput-object v8, v1, Lio/ktor/utils/io/u;->d:Lio/ktor/utils/io/t;

    .line 258
    .line 259
    iput-object v8, v1, Lio/ktor/utils/io/u;->e:Lio/ktor/utils/io/d0;

    .line 260
    .line 261
    iput-object v0, v1, Lio/ktor/utils/io/u;->f:Ljava/lang/Throwable;

    .line 262
    .line 263
    iput-wide v11, v1, Lio/ktor/utils/io/u;->g:J

    .line 264
    .line 265
    iput-wide v9, v1, Lio/ktor/utils/io/u;->h:J

    .line 266
    .line 267
    iput v4, v1, Lio/ktor/utils/io/u;->j:I

    .line 268
    .line 269
    check-cast v3, Lio/ktor/utils/io/m;

    .line 270
    .line 271
    invoke-virtual {v3, v1}, Lio/ktor/utils/io/m;->b(Lrx0/c;)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    if-ne v1, v2, :cond_a

    .line 276
    .line 277
    :goto_6
    return-object v2

    .line 278
    :cond_a
    move-object v1, v0

    .line 279
    :goto_7
    throw v1
.end method

.method public static final d(Lio/ktor/utils/io/t;JLrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p3, Lio/ktor/utils/io/v;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lio/ktor/utils/io/v;

    .line 7
    .line 8
    iget v1, v0, Lio/ktor/utils/io/v;->h:I

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
    iput v1, v0, Lio/ktor/utils/io/v;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lio/ktor/utils/io/v;

    .line 21
    .line 22
    invoke-direct {v0, p3}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lio/ktor/utils/io/v;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lio/ktor/utils/io/v;->h:I

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
    iget-wide p0, v0, Lio/ktor/utils/io/v;->f:J

    .line 37
    .line 38
    iget-wide v4, v0, Lio/ktor/utils/io/v;->e:J

    .line 39
    .line 40
    iget-object p2, v0, Lio/ktor/utils/io/v;->d:Lio/ktor/utils/io/t;

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
    move-wide v4, p1

    .line 58
    :goto_1
    const-wide/16 v6, 0x0

    .line 59
    .line 60
    cmp-long p3, p1, v6

    .line 61
    .line 62
    if-lez p3, :cond_5

    .line 63
    .line 64
    invoke-interface {p0}, Lio/ktor/utils/io/t;->g()Z

    .line 65
    .line 66
    .line 67
    move-result p3

    .line 68
    if-nez p3, :cond_5

    .line 69
    .line 70
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 71
    .line 72
    .line 73
    move-result-object p3

    .line 74
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    iget-wide v6, p3, Lnz0/a;->f:J

    .line 78
    .line 79
    long-to-int p3, v6

    .line 80
    if-nez p3, :cond_4

    .line 81
    .line 82
    iput-object p0, v0, Lio/ktor/utils/io/v;->d:Lio/ktor/utils/io/t;

    .line 83
    .line 84
    iput-wide v4, v0, Lio/ktor/utils/io/v;->e:J

    .line 85
    .line 86
    iput-wide p1, v0, Lio/ktor/utils/io/v;->f:J

    .line 87
    .line 88
    iput v3, v0, Lio/ktor/utils/io/v;->h:I

    .line 89
    .line 90
    invoke-interface {p0, v3, v0}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p3

    .line 94
    if-ne p3, v1, :cond_3

    .line 95
    .line 96
    return-object v1

    .line 97
    :cond_3
    move-wide v8, p1

    .line 98
    move-object p2, p0

    .line 99
    move-wide p0, v8

    .line 100
    :goto_2
    move-wide v8, p0

    .line 101
    move-object p0, p2

    .line 102
    move-wide p1, v8

    .line 103
    :cond_4
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 104
    .line 105
    .line 106
    move-result-object p3

    .line 107
    invoke-static {p3}, Ljp/hb;->c(Lnz0/i;)J

    .line 108
    .line 109
    .line 110
    move-result-wide v6

    .line 111
    invoke-static {p1, p2, v6, v7}, Ljava/lang/Math;->min(JJ)J

    .line 112
    .line 113
    .line 114
    move-result-wide v6

    .line 115
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 116
    .line 117
    .line 118
    move-result-object p3

    .line 119
    invoke-static {p3, v6, v7}, Ljp/hb;->a(Lnz0/i;J)J

    .line 120
    .line 121
    .line 122
    sub-long/2addr p1, v6

    .line 123
    goto :goto_1

    .line 124
    :cond_5
    sub-long/2addr v4, p1

    .line 125
    new-instance p0, Ljava/lang/Long;

    .line 126
    .line 127
    invoke-direct {p0, v4, v5}, Ljava/lang/Long;-><init>(J)V

    .line 128
    .line 129
    .line 130
    return-object p0
.end method

.method public static final e(Lio/ktor/utils/io/d0;Lrx0/c;)Ljava/lang/Object;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p0, Lio/ktor/utils/io/m;

    .line 7
    .line 8
    invoke-virtual {p0}, Lio/ktor/utils/io/m;->d()Ljava/lang/Throwable;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0}, Lio/ktor/utils/io/m;->j()Lnz0/a;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-wide v0, v0, Lnz0/a;->f:J

    .line 19
    .line 20
    long-to-int v0, v0

    .line 21
    const/high16 v1, 0x100000

    .line 22
    .line 23
    if-lt v0, v1, :cond_0

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lio/ktor/utils/io/m;->b(Lrx0/c;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    if-ne p0, p1, :cond_0

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_1
    throw v0
.end method

.method public static final f(Lio/ktor/utils/io/t;ILrx0/c;)Ljava/lang/Comparable;
    .locals 4

    .line 1
    instance-of v0, p2, Lio/ktor/utils/io/w;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lio/ktor/utils/io/w;

    .line 7
    .line 8
    iget v1, v0, Lio/ktor/utils/io/w;->g:I

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
    iput v1, v0, Lio/ktor/utils/io/w;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lio/ktor/utils/io/w;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lio/ktor/utils/io/w;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lio/ktor/utils/io/w;->g:I

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
    iget p1, v0, Lio/ktor/utils/io/w;->e:I

    .line 37
    .line 38
    iget-object p0, v0, Lio/ktor/utils/io/w;->d:Lio/ktor/utils/io/t;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-interface {p0}, Lio/ktor/utils/io/t;->g()Z

    .line 56
    .line 57
    .line 58
    move-result p2

    .line 59
    if-eqz p2, :cond_3

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_3
    iput-object p0, v0, Lio/ktor/utils/io/w;->d:Lio/ktor/utils/io/t;

    .line 63
    .line 64
    iput p1, v0, Lio/ktor/utils/io/w;->e:I

    .line 65
    .line 66
    iput v3, v0, Lio/ktor/utils/io/w;->g:I

    .line 67
    .line 68
    invoke-interface {p0, p1, v0}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    if-ne p2, v1, :cond_4

    .line 73
    .line 74
    return-object v1

    .line 75
    :cond_4
    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    .line 76
    .line 77
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 78
    .line 79
    .line 80
    move-result p2

    .line 81
    if-nez p2, :cond_5

    .line 82
    .line 83
    :goto_2
    const/4 p0, 0x0

    .line 84
    return-object p0

    .line 85
    :cond_5
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    new-instance p2, Lnz0/c;

    .line 93
    .line 94
    invoke-direct {p2, p0}, Lnz0/c;-><init>(Lnz0/i;)V

    .line 95
    .line 96
    .line 97
    new-instance p0, Lnz0/e;

    .line 98
    .line 99
    invoke-direct {p0, p2}, Lnz0/e;-><init>(Lnz0/c;)V

    .line 100
    .line 101
    .line 102
    invoke-static {p0, p1}, Lnz0/j;->e(Lnz0/i;I)[B

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    new-instance p1, Loz0/a;

    .line 107
    .line 108
    invoke-direct {p1, p0}, Loz0/a;-><init>([B)V

    .line 109
    .line 110
    .line 111
    return-object p1
.end method

.method public static final g(Lio/ktor/utils/io/t;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lio/ktor/utils/io/x;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lio/ktor/utils/io/x;

    .line 7
    .line 8
    iget v1, v0, Lio/ktor/utils/io/x;->g:I

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
    iput v1, v0, Lio/ktor/utils/io/x;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lio/ktor/utils/io/x;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lio/ktor/utils/io/x;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lio/ktor/utils/io/x;->g:I

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
    iget-object p0, v0, Lio/ktor/utils/io/x;->e:Lnz0/a;

    .line 37
    .line 38
    iget-object v2, v0, Lio/ktor/utils/io/x;->d:Lio/ktor/utils/io/t;

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    move-object p1, p0

    .line 44
    move-object p0, v2

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
    new-instance p1, Lnz0/a;

    .line 58
    .line 59
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 60
    .line 61
    .line 62
    :cond_3
    :goto_1
    invoke-interface {p0}, Lio/ktor/utils/io/t;->g()Z

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-nez v2, :cond_4

    .line 67
    .line 68
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    invoke-virtual {p1, v2}, Lnz0/a;->g(Lnz0/d;)J

    .line 73
    .line 74
    .line 75
    iput-object p0, v0, Lio/ktor/utils/io/x;->d:Lio/ktor/utils/io/t;

    .line 76
    .line 77
    iput-object p1, v0, Lio/ktor/utils/io/x;->e:Lnz0/a;

    .line 78
    .line 79
    iput v3, v0, Lio/ktor/utils/io/x;->g:I

    .line 80
    .line 81
    invoke-interface {p0, v3, v0}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    if-ne v2, v1, :cond_3

    .line 86
    .line 87
    return-object v1

    .line 88
    :cond_4
    invoke-interface {p0}, Lio/ktor/utils/io/t;->d()Ljava/lang/Throwable;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    if-nez p0, :cond_5

    .line 93
    .line 94
    return-object p1

    .line 95
    :cond_5
    throw p0
.end method

.method public static final h(Lio/ktor/utils/io/o0;ILrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p2, Lio/ktor/utils/io/y;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lio/ktor/utils/io/y;

    .line 7
    .line 8
    iget v1, v0, Lio/ktor/utils/io/y;->h:I

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
    iput v1, v0, Lio/ktor/utils/io/y;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lio/ktor/utils/io/y;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lio/ktor/utils/io/y;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lio/ktor/utils/io/y;->h:I

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
    iget p0, v0, Lio/ktor/utils/io/y;->f:I

    .line 37
    .line 38
    iget-object p1, v0, Lio/ktor/utils/io/y;->e:Lnz0/a;

    .line 39
    .line 40
    iget-object v2, v0, Lio/ktor/utils/io/y;->d:Lio/ktor/utils/io/t;

    .line 41
    .line 42
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    new-instance p2, Lnz0/a;

    .line 58
    .line 59
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 60
    .line 61
    .line 62
    move-object v10, p2

    .line 63
    move p2, p1

    .line 64
    move-object p1, v10

    .line 65
    :goto_1
    iget-wide v4, p1, Lnz0/a;->f:J

    .line 66
    .line 67
    int-to-long v6, p2

    .line 68
    cmp-long v2, v4, v6

    .line 69
    .line 70
    if-gez v2, :cond_6

    .line 71
    .line 72
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    invoke-virtual {v2}, Lnz0/a;->Z()Z

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    if-eqz v2, :cond_4

    .line 81
    .line 82
    iput-object p0, v0, Lio/ktor/utils/io/y;->d:Lio/ktor/utils/io/t;

    .line 83
    .line 84
    iput-object p1, v0, Lio/ktor/utils/io/y;->e:Lnz0/a;

    .line 85
    .line 86
    iput p2, v0, Lio/ktor/utils/io/y;->f:I

    .line 87
    .line 88
    iput v3, v0, Lio/ktor/utils/io/y;->h:I

    .line 89
    .line 90
    invoke-interface {p0, v3, v0}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    if-ne v2, v1, :cond_3

    .line 95
    .line 96
    return-object v1

    .line 97
    :cond_3
    move-object v2, p0

    .line 98
    move p0, p2

    .line 99
    :goto_2
    move p2, p0

    .line 100
    move-object p0, v2

    .line 101
    :cond_4
    invoke-interface {p0}, Lio/ktor/utils/io/t;->g()Z

    .line 102
    .line 103
    .line 104
    move-result v2

    .line 105
    if-nez v2, :cond_6

    .line 106
    .line 107
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    invoke-static {v2}, Ljp/hb;->c(Lnz0/i;)J

    .line 112
    .line 113
    .line 114
    move-result-wide v4

    .line 115
    int-to-long v6, p2

    .line 116
    iget-wide v8, p1, Lnz0/a;->f:J

    .line 117
    .line 118
    sub-long v8, v6, v8

    .line 119
    .line 120
    cmp-long v2, v4, v8

    .line 121
    .line 122
    if-lez v2, :cond_5

    .line 123
    .line 124
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 125
    .line 126
    .line 127
    move-result-object v2

    .line 128
    iget-wide v4, p1, Lnz0/a;->f:J

    .line 129
    .line 130
    sub-long/2addr v6, v4

    .line 131
    invoke-virtual {v2, p1, v6, v7}, Lnz0/a;->b(Lnz0/a;J)V

    .line 132
    .line 133
    .line 134
    goto :goto_1

    .line 135
    :cond_5
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 136
    .line 137
    .line 138
    move-result-object v2

    .line 139
    invoke-virtual {v2, p1}, Lnz0/a;->h(Lnz0/a;)J

    .line 140
    .line 141
    .line 142
    move-result-wide v4

    .line 143
    new-instance v2, Ljava/lang/Long;

    .line 144
    .line 145
    invoke-direct {v2, v4, v5}, Ljava/lang/Long;-><init>(J)V

    .line 146
    .line 147
    .line 148
    goto :goto_1

    .line 149
    :cond_6
    iget-wide v0, p1, Lnz0/a;->f:J

    .line 150
    .line 151
    int-to-long v2, p2

    .line 152
    cmp-long p0, v0, v2

    .line 153
    .line 154
    if-ltz p0, :cond_7

    .line 155
    .line 156
    return-object p1

    .line 157
    :cond_7
    new-instance p0, Ljava/io/EOFException;

    .line 158
    .line 159
    const-string v0, "Not enough data available, required "

    .line 160
    .line 161
    const-string v1, " bytes but only "

    .line 162
    .line 163
    invoke-static {v0, p2, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    move-result-object p2

    .line 167
    iget-wide v0, p1, Lnz0/a;->f:J

    .line 168
    .line 169
    const-string p1, " available"

    .line 170
    .line 171
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->k(JLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    invoke-direct {p0, p1}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    throw p0
.end method

.method public static final i(Lio/ktor/utils/io/t;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lio/ktor/utils/io/z;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lio/ktor/utils/io/z;

    .line 7
    .line 8
    iget v1, v0, Lio/ktor/utils/io/z;->g:I

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
    iput v1, v0, Lio/ktor/utils/io/z;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lio/ktor/utils/io/z;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lio/ktor/utils/io/z;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lio/ktor/utils/io/z;->g:I

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
    iget-object p0, v0, Lio/ktor/utils/io/z;->e:Lnz0/a;

    .line 37
    .line 38
    iget-object v2, v0, Lio/ktor/utils/io/z;->d:Lio/ktor/utils/io/t;

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    move-object p1, p0

    .line 44
    move-object p0, v2

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
    new-instance p1, Lnz0/a;

    .line 58
    .line 59
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 60
    .line 61
    .line 62
    :cond_3
    :goto_1
    invoke-interface {p0}, Lio/ktor/utils/io/t;->g()Z

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-nez v2, :cond_4

    .line 67
    .line 68
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    invoke-virtual {p1, v2}, Lnz0/a;->g(Lnz0/d;)J

    .line 73
    .line 74
    .line 75
    iput-object p0, v0, Lio/ktor/utils/io/z;->d:Lio/ktor/utils/io/t;

    .line 76
    .line 77
    iput-object p1, v0, Lio/ktor/utils/io/z;->e:Lnz0/a;

    .line 78
    .line 79
    iput v3, v0, Lio/ktor/utils/io/z;->g:I

    .line 80
    .line 81
    invoke-interface {p0, v3, v0}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    if-ne v2, v1, :cond_3

    .line 86
    .line 87
    return-object v1

    .line 88
    :cond_4
    invoke-interface {p0}, Lio/ktor/utils/io/t;->d()Ljava/lang/Throwable;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    if-nez p0, :cond_5

    .line 93
    .line 94
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    return-object p1

    .line 98
    :cond_5
    throw p0
.end method

.method public static final j(Lio/ktor/utils/io/t;Lqw0/c;IILrx0/c;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p4

    .line 4
    .line 5
    instance-of v2, v1, Lio/ktor/utils/io/a0;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lio/ktor/utils/io/a0;

    .line 11
    .line 12
    iget v3, v2, Lio/ktor/utils/io/a0;->l:I

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
    iput v3, v2, Lio/ktor/utils/io/a0;->l:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lio/ktor/utils/io/a0;

    .line 25
    .line 26
    invoke-direct {v2, v1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lio/ktor/utils/io/a0;->k:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lio/ktor/utils/io/a0;->l:I

    .line 34
    .line 35
    const-string v5, "<this>"

    .line 36
    .line 37
    const/16 v6, 0xa

    .line 38
    .line 39
    const/4 v9, 0x3

    .line 40
    const/4 v10, 0x2

    .line 41
    const/4 v11, 0x0

    .line 42
    const/4 v12, 0x1

    .line 43
    if-eqz v4, :cond_4

    .line 44
    .line 45
    if-eq v4, v12, :cond_3

    .line 46
    .line 47
    if-eq v4, v10, :cond_2

    .line 48
    .line 49
    if-ne v4, v9, :cond_1

    .line 50
    .line 51
    iget v0, v2, Lio/ktor/utils/io/a0;->j:I

    .line 52
    .line 53
    iget v4, v2, Lio/ktor/utils/io/a0;->i:I

    .line 54
    .line 55
    iget v14, v2, Lio/ktor/utils/io/a0;->h:I

    .line 56
    .line 57
    iget-object v15, v2, Lio/ktor/utils/io/a0;->g:Lnz0/a;

    .line 58
    .line 59
    const-wide/16 v16, 0x0

    .line 60
    .line 61
    iget-object v7, v2, Lio/ktor/utils/io/a0;->f:Ljava/lang/AutoCloseable;

    .line 62
    .line 63
    iget-object v8, v2, Lio/ktor/utils/io/a0;->e:Ljava/lang/Appendable;

    .line 64
    .line 65
    iget-object v9, v2, Lio/ktor/utils/io/a0;->d:Lio/ktor/utils/io/t;

    .line 66
    .line 67
    :try_start_0
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 68
    .line 69
    .line 70
    move v11, v12

    .line 71
    const/4 v10, 0x3

    .line 72
    goto/16 :goto_7

    .line 73
    .line 74
    :catchall_0
    move-exception v0

    .line 75
    move-object v1, v0

    .line 76
    goto/16 :goto_9

    .line 77
    .line 78
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 79
    .line 80
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 81
    .line 82
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    throw v0

    .line 86
    :cond_2
    const-wide/16 v16, 0x0

    .line 87
    .line 88
    iget v0, v2, Lio/ktor/utils/io/a0;->i:I

    .line 89
    .line 90
    iget-object v3, v2, Lio/ktor/utils/io/a0;->g:Lnz0/a;

    .line 91
    .line 92
    iget-object v7, v2, Lio/ktor/utils/io/a0;->f:Ljava/lang/AutoCloseable;

    .line 93
    .line 94
    iget-object v4, v2, Lio/ktor/utils/io/a0;->e:Ljava/lang/Appendable;

    .line 95
    .line 96
    iget-object v2, v2, Lio/ktor/utils/io/a0;->d:Lio/ktor/utils/io/t;

    .line 97
    .line 98
    :try_start_1
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 99
    .line 100
    .line 101
    goto/16 :goto_4

    .line 102
    .line 103
    :cond_3
    const-wide/16 v16, 0x0

    .line 104
    .line 105
    iget v0, v2, Lio/ktor/utils/io/a0;->i:I

    .line 106
    .line 107
    iget v4, v2, Lio/ktor/utils/io/a0;->h:I

    .line 108
    .line 109
    iget-object v7, v2, Lio/ktor/utils/io/a0;->e:Ljava/lang/Appendable;

    .line 110
    .line 111
    iget-object v8, v2, Lio/ktor/utils/io/a0;->d:Lio/ktor/utils/io/t;

    .line 112
    .line 113
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    move-object v1, v7

    .line 117
    move v7, v0

    .line 118
    move-object v0, v8

    .line 119
    goto :goto_1

    .line 120
    :cond_4
    const-wide/16 v16, 0x0

    .line 121
    .line 122
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    invoke-interface {v0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    invoke-virtual {v1}, Lnz0/a;->Z()Z

    .line 130
    .line 131
    .line 132
    move-result v1

    .line 133
    if-eqz v1, :cond_5

    .line 134
    .line 135
    iput-object v0, v2, Lio/ktor/utils/io/a0;->d:Lio/ktor/utils/io/t;

    .line 136
    .line 137
    move-object/from16 v1, p1

    .line 138
    .line 139
    iput-object v1, v2, Lio/ktor/utils/io/a0;->e:Ljava/lang/Appendable;

    .line 140
    .line 141
    move/from16 v4, p2

    .line 142
    .line 143
    iput v4, v2, Lio/ktor/utils/io/a0;->h:I

    .line 144
    .line 145
    move/from16 v7, p3

    .line 146
    .line 147
    iput v7, v2, Lio/ktor/utils/io/a0;->i:I

    .line 148
    .line 149
    iput v12, v2, Lio/ktor/utils/io/a0;->l:I

    .line 150
    .line 151
    invoke-interface {v0, v12, v2}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v8

    .line 155
    if-ne v8, v3, :cond_6

    .line 156
    .line 157
    goto/16 :goto_6

    .line 158
    .line 159
    :cond_5
    move-object/from16 v1, p1

    .line 160
    .line 161
    move/from16 v4, p2

    .line 162
    .line 163
    move/from16 v7, p3

    .line 164
    .line 165
    :cond_6
    :goto_1
    invoke-interface {v0}, Lio/ktor/utils/io/t;->g()Z

    .line 166
    .line 167
    .line 168
    move-result v8

    .line 169
    if-eqz v8, :cond_7

    .line 170
    .line 171
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 172
    .line 173
    return-object v0

    .line 174
    :cond_7
    new-instance v8, Lnz0/a;

    .line 175
    .line 176
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 177
    .line 178
    .line 179
    move-object v9, v0

    .line 180
    move v14, v4

    .line 181
    move v4, v7

    .line 182
    move-object v7, v8

    .line 183
    move-object v15, v7

    .line 184
    move v0, v11

    .line 185
    move-object v8, v1

    .line 186
    :goto_2
    :try_start_2
    invoke-interface {v9}, Lio/ktor/utils/io/t;->g()Z

    .line 187
    .line 188
    .line 189
    move-result v1

    .line 190
    if-nez v1, :cond_11

    .line 191
    .line 192
    :goto_3
    invoke-interface {v9}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    invoke-virtual {v1}, Lnz0/a;->Z()Z

    .line 197
    .line 198
    .line 199
    move-result v1

    .line 200
    if-nez v1, :cond_e

    .line 201
    .line 202
    invoke-interface {v9}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 203
    .line 204
    .line 205
    move-result-object v1

    .line 206
    invoke-virtual {v1}, Lnz0/a;->readByte()B

    .line 207
    .line 208
    .line 209
    move-result v1

    .line 210
    const/16 v13, 0xd

    .line 211
    .line 212
    if-ne v1, v13, :cond_c

    .line 213
    .line 214
    invoke-interface {v9}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 215
    .line 216
    .line 217
    move-result-object v1

    .line 218
    invoke-virtual {v1}, Lnz0/a;->Z()Z

    .line 219
    .line 220
    .line 221
    move-result v1

    .line 222
    if-eqz v1, :cond_9

    .line 223
    .line 224
    iput-object v9, v2, Lio/ktor/utils/io/a0;->d:Lio/ktor/utils/io/t;

    .line 225
    .line 226
    iput-object v8, v2, Lio/ktor/utils/io/a0;->e:Ljava/lang/Appendable;

    .line 227
    .line 228
    iput-object v7, v2, Lio/ktor/utils/io/a0;->f:Ljava/lang/AutoCloseable;

    .line 229
    .line 230
    iput-object v15, v2, Lio/ktor/utils/io/a0;->g:Lnz0/a;

    .line 231
    .line 232
    iput v14, v2, Lio/ktor/utils/io/a0;->h:I

    .line 233
    .line 234
    iput v4, v2, Lio/ktor/utils/io/a0;->i:I

    .line 235
    .line 236
    iput v0, v2, Lio/ktor/utils/io/a0;->j:I

    .line 237
    .line 238
    iput v10, v2, Lio/ktor/utils/io/a0;->l:I

    .line 239
    .line 240
    invoke-interface {v9, v12, v2}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    if-ne v0, v3, :cond_8

    .line 245
    .line 246
    goto/16 :goto_6

    .line 247
    .line 248
    :cond_8
    move v0, v4

    .line 249
    move-object v4, v8

    .line 250
    move-object v2, v9

    .line 251
    move-object v3, v15

    .line 252
    :goto_4
    move-object v9, v2

    .line 253
    move-object v15, v3

    .line 254
    move-object v8, v4

    .line 255
    move v4, v0

    .line 256
    :cond_9
    invoke-interface {v9}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 257
    .line 258
    .line 259
    move-result-object v0

    .line 260
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 261
    .line 262
    .line 263
    iget-wide v1, v0, Lnz0/a;->f:J

    .line 264
    .line 265
    cmp-long v1, v16, v1

    .line 266
    .line 267
    if-gez v1, :cond_b

    .line 268
    .line 269
    iget-object v0, v0, Lnz0/a;->d:Lnz0/g;

    .line 270
    .line 271
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 272
    .line 273
    .line 274
    invoke-virtual {v0, v11}, Lnz0/g;->c(I)B

    .line 275
    .line 276
    .line 277
    move-result v0

    .line 278
    if-ne v0, v6, :cond_a

    .line 279
    .line 280
    sget-object v0, Lio/ktor/utils/io/p0;->b:Ljava/util/List;

    .line 281
    .line 282
    const/4 v0, 0x4

    .line 283
    invoke-static {v4, v0}, Lio/ktor/utils/io/h0;->k(II)V

    .line 284
    .line 285
    .line 286
    invoke-interface {v9}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    .line 287
    .line 288
    .line 289
    move-result-object v0

    .line 290
    const-wide/16 v1, 0x1

    .line 291
    .line 292
    invoke-static {v0, v1, v2}, Ljp/hb;->a(Lnz0/i;J)J

    .line 293
    .line 294
    .line 295
    move-result-wide v0

    .line 296
    new-instance v2, Ljava/lang/Long;

    .line 297
    .line 298
    invoke-direct {v2, v0, v1}, Ljava/lang/Long;-><init>(J)V

    .line 299
    .line 300
    .line 301
    goto :goto_5

    .line 302
    :cond_a
    sget-object v0, Lio/ktor/utils/io/p0;->b:Ljava/util/List;

    .line 303
    .line 304
    invoke-static {v4, v12}, Lio/ktor/utils/io/h0;->k(II)V

    .line 305
    .line 306
    .line 307
    :goto_5
    invoke-static {v15, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    iget-wide v0, v15, Lnz0/a;->f:J

    .line 311
    .line 312
    invoke-static {v15, v0, v1}, Lnz0/j;->b(Lnz0/a;J)Ljava/lang/String;

    .line 313
    .line 314
    .line 315
    move-result-object v0

    .line 316
    invoke-interface {v8, v0}, Ljava/lang/Appendable;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 317
    .line 318
    .line 319
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 320
    .line 321
    const/4 v1, 0x0

    .line 322
    invoke-static {v7, v1}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 323
    .line 324
    .line 325
    return-object v0

    .line 326
    :cond_b
    :try_start_3
    new-instance v1, Ljava/lang/IndexOutOfBoundsException;

    .line 327
    .line 328
    new-instance v2, Ljava/lang/StringBuilder;

    .line 329
    .line 330
    const-string v3, "position (0) is not within the range [0..size("

    .line 331
    .line 332
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 333
    .line 334
    .line 335
    iget-wide v3, v0, Lnz0/a;->f:J

    .line 336
    .line 337
    const-string v0, "))"

    .line 338
    .line 339
    invoke-static {v3, v4, v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->k(JLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object v0

    .line 343
    invoke-direct {v1, v0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    throw v1

    .line 347
    :cond_c
    if-ne v1, v6, :cond_d

    .line 348
    .line 349
    sget-object v0, Lio/ktor/utils/io/p0;->b:Ljava/util/List;

    .line 350
    .line 351
    invoke-static {v4, v10}, Lio/ktor/utils/io/h0;->k(II)V

    .line 352
    .line 353
    .line 354
    invoke-static {v15, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    iget-wide v0, v15, Lnz0/a;->f:J

    .line 358
    .line 359
    invoke-static {v15, v0, v1}, Lnz0/j;->b(Lnz0/a;J)Ljava/lang/String;

    .line 360
    .line 361
    .line 362
    move-result-object v0

    .line 363
    invoke-interface {v8, v0}, Ljava/lang/Appendable;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 364
    .line 365
    .line 366
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 367
    .line 368
    const/4 v1, 0x0

    .line 369
    invoke-static {v7, v1}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 370
    .line 371
    .line 372
    return-object v0

    .line 373
    :cond_d
    int-to-byte v1, v1

    .line 374
    :try_start_4
    invoke-virtual {v15, v1}, Lnz0/a;->q(B)V

    .line 375
    .line 376
    .line 377
    goto/16 :goto_3

    .line 378
    .line 379
    :cond_e
    iget-wide v10, v15, Lnz0/a;->f:J

    .line 380
    .line 381
    int-to-long v12, v14

    .line 382
    cmp-long v10, v10, v12

    .line 383
    .line 384
    if-gez v10, :cond_10

    .line 385
    .line 386
    iput-object v9, v2, Lio/ktor/utils/io/a0;->d:Lio/ktor/utils/io/t;

    .line 387
    .line 388
    iput-object v8, v2, Lio/ktor/utils/io/a0;->e:Ljava/lang/Appendable;

    .line 389
    .line 390
    iput-object v7, v2, Lio/ktor/utils/io/a0;->f:Ljava/lang/AutoCloseable;

    .line 391
    .line 392
    iput-object v15, v2, Lio/ktor/utils/io/a0;->g:Lnz0/a;

    .line 393
    .line 394
    iput v14, v2, Lio/ktor/utils/io/a0;->h:I

    .line 395
    .line 396
    iput v4, v2, Lio/ktor/utils/io/a0;->i:I

    .line 397
    .line 398
    iput v0, v2, Lio/ktor/utils/io/a0;->j:I

    .line 399
    .line 400
    const/4 v10, 0x3

    .line 401
    iput v10, v2, Lio/ktor/utils/io/a0;->l:I

    .line 402
    .line 403
    const/4 v11, 0x1

    .line 404
    invoke-interface {v9, v11, v2}, Lio/ktor/utils/io/t;->f(ILrx0/c;)Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object v12

    .line 408
    if-ne v12, v3, :cond_f

    .line 409
    .line 410
    :goto_6
    return-object v3

    .line 411
    :cond_f
    :goto_7
    move v12, v11

    .line 412
    const/4 v10, 0x2

    .line 413
    const/4 v11, 0x0

    .line 414
    goto/16 :goto_2

    .line 415
    .line 416
    :cond_10
    new-instance v0, Lax0/a;

    .line 417
    .line 418
    new-instance v1, Ljava/lang/StringBuilder;

    .line 419
    .line 420
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 421
    .line 422
    .line 423
    const-string v2, "Line exceeds limit of "

    .line 424
    .line 425
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 426
    .line 427
    .line 428
    invoke-virtual {v1, v14}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 429
    .line 430
    .line 431
    const-string v2, " characters"

    .line 432
    .line 433
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 434
    .line 435
    .line 436
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 437
    .line 438
    .line 439
    move-result-object v1

    .line 440
    invoke-direct {v0, v1}, Lax0/a;-><init>(Ljava/lang/String;)V

    .line 441
    .line 442
    .line 443
    throw v0

    .line 444
    :cond_11
    move v11, v12

    .line 445
    iget-wide v2, v15, Lnz0/a;->f:J

    .line 446
    .line 447
    cmp-long v0, v2, v16

    .line 448
    .line 449
    if-lez v0, :cond_12

    .line 450
    .line 451
    goto :goto_8

    .line 452
    :cond_12
    const/4 v11, 0x0

    .line 453
    :goto_8
    invoke-static {v11}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 454
    .line 455
    .line 456
    move-result-object v0

    .line 457
    if-eqz v11, :cond_13

    .line 458
    .line 459
    iget-wide v1, v15, Lnz0/a;->f:J

    .line 460
    .line 461
    invoke-static {v15, v1, v2}, Lnz0/j;->b(Lnz0/a;J)Ljava/lang/String;

    .line 462
    .line 463
    .line 464
    move-result-object v1

    .line 465
    invoke-interface {v8, v1}, Ljava/lang/Appendable;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 466
    .line 467
    .line 468
    :cond_13
    const/4 v1, 0x0

    .line 469
    invoke-static {v7, v1}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 470
    .line 471
    .line 472
    return-object v0

    .line 473
    :goto_9
    :try_start_5
    throw v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 474
    :catchall_1
    move-exception v0

    .line 475
    invoke-static {v7, v1}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 476
    .line 477
    .line 478
    throw v0
.end method

.method public static final k(II)V
    .locals 3

    .line 1
    sget-object v0, Lio/ktor/utils/io/p0;->b:Ljava/util/List;

    .line 2
    .line 3
    or-int v0, p0, p1

    .line 4
    .line 5
    if-ne v0, p0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    new-instance v0, Ljava/io/IOException;

    .line 9
    .line 10
    new-instance v1, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, "Unexpected line ending "

    .line 13
    .line 14
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1}, Lio/ktor/utils/io/p0;->a(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string p1, ", while expected "

    .line 25
    .line 26
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-static {p0}, Lio/ktor/utils/io/p0;->a(I)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-direct {v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw v0
.end method

.method public static final l(Lio/ktor/utils/io/t;Loz0/a;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lio/ktor/utils/io/b0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lio/ktor/utils/io/b0;

    .line 7
    .line 8
    iget v1, v0, Lio/ktor/utils/io/b0;->g:I

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
    iput v1, v0, Lio/ktor/utils/io/b0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lio/ktor/utils/io/b0;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lio/ktor/utils/io/b0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lio/ktor/utils/io/b0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    iget-object p1, v0, Lio/ktor/utils/io/b0;->e:Loz0/a;

    .line 52
    .line 53
    iget-object p0, v0, Lio/ktor/utils/io/b0;->d:Lio/ktor/utils/io/t;

    .line 54
    .line 55
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iget-object p2, p1, Loz0/a;->d:[B

    .line 63
    .line 64
    array-length p2, p2

    .line 65
    iput-object p0, v0, Lio/ktor/utils/io/b0;->d:Lio/ktor/utils/io/t;

    .line 66
    .line 67
    iput-object p1, v0, Lio/ktor/utils/io/b0;->e:Loz0/a;

    .line 68
    .line 69
    iput v4, v0, Lio/ktor/utils/io/b0;->g:I

    .line 70
    .line 71
    invoke-static {p0, p2, v0}, Lio/ktor/utils/io/h0;->f(Lio/ktor/utils/io/t;ILrx0/c;)Ljava/lang/Comparable;

    .line 72
    .line 73
    .line 74
    move-result-object p2

    .line 75
    if-ne p2, v1, :cond_4

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_4
    :goto_1
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result p2

    .line 82
    if-eqz p2, :cond_6

    .line 83
    .line 84
    iget-object p1, p1, Loz0/a;->d:[B

    .line 85
    .line 86
    array-length p1, p1

    .line 87
    int-to-long p1, p1

    .line 88
    const/4 v2, 0x0

    .line 89
    iput-object v2, v0, Lio/ktor/utils/io/b0;->d:Lio/ktor/utils/io/t;

    .line 90
    .line 91
    iput-object v2, v0, Lio/ktor/utils/io/b0;->e:Loz0/a;

    .line 92
    .line 93
    iput v3, v0, Lio/ktor/utils/io/b0;->g:I

    .line 94
    .line 95
    invoke-static {p0, p1, p2, v0}, Lio/ktor/utils/io/h0;->d(Lio/ktor/utils/io/t;JLrx0/c;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    if-ne p0, v1, :cond_5

    .line 100
    .line 101
    :goto_2
    return-object v1

    .line 102
    :cond_5
    :goto_3
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 103
    .line 104
    return-object p0

    .line 105
    :cond_6
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 106
    .line 107
    return-object p0
.end method

.method public static final m(Lio/ktor/utils/io/t;Lrx0/c;)Ljava/io/Serializable;
    .locals 4

    .line 1
    instance-of v0, p1, Lio/ktor/utils/io/c0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lio/ktor/utils/io/c0;

    .line 7
    .line 8
    iget v1, v0, Lio/ktor/utils/io/c0;->e:I

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
    iput v1, v0, Lio/ktor/utils/io/c0;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lio/ktor/utils/io/c0;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lio/ktor/utils/io/c0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lio/ktor/utils/io/c0;->e:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput v3, v0, Lio/ktor/utils/io/c0;->e:I

    .line 52
    .line 53
    invoke-static {p0, v0}, Lio/ktor/utils/io/h0;->g(Lio/ktor/utils/io/t;Lrx0/c;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    if-ne p1, v1, :cond_3

    .line 58
    .line 59
    return-object v1

    .line 60
    :cond_3
    :goto_1
    check-cast p1, Lnz0/a;

    .line 61
    .line 62
    iget-wide v0, p1, Lnz0/a;->f:J

    .line 63
    .line 64
    long-to-int p0, v0

    .line 65
    invoke-static {p1, p0}, Lnz0/j;->e(Lnz0/i;I)[B

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0
.end method

.method public static n(Lio/ktor/utils/io/d0;Lbg/a;Ldw0/f;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p0, Lio/ktor/utils/io/m;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/ktor/utils/io/m;->j()Lnz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-virtual {v0, v1}, Lnz0/a;->j(I)Lnz0/g;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    iget-object v3, v2, Lnz0/g;->a:[B

    .line 13
    .line 14
    iget v4, v2, Lnz0/g;->c:I

    .line 15
    .line 16
    array-length v5, v3

    .line 17
    sub-int/2addr v5, v4

    .line 18
    invoke-static {v3, v4, v5}, Ljava/nio/ByteBuffer;->wrap([BII)Ljava/nio/ByteBuffer;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, v3}, Lbg/a;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v3}, Ljava/nio/Buffer;->position()I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    sub-int/2addr p1, v4

    .line 33
    if-ne p1, v1, :cond_0

    .line 34
    .line 35
    iget v1, v2, Lnz0/g;->c:I

    .line 36
    .line 37
    add-int/2addr v1, p1

    .line 38
    iput v1, v2, Lnz0/g;->c:I

    .line 39
    .line 40
    iget-wide v1, v0, Lnz0/a;->f:J

    .line 41
    .line 42
    int-to-long v3, p1

    .line 43
    add-long/2addr v1, v3

    .line 44
    iput-wide v1, v0, Lnz0/a;->f:J

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    if-ltz p1, :cond_4

    .line 48
    .line 49
    invoke-virtual {v2}, Lnz0/g;->a()I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-gt p1, v1, :cond_4

    .line 54
    .line 55
    if-eqz p1, :cond_1

    .line 56
    .line 57
    iget v1, v2, Lnz0/g;->c:I

    .line 58
    .line 59
    add-int/2addr v1, p1

    .line 60
    iput v1, v2, Lnz0/g;->c:I

    .line 61
    .line 62
    iget-wide v1, v0, Lnz0/a;->f:J

    .line 63
    .line 64
    int-to-long v3, p1

    .line 65
    add-long/2addr v1, v3

    .line 66
    iput-wide v1, v0, Lnz0/a;->f:J

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_1
    invoke-static {v2}, Lnz0/j;->d(Lnz0/g;)Z

    .line 70
    .line 71
    .line 72
    move-result p1

    .line 73
    if-eqz p1, :cond_2

    .line 74
    .line 75
    invoke-virtual {v0}, Lnz0/a;->f()V

    .line 76
    .line 77
    .line 78
    :cond_2
    :goto_0
    invoke-virtual {p0, p2}, Lio/ktor/utils/io/m;->b(Lrx0/c;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 83
    .line 84
    if-ne p0, p1, :cond_3

    .line 85
    .line 86
    return-object p0

    .line 87
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object p0

    .line 90
    :cond_4
    const-string p0, "Invalid number of bytes written: "

    .line 91
    .line 92
    const-string p2, ". Should be in 0.."

    .line 93
    .line 94
    invoke-static {p0, p1, p2}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-virtual {v2}, Lnz0/g;->a()I

    .line 99
    .line 100
    .line 101
    move-result p1

    .line 102
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 110
    .line 111
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    throw p1
.end method

.method public static o(Lio/ktor/utils/io/d0;[BLrx0/c;)Ljava/lang/Object;
    .locals 2

    .line 1
    array-length v0, p1

    .line 2
    check-cast p0, Lio/ktor/utils/io/m;

    .line 3
    .line 4
    invoke-virtual {p0}, Lio/ktor/utils/io/m;->j()Lnz0/a;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    invoke-virtual {v1, v0, p1}, Lnz0/a;->k(I[B)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, p2}, Lio/ktor/utils/io/h0;->e(Lio/ktor/utils/io/d0;Lrx0/c;)Ljava/lang/Object;

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

.method public static p(Lvy0/b0;Lpx0/g;Lay0/n;I)Lb81/d;
    .locals 2

    .line 1
    and-int/lit8 p3, p3, 0x1

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    sget-object p1, Lpx0/h;->d:Lpx0/h;

    .line 6
    .line 7
    :cond_0
    const-string p3, "<this>"

    .line 8
    .line 9
    invoke-static {p0, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string p3, "coroutineContext"

    .line 13
    .line 14
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    new-instance p3, Lio/ktor/utils/io/m;

    .line 18
    .line 19
    invoke-direct {p3}, Lio/ktor/utils/io/m;-><init>()V

    .line 20
    .line 21
    .line 22
    new-instance v0, Laa/i0;

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    invoke-direct {v0, p2, p3, v1}, Laa/i0;-><init>(Lay0/n;Lio/ktor/utils/io/m;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    const/4 p2, 0x2

    .line 29
    invoke-static {p0, p1, v1, v0, p2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    new-instance p1, Lio/ktor/utils/io/e0;

    .line 34
    .line 35
    invoke-direct {p1, p3}, Lio/ktor/utils/io/e0;-><init>(Lio/ktor/utils/io/m;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, p1}, Lvy0/p1;->E(Lay0/k;)Lvy0/r0;

    .line 39
    .line 40
    .line 41
    new-instance p1, Lb81/d;

    .line 42
    .line 43
    const/16 p2, 0x8

    .line 44
    .line 45
    invoke-direct {p1, p2, p3, p0}, Lb81/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-object p1
.end method
