.class public final Lq40/t;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lo40/x;

.field public final i:Lbd0/c;

.field public final j:Lo40/e0;

.field public final k:Lnn0/e;

.field public final l:Lo40/h;

.field public final m:Ltr0/b;

.field public final n:Lo40/r;

.field public final o:Lij0/a;

.field public final p:Lkf0/z;


# direct methods
.method public constructor <init>(Lo40/i;Lo40/x;Lbd0/c;Lo40/e0;Lnn0/e;Lo40/h;Ltr0/b;Lo40/r;Lij0/a;Lkf0/z;)V
    .locals 12

    .line 1
    new-instance v0, Lq40/p;

    .line 2
    .line 3
    const/16 v1, 0x7ff

    .line 4
    .line 5
    and-int/lit8 v1, v1, 0x1

    .line 6
    .line 7
    const-string v5, ""

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    move-object v1, v5

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const-string v1, "https://google.com"

    .line 14
    .line 15
    :goto_0
    sget-object v6, Lon0/y;->e:Lon0/y;

    .line 16
    .line 17
    const/4 v10, 0x0

    .line 18
    const/4 v11, 0x0

    .line 19
    const/4 v2, 0x0

    .line 20
    const/4 v3, 0x0

    .line 21
    const/4 v4, 0x0

    .line 22
    const/4 v7, 0x0

    .line 23
    const/4 v8, 0x0

    .line 24
    const/4 v9, 0x0

    .line 25
    invoke-direct/range {v0 .. v11}, Lq40/p;-><init>(Ljava/lang/String;ZLon0/w;Lon0/x;Ljava/lang/String;Lon0/y;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZZ)V

    .line 26
    .line 27
    .line 28
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 29
    .line 30
    .line 31
    iput-object p2, p0, Lq40/t;->h:Lo40/x;

    .line 32
    .line 33
    iput-object p3, p0, Lq40/t;->i:Lbd0/c;

    .line 34
    .line 35
    move-object/from16 p2, p4

    .line 36
    .line 37
    iput-object p2, p0, Lq40/t;->j:Lo40/e0;

    .line 38
    .line 39
    move-object/from16 p2, p5

    .line 40
    .line 41
    iput-object p2, p0, Lq40/t;->k:Lnn0/e;

    .line 42
    .line 43
    move-object/from16 p2, p6

    .line 44
    .line 45
    iput-object p2, p0, Lq40/t;->l:Lo40/h;

    .line 46
    .line 47
    move-object/from16 v0, p7

    .line 48
    .line 49
    iput-object v0, p0, Lq40/t;->m:Ltr0/b;

    .line 50
    .line 51
    move-object/from16 v1, p8

    .line 52
    .line 53
    iput-object v1, p0, Lq40/t;->n:Lo40/r;

    .line 54
    .line 55
    move-object/from16 v1, p9

    .line 56
    .line 57
    iput-object v1, p0, Lq40/t;->o:Lij0/a;

    .line 58
    .line 59
    move-object/from16 v1, p10

    .line 60
    .line 61
    iput-object v1, p0, Lq40/t;->p:Lkf0/z;

    .line 62
    .line 63
    invoke-virtual {p2}, Lo40/h;->invoke()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    check-cast p2, Lon0/m;

    .line 68
    .line 69
    if-nez p2, :cond_1

    .line 70
    .line 71
    invoke-virtual {v0}, Ltr0/b;->invoke()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    return-void

    .line 75
    :cond_1
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    new-instance v1, Lny/f0;

    .line 80
    .line 81
    const/16 v2, 0xe

    .line 82
    .line 83
    const/4 v3, 0x0

    .line 84
    move-object/from16 p5, p0

    .line 85
    .line 86
    move-object/from16 p6, p1

    .line 87
    .line 88
    move-object/from16 p7, p2

    .line 89
    .line 90
    move-object p3, v1

    .line 91
    move/from16 p4, v2

    .line 92
    .line 93
    move-object/from16 p8, v3

    .line 94
    .line 95
    invoke-direct/range {p3 .. p8}, Lny/f0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 96
    .line 97
    .line 98
    move-object p0, p3

    .line 99
    move-object/from16 p1, p8

    .line 100
    .line 101
    const/4 p2, 0x3

    .line 102
    invoke-static {v0, p1, p1, p0, p2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 103
    .line 104
    .line 105
    return-void
.end method

.method public static final h(Lq40/t;Lp40/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lq40/r;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lq40/r;

    .line 7
    .line 8
    iget v1, v0, Lq40/r;->f:I

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
    iput v1, v0, Lq40/r;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lq40/r;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lq40/r;-><init>(Lq40/t;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lq40/r;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lq40/r;->f:I

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
    iget-object p2, p0, Lq40/t;->h:Lo40/x;

    .line 52
    .line 53
    iget-object p1, p1, Lp40/a;->a:Ljava/lang/String;

    .line 54
    .line 55
    iput v3, v0, Lq40/r;->f:I

    .line 56
    .line 57
    invoke-virtual {p2, p1, v0}, Lo40/x;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-ne p1, v1, :cond_3

    .line 62
    .line 63
    return-object v1

    .line 64
    :cond_3
    :goto_1
    iget-object p0, p0, Lq40/t;->n:Lo40/r;

    .line 65
    .line 66
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    return-object p0
.end method

.method public static final j(Lq40/t;Lon0/q;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    instance-of v3, v2, Lq40/s;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lq40/s;

    .line 13
    .line 14
    iget v4, v3, Lq40/s;->f:I

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
    iput v4, v3, Lq40/s;->f:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lq40/s;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Lq40/s;-><init>(Lq40/t;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lq40/s;->d:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lq40/s;->f:I

    .line 36
    .line 37
    const/4 v6, 0x2

    .line 38
    const/4 v7, 0x1

    .line 39
    if-eqz v5, :cond_3

    .line 40
    .line 41
    if-eq v5, v7, :cond_2

    .line 42
    .line 43
    if-ne v5, v6, :cond_1

    .line 44
    .line 45
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto/16 :goto_13

    .line 49
    .line 50
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw v0

    .line 58
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto/16 :goto_11

    .line 62
    .line 63
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object v2, v0, Lq40/t;->j:Lo40/e0;

    .line 67
    .line 68
    iget-object v5, v1, Lon0/q;->g:Ljava/util/List;

    .line 69
    .line 70
    check-cast v5, Ljava/lang/Iterable;

    .line 71
    .line 72
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    :cond_4
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v8

    .line 80
    if-eqz v8, :cond_5

    .line 81
    .line 82
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v8

    .line 86
    move-object v10, v8

    .line 87
    check-cast v10, Lon0/a0;

    .line 88
    .line 89
    iget-boolean v10, v10, Lon0/a0;->a:Z

    .line 90
    .line 91
    if-eqz v10, :cond_4

    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_5
    const/4 v8, 0x0

    .line 95
    :goto_1
    check-cast v8, Lon0/a0;

    .line 96
    .line 97
    if-eqz v8, :cond_7

    .line 98
    .line 99
    iget-object v5, v8, Lon0/a0;->d:Ljava/lang/String;

    .line 100
    .line 101
    if-nez v5, :cond_6

    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_6
    :goto_2
    move-object/from16 v17, v5

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_7
    :goto_3
    iget-object v5, v1, Lon0/q;->g:Ljava/util/List;

    .line 108
    .line 109
    invoke-static {v5}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v5

    .line 113
    check-cast v5, Lon0/a0;

    .line 114
    .line 115
    iget-object v5, v5, Lon0/a0;->d:Ljava/lang/String;

    .line 116
    .line 117
    goto :goto_2

    .line 118
    :goto_4
    iget-object v1, v1, Lon0/q;->f:Ljava/util/ArrayList;

    .line 119
    .line 120
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    :cond_8
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 125
    .line 126
    .line 127
    move-result v5

    .line 128
    if-eqz v5, :cond_a

    .line 129
    .line 130
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v5

    .line 134
    move-object v8, v5

    .line 135
    check-cast v8, Lon0/p;

    .line 136
    .line 137
    iget-object v8, v8, Lon0/p;->c:Ljava/lang/String;

    .line 138
    .line 139
    iget-object v10, v0, Lq40/t;->l:Lo40/h;

    .line 140
    .line 141
    invoke-static {v10}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v10

    .line 145
    check-cast v10, Lon0/m;

    .line 146
    .line 147
    if-eqz v10, :cond_9

    .line 148
    .line 149
    iget-object v10, v10, Lon0/m;->f:Ljava/lang/String;

    .line 150
    .line 151
    goto :goto_5

    .line 152
    :cond_9
    const/4 v10, 0x0

    .line 153
    :goto_5
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    move-result v8

    .line 157
    if-eqz v8, :cond_8

    .line 158
    .line 159
    goto :goto_6

    .line 160
    :cond_a
    const/4 v5, 0x0

    .line 161
    :goto_6
    check-cast v5, Lon0/p;

    .line 162
    .line 163
    const-string v1, ""

    .line 164
    .line 165
    if-eqz v5, :cond_c

    .line 166
    .line 167
    iget-object v5, v5, Lon0/p;->b:Ljava/lang/String;

    .line 168
    .line 169
    if-nez v5, :cond_b

    .line 170
    .line 171
    goto :goto_7

    .line 172
    :cond_b
    move-object/from16 v18, v5

    .line 173
    .line 174
    goto :goto_8

    .line 175
    :cond_c
    :goto_7
    move-object/from16 v18, v1

    .line 176
    .line 177
    :goto_8
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    check-cast v5, Lq40/p;

    .line 182
    .line 183
    iget-object v5, v5, Lq40/p;->d:Lon0/x;

    .line 184
    .line 185
    if-eqz v5, :cond_e

    .line 186
    .line 187
    iget-object v5, v5, Lon0/x;->a:Ljava/lang/String;

    .line 188
    .line 189
    if-nez v5, :cond_d

    .line 190
    .line 191
    goto :goto_9

    .line 192
    :cond_d
    move-object v11, v5

    .line 193
    goto :goto_a

    .line 194
    :cond_e
    :goto_9
    move-object v11, v1

    .line 195
    :goto_a
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 196
    .line 197
    .line 198
    move-result-object v5

    .line 199
    check-cast v5, Lq40/p;

    .line 200
    .line 201
    iget-object v12, v5, Lq40/p;->e:Ljava/lang/String;

    .line 202
    .line 203
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 204
    .line 205
    .line 206
    move-result-object v5

    .line 207
    check-cast v5, Lq40/p;

    .line 208
    .line 209
    iget-object v5, v5, Lq40/p;->d:Lon0/x;

    .line 210
    .line 211
    if-eqz v5, :cond_f

    .line 212
    .line 213
    iget-object v5, v5, Lon0/x;->b:Ljava/lang/String;

    .line 214
    .line 215
    move-object v15, v5

    .line 216
    goto :goto_b

    .line 217
    :cond_f
    const/4 v15, 0x0

    .line 218
    :goto_b
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 219
    .line 220
    .line 221
    move-result-object v5

    .line 222
    check-cast v5, Lq40/p;

    .line 223
    .line 224
    iget-object v5, v5, Lq40/p;->f:Lon0/y;

    .line 225
    .line 226
    invoke-virtual {v5}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 227
    .line 228
    .line 229
    move-result-object v5

    .line 230
    sget-object v8, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 231
    .line 232
    invoke-virtual {v5, v8}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 233
    .line 234
    .line 235
    move-result-object v13

    .line 236
    const-string v5, "toUpperCase(...)"

    .line 237
    .line 238
    invoke-static {v13, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 242
    .line 243
    .line 244
    move-result-object v5

    .line 245
    check-cast v5, Lq40/p;

    .line 246
    .line 247
    iget-object v5, v5, Lq40/p;->d:Lon0/x;

    .line 248
    .line 249
    if-eqz v5, :cond_11

    .line 250
    .line 251
    iget-object v5, v5, Lon0/x;->e:Ljava/lang/String;

    .line 252
    .line 253
    if-nez v5, :cond_10

    .line 254
    .line 255
    goto :goto_c

    .line 256
    :cond_10
    move-object v14, v5

    .line 257
    goto :goto_d

    .line 258
    :cond_11
    :goto_c
    move-object v14, v1

    .line 259
    :goto_d
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 260
    .line 261
    .line 262
    move-result-object v1

    .line 263
    check-cast v1, Lq40/p;

    .line 264
    .line 265
    iget-object v1, v1, Lq40/p;->c:Lon0/w;

    .line 266
    .line 267
    if-eqz v1, :cond_13

    .line 268
    .line 269
    new-instance v5, Lon0/k;

    .line 270
    .line 271
    iget-object v8, v1, Lon0/w;->a:Ljava/lang/String;

    .line 272
    .line 273
    iget-object v10, v1, Lon0/w;->b:Ljava/lang/String;

    .line 274
    .line 275
    iget-object v9, v1, Lon0/w;->c:Ljava/lang/String;

    .line 276
    .line 277
    iget-object v1, v1, Lon0/w;->d:Lol0/a;

    .line 278
    .line 279
    if-eqz v1, :cond_12

    .line 280
    .line 281
    iget-object v1, v1, Lol0/a;->a:Ljava/math/BigDecimal;

    .line 282
    .line 283
    invoke-virtual {v1}, Ljava/math/BigDecimal;->doubleValue()D

    .line 284
    .line 285
    .line 286
    move-result-wide v6

    .line 287
    new-instance v1, Ljava/lang/Double;

    .line 288
    .line 289
    invoke-direct {v1, v6, v7}, Ljava/lang/Double;-><init>(D)V

    .line 290
    .line 291
    .line 292
    goto :goto_e

    .line 293
    :cond_12
    const/4 v1, 0x0

    .line 294
    :goto_e
    invoke-direct {v5, v8, v10, v9, v1}, Lon0/k;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Double;)V

    .line 295
    .line 296
    .line 297
    move-object/from16 v16, v5

    .line 298
    .line 299
    goto :goto_f

    .line 300
    :cond_13
    const/16 v16, 0x0

    .line 301
    .line 302
    :goto_f
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 303
    .line 304
    .line 305
    move-result-object v1

    .line 306
    check-cast v1, Lq40/p;

    .line 307
    .line 308
    iget-object v1, v1, Lq40/p;->g:Ljava/lang/String;

    .line 309
    .line 310
    if-nez v1, :cond_14

    .line 311
    .line 312
    const/16 v19, 0x0

    .line 313
    .line 314
    goto :goto_10

    .line 315
    :cond_14
    move-object/from16 v19, v1

    .line 316
    .line 317
    :goto_10
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 318
    .line 319
    .line 320
    move-result-object v1

    .line 321
    check-cast v1, Lq40/p;

    .line 322
    .line 323
    iget-object v1, v1, Lq40/p;->h:Ljava/lang/String;

    .line 324
    .line 325
    new-instance v10, Lp40/b;

    .line 326
    .line 327
    move-object/from16 v20, v1

    .line 328
    .line 329
    invoke-direct/range {v10 .. v20}, Lp40/b;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/k;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 330
    .line 331
    .line 332
    const/4 v1, 0x1

    .line 333
    iput v1, v3, Lq40/s;->f:I

    .line 334
    .line 335
    invoke-virtual {v2, v10}, Lo40/e0;->b(Lp40/b;)Lyy0/m1;

    .line 336
    .line 337
    .line 338
    move-result-object v2

    .line 339
    if-ne v2, v4, :cond_15

    .line 340
    .line 341
    goto :goto_12

    .line 342
    :cond_15
    :goto_11
    check-cast v2, Lyy0/i;

    .line 343
    .line 344
    new-instance v1, Lq40/q;

    .line 345
    .line 346
    const/4 v5, 0x1

    .line 347
    invoke-direct {v1, v0, v5}, Lq40/q;-><init>(Lq40/t;I)V

    .line 348
    .line 349
    .line 350
    const/4 v0, 0x2

    .line 351
    iput v0, v3, Lq40/s;->f:I

    .line 352
    .line 353
    invoke-interface {v2, v1, v3}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v0

    .line 357
    if-ne v0, v4, :cond_16

    .line 358
    .line 359
    :goto_12
    return-object v4

    .line 360
    :cond_16
    :goto_13
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 361
    .line 362
    return-object v0
.end method

.method public static l(Lne0/c;Ljava/util/List;)Z
    .locals 2

    .line 1
    iget-object p0, p0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 2
    .line 3
    instance-of v0, p0, Lbm0/d;

    .line 4
    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    check-cast p1, Ljava/lang/Iterable;

    .line 8
    .line 9
    new-instance v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    const/16 v1, 0xa

    .line 12
    .line 13
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_0

    .line 29
    .line 30
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    check-cast v1, Lon0/o;

    .line 35
    .line 36
    iget-object v1, v1, Lon0/o;->d:Ljava/lang/String;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    check-cast p0, Lbm0/d;

    .line 43
    .line 44
    iget-object p0, p0, Lbm0/d;->e:Lbm0/c;

    .line 45
    .line 46
    if-eqz p0, :cond_1

    .line 47
    .line 48
    iget-object p0, p0, Lbm0/c;->a:Ljava/lang/String;

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    const/4 p0, 0x0

    .line 52
    :goto_1
    invoke-static {v0, p0}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    if-eqz p0, :cond_2

    .line 57
    .line 58
    const/4 p0, 0x1

    .line 59
    return p0

    .line 60
    :cond_2
    const/4 p0, 0x0

    .line 61
    return p0
.end method


# virtual methods
.method public final k(IIILjava/lang/Integer;)Lql0/g;
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v1, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    iget-object v2, p0, Lq40/t;->o:Lij0/a;

    .line 5
    .line 6
    move-object v3, v2

    .line 7
    check-cast v3, Ljj0/f;

    .line 8
    .line 9
    invoke-virtual {v3, p1, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    new-array p1, v0, [Ljava/lang/Object;

    .line 14
    .line 15
    iget-object p0, p0, Lq40/t;->o:Lij0/a;

    .line 16
    .line 17
    check-cast p0, Ljj0/f;

    .line 18
    .line 19
    invoke-virtual {p0, p2, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    new-array p1, v0, [Ljava/lang/Object;

    .line 24
    .line 25
    invoke-virtual {p0, p3, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v5

    .line 29
    if-eqz p4, :cond_0

    .line 30
    .line 31
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    new-array p2, v0, [Ljava/lang/Object;

    .line 36
    .line 37
    invoke-virtual {p0, p1, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    :goto_0
    move-object v6, p0

    .line 42
    goto :goto_1

    .line 43
    :cond_0
    const/4 p0, 0x0

    .line 44
    goto :goto_0

    .line 45
    :goto_1
    const/16 v7, 0x60

    .line 46
    .line 47
    invoke-static/range {v2 .. v7}, Ljp/rf;->a(Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lql0/g;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0
.end method
