.class public final Lx21/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lt1/j0;

.field public final b:Lvy0/b0;

.field public final c:Ll2/b1;

.field public final d:F

.field public final e:Lx21/a;

.field public final f:Lx21/g0;

.field public final g:Lx21/a0;

.field public final h:Lt4/m;

.field public final i:Lay0/n;

.field public final j:Lez0/c;

.field public final k:Ll2/j1;

.field public final l:Ll2/h0;

.field public final m:Ll2/j1;

.field public final n:Ll2/j1;

.field public final o:Ll2/j1;

.field public final p:Ll2/j1;

.field public q:J

.field public final r:Ljava/util/HashSet;

.field public final s:Ll2/j1;

.field public final t:Lc1/c;

.field public final u:Lyy0/m1;


# direct methods
.method public constructor <init>(Lt1/j0;Lvy0/b0;Ll2/b1;FLx21/a;Lx21/g0;Lt4/m;Lay0/n;)V
    .locals 1

    .line 1
    sget-object v0, Lx21/a0;->d:Lx21/a0;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lx21/y;->a:Lt1/j0;

    .line 7
    .line 8
    iput-object p2, p0, Lx21/y;->b:Lvy0/b0;

    .line 9
    .line 10
    iput-object p3, p0, Lx21/y;->c:Ll2/b1;

    .line 11
    .line 12
    iput p4, p0, Lx21/y;->d:F

    .line 13
    .line 14
    iput-object p5, p0, Lx21/y;->e:Lx21/a;

    .line 15
    .line 16
    iput-object p6, p0, Lx21/y;->f:Lx21/g0;

    .line 17
    .line 18
    iput-object v0, p0, Lx21/y;->g:Lx21/a0;

    .line 19
    .line 20
    iput-object p7, p0, Lx21/y;->h:Lt4/m;

    .line 21
    .line 22
    iput-object p8, p0, Lx21/y;->i:Lay0/n;

    .line 23
    .line 24
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    iput-object p1, p0, Lx21/y;->j:Lez0/c;

    .line 29
    .line 30
    const/4 p1, 0x0

    .line 31
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    iput-object p2, p0, Lx21/y;->k:Ll2/j1;

    .line 36
    .line 37
    new-instance p2, Lx21/n;

    .line 38
    .line 39
    const/4 p3, 0x0

    .line 40
    invoke-direct {p2, p0, p3}, Lx21/n;-><init>(Lx21/y;I)V

    .line 41
    .line 42
    .line 43
    invoke-static {p2}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    iput-object p2, p0, Lx21/y;->l:Ll2/h0;

    .line 48
    .line 49
    new-instance p2, Ld3/b;

    .line 50
    .line 51
    const-wide/16 p3, 0x0

    .line 52
    .line 53
    invoke-direct {p2, p3, p4}, Ld3/b;-><init>(J)V

    .line 54
    .line 55
    .line 56
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    iput-object p2, p0, Lx21/y;->m:Ll2/j1;

    .line 61
    .line 62
    new-instance p2, Lt4/j;

    .line 63
    .line 64
    invoke-direct {p2, p3, p4}, Lt4/j;-><init>(J)V

    .line 65
    .line 66
    .line 67
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    iput-object p2, p0, Lx21/y;->n:Ll2/j1;

    .line 72
    .line 73
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 74
    .line 75
    .line 76
    move-result-object p2

    .line 77
    iput-object p2, p0, Lx21/y;->o:Ll2/j1;

    .line 78
    .line 79
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 80
    .line 81
    .line 82
    move-result-object p2

    .line 83
    iput-object p2, p0, Lx21/y;->p:Ll2/j1;

    .line 84
    .line 85
    iput-wide p3, p0, Lx21/y;->q:J

    .line 86
    .line 87
    new-instance p2, Ljava/util/HashSet;

    .line 88
    .line 89
    invoke-direct {p2}, Ljava/util/HashSet;-><init>()V

    .line 90
    .line 91
    .line 92
    iput-object p2, p0, Lx21/y;->r:Ljava/util/HashSet;

    .line 93
    .line 94
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 95
    .line 96
    .line 97
    move-result-object p2

    .line 98
    iput-object p2, p0, Lx21/y;->s:Ll2/j1;

    .line 99
    .line 100
    new-instance p2, Lc1/c;

    .line 101
    .line 102
    new-instance p5, Ld3/b;

    .line 103
    .line 104
    invoke-direct {p5, p3, p4}, Ld3/b;-><init>(J)V

    .line 105
    .line 106
    .line 107
    sget-object p3, Lc1/d;->o:Lc1/b2;

    .line 108
    .line 109
    const/16 p4, 0xc

    .line 110
    .line 111
    invoke-direct {p2, p5, p3, p1, p4}, Lc1/c;-><init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;I)V

    .line 112
    .line 113
    .line 114
    iput-object p2, p0, Lx21/y;->t:Lc1/c;

    .line 115
    .line 116
    new-instance p1, Lx21/n;

    .line 117
    .line 118
    const/4 p2, 0x1

    .line 119
    invoke-direct {p1, p0, p2}, Lx21/n;-><init>(Lx21/y;I)V

    .line 120
    .line 121
    .line 122
    invoke-static {p1}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    iput-object p1, p0, Lx21/y;->u:Lyy0/m1;

    .line 127
    .line 128
    return-void
.end method

.method public static final a(Lx21/y;Lx21/b0;Lrx0/c;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Lx21/o;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lx21/o;

    .line 11
    .line 12
    iget v3, v2, Lx21/o;->h:I

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
    iput v3, v2, Lx21/o;->h:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lx21/o;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lx21/o;-><init>(Lx21/y;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lx21/o;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lx21/o;->h:I

    .line 34
    .line 35
    const/4 v5, 0x2

    .line 36
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    const/4 v7, 0x1

    .line 39
    if-eqz v4, :cond_3

    .line 40
    .line 41
    if-eq v4, v7, :cond_2

    .line 42
    .line 43
    if-ne v4, v5, :cond_1

    .line 44
    .line 45
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-object v6

    .line 49
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw v0

    .line 57
    :cond_2
    iget-object v0, v2, Lx21/o;->e:Lx21/b0;

    .line 58
    .line 59
    iget-object v4, v2, Lx21/o;->d:Lx21/y;

    .line 60
    .line 61
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    move-object v8, v4

    .line 65
    goto :goto_1

    .line 66
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iget-object v1, v0, Lx21/y;->j:Lez0/c;

    .line 70
    .line 71
    iput-object v0, v2, Lx21/o;->d:Lx21/y;

    .line 72
    .line 73
    move-object/from16 v4, p1

    .line 74
    .line 75
    iput-object v4, v2, Lx21/o;->e:Lx21/b0;

    .line 76
    .line 77
    iput v7, v2, Lx21/o;->h:I

    .line 78
    .line 79
    invoke-virtual {v1, v2}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    if-ne v1, v3, :cond_4

    .line 84
    .line 85
    goto/16 :goto_13

    .line 86
    .line 87
    :cond_4
    move-object v8, v0

    .line 88
    move-object v0, v4

    .line 89
    :goto_1
    invoke-virtual {v8}, Lx21/y;->d()Lx21/x;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    iget-object v4, v8, Lx21/y;->a:Lt1/j0;

    .line 94
    .line 95
    iget-object v14, v8, Lx21/y;->j:Lez0/c;

    .line 96
    .line 97
    const/4 v15, 0x0

    .line 98
    if-nez v1, :cond_5

    .line 99
    .line 100
    invoke-virtual {v14, v15}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    return-object v6

    .line 104
    :cond_5
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 105
    .line 106
    .line 107
    move-result v9

    .line 108
    if-eqz v9, :cond_7

    .line 109
    .line 110
    if-ne v9, v7, :cond_6

    .line 111
    .line 112
    invoke-virtual {v4}, Lt1/j0;->m()Lpv/g;

    .line 113
    .line 114
    .line 115
    move-result-object v9

    .line 116
    invoke-virtual {v9}, Lpv/g;->i()Ljava/util/ArrayList;

    .line 117
    .line 118
    .line 119
    move-result-object v9

    .line 120
    invoke-static {v9}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v9

    .line 124
    check-cast v9, Lx21/x;

    .line 125
    .line 126
    if-eqz v9, :cond_8

    .line 127
    .line 128
    invoke-virtual {v1}, Lx21/x;->a()I

    .line 129
    .line 130
    .line 131
    move-result v10

    .line 132
    invoke-virtual {v9}, Lx21/x;->a()I

    .line 133
    .line 134
    .line 135
    move-result v9

    .line 136
    if-ne v10, v9, :cond_8

    .line 137
    .line 138
    goto :goto_2

    .line 139
    :cond_6
    new-instance v0, La8/r0;

    .line 140
    .line 141
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 142
    .line 143
    .line 144
    throw v0

    .line 145
    :cond_7
    invoke-virtual {v1}, Lx21/x;->a()I

    .line 146
    .line 147
    .line 148
    move-result v9

    .line 149
    iget-object v10, v4, Lt1/j0;->e:Ljava/lang/Object;

    .line 150
    .line 151
    check-cast v10, Lm1/t;

    .line 152
    .line 153
    iget-object v10, v10, Lm1/t;->e:Lm1/o;

    .line 154
    .line 155
    iget-object v10, v10, Lm1/o;->b:Ll2/g1;

    .line 156
    .line 157
    invoke-virtual {v10}, Ll2/g1;->o()I

    .line 158
    .line 159
    .line 160
    move-result v10

    .line 161
    if-ne v9, v10, :cond_8

    .line 162
    .line 163
    :goto_2
    invoke-virtual {v14, v15}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    return-object v6

    .line 167
    :cond_8
    invoke-virtual {v8}, Lx21/y;->e()J

    .line 168
    .line 169
    .line 170
    move-result-wide v9

    .line 171
    invoke-virtual {v8, v9, v10}, Lx21/y;->i(J)J

    .line 172
    .line 173
    .line 174
    move-result-wide v9

    .line 175
    invoke-virtual {v8, v9, v10}, Lx21/y;->j(J)J

    .line 176
    .line 177
    .line 178
    invoke-virtual {v1}, Lx21/x;->b()J

    .line 179
    .line 180
    .line 181
    move-result-wide v11

    .line 182
    const/16 v13, 0x20

    .line 183
    .line 184
    move-object/from16 v16, v6

    .line 185
    .line 186
    shr-long v5, v11, v13

    .line 187
    .line 188
    long-to-int v5, v5

    .line 189
    int-to-float v5, v5

    .line 190
    const-wide v17, 0xffffffffL

    .line 191
    .line 192
    .line 193
    .line 194
    .line 195
    and-long v11, v11, v17

    .line 196
    .line 197
    long-to-int v6, v11

    .line 198
    int-to-float v6, v6

    .line 199
    invoke-static {v5, v6}, Ljp/bf;->a(FF)J

    .line 200
    .line 201
    .line 202
    move-result-wide v5

    .line 203
    invoke-static {v5, v6, v9, v10}, Ld3/b;->h(JJ)J

    .line 204
    .line 205
    .line 206
    move-result-wide v5

    .line 207
    invoke-virtual {v1}, Lx21/x;->c()J

    .line 208
    .line 209
    .line 210
    move-result-wide v9

    .line 211
    invoke-static {v9, v10}, Lkp/f9;->c(J)J

    .line 212
    .line 213
    .line 214
    move-result-wide v9

    .line 215
    invoke-static {v5, v6}, Ld3/b;->e(J)F

    .line 216
    .line 217
    .line 218
    move-result v11

    .line 219
    invoke-static {v9, v10}, Ld3/e;->d(J)F

    .line 220
    .line 221
    .line 222
    move-result v12

    .line 223
    add-float/2addr v12, v11

    .line 224
    invoke-static {v5, v6}, Ld3/b;->f(J)F

    .line 225
    .line 226
    .line 227
    move-result v11

    .line 228
    invoke-static {v9, v10}, Ld3/e;->b(J)F

    .line 229
    .line 230
    .line 231
    move-result v9

    .line 232
    add-float/2addr v9, v11

    .line 233
    invoke-static {v12, v9}, Ljp/bf;->a(FF)J

    .line 234
    .line 235
    .line 236
    move-result-wide v9

    .line 237
    invoke-static {v5, v6, v9, v10}, Ljp/cf;->a(JJ)Ld3/c;

    .line 238
    .line 239
    .line 240
    move-result-object v5

    .line 241
    iget-object v6, v8, Lx21/y;->g:Lx21/a0;

    .line 242
    .line 243
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 244
    .line 245
    .line 246
    move-result v6

    .line 247
    if-eqz v6, :cond_d

    .line 248
    .line 249
    if-ne v6, v7, :cond_e

    .line 250
    .line 251
    invoke-virtual {v8}, Lx21/y;->f()Lg1/w1;

    .line 252
    .line 253
    .line 254
    move-result-object v6

    .line 255
    const-string v9, "<this>"

    .line 256
    .line 257
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 261
    .line 262
    .line 263
    move-result v6

    .line 264
    if-eqz v6, :cond_a

    .line 265
    .line 266
    if-ne v6, v7, :cond_9

    .line 267
    .line 268
    sget-object v6, Lg1/w1;->d:Lg1/w1;

    .line 269
    .line 270
    goto :goto_3

    .line 271
    :cond_9
    new-instance v0, La8/r0;

    .line 272
    .line 273
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 274
    .line 275
    .line 276
    throw v0

    .line 277
    :cond_a
    sget-object v6, Lg1/w1;->e:Lg1/w1;

    .line 278
    .line 279
    :goto_3
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 280
    .line 281
    .line 282
    move-result v6

    .line 283
    if-eqz v6, :cond_c

    .line 284
    .line 285
    if-ne v6, v7, :cond_b

    .line 286
    .line 287
    const/high16 v6, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 288
    .line 289
    const/16 v9, 0xa

    .line 290
    .line 291
    const/high16 v10, -0x800000    # Float.NEGATIVE_INFINITY

    .line 292
    .line 293
    invoke-static {v5, v10, v6, v9}, Ld3/c;->a(Ld3/c;FFI)Ld3/c;

    .line 294
    .line 295
    .line 296
    move-result-object v5

    .line 297
    goto :goto_4

    .line 298
    :cond_b
    new-instance v0, La8/r0;

    .line 299
    .line 300
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 301
    .line 302
    .line 303
    throw v0

    .line 304
    :cond_c
    const/4 v6, 0x5

    .line 305
    const/4 v9, 0x0

    .line 306
    invoke-static {v5, v9, v9, v6}, Ld3/c;->a(Ld3/c;FFI)Ld3/c;

    .line 307
    .line 308
    .line 309
    move-result-object v5

    .line 310
    :cond_d
    :goto_4
    move-object v9, v5

    .line 311
    goto :goto_5

    .line 312
    :cond_e
    new-instance v0, La8/r0;

    .line 313
    .line 314
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 315
    .line 316
    .line 317
    throw v0

    .line 318
    :goto_5
    invoke-virtual {v4}, Lt1/j0;->m()Lpv/g;

    .line 319
    .line 320
    .line 321
    move-result-object v5

    .line 322
    iget-object v6, v8, Lx21/y;->e:Lx21/a;

    .line 323
    .line 324
    const-string v10, "padding"

    .line 325
    .line 326
    invoke-static {v6, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    invoke-virtual {v5}, Lpv/g;->g()Lg1/w1;

    .line 330
    .line 331
    .line 332
    move-result-object v10

    .line 333
    iget-object v11, v5, Lpv/g;->e:Ljava/lang/Object;

    .line 334
    .line 335
    check-cast v11, Lm1/l;

    .line 336
    .line 337
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 338
    .line 339
    .line 340
    const-string v11, "orientation"

    .line 341
    .line 342
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 343
    .line 344
    .line 345
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 346
    .line 347
    .line 348
    move-result v10

    .line 349
    if-eqz v10, :cond_10

    .line 350
    .line 351
    if-ne v10, v7, :cond_f

    .line 352
    .line 353
    new-instance v10, Lx21/b;

    .line 354
    .line 355
    iget v11, v6, Lx21/a;->a:F

    .line 356
    .line 357
    iget v6, v6, Lx21/a;->b:F

    .line 358
    .line 359
    invoke-direct {v10, v11, v6}, Lx21/b;-><init>(FF)V

    .line 360
    .line 361
    .line 362
    goto :goto_6

    .line 363
    :cond_f
    new-instance v0, La8/r0;

    .line 364
    .line 365
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 366
    .line 367
    .line 368
    throw v0

    .line 369
    :cond_10
    new-instance v10, Lx21/b;

    .line 370
    .line 371
    iget v11, v6, Lx21/a;->c:F

    .line 372
    .line 373
    iget v6, v6, Lx21/a;->d:F

    .line 374
    .line 375
    invoke-direct {v10, v11, v6}, Lx21/b;-><init>(FF)V

    .line 376
    .line 377
    .line 378
    :goto_6
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 379
    .line 380
    .line 381
    const-string v6, "padding"

    .line 382
    .line 383
    invoke-static {v10, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 384
    .line 385
    .line 386
    invoke-virtual {v5, v10}, Lpv/g;->h(Lx21/b;)Lx21/z;

    .line 387
    .line 388
    .line 389
    move-result-object v6

    .line 390
    iget v10, v6, Lx21/z;->a:F

    .line 391
    .line 392
    iget v6, v6, Lx21/z;->b:F

    .line 393
    .line 394
    invoke-virtual {v5}, Lpv/g;->g()Lg1/w1;

    .line 395
    .line 396
    .line 397
    move-result-object v11

    .line 398
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 399
    .line 400
    .line 401
    move-result v11

    .line 402
    if-eqz v11, :cond_15

    .line 403
    .line 404
    const/4 v12, 0x1

    .line 405
    if-ne v11, v12, :cond_14

    .line 406
    .line 407
    invoke-virtual {v5}, Lpv/g;->i()Ljava/util/ArrayList;

    .line 408
    .line 409
    .line 410
    move-result-object v5

    .line 411
    new-instance v11, Ljava/util/ArrayList;

    .line 412
    .line 413
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 414
    .line 415
    .line 416
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 417
    .line 418
    .line 419
    move-result-object v5

    .line 420
    :goto_7
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 421
    .line 422
    .line 423
    move-result v12

    .line 424
    if-eqz v12, :cond_13

    .line 425
    .line 426
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 427
    .line 428
    .line 429
    move-result-object v12

    .line 430
    move-object v13, v12

    .line 431
    check-cast v13, Lx21/x;

    .line 432
    .line 433
    invoke-virtual {v13}, Lx21/x;->b()J

    .line 434
    .line 435
    .line 436
    move-result-wide v17

    .line 437
    const/16 v19, 0x20

    .line 438
    .line 439
    move-object/from16 p0, v8

    .line 440
    .line 441
    shr-long v7, v17, v19

    .line 442
    .line 443
    long-to-int v7, v7

    .line 444
    int-to-float v7, v7

    .line 445
    cmpl-float v7, v7, v10

    .line 446
    .line 447
    if-ltz v7, :cond_12

    .line 448
    .line 449
    invoke-virtual {v13}, Lx21/x;->b()J

    .line 450
    .line 451
    .line 452
    move-result-wide v7

    .line 453
    shr-long v7, v7, v19

    .line 454
    .line 455
    long-to-int v7, v7

    .line 456
    invoke-virtual {v13}, Lx21/x;->c()J

    .line 457
    .line 458
    .line 459
    move-result-wide v17

    .line 460
    move-object v8, v4

    .line 461
    move-object/from16 p1, v5

    .line 462
    .line 463
    shr-long v4, v17, v19

    .line 464
    .line 465
    long-to-int v4, v4

    .line 466
    add-int/2addr v7, v4

    .line 467
    int-to-float v4, v7

    .line 468
    cmpg-float v4, v4, v6

    .line 469
    .line 470
    if-gtz v4, :cond_11

    .line 471
    .line 472
    invoke-virtual {v11, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 473
    .line 474
    .line 475
    :cond_11
    :goto_8
    const/4 v7, 0x1

    .line 476
    move-object/from16 v5, p1

    .line 477
    .line 478
    move-object v4, v8

    .line 479
    move-object/from16 v8, p0

    .line 480
    .line 481
    goto :goto_7

    .line 482
    :cond_12
    move-object v8, v4

    .line 483
    move-object/from16 p1, v5

    .line 484
    .line 485
    goto :goto_8

    .line 486
    :cond_13
    move-object/from16 p0, v8

    .line 487
    .line 488
    move-object v8, v4

    .line 489
    goto :goto_b

    .line 490
    :cond_14
    new-instance v0, La8/r0;

    .line 491
    .line 492
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 493
    .line 494
    .line 495
    throw v0

    .line 496
    :cond_15
    move-object/from16 p0, v8

    .line 497
    .line 498
    move-object v8, v4

    .line 499
    invoke-virtual {v5}, Lpv/g;->i()Ljava/util/ArrayList;

    .line 500
    .line 501
    .line 502
    move-result-object v4

    .line 503
    new-instance v11, Ljava/util/ArrayList;

    .line 504
    .line 505
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 506
    .line 507
    .line 508
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 509
    .line 510
    .line 511
    move-result-object v4

    .line 512
    :goto_9
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 513
    .line 514
    .line 515
    move-result v5

    .line 516
    if-eqz v5, :cond_18

    .line 517
    .line 518
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    move-result-object v5

    .line 522
    move-object v7, v5

    .line 523
    check-cast v7, Lx21/x;

    .line 524
    .line 525
    invoke-virtual {v7}, Lx21/x;->b()J

    .line 526
    .line 527
    .line 528
    move-result-wide v12

    .line 529
    const-wide v17, 0xffffffffL

    .line 530
    .line 531
    .line 532
    .line 533
    .line 534
    and-long v12, v12, v17

    .line 535
    .line 536
    long-to-int v12, v12

    .line 537
    int-to-float v12, v12

    .line 538
    cmpl-float v12, v12, v10

    .line 539
    .line 540
    if-ltz v12, :cond_17

    .line 541
    .line 542
    invoke-virtual {v7}, Lx21/x;->b()J

    .line 543
    .line 544
    .line 545
    move-result-wide v12

    .line 546
    and-long v12, v12, v17

    .line 547
    .line 548
    long-to-int v12, v12

    .line 549
    invoke-virtual {v7}, Lx21/x;->c()J

    .line 550
    .line 551
    .line 552
    move-result-wide v20

    .line 553
    move v13, v6

    .line 554
    and-long v6, v20, v17

    .line 555
    .line 556
    long-to-int v6, v6

    .line 557
    add-int/2addr v12, v6

    .line 558
    int-to-float v6, v12

    .line 559
    cmpg-float v6, v6, v13

    .line 560
    .line 561
    if-gtz v6, :cond_16

    .line 562
    .line 563
    invoke-virtual {v11, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 564
    .line 565
    .line 566
    :cond_16
    :goto_a
    move v6, v13

    .line 567
    goto :goto_9

    .line 568
    :cond_17
    move v13, v6

    .line 569
    goto :goto_a

    .line 570
    :cond_18
    :goto_b
    invoke-virtual {v11}, Ljava/util/ArrayList;->isEmpty()Z

    .line 571
    .line 572
    .line 573
    move-result v4

    .line 574
    if-eqz v4, :cond_19

    .line 575
    .line 576
    invoke-virtual {v8}, Lt1/j0;->m()Lpv/g;

    .line 577
    .line 578
    .line 579
    move-result-object v4

    .line 580
    invoke-virtual {v4}, Lpv/g;->i()Ljava/util/ArrayList;

    .line 581
    .line 582
    .line 583
    move-result-object v11

    .line 584
    :cond_19
    move-object v10, v11

    .line 585
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 586
    .line 587
    .line 588
    move-result v4

    .line 589
    if-eqz v4, :cond_1b

    .line 590
    .line 591
    const/4 v5, 0x1

    .line 592
    if-ne v4, v5, :cond_1a

    .line 593
    .line 594
    sget-object v4, Lx21/b0;->d:Lx21/b0;

    .line 595
    .line 596
    :goto_c
    move-object v11, v4

    .line 597
    goto :goto_d

    .line 598
    :cond_1a
    new-instance v0, La8/r0;

    .line 599
    .line 600
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 601
    .line 602
    .line 603
    throw v0

    .line 604
    :cond_1b
    sget-object v4, Lx21/b0;->e:Lx21/b0;

    .line 605
    .line 606
    goto :goto_c

    .line 607
    :goto_d
    const/4 v12, 0x0

    .line 608
    const/16 v13, 0x8

    .line 609
    .line 610
    move-object/from16 v8, p0

    .line 611
    .line 612
    invoke-static/range {v8 .. v13}, Lx21/y;->c(Lx21/y;Ld3/c;Ljava/util/ArrayList;Lx21/b0;Lw3/a0;I)Lx21/x;

    .line 613
    .line 614
    .line 615
    move-result-object v4

    .line 616
    if-nez v4, :cond_22

    .line 617
    .line 618
    new-instance v4, Lb1/e;

    .line 619
    .line 620
    const/16 v5, 0x17

    .line 621
    .line 622
    invoke-direct {v4, v5, v8, v1}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 623
    .line 624
    .line 625
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 626
    .line 627
    .line 628
    move-result v5

    .line 629
    if-eqz v5, :cond_1f

    .line 630
    .line 631
    const/4 v6, 0x1

    .line 632
    if-ne v5, v6, :cond_1e

    .line 633
    .line 634
    invoke-interface {v10}, Ljava/util/List;->size()I

    .line 635
    .line 636
    .line 637
    move-result v5

    .line 638
    invoke-interface {v10, v5}, Ljava/util/List;->listIterator(I)Ljava/util/ListIterator;

    .line 639
    .line 640
    .line 641
    move-result-object v5

    .line 642
    :cond_1c
    invoke-interface {v5}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 643
    .line 644
    .line 645
    move-result v6

    .line 646
    if-eqz v6, :cond_1d

    .line 647
    .line 648
    invoke-interface {v5}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 649
    .line 650
    .line 651
    move-result-object v6

    .line 652
    invoke-virtual {v4, v6}, Lb1/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 653
    .line 654
    .line 655
    move-result-object v7

    .line 656
    check-cast v7, Ljava/lang/Boolean;

    .line 657
    .line 658
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 659
    .line 660
    .line 661
    move-result v7

    .line 662
    if-eqz v7, :cond_1c

    .line 663
    .line 664
    goto :goto_e

    .line 665
    :cond_1d
    move-object v6, v15

    .line 666
    :goto_e
    check-cast v6, Lx21/x;

    .line 667
    .line 668
    :goto_f
    move-object v4, v6

    .line 669
    goto :goto_11

    .line 670
    :cond_1e
    new-instance v0, La8/r0;

    .line 671
    .line 672
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 673
    .line 674
    .line 675
    throw v0

    .line 676
    :cond_1f
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 677
    .line 678
    .line 679
    move-result-object v5

    .line 680
    :cond_20
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 681
    .line 682
    .line 683
    move-result v6

    .line 684
    if-eqz v6, :cond_21

    .line 685
    .line 686
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 687
    .line 688
    .line 689
    move-result-object v6

    .line 690
    invoke-virtual {v4, v6}, Lb1/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 691
    .line 692
    .line 693
    move-result-object v7

    .line 694
    check-cast v7, Ljava/lang/Boolean;

    .line 695
    .line 696
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 697
    .line 698
    .line 699
    move-result v7

    .line 700
    if-eqz v7, :cond_20

    .line 701
    .line 702
    goto :goto_10

    .line 703
    :cond_21
    move-object v6, v15

    .line 704
    :goto_10
    check-cast v6, Lx21/x;

    .line 705
    .line 706
    goto :goto_f

    .line 707
    :cond_22
    :goto_11
    move-object v11, v4

    .line 708
    if-nez v11, :cond_23

    .line 709
    .line 710
    invoke-virtual {v14, v15}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 711
    .line 712
    .line 713
    return-object v16

    .line 714
    :cond_23
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 715
    .line 716
    .line 717
    move-result v0

    .line 718
    if-eqz v0, :cond_26

    .line 719
    .line 720
    const/4 v5, 0x1

    .line 721
    if-ne v0, v5, :cond_25

    .line 722
    .line 723
    invoke-virtual {v11}, Lx21/x;->a()I

    .line 724
    .line 725
    .line 726
    move-result v0

    .line 727
    invoke-virtual {v1}, Lx21/x;->a()I

    .line 728
    .line 729
    .line 730
    move-result v4

    .line 731
    if-le v0, v4, :cond_24

    .line 732
    .line 733
    goto :goto_12

    .line 734
    :cond_24
    move-object v12, v15

    .line 735
    goto :goto_14

    .line 736
    :cond_25
    new-instance v0, La8/r0;

    .line 737
    .line 738
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 739
    .line 740
    .line 741
    throw v0

    .line 742
    :cond_26
    invoke-virtual {v11}, Lx21/x;->a()I

    .line 743
    .line 744
    .line 745
    move-result v0

    .line 746
    invoke-virtual {v1}, Lx21/x;->a()I

    .line 747
    .line 748
    .line 749
    move-result v4

    .line 750
    if-ge v0, v4, :cond_24

    .line 751
    .line 752
    :goto_12
    iget-object v0, v8, Lx21/y;->b:Lvy0/b0;

    .line 753
    .line 754
    move-object v9, v8

    .line 755
    new-instance v8, Lx21/p;

    .line 756
    .line 757
    const/4 v13, 0x0

    .line 758
    move-object v10, v1

    .line 759
    move-object v12, v15

    .line 760
    invoke-direct/range {v8 .. v13}, Lx21/p;-><init>(Lx21/y;Lx21/x;Lx21/x;Lkotlin/coroutines/Continuation;I)V

    .line 761
    .line 762
    .line 763
    const/4 v1, 0x3

    .line 764
    invoke-static {v0, v12, v12, v8, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 765
    .line 766
    .line 767
    move-result-object v0

    .line 768
    invoke-virtual {v14, v12}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 769
    .line 770
    .line 771
    iput-object v12, v2, Lx21/o;->d:Lx21/y;

    .line 772
    .line 773
    iput-object v12, v2, Lx21/o;->e:Lx21/b0;

    .line 774
    .line 775
    const/4 v1, 0x2

    .line 776
    iput v1, v2, Lx21/o;->h:I

    .line 777
    .line 778
    invoke-virtual {v0, v2}, Lvy0/p1;->l(Lrx0/c;)Ljava/lang/Object;

    .line 779
    .line 780
    .line 781
    move-result-object v0

    .line 782
    if-ne v0, v3, :cond_27

    .line 783
    .line 784
    :goto_13
    return-object v3

    .line 785
    :cond_27
    return-object v16

    .line 786
    :goto_14
    invoke-virtual {v14, v12}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 787
    .line 788
    .line 789
    return-object v16
.end method

.method public static final b(Lx21/y;Lx21/x;Lx21/x;Lrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    instance-of v2, v1, Lx21/q;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lx21/q;

    .line 11
    .line 12
    iget v3, v2, Lx21/q;->j:I

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
    iput v3, v2, Lx21/q;->j:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lx21/q;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lx21/q;-><init>(Lx21/y;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lx21/q;->h:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lx21/q;->j:I

    .line 34
    .line 35
    const/4 v5, 0x4

    .line 36
    const/4 v6, 0x3

    .line 37
    const/4 v7, 0x2

    .line 38
    const/4 v8, 0x1

    .line 39
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    const/4 v10, 0x0

    .line 42
    if-eqz v4, :cond_5

    .line 43
    .line 44
    if-eq v4, v8, :cond_4

    .line 45
    .line 46
    if-eq v4, v7, :cond_3

    .line 47
    .line 48
    if-eq v4, v6, :cond_2

    .line 49
    .line 50
    if-ne v4, v5, :cond_1

    .line 51
    .line 52
    iget-object v0, v2, Lx21/q;->e:Ljava/lang/Object;

    .line 53
    .line 54
    move-object v3, v0

    .line 55
    check-cast v3, Lez0/a;

    .line 56
    .line 57
    iget-object v0, v2, Lx21/q;->d:Lx21/y;

    .line 58
    .line 59
    :try_start_0
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 60
    .line 61
    .line 62
    goto/16 :goto_8

    .line 63
    .line 64
    :catchall_0
    move-exception v0

    .line 65
    goto/16 :goto_9

    .line 66
    .line 67
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 68
    .line 69
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 70
    .line 71
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw v0

    .line 75
    :cond_2
    iget-object v4, v2, Lx21/q;->g:Lez0/a;

    .line 76
    .line 77
    iget-object v0, v2, Lx21/q;->f:Lx21/x;

    .line 78
    .line 79
    iget-object v6, v2, Lx21/q;->e:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v6, Lx21/x;

    .line 82
    .line 83
    iget-object v7, v2, Lx21/q;->d:Lx21/y;

    .line 84
    .line 85
    :try_start_1
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 86
    .line 87
    .line 88
    move-object v11, v0

    .line 89
    move-object v1, v4

    .line 90
    move-object v0, v7

    .line 91
    goto/16 :goto_5

    .line 92
    .line 93
    :catchall_1
    move-exception v0

    .line 94
    move-object v3, v4

    .line 95
    goto/16 :goto_9

    .line 96
    .line 97
    :cond_3
    iget-object v4, v2, Lx21/q;->g:Lez0/a;

    .line 98
    .line 99
    iget-object v0, v2, Lx21/q;->f:Lx21/x;

    .line 100
    .line 101
    iget-object v7, v2, Lx21/q;->e:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast v7, Lx21/x;

    .line 104
    .line 105
    iget-object v8, v2, Lx21/q;->d:Lx21/y;

    .line 106
    .line 107
    :try_start_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 108
    .line 109
    .line 110
    goto/16 :goto_4

    .line 111
    .line 112
    :cond_4
    iget-object v0, v2, Lx21/q;->g:Lez0/a;

    .line 113
    .line 114
    iget-object v4, v2, Lx21/q;->f:Lx21/x;

    .line 115
    .line 116
    iget-object v8, v2, Lx21/q;->e:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast v8, Lx21/x;

    .line 119
    .line 120
    iget-object v11, v2, Lx21/q;->d:Lx21/y;

    .line 121
    .line 122
    :try_start_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_3
    .catch Ljava/util/concurrent/CancellationException; {:try_start_3 .. :try_end_3} :catch_0

    .line 123
    .line 124
    .line 125
    move-object v1, v0

    .line 126
    move-object v0, v11

    .line 127
    move-object v11, v4

    .line 128
    move-object v4, v8

    .line 129
    goto :goto_1

    .line 130
    :cond_5
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    invoke-virtual/range {p1 .. p1}, Lx21/x;->a()I

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    invoke-virtual/range {p2 .. p2}, Lx21/x;->a()I

    .line 138
    .line 139
    .line 140
    move-result v4

    .line 141
    if-ne v1, v4, :cond_6

    .line 142
    .line 143
    goto/16 :goto_a

    .line 144
    .line 145
    :cond_6
    :try_start_4
    iget-object v1, v0, Lx21/y;->j:Lez0/c;

    .line 146
    .line 147
    iput-object v0, v2, Lx21/q;->d:Lx21/y;

    .line 148
    .line 149
    move-object/from16 v4, p1

    .line 150
    .line 151
    iput-object v4, v2, Lx21/q;->e:Ljava/lang/Object;

    .line 152
    .line 153
    move-object/from16 v11, p2

    .line 154
    .line 155
    iput-object v11, v2, Lx21/q;->f:Lx21/x;

    .line 156
    .line 157
    iput-object v1, v2, Lx21/q;->g:Lez0/a;

    .line 158
    .line 159
    iput v8, v2, Lx21/q;->j:I

    .line 160
    .line 161
    invoke-virtual {v1, v2}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v8
    :try_end_4
    .catch Ljava/util/concurrent/CancellationException; {:try_start_4 .. :try_end_4} :catch_0

    .line 165
    if-ne v8, v3, :cond_7

    .line 166
    .line 167
    goto/16 :goto_7

    .line 168
    .line 169
    :cond_7
    :goto_1
    :try_start_5
    invoke-virtual {v0}, Lx21/y;->g()Z

    .line 170
    .line 171
    .line 172
    move-result v8
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 173
    iget-object v12, v0, Lx21/y;->a:Lt1/j0;

    .line 174
    .line 175
    if-nez v8, :cond_8

    .line 176
    .line 177
    :try_start_6
    invoke-interface {v1, v10}, Lez0/a;->d(Ljava/lang/Object;)V
    :try_end_6
    .catch Ljava/util/concurrent/CancellationException; {:try_start_6 .. :try_end_6} :catch_0

    .line 178
    .line 179
    .line 180
    return-object v9

    .line 181
    :cond_8
    :try_start_7
    invoke-virtual {v4}, Lx21/x;->a()I

    .line 182
    .line 183
    .line 184
    move-result v8

    .line 185
    iget-object v13, v12, Lt1/j0;->e:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast v13, Lm1/t;

    .line 188
    .line 189
    iget-object v12, v12, Lt1/j0;->e:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast v12, Lm1/t;

    .line 192
    .line 193
    iget-object v13, v13, Lm1/t;->e:Lm1/o;

    .line 194
    .line 195
    iget-object v13, v13, Lm1/o;->b:Ll2/g1;

    .line 196
    .line 197
    invoke-virtual {v13}, Ll2/g1;->o()I

    .line 198
    .line 199
    .line 200
    move-result v13

    .line 201
    if-eq v8, v13, :cond_9

    .line 202
    .line 203
    invoke-virtual {v11}, Lx21/x;->a()I

    .line 204
    .line 205
    .line 206
    move-result v8

    .line 207
    iget-object v13, v12, Lm1/t;->e:Lm1/o;

    .line 208
    .line 209
    iget-object v13, v13, Lm1/o;->b:Ll2/g1;

    .line 210
    .line 211
    invoke-virtual {v13}, Ll2/g1;->o()I

    .line 212
    .line 213
    .line 214
    move-result v13

    .line 215
    if-ne v8, v13, :cond_c

    .line 216
    .line 217
    goto :goto_3

    .line 218
    :goto_2
    move-object v3, v1

    .line 219
    goto/16 :goto_9

    .line 220
    .line 221
    :catchall_2
    move-exception v0

    .line 222
    goto :goto_2

    .line 223
    :cond_9
    :goto_3
    iget-object v8, v12, Lm1/t;->e:Lm1/o;

    .line 224
    .line 225
    iget-object v8, v8, Lm1/o;->b:Ll2/g1;

    .line 226
    .line 227
    invoke-virtual {v8}, Ll2/g1;->o()I

    .line 228
    .line 229
    .line 230
    move-result v8

    .line 231
    iget-object v13, v12, Lm1/t;->e:Lm1/o;

    .line 232
    .line 233
    iget-object v13, v13, Lm1/o;->c:Ll2/g1;

    .line 234
    .line 235
    invoke-virtual {v13}, Ll2/g1;->o()I

    .line 236
    .line 237
    .line 238
    move-result v13

    .line 239
    iput-object v0, v2, Lx21/q;->d:Lx21/y;

    .line 240
    .line 241
    iput-object v4, v2, Lx21/q;->e:Ljava/lang/Object;

    .line 242
    .line 243
    iput-object v11, v2, Lx21/q;->f:Lx21/x;

    .line 244
    .line 245
    iput-object v1, v2, Lx21/q;->g:Lez0/a;

    .line 246
    .line 247
    iput v7, v2, Lx21/q;->j:I

    .line 248
    .line 249
    iget-object v7, v12, Lm1/t;->i:Lg1/f0;

    .line 250
    .line 251
    invoke-virtual {v7}, Lg1/f0;->a()Z

    .line 252
    .line 253
    .line 254
    move-result v7

    .line 255
    if-eqz v7, :cond_a

    .line 256
    .line 257
    iget-object v7, v12, Lm1/t;->f:Ll2/j1;

    .line 258
    .line 259
    invoke-virtual {v7}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v7

    .line 263
    check-cast v7, Lm1/l;

    .line 264
    .line 265
    iget-object v7, v7, Lm1/l;->h:Lvy0/b0;

    .line 266
    .line 267
    new-instance v14, Lh2/x2;

    .line 268
    .line 269
    const/4 v15, 0x4

    .line 270
    invoke-direct {v14, v12, v10, v15}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 271
    .line 272
    .line 273
    invoke-static {v7, v10, v10, v14, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 274
    .line 275
    .line 276
    :cond_a
    const/4 v7, 0x0

    .line 277
    invoke-virtual {v12, v8, v13, v7}, Lm1/t;->k(IIZ)V

    .line 278
    .line 279
    .line 280
    if-ne v9, v3, :cond_b

    .line 281
    .line 282
    goto/16 :goto_7

    .line 283
    .line 284
    :cond_b
    move-object v8, v0

    .line 285
    move-object v7, v4

    .line 286
    move-object v0, v11

    .line 287
    move-object v4, v1

    .line 288
    :goto_4
    move-object v11, v0

    .line 289
    move-object v1, v4

    .line 290
    move-object v4, v7

    .line 291
    move-object v0, v8

    .line 292
    :cond_c
    invoke-virtual {v4}, Lx21/x;->a()I

    .line 293
    .line 294
    .line 295
    move-result v7

    .line 296
    new-instance v8, Ljava/lang/Integer;

    .line 297
    .line 298
    invoke-direct {v8, v7}, Ljava/lang/Integer;-><init>(I)V

    .line 299
    .line 300
    .line 301
    iget-object v7, v0, Lx21/y;->o:Ll2/j1;

    .line 302
    .line 303
    invoke-virtual {v7, v8}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 304
    .line 305
    .line 306
    iget-object v7, v0, Lx21/y;->c:Ll2/b1;

    .line 307
    .line 308
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object v7

    .line 312
    check-cast v7, Lay0/p;

    .line 313
    .line 314
    iget-object v8, v0, Lx21/y;->b:Lvy0/b0;

    .line 315
    .line 316
    iget-object v12, v4, Lx21/x;->a:Lm1/m;

    .line 317
    .line 318
    iget-object v13, v11, Lx21/x;->a:Lm1/m;

    .line 319
    .line 320
    iput-object v0, v2, Lx21/q;->d:Lx21/y;

    .line 321
    .line 322
    iput-object v4, v2, Lx21/q;->e:Ljava/lang/Object;

    .line 323
    .line 324
    iput-object v11, v2, Lx21/q;->f:Lx21/x;

    .line 325
    .line 326
    iput-object v1, v2, Lx21/q;->g:Lez0/a;

    .line 327
    .line 328
    iput v6, v2, Lx21/q;->j:I

    .line 329
    .line 330
    invoke-interface {v7, v8, v12, v13, v2}, Lay0/p;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v6

    .line 334
    if-ne v6, v3, :cond_d

    .line 335
    .line 336
    goto :goto_7

    .line 337
    :cond_d
    move-object v6, v4

    .line 338
    :goto_5
    invoke-virtual {v11}, Lx21/x;->a()I

    .line 339
    .line 340
    .line 341
    move-result v4

    .line 342
    invoke-virtual {v6}, Lx21/x;->a()I

    .line 343
    .line 344
    .line 345
    move-result v7

    .line 346
    if-le v4, v7, :cond_e

    .line 347
    .line 348
    invoke-virtual {v11}, Lx21/x;->b()J

    .line 349
    .line 350
    .line 351
    move-result-wide v7

    .line 352
    invoke-virtual {v11}, Lx21/x;->c()J

    .line 353
    .line 354
    .line 355
    move-result-wide v11

    .line 356
    const/16 v4, 0x20

    .line 357
    .line 358
    shr-long v13, v7, v4

    .line 359
    .line 360
    long-to-int v13, v13

    .line 361
    shr-long v14, v11, v4

    .line 362
    .line 363
    long-to-int v14, v14

    .line 364
    add-int/2addr v13, v14

    .line 365
    const-wide v14, 0xffffffffL

    .line 366
    .line 367
    .line 368
    .line 369
    .line 370
    and-long/2addr v7, v14

    .line 371
    long-to-int v7, v7

    .line 372
    and-long/2addr v11, v14

    .line 373
    long-to-int v8, v11

    .line 374
    add-int/2addr v7, v8

    .line 375
    invoke-static {v13, v7}, Lkp/d9;->a(II)J

    .line 376
    .line 377
    .line 378
    move-result-wide v7

    .line 379
    invoke-virtual {v6}, Lx21/x;->c()J

    .line 380
    .line 381
    .line 382
    move-result-wide v11

    .line 383
    move-wide/from16 p0, v14

    .line 384
    .line 385
    shr-long v14, v7, v4

    .line 386
    .line 387
    long-to-int v6, v14

    .line 388
    shr-long v13, v11, v4

    .line 389
    .line 390
    long-to-int v4, v13

    .line 391
    sub-int/2addr v6, v4

    .line 392
    and-long v7, v7, p0

    .line 393
    .line 394
    long-to-int v4, v7

    .line 395
    and-long v7, v11, p0

    .line 396
    .line 397
    long-to-int v7, v7

    .line 398
    sub-int/2addr v4, v7

    .line 399
    invoke-static {v6, v4}, Lkp/d9;->a(II)J

    .line 400
    .line 401
    .line 402
    move-result-wide v6

    .line 403
    new-instance v4, Lt4/j;

    .line 404
    .line 405
    invoke-direct {v4, v6, v7}, Lt4/j;-><init>(J)V

    .line 406
    .line 407
    .line 408
    goto :goto_6

    .line 409
    :cond_e
    invoke-virtual {v11}, Lx21/x;->b()J

    .line 410
    .line 411
    .line 412
    move-result-wide v6

    .line 413
    new-instance v4, Lt4/j;

    .line 414
    .line 415
    invoke-direct {v4, v6, v7}, Lt4/j;-><init>(J)V

    .line 416
    .line 417
    .line 418
    :goto_6
    iget-object v6, v0, Lx21/y;->p:Ll2/j1;

    .line 419
    .line 420
    invoke-virtual {v6, v4}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 421
    .line 422
    .line 423
    new-instance v4, Lvo0/e;

    .line 424
    .line 425
    const/16 v6, 0x12

    .line 426
    .line 427
    invoke-direct {v4, v0, v10, v6}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 428
    .line 429
    .line 430
    iput-object v0, v2, Lx21/q;->d:Lx21/y;

    .line 431
    .line 432
    iput-object v1, v2, Lx21/q;->e:Ljava/lang/Object;

    .line 433
    .line 434
    iput-object v10, v2, Lx21/q;->f:Lx21/x;

    .line 435
    .line 436
    iput-object v10, v2, Lx21/q;->g:Lez0/a;

    .line 437
    .line 438
    iput v5, v2, Lx21/q;->j:I

    .line 439
    .line 440
    const-wide/16 v5, 0x3e8

    .line 441
    .line 442
    invoke-static {v5, v6, v4, v2}, Lvy0/e0;->S(JLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 443
    .line 444
    .line 445
    move-result-object v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 446
    if-ne v2, v3, :cond_f

    .line 447
    .line 448
    :goto_7
    return-object v3

    .line 449
    :cond_f
    move-object v3, v1

    .line 450
    :goto_8
    :try_start_8
    iget-object v1, v0, Lx21/y;->o:Ll2/j1;

    .line 451
    .line 452
    invoke-virtual {v1, v10}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 453
    .line 454
    .line 455
    iget-object v0, v0, Lx21/y;->p:Ll2/j1;

    .line 456
    .line 457
    invoke-virtual {v0, v10}, Ll2/j1;->setValue(Ljava/lang/Object;)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 458
    .line 459
    .line 460
    :try_start_9
    invoke-interface {v3, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 461
    .line 462
    .line 463
    return-object v9

    .line 464
    :goto_9
    invoke-interface {v3, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 465
    .line 466
    .line 467
    throw v0
    :try_end_9
    .catch Ljava/util/concurrent/CancellationException; {:try_start_9 .. :try_end_9} :catch_0

    .line 468
    :catch_0
    :goto_a
    return-object v9
.end method

.method public static c(Lx21/y;Ld3/c;Ljava/util/ArrayList;Lx21/b0;Lw3/a0;I)Lx21/x;
    .locals 1

    .line 1
    and-int/lit8 v0, p5, 0x4

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object p3, Lx21/b0;->e:Lx21/b0;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p5, 0x8

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    sget-object p4, Lx21/i;->h:Lx21/i;

    .line 12
    .line 13
    :cond_1
    new-instance p5, La3/g;

    .line 14
    .line 15
    const/16 v0, 0x9

    .line 16
    .line 17
    invoke-direct {p5, p0, p1, p4, v0}, La3/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p3}, Ljava/lang/Enum;->ordinal()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    const/4 p1, 0x0

    .line 25
    if-eqz p0, :cond_5

    .line 26
    .line 27
    const/4 p3, 0x1

    .line 28
    if-ne p0, p3, :cond_4

    .line 29
    .line 30
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    :cond_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    if-eqz p2, :cond_3

    .line 39
    .line 40
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p2

    .line 44
    invoke-virtual {p5, p2}, La3/g;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p3

    .line 48
    check-cast p3, Ljava/lang/Boolean;

    .line 49
    .line 50
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 51
    .line 52
    .line 53
    move-result p3

    .line 54
    if-eqz p3, :cond_2

    .line 55
    .line 56
    move-object p1, p2

    .line 57
    :cond_3
    check-cast p1, Lx21/x;

    .line 58
    .line 59
    return-object p1

    .line 60
    :cond_4
    new-instance p0, La8/r0;

    .line 61
    .line 62
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 63
    .line 64
    .line 65
    throw p0

    .line 66
    :cond_5
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    invoke-interface {p2, p0}, Ljava/util/List;->listIterator(I)Ljava/util/ListIterator;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    :cond_6
    invoke-interface {p0}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 75
    .line 76
    .line 77
    move-result p2

    .line 78
    if-eqz p2, :cond_7

    .line 79
    .line 80
    invoke-interface {p0}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    invoke-virtual {p5, p2}, La3/g;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p3

    .line 88
    check-cast p3, Ljava/lang/Boolean;

    .line 89
    .line 90
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 91
    .line 92
    .line 93
    move-result p3

    .line 94
    if-eqz p3, :cond_6

    .line 95
    .line 96
    move-object p1, p2

    .line 97
    :cond_7
    check-cast p1, Lx21/x;

    .line 98
    .line 99
    return-object p1
.end method


# virtual methods
.method public final d()Lx21/x;
    .locals 4

    .line 1
    iget-object v0, p0, Lx21/y;->k:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_2

    .line 9
    .line 10
    iget-object p0, p0, Lx21/y;->a:Lt1/j0;

    .line 11
    .line 12
    invoke-virtual {p0}, Lt1/j0;->m()Lpv/g;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-virtual {p0}, Lpv/g;->i()Ljava/util/ArrayList;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz v2, :cond_1

    .line 29
    .line 30
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    move-object v3, v2

    .line 35
    check-cast v3, Lx21/x;

    .line 36
    .line 37
    iget-object v3, v3, Lx21/x;->a:Lm1/m;

    .line 38
    .line 39
    iget-object v3, v3, Lm1/m;->k:Ljava/lang/Object;

    .line 40
    .line 41
    invoke-virtual {v3, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    if-eqz v3, :cond_0

    .line 46
    .line 47
    move-object v1, v2

    .line 48
    :cond_1
    check-cast v1, Lx21/x;

    .line 49
    .line 50
    :cond_2
    return-object v1
.end method

.method public final e()J
    .locals 10

    .line 1
    invoke-virtual {p0}, Lx21/y;->d()Lx21/x;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_4

    .line 6
    .line 7
    invoke-virtual {v0}, Lx21/x;->a()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    iget-object v2, p0, Lx21/y;->o:Ll2/j1;

    .line 12
    .line 13
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    check-cast v3, Ljava/lang/Integer;

    .line 18
    .line 19
    iget-object v4, p0, Lx21/y;->p:Ll2/j1;

    .line 20
    .line 21
    if-nez v3, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-ne v1, v3, :cond_3

    .line 29
    .line 30
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    check-cast v1, Ljava/lang/Integer;

    .line 35
    .line 36
    if-nez v1, :cond_1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, Lt4/j;

    .line 44
    .line 45
    if-eqz v1, :cond_2

    .line 46
    .line 47
    iget-wide v0, v1, Lt4/j;->a:J

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    invoke-virtual {v0}, Lx21/x;->b()J

    .line 51
    .line 52
    .line 53
    move-result-wide v0

    .line 54
    goto :goto_1

    .line 55
    :cond_3
    :goto_0
    const/4 v1, 0x0

    .line 56
    invoke-virtual {v2, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v4, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v0}, Lx21/x;->b()J

    .line 63
    .line 64
    .line 65
    move-result-wide v0

    .line 66
    :goto_1
    iget-object v2, p0, Lx21/y;->m:Ll2/j1;

    .line 67
    .line 68
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    check-cast v2, Ld3/b;

    .line 73
    .line 74
    iget-wide v2, v2, Ld3/b;->a:J

    .line 75
    .line 76
    iget-object v4, p0, Lx21/y;->n:Ll2/j1;

    .line 77
    .line 78
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    check-cast v4, Lt4/j;

    .line 83
    .line 84
    iget-wide v4, v4, Lt4/j;->a:J

    .line 85
    .line 86
    const/16 v6, 0x20

    .line 87
    .line 88
    shr-long v7, v4, v6

    .line 89
    .line 90
    long-to-int v7, v7

    .line 91
    int-to-float v7, v7

    .line 92
    const-wide v8, 0xffffffffL

    .line 93
    .line 94
    .line 95
    .line 96
    .line 97
    and-long/2addr v4, v8

    .line 98
    long-to-int v4, v4

    .line 99
    int-to-float v4, v4

    .line 100
    invoke-static {v7, v4}, Ljp/bf;->a(FF)J

    .line 101
    .line 102
    .line 103
    move-result-wide v4

    .line 104
    shr-long v6, v0, v6

    .line 105
    .line 106
    long-to-int v6, v6

    .line 107
    int-to-float v6, v6

    .line 108
    and-long/2addr v0, v8

    .line 109
    long-to-int v0, v0

    .line 110
    int-to-float v0, v0

    .line 111
    invoke-static {v6, v0}, Ljp/bf;->a(FF)J

    .line 112
    .line 113
    .line 114
    move-result-wide v0

    .line 115
    invoke-static {v4, v5, v0, v1}, Ld3/b;->g(JJ)J

    .line 116
    .line 117
    .line 118
    move-result-wide v0

    .line 119
    invoke-virtual {p0, v0, v1}, Lx21/y;->i(J)J

    .line 120
    .line 121
    .line 122
    move-result-wide v0

    .line 123
    invoke-virtual {p0, v0, v1}, Lx21/y;->j(J)J

    .line 124
    .line 125
    .line 126
    invoke-static {v2, v3, v0, v1}, Ld3/b;->h(JJ)J

    .line 127
    .line 128
    .line 129
    move-result-wide v0

    .line 130
    return-wide v0

    .line 131
    :cond_4
    const-wide/16 v0, 0x0

    .line 132
    .line 133
    return-wide v0
.end method

.method public final f()Lg1/w1;
    .locals 0

    .line 1
    iget-object p0, p0, Lx21/y;->a:Lt1/j0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lt1/j0;->m()Lpv/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lpv/g;->g()Lg1/w1;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final g()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lx21/y;->l:Ll2/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final h(Ljava/lang/Integer;JLrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p4, Lx21/s;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lx21/s;

    .line 7
    .line 8
    iget v1, v0, Lx21/s;->j:I

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
    iput v1, v0, Lx21/s;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lx21/s;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Lx21/s;-><init>(Lx21/y;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Lx21/s;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lx21/s;->j:I

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
    iget-wide p2, v0, Lx21/s;->g:J

    .line 37
    .line 38
    iget-object p0, v0, Lx21/s;->f:Lx21/x;

    .line 39
    .line 40
    iget-object p1, v0, Lx21/s;->e:Ljava/lang/Object;

    .line 41
    .line 42
    iget-object v0, v0, Lx21/s;->d:Lx21/y;

    .line 43
    .line 44
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    move-object v2, p0

    .line 48
    move-object p0, v0

    .line 49
    goto/16 :goto_4

    .line 50
    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iget-object p4, p0, Lx21/y;->a:Lt1/j0;

    .line 63
    .line 64
    invoke-virtual {p4}, Lt1/j0;->m()Lpv/g;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    invoke-virtual {v2}, Lpv/g;->i()Ljava/util/ArrayList;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    :cond_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    const/4 v5, 0x0

    .line 81
    if-eqz v4, :cond_4

    .line 82
    .line 83
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    move-object v6, v4

    .line 88
    check-cast v6, Lx21/x;

    .line 89
    .line 90
    iget-object v6, v6, Lx21/x;->a:Lm1/m;

    .line 91
    .line 92
    iget-object v6, v6, Lm1/m;->k:Ljava/lang/Object;

    .line 93
    .line 94
    invoke-virtual {v6, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v6

    .line 98
    if-eqz v6, :cond_3

    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_4
    move-object v4, v5

    .line 102
    :goto_1
    move-object v2, v4

    .line 103
    check-cast v2, Lx21/x;

    .line 104
    .line 105
    if-eqz v2, :cond_8

    .line 106
    .line 107
    invoke-virtual {v2}, Lx21/x;->b()J

    .line 108
    .line 109
    .line 110
    move-result-wide v6

    .line 111
    invoke-virtual {p0}, Lx21/y;->f()Lg1/w1;

    .line 112
    .line 113
    .line 114
    move-result-object v4

    .line 115
    const-string v8, "orientation"

    .line 116
    .line 117
    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 121
    .line 122
    .line 123
    move-result v4

    .line 124
    if-eqz v4, :cond_6

    .line 125
    .line 126
    if-ne v4, v3, :cond_5

    .line 127
    .line 128
    const/16 v4, 0x20

    .line 129
    .line 130
    shr-long/2addr v6, v4

    .line 131
    :goto_2
    long-to-int v4, v6

    .line 132
    goto :goto_3

    .line 133
    :cond_5
    new-instance p0, La8/r0;

    .line 134
    .line 135
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 136
    .line 137
    .line 138
    throw p0

    .line 139
    :cond_6
    const-wide v8, 0xffffffffL

    .line 140
    .line 141
    .line 142
    .line 143
    .line 144
    and-long/2addr v6, v8

    .line 145
    goto :goto_2

    .line 146
    :goto_3
    if-gez v4, :cond_7

    .line 147
    .line 148
    int-to-float v4, v4

    .line 149
    const/4 v6, 0x7

    .line 150
    const/4 v7, 0x0

    .line 151
    invoke-static {v7, v7, v5, v6}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 152
    .line 153
    .line 154
    move-result-object v5

    .line 155
    iput-object p0, v0, Lx21/s;->d:Lx21/y;

    .line 156
    .line 157
    iput-object p1, v0, Lx21/s;->e:Ljava/lang/Object;

    .line 158
    .line 159
    iput-object v2, v0, Lx21/s;->f:Lx21/x;

    .line 160
    .line 161
    iput-wide p2, v0, Lx21/s;->g:J

    .line 162
    .line 163
    iput v3, v0, Lx21/s;->j:I

    .line 164
    .line 165
    iget-object p4, p4, Lt1/j0;->e:Ljava/lang/Object;

    .line 166
    .line 167
    check-cast p4, Lm1/t;

    .line 168
    .line 169
    invoke-static {p4, v4, v5, v0}, Lg1/h3;->a(Lg1/q2;FLc1/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p4

    .line 173
    if-ne p4, v1, :cond_7

    .line 174
    .line 175
    return-object v1

    .line 176
    :cond_7
    :goto_4
    iget-object p4, p0, Lx21/y;->k:Ll2/j1;

    .line 177
    .line 178
    invoke-virtual {p4, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v2}, Lx21/x;->b()J

    .line 182
    .line 183
    .line 184
    move-result-wide v0

    .line 185
    iget-object p1, p0, Lx21/y;->n:Ll2/j1;

    .line 186
    .line 187
    new-instance p4, Lt4/j;

    .line 188
    .line 189
    invoke-direct {p4, v0, v1}, Lt4/j;-><init>(J)V

    .line 190
    .line 191
    .line 192
    invoke-virtual {p1, p4}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    iput-wide p2, p0, Lx21/y;->q:J

    .line 196
    .line 197
    :cond_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 198
    .line 199
    return-object p0
.end method

.method public final i(J)J
    .locals 2

    .line 1
    iget-object v0, p0, Lx21/y;->a:Lt1/j0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lt1/j0;->m()Lpv/g;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v0, v0, Lpv/g;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lm1/l;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Lx21/y;->f()Lg1/w1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_4

    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    if-ne v0, v1, :cond_3

    .line 26
    .line 27
    iget-object p0, p0, Lx21/y;->h:Lt4/m;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-eqz p0, :cond_4

    .line 34
    .line 35
    if-ne p0, v1, :cond_2

    .line 36
    .line 37
    sget-object p0, Lg1/w1;->e:Lg1/w1;

    .line 38
    .line 39
    const-string v0, "orientation"

    .line 40
    .line 41
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    if-eqz p0, :cond_1

    .line 49
    .line 50
    const/4 v0, 0x1

    .line 51
    if-ne p0, v0, :cond_0

    .line 52
    .line 53
    invoke-static {p1, p2}, Ld3/b;->e(J)F

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    neg-float p0, p0

    .line 58
    invoke-static {p1, p2}, Ld3/b;->f(J)F

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    invoke-static {p0, p1}, Ljp/bf;->a(FF)J

    .line 63
    .line 64
    .line 65
    move-result-wide p0

    .line 66
    goto :goto_0

    .line 67
    :cond_0
    new-instance p0, La8/r0;

    .line 68
    .line 69
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_1
    invoke-static {p1, p2}, Ld3/b;->e(J)F

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    invoke-static {p1, p2}, Ld3/b;->f(J)F

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    neg-float p1, p1

    .line 82
    invoke-static {p0, p1}, Ljp/bf;->a(FF)J

    .line 83
    .line 84
    .line 85
    move-result-wide p0

    .line 86
    :goto_0
    return-wide p0

    .line 87
    :cond_2
    new-instance p0, La8/r0;

    .line 88
    .line 89
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_3
    new-instance p0, La8/r0;

    .line 94
    .line 95
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 96
    .line 97
    .line 98
    throw p0

    .line 99
    :cond_4
    return-wide p1
.end method

.method public final j(J)J
    .locals 1

    .line 1
    iget-object p0, p0, Lx21/y;->h:Lt4/m;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-eqz p0, :cond_1

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    if-ne p0, v0, :cond_0

    .line 11
    .line 12
    return-wide p1

    .line 13
    :cond_0
    new-instance p0, La8/r0;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :cond_1
    return-wide p1
.end method
