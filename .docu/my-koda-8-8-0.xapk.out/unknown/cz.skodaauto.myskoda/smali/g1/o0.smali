.class public final Lg1/o0;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:Lp3/k;

.field public f:I

.field public g:I

.field public synthetic h:Ljava/lang/Object;

.field public final synthetic i:Lkotlin/jvm/internal/b0;

.field public final synthetic j:Lkotlin/jvm/internal/f0;

.field public final synthetic k:Lkotlin/jvm/internal/f0;


# direct methods
.method public constructor <init>(Lkotlin/jvm/internal/b0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lg1/o0;->i:Lkotlin/jvm/internal/b0;

    .line 2
    .line 3
    iput-object p2, p0, Lg1/o0;->j:Lkotlin/jvm/internal/f0;

    .line 4
    .line 5
    iput-object p3, p0, Lg1/o0;->k:Lkotlin/jvm/internal/f0;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, Lg1/o0;

    .line 2
    .line 3
    iget-object v1, p0, Lg1/o0;->j:Lkotlin/jvm/internal/f0;

    .line 4
    .line 5
    iget-object v2, p0, Lg1/o0;->k:Lkotlin/jvm/internal/f0;

    .line 6
    .line 7
    iget-object p0, p0, Lg1/o0;->i:Lkotlin/jvm/internal/b0;

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2, p2}, Lg1/o0;-><init>(Lkotlin/jvm/internal/b0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Lg1/o0;->h:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lp3/i0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lg1/o0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lg1/o0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lg1/o0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Lg1/o0;->g:I

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x2

    .line 9
    const/4 v6, 0x1

    .line 10
    if-eqz v2, :cond_2

    .line 11
    .line 12
    if-eq v2, v6, :cond_1

    .line 13
    .line 14
    if-ne v2, v4, :cond_0

    .line 15
    .line 16
    iget v2, v0, Lg1/o0;->f:I

    .line 17
    .line 18
    iget-object v7, v0, Lg1/o0;->e:Lp3/k;

    .line 19
    .line 20
    iget-object v8, v0, Lg1/o0;->h:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v8, Lp3/i0;

    .line 23
    .line 24
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    move v5, v6

    .line 28
    move-object/from16 v6, p1

    .line 29
    .line 30
    goto/16 :goto_8

    .line 31
    .line 32
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 35
    .line 36
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw v0

    .line 40
    :cond_1
    iget v2, v0, Lg1/o0;->f:I

    .line 41
    .line 42
    iget-object v7, v0, Lg1/o0;->h:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v7, Lp3/i0;

    .line 45
    .line 46
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    move-object/from16 v8, p1

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iget-object v2, v0, Lg1/o0;->h:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v2, Lp3/i0;

    .line 58
    .line 59
    move-object v7, v2

    .line 60
    const/4 v2, 0x0

    .line 61
    :goto_0
    if-nez v2, :cond_13

    .line 62
    .line 63
    sget-object v8, Lp3/l;->e:Lp3/l;

    .line 64
    .line 65
    iput-object v7, v0, Lg1/o0;->h:Ljava/lang/Object;

    .line 66
    .line 67
    iput-object v3, v0, Lg1/o0;->e:Lp3/k;

    .line 68
    .line 69
    iput v2, v0, Lg1/o0;->f:I

    .line 70
    .line 71
    iput v6, v0, Lg1/o0;->g:I

    .line 72
    .line 73
    invoke-virtual {v7, v8, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v8

    .line 77
    if-ne v8, v1, :cond_3

    .line 78
    .line 79
    goto :goto_7

    .line 80
    :cond_3
    :goto_1
    check-cast v8, Lp3/k;

    .line 81
    .line 82
    iget-object v9, v8, Lp3/k;->a:Ljava/lang/Object;

    .line 83
    .line 84
    move-object v10, v9

    .line 85
    check-cast v10, Ljava/util/Collection;

    .line 86
    .line 87
    invoke-interface {v10}, Ljava/util/Collection;->size()I

    .line 88
    .line 89
    .line 90
    move-result v10

    .line 91
    const/4 v11, 0x0

    .line 92
    :goto_2
    if-ge v11, v10, :cond_5

    .line 93
    .line 94
    invoke-interface {v9, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v12

    .line 98
    check-cast v12, Lp3/t;

    .line 99
    .line 100
    invoke-static {v12}, Lp3/s;->d(Lp3/t;)Z

    .line 101
    .line 102
    .line 103
    move-result v12

    .line 104
    if-nez v12, :cond_4

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_4
    add-int/lit8 v11, v11, 0x1

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_5
    move v2, v6

    .line 111
    :goto_3
    iget-object v9, v8, Lp3/k;->a:Ljava/lang/Object;

    .line 112
    .line 113
    move-object v10, v9

    .line 114
    check-cast v10, Ljava/util/Collection;

    .line 115
    .line 116
    invoke-interface {v10}, Ljava/util/Collection;->size()I

    .line 117
    .line 118
    .line 119
    move-result v10

    .line 120
    const/4 v11, 0x0

    .line 121
    :goto_4
    if-ge v11, v10, :cond_8

    .line 122
    .line 123
    invoke-interface {v9, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v12

    .line 127
    check-cast v12, Lp3/t;

    .line 128
    .line 129
    invoke-virtual {v12}, Lp3/t;->b()Z

    .line 130
    .line 131
    .line 132
    move-result v13

    .line 133
    if-nez v13, :cond_7

    .line 134
    .line 135
    iget-object v13, v7, Lp3/i0;->i:Lp3/j0;

    .line 136
    .line 137
    iget-wide v13, v13, Lp3/j0;->B:J

    .line 138
    .line 139
    invoke-virtual {v7}, Lp3/i0;->d()J

    .line 140
    .line 141
    .line 142
    move-result-wide v5

    .line 143
    invoke-static {v12, v13, v14, v5, v6}, Lp3/s;->f(Lp3/t;JJ)Z

    .line 144
    .line 145
    .line 146
    move-result v5

    .line 147
    if-eqz v5, :cond_6

    .line 148
    .line 149
    goto :goto_5

    .line 150
    :cond_6
    add-int/lit8 v11, v11, 0x1

    .line 151
    .line 152
    const/4 v6, 0x1

    .line 153
    goto :goto_4

    .line 154
    :cond_7
    :goto_5
    const/4 v2, 0x1

    .line 155
    :cond_8
    iget v5, v8, Lp3/k;->c:I

    .line 156
    .line 157
    if-ne v5, v4, :cond_9

    .line 158
    .line 159
    iget-object v2, v0, Lg1/o0;->i:Lkotlin/jvm/internal/b0;

    .line 160
    .line 161
    const/4 v5, 0x1

    .line 162
    iput-boolean v5, v2, Lkotlin/jvm/internal/b0;->d:Z

    .line 163
    .line 164
    move v2, v5

    .line 165
    goto :goto_6

    .line 166
    :cond_9
    const/4 v5, 0x1

    .line 167
    :goto_6
    sget-object v6, Lp3/l;->f:Lp3/l;

    .line 168
    .line 169
    iput-object v7, v0, Lg1/o0;->h:Ljava/lang/Object;

    .line 170
    .line 171
    iput-object v8, v0, Lg1/o0;->e:Lp3/k;

    .line 172
    .line 173
    iput v2, v0, Lg1/o0;->f:I

    .line 174
    .line 175
    iput v4, v0, Lg1/o0;->g:I

    .line 176
    .line 177
    invoke-virtual {v7, v6, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v6

    .line 181
    if-ne v6, v1, :cond_a

    .line 182
    .line 183
    :goto_7
    return-object v1

    .line 184
    :cond_a
    move-object v15, v8

    .line 185
    move-object v8, v7

    .line 186
    move-object v7, v15

    .line 187
    :goto_8
    check-cast v6, Lp3/k;

    .line 188
    .line 189
    iget-object v6, v6, Lp3/k;->a:Ljava/lang/Object;

    .line 190
    .line 191
    move-object v9, v6

    .line 192
    check-cast v9, Ljava/util/Collection;

    .line 193
    .line 194
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 195
    .line 196
    .line 197
    move-result v9

    .line 198
    const/4 v10, 0x0

    .line 199
    :goto_9
    if-ge v10, v9, :cond_c

    .line 200
    .line 201
    invoke-interface {v6, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v11

    .line 205
    check-cast v11, Lp3/t;

    .line 206
    .line 207
    invoke-virtual {v11}, Lp3/t;->b()Z

    .line 208
    .line 209
    .line 210
    move-result v11

    .line 211
    if-eqz v11, :cond_b

    .line 212
    .line 213
    move v2, v5

    .line 214
    goto :goto_a

    .line 215
    :cond_b
    add-int/lit8 v10, v10, 0x1

    .line 216
    .line 217
    goto :goto_9

    .line 218
    :cond_c
    :goto_a
    iget-object v6, v0, Lg1/o0;->j:Lkotlin/jvm/internal/f0;

    .line 219
    .line 220
    iget-object v9, v6, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 221
    .line 222
    check-cast v9, Lp3/t;

    .line 223
    .line 224
    iget-wide v9, v9, Lp3/t;->a:J

    .line 225
    .line 226
    invoke-static {v7, v9, v10}, Lg1/w0;->g(Lp3/k;J)Z

    .line 227
    .line 228
    .line 229
    move-result v9

    .line 230
    iget-object v7, v7, Lp3/k;->a:Ljava/lang/Object;

    .line 231
    .line 232
    iget-object v10, v0, Lg1/o0;->k:Lkotlin/jvm/internal/f0;

    .line 233
    .line 234
    if-eqz v9, :cond_10

    .line 235
    .line 236
    move-object v9, v7

    .line 237
    check-cast v9, Ljava/util/Collection;

    .line 238
    .line 239
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 240
    .line 241
    .line 242
    move-result v9

    .line 243
    const/4 v11, 0x0

    .line 244
    :goto_b
    if-ge v11, v9, :cond_e

    .line 245
    .line 246
    invoke-interface {v7, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object v12

    .line 250
    move-object v13, v12

    .line 251
    check-cast v13, Lp3/t;

    .line 252
    .line 253
    iget-boolean v13, v13, Lp3/t;->d:Z

    .line 254
    .line 255
    if-eqz v13, :cond_d

    .line 256
    .line 257
    goto :goto_c

    .line 258
    :cond_d
    add-int/lit8 v11, v11, 0x1

    .line 259
    .line 260
    goto :goto_b

    .line 261
    :cond_e
    move-object v12, v3

    .line 262
    :goto_c
    check-cast v12, Lp3/t;

    .line 263
    .line 264
    if-eqz v12, :cond_f

    .line 265
    .line 266
    iput-object v12, v6, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 267
    .line 268
    iput-object v12, v10, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 269
    .line 270
    goto :goto_f

    .line 271
    :cond_f
    move v2, v5

    .line 272
    move v6, v2

    .line 273
    move-object v7, v8

    .line 274
    goto/16 :goto_0

    .line 275
    .line 276
    :cond_10
    move-object v9, v7

    .line 277
    check-cast v9, Ljava/util/Collection;

    .line 278
    .line 279
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 280
    .line 281
    .line 282
    move-result v9

    .line 283
    const/4 v11, 0x0

    .line 284
    :goto_d
    if-ge v11, v9, :cond_12

    .line 285
    .line 286
    invoke-interface {v7, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v12

    .line 290
    move-object v13, v12

    .line 291
    check-cast v13, Lp3/t;

    .line 292
    .line 293
    iget-wide v13, v13, Lp3/t;->a:J

    .line 294
    .line 295
    iget-object v3, v6, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 296
    .line 297
    check-cast v3, Lp3/t;

    .line 298
    .line 299
    iget-wide v4, v3, Lp3/t;->a:J

    .line 300
    .line 301
    invoke-static {v13, v14, v4, v5}, Lp3/s;->e(JJ)Z

    .line 302
    .line 303
    .line 304
    move-result v3

    .line 305
    if-eqz v3, :cond_11

    .line 306
    .line 307
    goto :goto_e

    .line 308
    :cond_11
    add-int/lit8 v11, v11, 0x1

    .line 309
    .line 310
    const/4 v3, 0x0

    .line 311
    const/4 v4, 0x2

    .line 312
    const/4 v5, 0x1

    .line 313
    goto :goto_d

    .line 314
    :cond_12
    const/4 v12, 0x0

    .line 315
    :goto_e
    iput-object v12, v10, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 316
    .line 317
    :goto_f
    move-object v7, v8

    .line 318
    const/4 v3, 0x0

    .line 319
    const/4 v4, 0x2

    .line 320
    const/4 v6, 0x1

    .line 321
    goto/16 :goto_0

    .line 322
    .line 323
    :cond_13
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 324
    .line 325
    return-object v0
.end method
