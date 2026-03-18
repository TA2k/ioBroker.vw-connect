.class public final Lc00/p1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:J

.field public f:I

.field public g:I

.field public synthetic h:Ljava/lang/Object;

.field public i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lc00/t1;JLkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lc00/p1;->d:I

    .line 1
    iput-object p1, p0, Lc00/p1;->j:Ljava/lang/Object;

    iput-wide p2, p0, Lc00/p1;->e:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/Long;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lc00/p1;->d:I

    .line 2
    iput-object p1, p0, Lc00/p1;->j:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 4

    .line 1
    iget v0, p0, Lc00/p1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lc00/p1;

    .line 7
    .line 8
    iget-object p0, p0, Lc00/p1;->j:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Ljava/lang/Long;

    .line 11
    .line 12
    invoke-direct {v0, p0, p2}, Lc00/p1;-><init>(Ljava/lang/Long;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, v0, Lc00/p1;->h:Ljava/lang/Object;

    .line 16
    .line 17
    return-object v0

    .line 18
    :pswitch_0
    new-instance v0, Lc00/p1;

    .line 19
    .line 20
    iget-object v1, p0, Lc00/p1;->j:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v1, Lc00/t1;

    .line 23
    .line 24
    iget-wide v2, p0, Lc00/p1;->e:J

    .line 25
    .line 26
    invoke-direct {v0, v1, v2, v3, p2}, Lc00/p1;-><init>(Lc00/t1;JLkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Lc00/p1;->h:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lc00/p1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lyy0/j;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lc00/p1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc00/p1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc00/p1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lvy0/b0;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lc00/p1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lc00/p1;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lc00/p1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc00/p1;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lc00/p1;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lyy0/j;

    .line 11
    .line 12
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v3, v0, Lc00/p1;->g:I

    .line 15
    .line 16
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    const/4 v5, 0x2

    .line 19
    const/4 v6, 0x1

    .line 20
    if-eqz v3, :cond_3

    .line 21
    .line 22
    if-eq v3, v6, :cond_2

    .line 23
    .line 24
    if-ne v3, v5, :cond_1

    .line 25
    .line 26
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    :cond_0
    move-object v2, v4

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 34
    .line 35
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw v0

    .line 39
    :cond_2
    iget v3, v0, Lc00/p1;->f:I

    .line 40
    .line 41
    iget-wide v7, v0, Lc00/p1;->e:J

    .line 42
    .line 43
    iget-object v9, v0, Lc00/p1;->i:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v9, Ljava/lang/Long;

    .line 46
    .line 47
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-object v3, v0, Lc00/p1;->j:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v3, Ljava/lang/Long;

    .line 57
    .line 58
    if-eqz v3, :cond_0

    .line 59
    .line 60
    invoke-virtual {v3}, Ljava/lang/Number;->longValue()J

    .line 61
    .line 62
    .line 63
    move-result-wide v7

    .line 64
    const/4 v9, 0x0

    .line 65
    move/from16 v18, v9

    .line 66
    .line 67
    move-object v9, v3

    .line 68
    move/from16 v3, v18

    .line 69
    .line 70
    :cond_4
    iput-object v1, v0, Lc00/p1;->h:Ljava/lang/Object;

    .line 71
    .line 72
    iput-object v9, v0, Lc00/p1;->i:Ljava/lang/Object;

    .line 73
    .line 74
    iput-wide v7, v0, Lc00/p1;->e:J

    .line 75
    .line 76
    iput v3, v0, Lc00/p1;->f:I

    .line 77
    .line 78
    iput v6, v0, Lc00/p1;->g:I

    .line 79
    .line 80
    const-wide/16 v10, 0x1388

    .line 81
    .line 82
    invoke-static {v10, v11, v0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v10

    .line 86
    if-ne v10, v2, :cond_5

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_5
    :goto_0
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 90
    .line 91
    .line 92
    move-result-wide v10

    .line 93
    invoke-virtual {v9}, Ljava/lang/Long;->longValue()J

    .line 94
    .line 95
    .line 96
    move-result-wide v12

    .line 97
    sub-long/2addr v10, v12

    .line 98
    const-wide/32 v12, 0x1d4c0

    .line 99
    .line 100
    .line 101
    cmp-long v10, v10, v12

    .line 102
    .line 103
    if-lez v10, :cond_4

    .line 104
    .line 105
    const/4 v6, 0x0

    .line 106
    iput-object v6, v0, Lc00/p1;->h:Ljava/lang/Object;

    .line 107
    .line 108
    iput-object v6, v0, Lc00/p1;->i:Ljava/lang/Object;

    .line 109
    .line 110
    iput-wide v7, v0, Lc00/p1;->e:J

    .line 111
    .line 112
    iput v3, v0, Lc00/p1;->f:I

    .line 113
    .line 114
    iput v5, v0, Lc00/p1;->g:I

    .line 115
    .line 116
    invoke-interface {v1, v4, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    if-ne v0, v2, :cond_0

    .line 121
    .line 122
    :goto_1
    return-object v2

    .line 123
    :pswitch_0
    iget-wide v1, v0, Lc00/p1;->e:J

    .line 124
    .line 125
    iget-object v3, v0, Lc00/p1;->j:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast v3, Lc00/t1;

    .line 128
    .line 129
    iget-object v4, v0, Lc00/p1;->h:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v4, Lvy0/b0;

    .line 132
    .line 133
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 134
    .line 135
    iget v6, v0, Lc00/p1;->g:I

    .line 136
    .line 137
    const/4 v7, 0x2

    .line 138
    const/4 v8, 0x1

    .line 139
    const/4 v9, 0x0

    .line 140
    if-eqz v6, :cond_8

    .line 141
    .line 142
    if-eq v6, v8, :cond_7

    .line 143
    .line 144
    if-ne v6, v7, :cond_6

    .line 145
    .line 146
    iget-object v0, v0, Lc00/p1;->i:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v0, Lc00/t1;

    .line 149
    .line 150
    check-cast v0, Lao0/c;

    .line 151
    .line 152
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    goto/16 :goto_6

    .line 156
    .line 157
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 158
    .line 159
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 160
    .line 161
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    throw v0

    .line 165
    :cond_7
    iget v1, v0, Lc00/p1;->f:I

    .line 166
    .line 167
    iget-object v2, v0, Lc00/p1;->i:Ljava/lang/Object;

    .line 168
    .line 169
    move-object v3, v2

    .line 170
    check-cast v3, Lc00/t1;

    .line 171
    .line 172
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    move v2, v1

    .line 176
    move-object/from16 v1, p1

    .line 177
    .line 178
    goto/16 :goto_4

    .line 179
    .line 180
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 184
    .line 185
    .line 186
    iget-object v6, v3, Lc00/t1;->i:Lij0/a;

    .line 187
    .line 188
    const-wide/16 v10, 0x1

    .line 189
    .line 190
    invoke-static {v1, v2, v10, v11}, Lao0/d;->a(JJ)Z

    .line 191
    .line 192
    .line 193
    move-result v10

    .line 194
    if-eqz v10, :cond_9

    .line 195
    .line 196
    const v10, 0x7f12008d

    .line 197
    .line 198
    .line 199
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 200
    .line 201
    .line 202
    move-result-object v10

    .line 203
    goto :goto_2

    .line 204
    :cond_9
    const-wide/16 v10, 0x2

    .line 205
    .line 206
    invoke-static {v1, v2, v10, v11}, Lao0/d;->a(JJ)Z

    .line 207
    .line 208
    .line 209
    move-result v10

    .line 210
    if-eqz v10, :cond_a

    .line 211
    .line 212
    const v10, 0x7f12008e

    .line 213
    .line 214
    .line 215
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 216
    .line 217
    .line 218
    move-result-object v10

    .line 219
    goto :goto_2

    .line 220
    :cond_a
    const-wide/16 v10, 0x3

    .line 221
    .line 222
    invoke-static {v1, v2, v10, v11}, Lao0/d;->a(JJ)Z

    .line 223
    .line 224
    .line 225
    move-result v10

    .line 226
    if-eqz v10, :cond_b

    .line 227
    .line 228
    const v10, 0x7f12008f

    .line 229
    .line 230
    .line 231
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 232
    .line 233
    .line 234
    move-result-object v10

    .line 235
    goto :goto_2

    .line 236
    :cond_b
    move-object v10, v9

    .line 237
    :goto_2
    if-eqz v10, :cond_c

    .line 238
    .line 239
    invoke-virtual {v10}, Ljava/lang/Number;->intValue()I

    .line 240
    .line 241
    .line 242
    move-result v10

    .line 243
    move-object v11, v6

    .line 244
    check-cast v11, Ljj0/f;

    .line 245
    .line 246
    invoke-virtual {v11, v10}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 247
    .line 248
    .line 249
    move-result-object v10

    .line 250
    new-instance v11, Lac0/a;

    .line 251
    .line 252
    const/16 v12, 0xd

    .line 253
    .line 254
    invoke-direct {v11, v10, v12}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 255
    .line 256
    .line 257
    invoke-static {v3, v11}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 258
    .line 259
    .line 260
    :cond_c
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 261
    .line 262
    .line 263
    move-result-object v10

    .line 264
    check-cast v10, Lc00/n1;

    .line 265
    .line 266
    iget-object v10, v10, Lc00/n1;->d:Ljava/util/List;

    .line 267
    .line 268
    check-cast v10, Ljava/lang/Iterable;

    .line 269
    .line 270
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 271
    .line 272
    .line 273
    move-result-object v10

    .line 274
    :cond_d
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 275
    .line 276
    .line 277
    move-result v11

    .line 278
    if-eqz v11, :cond_e

    .line 279
    .line 280
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v11

    .line 284
    move-object v12, v11

    .line 285
    check-cast v12, Lao0/c;

    .line 286
    .line 287
    iget-wide v12, v12, Lao0/c;->a:J

    .line 288
    .line 289
    cmp-long v12, v12, v1

    .line 290
    .line 291
    if-nez v12, :cond_d

    .line 292
    .line 293
    goto :goto_3

    .line 294
    :cond_e
    move-object v11, v9

    .line 295
    :goto_3
    move-object v13, v11

    .line 296
    check-cast v13, Lao0/c;

    .line 297
    .line 298
    if-eqz v13, :cond_12

    .line 299
    .line 300
    iget-object v1, v3, Lc00/t1;->h:Lyn0/r;

    .line 301
    .line 302
    new-instance v12, Lao0/e;

    .line 303
    .line 304
    iget-wide v10, v13, Lao0/c;->a:J

    .line 305
    .line 306
    invoke-static {v10, v11, v6}, Ljp/fc;->g(JLij0/a;)Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object v14

    .line 310
    const/16 v16, 0x1

    .line 311
    .line 312
    const/16 v17, 0x24

    .line 313
    .line 314
    const/4 v15, 0x1

    .line 315
    invoke-direct/range {v12 .. v17}, Lao0/e;-><init>(Lao0/c;Ljava/lang/String;ZZI)V

    .line 316
    .line 317
    .line 318
    iput-object v4, v0, Lc00/p1;->h:Ljava/lang/Object;

    .line 319
    .line 320
    iput-object v3, v0, Lc00/p1;->i:Ljava/lang/Object;

    .line 321
    .line 322
    const/4 v2, 0x0

    .line 323
    iput v2, v0, Lc00/p1;->f:I

    .line 324
    .line 325
    iput v8, v0, Lc00/p1;->g:I

    .line 326
    .line 327
    invoke-virtual {v1, v12, v0}, Lyn0/r;->b(Lao0/e;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v1

    .line 331
    if-ne v1, v5, :cond_f

    .line 332
    .line 333
    goto :goto_7

    .line 334
    :cond_f
    :goto_4
    move-object v10, v1

    .line 335
    check-cast v10, Lao0/c;

    .line 336
    .line 337
    if-eqz v10, :cond_12

    .line 338
    .line 339
    iget-object v1, v3, Lc00/t1;->p:Llb0/u;

    .line 340
    .line 341
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 342
    .line 343
    .line 344
    move-result-object v6

    .line 345
    check-cast v6, Lc00/n1;

    .line 346
    .line 347
    iget-object v6, v6, Lc00/n1;->d:Ljava/util/List;

    .line 348
    .line 349
    check-cast v6, Ljava/lang/Iterable;

    .line 350
    .line 351
    new-instance v8, Ljava/util/ArrayList;

    .line 352
    .line 353
    const/16 v11, 0xa

    .line 354
    .line 355
    invoke-static {v6, v11}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 356
    .line 357
    .line 358
    move-result v11

    .line 359
    invoke-direct {v8, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 360
    .line 361
    .line 362
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 363
    .line 364
    .line 365
    move-result-object v6

    .line 366
    :goto_5
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 367
    .line 368
    .line 369
    move-result v11

    .line 370
    if-eqz v11, :cond_11

    .line 371
    .line 372
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object v11

    .line 376
    check-cast v11, Lao0/c;

    .line 377
    .line 378
    iget-wide v12, v11, Lao0/c;->a:J

    .line 379
    .line 380
    iget-wide v14, v10, Lao0/c;->a:J

    .line 381
    .line 382
    invoke-static {v12, v13, v14, v15}, Lao0/d;->a(JJ)Z

    .line 383
    .line 384
    .line 385
    move-result v12

    .line 386
    if-eqz v12, :cond_10

    .line 387
    .line 388
    const/4 v15, 0x0

    .line 389
    const/16 v16, 0x3d

    .line 390
    .line 391
    const/4 v11, 0x1

    .line 392
    const/4 v12, 0x0

    .line 393
    const/4 v13, 0x0

    .line 394
    const/4 v14, 0x0

    .line 395
    invoke-static/range {v10 .. v16}, Lao0/c;->a(Lao0/c;ZLjava/time/LocalTime;Lao0/f;Ljava/util/Set;ZI)Lao0/c;

    .line 396
    .line 397
    .line 398
    move-result-object v11

    .line 399
    :cond_10
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 400
    .line 401
    .line 402
    goto :goto_5

    .line 403
    :cond_11
    invoke-virtual {v1, v8}, Llb0/u;->a(Ljava/util/List;)Lyy0/m1;

    .line 404
    .line 405
    .line 406
    move-result-object v1

    .line 407
    new-instance v6, Lai/k;

    .line 408
    .line 409
    const/16 v8, 0x8

    .line 410
    .line 411
    invoke-direct {v6, v8, v4, v3}, Lai/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 412
    .line 413
    .line 414
    iput-object v9, v0, Lc00/p1;->h:Ljava/lang/Object;

    .line 415
    .line 416
    iput-object v9, v0, Lc00/p1;->i:Ljava/lang/Object;

    .line 417
    .line 418
    iput v2, v0, Lc00/p1;->f:I

    .line 419
    .line 420
    iput v7, v0, Lc00/p1;->g:I

    .line 421
    .line 422
    invoke-virtual {v1, v6, v0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v0

    .line 426
    if-ne v0, v5, :cond_12

    .line 427
    .line 428
    goto :goto_7

    .line 429
    :cond_12
    :goto_6
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 430
    .line 431
    :goto_7
    return-object v5

    .line 432
    nop

    .line 433
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
