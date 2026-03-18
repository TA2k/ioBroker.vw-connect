.class public final Lpw0/i;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Lio/ktor/utils/io/o0;

.field public e:Loz0/a;

.field public f:Ljava/lang/Object;

.field public g:Lvy0/q;

.field public h:Lpw0/d;

.field public i:J

.field public j:J

.field public k:J

.field public l:I

.field public synthetic m:Ljava/lang/Object;

.field public final synthetic n:Lio/ktor/utils/io/t;

.field public final synthetic o:Loz0/a;

.field public final synthetic p:Ljava/lang/Long;


# direct methods
.method public constructor <init>(Lio/ktor/utils/io/t;Loz0/a;Ljava/lang/Long;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lpw0/i;->n:Lio/ktor/utils/io/t;

    .line 2
    .line 3
    iput-object p2, p0, Lpw0/i;->o:Loz0/a;

    .line 4
    .line 5
    iput-object p3, p0, Lpw0/i;->p:Ljava/lang/Long;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, Lpw0/i;

    .line 2
    .line 3
    iget-object v1, p0, Lpw0/i;->o:Loz0/a;

    .line 4
    .line 5
    iget-object v2, p0, Lpw0/i;->p:Ljava/lang/Long;

    .line 6
    .line 7
    iget-object p0, p0, Lpw0/i;->n:Lio/ktor/utils/io/t;

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2, p2}, Lpw0/i;-><init>(Lio/ktor/utils/io/t;Loz0/a;Ljava/lang/Long;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Lpw0/i;->m:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lxy0/x;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lpw0/i;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lpw0/i;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lpw0/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v6, p0

    .line 2
    .line 3
    iget-object v0, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 4
    .line 5
    move-object v7, v0

    .line 6
    check-cast v7, Lxy0/x;

    .line 7
    .line 8
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v0, v6, Lpw0/i;->l:I

    .line 11
    .line 12
    const/4 v9, 0x3

    .line 13
    move v1, v0

    .line 14
    iget-object v0, v6, Lpw0/i;->o:Loz0/a;

    .line 15
    .line 16
    const-wide/16 v10, 0x0

    .line 17
    .line 18
    const/4 v12, 0x0

    .line 19
    packed-switch v1, :pswitch_data_0

    .line 20
    .line 21
    .line 22
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw v0

    .line 30
    :pswitch_0
    iget-object v0, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v0, Lnz0/i;

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :pswitch_1
    iget-wide v0, v6, Lpw0/i;->i:J

    .line 36
    .line 37
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    move-object/from16 v2, p1

    .line 41
    .line 42
    goto/16 :goto_13

    .line 43
    .line 44
    :goto_0
    :pswitch_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto/16 :goto_15

    .line 48
    .line 49
    :pswitch_3
    iget-wide v0, v6, Lpw0/i;->k:J

    .line 50
    .line 51
    iget-wide v2, v6, Lpw0/i;->j:J

    .line 52
    .line 53
    iget-wide v4, v6, Lpw0/i;->i:J

    .line 54
    .line 55
    iget-object v7, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v7, Lxy0/x;

    .line 58
    .line 59
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    move-wide v9, v4

    .line 63
    move-wide v4, v2

    .line 64
    move-object/from16 v2, p1

    .line 65
    .line 66
    goto/16 :goto_12

    .line 67
    .line 68
    :pswitch_4
    iget-wide v0, v6, Lpw0/i;->i:J

    .line 69
    .line 70
    iget-object v2, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 71
    .line 72
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto/16 :goto_11

    .line 76
    .line 77
    :pswitch_5
    iget-wide v0, v6, Lpw0/i;->i:J

    .line 78
    .line 79
    iget-object v2, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 80
    .line 81
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    goto/16 :goto_10

    .line 85
    .line 86
    :pswitch_6
    iget-wide v1, v6, Lpw0/i;->i:J

    .line 87
    .line 88
    iget-object v3, v6, Lpw0/i;->h:Lpw0/d;

    .line 89
    .line 90
    iget-object v4, v6, Lpw0/i;->g:Lvy0/q;

    .line 91
    .line 92
    iget-object v5, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v5, Lio/ktor/utils/io/m;

    .line 95
    .line 96
    iget-object v13, v6, Lpw0/i;->e:Loz0/a;

    .line 97
    .line 98
    iget-object v14, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 99
    .line 100
    :try_start_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 101
    .line 102
    .line 103
    move-object/from16 v18, v4

    .line 104
    .line 105
    move-object v4, v3

    .line 106
    move-object v3, v13

    .line 107
    move-object/from16 v13, v18

    .line 108
    .line 109
    goto/16 :goto_a

    .line 110
    .line 111
    :catchall_0
    move-exception v0

    .line 112
    move-object v12, v3

    .line 113
    goto/16 :goto_f

    .line 114
    .line 115
    :pswitch_7
    iget-wide v1, v6, Lpw0/i;->i:J

    .line 116
    .line 117
    iget-object v4, v6, Lpw0/i;->g:Lvy0/q;

    .line 118
    .line 119
    iget-object v3, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 120
    .line 121
    move-object v5, v3

    .line 122
    check-cast v5, Lio/ktor/utils/io/m;

    .line 123
    .line 124
    iget-object v3, v6, Lpw0/i;->e:Loz0/a;

    .line 125
    .line 126
    iget-object v13, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 127
    .line 128
    :try_start_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 129
    .line 130
    .line 131
    move-object/from16 v14, p1

    .line 132
    .line 133
    move-object v15, v3

    .line 134
    :goto_1
    move-object v3, v13

    .line 135
    move-object v13, v4

    .line 136
    goto/16 :goto_9

    .line 137
    .line 138
    :catchall_1
    move-exception v0

    .line 139
    goto/16 :goto_f

    .line 140
    .line 141
    :pswitch_8
    iget-wide v1, v6, Lpw0/i;->i:J

    .line 142
    .line 143
    iget-object v3, v6, Lpw0/i;->g:Lvy0/q;

    .line 144
    .line 145
    iget-object v4, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v4, Lio/ktor/utils/io/m;

    .line 148
    .line 149
    iget-object v5, v6, Lpw0/i;->e:Loz0/a;

    .line 150
    .line 151
    iget-object v13, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 152
    .line 153
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    move-object/from16 v18, v4

    .line 157
    .line 158
    move-object v4, v3

    .line 159
    move-object/from16 v3, v18

    .line 160
    .line 161
    goto/16 :goto_8

    .line 162
    .line 163
    :pswitch_9
    iget-wide v1, v6, Lpw0/i;->i:J

    .line 164
    .line 165
    iget-object v3, v6, Lpw0/i;->e:Loz0/a;

    .line 166
    .line 167
    iget-object v4, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 168
    .line 169
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    move-object/from16 v5, p1

    .line 173
    .line 174
    goto/16 :goto_7

    .line 175
    .line 176
    :pswitch_a
    iget-wide v1, v6, Lpw0/i;->i:J

    .line 177
    .line 178
    iget-object v3, v6, Lpw0/i;->e:Loz0/a;

    .line 179
    .line 180
    iget-object v4, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 181
    .line 182
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    goto/16 :goto_6

    .line 186
    .line 187
    :pswitch_b
    iget-wide v1, v6, Lpw0/i;->i:J

    .line 188
    .line 189
    iget-object v3, v6, Lpw0/i;->e:Loz0/a;

    .line 190
    .line 191
    iget-object v4, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 192
    .line 193
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 194
    .line 195
    .line 196
    move-object/from16 v5, p1

    .line 197
    .line 198
    goto/16 :goto_5

    .line 199
    .line 200
    :pswitch_c
    iget-wide v1, v6, Lpw0/i;->i:J

    .line 201
    .line 202
    iget-object v3, v6, Lpw0/i;->e:Loz0/a;

    .line 203
    .line 204
    iget-object v4, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 205
    .line 206
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 207
    .line 208
    .line 209
    goto/16 :goto_4

    .line 210
    .line 211
    :pswitch_d
    iget-wide v1, v6, Lpw0/i;->i:J

    .line 212
    .line 213
    iget-object v3, v6, Lpw0/i;->e:Loz0/a;

    .line 214
    .line 215
    iget-object v4, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 216
    .line 217
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 218
    .line 219
    .line 220
    move-object/from16 v5, p1

    .line 221
    .line 222
    goto :goto_3

    .line 223
    :pswitch_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    const-string v1, "<this>"

    .line 227
    .line 228
    iget-object v2, v6, Lpw0/i;->n:Lio/ktor/utils/io/t;

    .line 229
    .line 230
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    new-instance v1, Lio/ktor/utils/io/o0;

    .line 234
    .line 235
    invoke-direct {v1, v2}, Lio/ktor/utils/io/o0;-><init>(Lio/ktor/utils/io/t;)V

    .line 236
    .line 237
    .line 238
    invoke-virtual {v1}, Lio/ktor/utils/io/o0;->b()V

    .line 239
    .line 240
    .line 241
    iget-wide v2, v1, Lio/ktor/utils/io/o0;->e:J

    .line 242
    .line 243
    iget-object v4, v0, Loz0/a;->d:[B

    .line 244
    .line 245
    sget-object v5, Lpw0/m;->b:Loz0/a;

    .line 246
    .line 247
    iget-object v5, v5, Loz0/a;->d:[B

    .line 248
    .line 249
    array-length v5, v5

    .line 250
    array-length v13, v4

    .line 251
    if-ne v5, v13, :cond_0

    .line 252
    .line 253
    sget-object v4, Loz0/a;->f:Loz0/a;

    .line 254
    .line 255
    goto :goto_2

    .line 256
    :cond_0
    new-instance v14, Loz0/a;

    .line 257
    .line 258
    invoke-direct {v14, v4, v5, v13}, Loz0/a;-><init>([BII)V

    .line 259
    .line 260
    .line 261
    move-object v4, v14

    .line 262
    :goto_2
    new-instance v5, Lny/f0;

    .line 263
    .line 264
    const/16 v13, 0x8

    .line 265
    .line 266
    invoke-direct {v5, v13, v4, v1, v12}, Lny/f0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 267
    .line 268
    .line 269
    invoke-static {v7, v12, v5, v9}, Lio/ktor/utils/io/h0;->p(Lvy0/b0;Lpx0/g;Lay0/n;I)Lb81/d;

    .line 270
    .line 271
    .line 272
    move-result-object v5

    .line 273
    iget-object v5, v5, Lb81/d;->e:Ljava/lang/Object;

    .line 274
    .line 275
    check-cast v5, Lio/ktor/utils/io/m;

    .line 276
    .line 277
    iput-object v7, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 278
    .line 279
    iput-object v1, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 280
    .line 281
    iput-object v4, v6, Lpw0/i;->e:Loz0/a;

    .line 282
    .line 283
    iput-wide v2, v6, Lpw0/i;->i:J

    .line 284
    .line 285
    const/4 v13, 0x1

    .line 286
    iput v13, v6, Lpw0/i;->l:I

    .line 287
    .line 288
    invoke-static {v5, v6}, Lio/ktor/utils/io/h0;->i(Lio/ktor/utils/io/t;Lrx0/c;)Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object v5

    .line 292
    if-ne v5, v8, :cond_1

    .line 293
    .line 294
    goto/16 :goto_14

    .line 295
    .line 296
    :cond_1
    move-object/from16 v18, v4

    .line 297
    .line 298
    move-object v4, v1

    .line 299
    move-wide v1, v2

    .line 300
    move-object/from16 v3, v18

    .line 301
    .line 302
    :goto_3
    check-cast v5, Lnz0/i;

    .line 303
    .line 304
    invoke-static {v5}, Ljp/hb;->c(Lnz0/i;)J

    .line 305
    .line 306
    .line 307
    move-result-wide v13

    .line 308
    cmp-long v5, v13, v10

    .line 309
    .line 310
    if-lez v5, :cond_2

    .line 311
    .line 312
    new-instance v5, Lpw0/h;

    .line 313
    .line 314
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 315
    .line 316
    .line 317
    iput-object v7, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 318
    .line 319
    iput-object v4, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 320
    .line 321
    iput-object v3, v6, Lpw0/i;->e:Loz0/a;

    .line 322
    .line 323
    iput-wide v1, v6, Lpw0/i;->i:J

    .line 324
    .line 325
    const/4 v13, 0x2

    .line 326
    iput v13, v6, Lpw0/i;->l:I

    .line 327
    .line 328
    move-object v13, v7

    .line 329
    check-cast v13, Lxy0/w;

    .line 330
    .line 331
    iget-object v13, v13, Lxy0/w;->g:Lxy0/j;

    .line 332
    .line 333
    invoke-interface {v13, v5, v6}, Lxy0/a0;->u(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object v5

    .line 337
    if-ne v5, v8, :cond_2

    .line 338
    .line 339
    goto/16 :goto_14

    .line 340
    .line 341
    :cond_2
    :goto_4
    invoke-virtual {v4}, Lio/ktor/utils/io/o0;->g()Z

    .line 342
    .line 343
    .line 344
    move-result v5

    .line 345
    if-nez v5, :cond_e

    .line 346
    .line 347
    sget-object v5, Lpw0/m;->b:Loz0/a;

    .line 348
    .line 349
    iput-object v7, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 350
    .line 351
    iput-object v4, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 352
    .line 353
    iput-object v3, v6, Lpw0/i;->e:Loz0/a;

    .line 354
    .line 355
    iput-object v12, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 356
    .line 357
    iput-object v12, v6, Lpw0/i;->g:Lvy0/q;

    .line 358
    .line 359
    iput-object v12, v6, Lpw0/i;->h:Lpw0/d;

    .line 360
    .line 361
    iput-wide v1, v6, Lpw0/i;->i:J

    .line 362
    .line 363
    iput v9, v6, Lpw0/i;->l:I

    .line 364
    .line 365
    invoke-static {v4, v5, v6}, Lio/ktor/utils/io/h0;->l(Lio/ktor/utils/io/t;Loz0/a;Lrx0/c;)Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v5

    .line 369
    if-ne v5, v8, :cond_3

    .line 370
    .line 371
    goto/16 :goto_14

    .line 372
    .line 373
    :cond_3
    :goto_5
    check-cast v5, Ljava/lang/Boolean;

    .line 374
    .line 375
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 376
    .line 377
    .line 378
    move-result v5

    .line 379
    if-nez v5, :cond_e

    .line 380
    .line 381
    sget-object v5, Lpw0/m;->a:Loz0/a;

    .line 382
    .line 383
    iput-object v7, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 384
    .line 385
    iput-object v4, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 386
    .line 387
    iput-object v3, v6, Lpw0/i;->e:Loz0/a;

    .line 388
    .line 389
    iput-wide v1, v6, Lpw0/i;->i:J

    .line 390
    .line 391
    const/4 v13, 0x4

    .line 392
    iput v13, v6, Lpw0/i;->l:I

    .line 393
    .line 394
    invoke-static {v4, v5, v6}, Lio/ktor/utils/io/h0;->l(Lio/ktor/utils/io/t;Loz0/a;Lrx0/c;)Ljava/lang/Object;

    .line 395
    .line 396
    .line 397
    move-result-object v5

    .line 398
    if-ne v5, v8, :cond_4

    .line 399
    .line 400
    goto/16 :goto_14

    .line 401
    .line 402
    :cond_4
    :goto_6
    iput-object v7, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 403
    .line 404
    iput-object v4, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 405
    .line 406
    iput-object v3, v6, Lpw0/i;->e:Loz0/a;

    .line 407
    .line 408
    iput-wide v1, v6, Lpw0/i;->i:J

    .line 409
    .line 410
    const/4 v5, 0x5

    .line 411
    iput v5, v6, Lpw0/i;->l:I

    .line 412
    .line 413
    invoke-static {v4, v3, v6}, Lio/ktor/utils/io/h0;->l(Lio/ktor/utils/io/t;Loz0/a;Lrx0/c;)Ljava/lang/Object;

    .line 414
    .line 415
    .line 416
    move-result-object v5

    .line 417
    if-ne v5, v8, :cond_5

    .line 418
    .line 419
    goto/16 :goto_14

    .line 420
    .line 421
    :cond_5
    :goto_7
    check-cast v5, Ljava/lang/Boolean;

    .line 422
    .line 423
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 424
    .line 425
    .line 426
    move-result v5

    .line 427
    if-eqz v5, :cond_6

    .line 428
    .line 429
    goto :goto_4

    .line 430
    :cond_6
    new-instance v5, Lio/ktor/utils/io/m;

    .line 431
    .line 432
    invoke-direct {v5}, Lio/ktor/utils/io/m;-><init>()V

    .line 433
    .line 434
    .line 435
    invoke-static {}, Lvy0/e0;->b()Lvy0/r;

    .line 436
    .line 437
    .line 438
    move-result-object v13

    .line 439
    new-instance v14, Lpw0/h;

    .line 440
    .line 441
    invoke-direct {v14}, Ljava/lang/Object;-><init>()V

    .line 442
    .line 443
    .line 444
    iput-object v7, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 445
    .line 446
    iput-object v4, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 447
    .line 448
    iput-object v3, v6, Lpw0/i;->e:Loz0/a;

    .line 449
    .line 450
    iput-object v5, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 451
    .line 452
    iput-object v13, v6, Lpw0/i;->g:Lvy0/q;

    .line 453
    .line 454
    iput-wide v1, v6, Lpw0/i;->i:J

    .line 455
    .line 456
    const/4 v15, 0x6

    .line 457
    iput v15, v6, Lpw0/i;->l:I

    .line 458
    .line 459
    move-object v15, v7

    .line 460
    check-cast v15, Lxy0/w;

    .line 461
    .line 462
    iget-object v15, v15, Lxy0/w;->g:Lxy0/j;

    .line 463
    .line 464
    invoke-interface {v15, v14, v6}, Lxy0/a0;->u(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 465
    .line 466
    .line 467
    move-result-object v14

    .line 468
    if-ne v14, v8, :cond_7

    .line 469
    .line 470
    goto/16 :goto_14

    .line 471
    .line 472
    :cond_7
    move-object/from16 v18, v5

    .line 473
    .line 474
    move-object v5, v3

    .line 475
    move-object/from16 v3, v18

    .line 476
    .line 477
    move-object/from16 v18, v13

    .line 478
    .line 479
    move-object v13, v4

    .line 480
    move-object/from16 v4, v18

    .line 481
    .line 482
    :goto_8
    :try_start_2
    iput-object v7, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 483
    .line 484
    iput-object v13, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 485
    .line 486
    iput-object v5, v6, Lpw0/i;->e:Loz0/a;

    .line 487
    .line 488
    iput-object v3, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 489
    .line 490
    iput-object v4, v6, Lpw0/i;->g:Lvy0/q;

    .line 491
    .line 492
    iput-wide v1, v6, Lpw0/i;->i:J

    .line 493
    .line 494
    const/4 v14, 0x7

    .line 495
    iput v14, v6, Lpw0/i;->l:I

    .line 496
    .line 497
    invoke-static {v13, v6}, Lpw0/m;->b(Lio/ktor/utils/io/o0;Lrx0/c;)Ljava/lang/Object;

    .line 498
    .line 499
    .line 500
    move-result-object v14
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_7

    .line 501
    if-ne v14, v8, :cond_8

    .line 502
    .line 503
    goto/16 :goto_14

    .line 504
    .line 505
    :cond_8
    move-object v15, v5

    .line 506
    move-object v5, v3

    .line 507
    goto/16 :goto_1

    .line 508
    .line 509
    :goto_9
    :try_start_3
    check-cast v14, Lpw0/d;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_6

    .line 510
    .line 511
    :try_start_4
    move-object v4, v13

    .line 512
    check-cast v4, Lvy0/r;

    .line 513
    .line 514
    invoke-virtual {v4, v14}, Lvy0/p1;->W(Ljava/lang/Object;)Z

    .line 515
    .line 516
    .line 517
    move-result v4
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_5

    .line 518
    if-eqz v4, :cond_c

    .line 519
    .line 520
    :try_start_5
    iput-object v7, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 521
    .line 522
    iput-object v3, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 523
    .line 524
    iput-object v15, v6, Lpw0/i;->e:Loz0/a;

    .line 525
    .line 526
    iput-object v5, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 527
    .line 528
    iput-object v13, v6, Lpw0/i;->g:Lvy0/q;

    .line 529
    .line 530
    iput-object v14, v6, Lpw0/i;->h:Lpw0/d;

    .line 531
    .line 532
    iput-wide v1, v6, Lpw0/i;->i:J

    .line 533
    .line 534
    const/16 v4, 0x8

    .line 535
    .line 536
    iput v4, v6, Lpw0/i;->l:I
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    .line 537
    .line 538
    move-wide/from16 v16, v1

    .line 539
    .line 540
    move-object v2, v5

    .line 541
    const-wide/32 v4, 0x10000

    .line 542
    .line 543
    .line 544
    move-object v1, v3

    .line 545
    move-object v3, v14

    .line 546
    :try_start_6
    invoke-static/range {v0 .. v6}, Lpw0/m;->a(Loz0/a;Lio/ktor/utils/io/o0;Lio/ktor/utils/io/m;Lpw0/d;JLrx0/c;)Ljava/lang/Object;

    .line 547
    .line 548
    .line 549
    move-result-object v4
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 550
    if-ne v4, v8, :cond_9

    .line 551
    .line 552
    goto/16 :goto_14

    .line 553
    .line 554
    :cond_9
    move-object v14, v1

    .line 555
    move-object v5, v2

    .line 556
    move-object v4, v3

    .line 557
    move-object v3, v15

    .line 558
    move-wide/from16 v1, v16

    .line 559
    .line 560
    :goto_a
    :try_start_7
    invoke-virtual {v5}, Lio/ktor/utils/io/m;->i()V

    .line 561
    .line 562
    .line 563
    sget-object v15, Lio/ktor/utils/io/m;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 564
    .line 565
    sget-object v9, Lio/ktor/utils/io/h0;->b:Lio/ktor/utils/io/j0;

    .line 566
    .line 567
    :cond_a
    invoke-virtual {v15, v5, v12, v9}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 568
    .line 569
    .line 570
    move-result v17

    .line 571
    if-eqz v17, :cond_b

    .line 572
    .line 573
    invoke-virtual {v5, v12}, Lio/ktor/utils/io/m;->a(Ljava/lang/Throwable;)V

    .line 574
    .line 575
    .line 576
    goto :goto_b

    .line 577
    :cond_b
    invoke-virtual {v15, v5}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 578
    .line 579
    .line 580
    move-result-object v17
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 581
    if-eqz v17, :cond_a

    .line 582
    .line 583
    :goto_b
    move-object v4, v14

    .line 584
    const/4 v9, 0x3

    .line 585
    goto/16 :goto_4

    .line 586
    .line 587
    :catchall_2
    move-exception v0

    .line 588
    move-object v12, v4

    .line 589
    :goto_c
    move-object v4, v13

    .line 590
    goto :goto_f

    .line 591
    :catchall_3
    move-exception v0

    .line 592
    :goto_d
    move-object v5, v2

    .line 593
    :goto_e
    move-object v12, v3

    .line 594
    goto :goto_c

    .line 595
    :catchall_4
    move-exception v0

    .line 596
    move-object v2, v5

    .line 597
    move-object v3, v14

    .line 598
    goto :goto_e

    .line 599
    :cond_c
    move-object v2, v5

    .line 600
    move-object v3, v14

    .line 601
    :try_start_8
    invoke-virtual {v3}, Lpw0/d;->d()V

    .line 602
    .line 603
    .line 604
    new-instance v0, Ljava/util/concurrent/CancellationException;

    .line 605
    .line 606
    const-string v1, "Multipart processing has been cancelled"

    .line 607
    .line 608
    invoke-direct {v0, v1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 609
    .line 610
    .line 611
    throw v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 612
    :catchall_5
    move-exception v0

    .line 613
    move-object v2, v5

    .line 614
    move-object v3, v14

    .line 615
    goto :goto_d

    .line 616
    :catchall_6
    move-exception v0

    .line 617
    move-object v2, v5

    .line 618
    goto :goto_c

    .line 619
    :catchall_7
    move-exception v0

    .line 620
    move-object v5, v3

    .line 621
    :goto_f
    check-cast v4, Lvy0/r;

    .line 622
    .line 623
    invoke-virtual {v4, v0}, Lvy0/r;->l0(Ljava/lang/Throwable;)Z

    .line 624
    .line 625
    .line 626
    move-result v1

    .line 627
    if-eqz v1, :cond_d

    .line 628
    .line 629
    if-eqz v12, :cond_d

    .line 630
    .line 631
    invoke-virtual {v12}, Lpw0/d;->d()V

    .line 632
    .line 633
    .line 634
    :cond_d
    invoke-static {v5, v0}, Lio/ktor/utils/io/h0;->b(Lio/ktor/utils/io/d0;Ljava/lang/Throwable;)V

    .line 635
    .line 636
    .line 637
    throw v0

    .line 638
    :cond_e
    move-wide v0, v1

    .line 639
    sget-object v2, Lpw0/m;->a:Loz0/a;

    .line 640
    .line 641
    iput-object v7, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 642
    .line 643
    iput-object v4, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 644
    .line 645
    iput-object v12, v6, Lpw0/i;->e:Loz0/a;

    .line 646
    .line 647
    iput-object v12, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 648
    .line 649
    iput-object v12, v6, Lpw0/i;->g:Lvy0/q;

    .line 650
    .line 651
    iput-object v12, v6, Lpw0/i;->h:Lpw0/d;

    .line 652
    .line 653
    iput-wide v0, v6, Lpw0/i;->i:J

    .line 654
    .line 655
    const/16 v3, 0x9

    .line 656
    .line 657
    iput v3, v6, Lpw0/i;->l:I

    .line 658
    .line 659
    invoke-static {v4, v2, v6}, Lio/ktor/utils/io/h0;->l(Lio/ktor/utils/io/t;Loz0/a;Lrx0/c;)Ljava/lang/Object;

    .line 660
    .line 661
    .line 662
    move-result-object v2

    .line 663
    if-ne v2, v8, :cond_f

    .line 664
    .line 665
    goto/16 :goto_14

    .line 666
    .line 667
    :cond_f
    move-object v2, v4

    .line 668
    :goto_10
    sget-object v3, Lpw0/m;->a:Loz0/a;

    .line 669
    .line 670
    iput-object v7, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 671
    .line 672
    iput-object v2, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 673
    .line 674
    iput-object v12, v6, Lpw0/i;->e:Loz0/a;

    .line 675
    .line 676
    iput-wide v0, v6, Lpw0/i;->i:J

    .line 677
    .line 678
    const/16 v4, 0xa

    .line 679
    .line 680
    iput v4, v6, Lpw0/i;->l:I

    .line 681
    .line 682
    invoke-static {v2, v3, v6}, Lio/ktor/utils/io/h0;->l(Lio/ktor/utils/io/t;Loz0/a;Lrx0/c;)Ljava/lang/Object;

    .line 683
    .line 684
    .line 685
    move-result-object v3

    .line 686
    if-ne v3, v8, :cond_10

    .line 687
    .line 688
    goto/16 :goto_14

    .line 689
    .line 690
    :cond_10
    :goto_11
    iget-object v3, v6, Lpw0/i;->p:Ljava/lang/Long;

    .line 691
    .line 692
    if-eqz v3, :cond_13

    .line 693
    .line 694
    invoke-virtual {v2}, Lio/ktor/utils/io/o0;->b()V

    .line 695
    .line 696
    .line 697
    iget-wide v4, v2, Lio/ktor/utils/io/o0;->e:J

    .line 698
    .line 699
    sub-long/2addr v4, v0

    .line 700
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 701
    .line 702
    .line 703
    move-result-wide v13

    .line 704
    sub-long/2addr v13, v4

    .line 705
    const-wide/32 v15, 0x7fffffff

    .line 706
    .line 707
    .line 708
    cmp-long v3, v13, v15

    .line 709
    .line 710
    if-gtz v3, :cond_12

    .line 711
    .line 712
    cmp-long v3, v13, v10

    .line 713
    .line 714
    if-lez v3, :cond_15

    .line 715
    .line 716
    long-to-int v3, v13

    .line 717
    iput-object v12, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 718
    .line 719
    iput-object v12, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 720
    .line 721
    iput-object v12, v6, Lpw0/i;->e:Loz0/a;

    .line 722
    .line 723
    iput-object v7, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 724
    .line 725
    iput-wide v0, v6, Lpw0/i;->i:J

    .line 726
    .line 727
    iput-wide v4, v6, Lpw0/i;->j:J

    .line 728
    .line 729
    iput-wide v13, v6, Lpw0/i;->k:J

    .line 730
    .line 731
    const/16 v9, 0xb

    .line 732
    .line 733
    iput v9, v6, Lpw0/i;->l:I

    .line 734
    .line 735
    invoke-static {v2, v3, v6}, Lio/ktor/utils/io/h0;->h(Lio/ktor/utils/io/o0;ILrx0/c;)Ljava/lang/Object;

    .line 736
    .line 737
    .line 738
    move-result-object v2

    .line 739
    if-ne v2, v8, :cond_11

    .line 740
    .line 741
    goto :goto_14

    .line 742
    :cond_11
    move-wide v9, v0

    .line 743
    move-wide v0, v13

    .line 744
    :goto_12
    check-cast v2, Lnz0/i;

    .line 745
    .line 746
    new-instance v3, Lpw0/h;

    .line 747
    .line 748
    const-string v11, "body"

    .line 749
    .line 750
    invoke-static {v2, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 751
    .line 752
    .line 753
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 754
    .line 755
    .line 756
    iput-object v12, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 757
    .line 758
    iput-object v12, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 759
    .line 760
    iput-object v12, v6, Lpw0/i;->e:Loz0/a;

    .line 761
    .line 762
    iput-object v12, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 763
    .line 764
    iput-wide v9, v6, Lpw0/i;->i:J

    .line 765
    .line 766
    iput-wide v4, v6, Lpw0/i;->j:J

    .line 767
    .line 768
    iput-wide v0, v6, Lpw0/i;->k:J

    .line 769
    .line 770
    const/16 v0, 0xc

    .line 771
    .line 772
    iput v0, v6, Lpw0/i;->l:I

    .line 773
    .line 774
    check-cast v7, Lxy0/w;

    .line 775
    .line 776
    iget-object v0, v7, Lxy0/w;->g:Lxy0/j;

    .line 777
    .line 778
    invoke-interface {v0, v3, v6}, Lxy0/a0;->u(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 779
    .line 780
    .line 781
    move-result-object v0

    .line 782
    if-ne v0, v8, :cond_15

    .line 783
    .line 784
    goto :goto_14

    .line 785
    :cond_12
    new-instance v0, Ljava/io/IOException;

    .line 786
    .line 787
    const-string v1, "Failed to parse multipart: prologue is too long"

    .line 788
    .line 789
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 790
    .line 791
    .line 792
    throw v0

    .line 793
    :cond_13
    iput-object v7, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 794
    .line 795
    iput-object v12, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 796
    .line 797
    iput-object v12, v6, Lpw0/i;->e:Loz0/a;

    .line 798
    .line 799
    iput-wide v0, v6, Lpw0/i;->i:J

    .line 800
    .line 801
    const/16 v3, 0xd

    .line 802
    .line 803
    iput v3, v6, Lpw0/i;->l:I

    .line 804
    .line 805
    invoke-static {v2, v6}, Lio/ktor/utils/io/h0;->i(Lio/ktor/utils/io/t;Lrx0/c;)Ljava/lang/Object;

    .line 806
    .line 807
    .line 808
    move-result-object v2

    .line 809
    if-ne v2, v8, :cond_14

    .line 810
    .line 811
    goto :goto_14

    .line 812
    :cond_14
    :goto_13
    check-cast v2, Lnz0/i;

    .line 813
    .line 814
    invoke-interface {v2}, Lnz0/i;->Z()Z

    .line 815
    .line 816
    .line 817
    move-result v2

    .line 818
    if-nez v2, :cond_15

    .line 819
    .line 820
    new-instance v2, Lpw0/h;

    .line 821
    .line 822
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 823
    .line 824
    .line 825
    iput-object v12, v6, Lpw0/i;->m:Ljava/lang/Object;

    .line 826
    .line 827
    iput-object v12, v6, Lpw0/i;->d:Lio/ktor/utils/io/o0;

    .line 828
    .line 829
    iput-object v12, v6, Lpw0/i;->e:Loz0/a;

    .line 830
    .line 831
    iput-object v12, v6, Lpw0/i;->f:Ljava/lang/Object;

    .line 832
    .line 833
    iput-wide v0, v6, Lpw0/i;->i:J

    .line 834
    .line 835
    const/16 v0, 0xe

    .line 836
    .line 837
    iput v0, v6, Lpw0/i;->l:I

    .line 838
    .line 839
    check-cast v7, Lxy0/w;

    .line 840
    .line 841
    iget-object v0, v7, Lxy0/w;->g:Lxy0/j;

    .line 842
    .line 843
    invoke-interface {v0, v2, v6}, Lxy0/a0;->u(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 844
    .line 845
    .line 846
    move-result-object v0

    .line 847
    if-ne v0, v8, :cond_15

    .line 848
    .line 849
    :goto_14
    return-object v8

    .line 850
    :cond_15
    :goto_15
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 851
    .line 852
    return-object v0

    .line 853
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
