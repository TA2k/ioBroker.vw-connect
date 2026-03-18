.class public final Lq80/n;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Ljava/util/ArrayList;

.field public e:I

.field public f:I

.field public g:I

.field public h:I

.field public synthetic i:Ljava/lang/Object;

.field public final synthetic j:Lq80/o;


# direct methods
.method public constructor <init>(Lq80/o;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lq80/n;->j:Lq80/o;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    new-instance v0, Lq80/n;

    .line 2
    .line 3
    iget-object p0, p0, Lq80/n;->j:Lq80/o;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Lq80/n;-><init>(Lq80/o;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iput-object p1, v0, Lq80/n;->i:Ljava/lang/Object;

    .line 9
    .line 10
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lyy0/j;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lq80/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lq80/n;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lq80/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lq80/n;->i:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lyy0/j;

    .line 6
    .line 7
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v3, v0, Lq80/n;->h:I

    .line 10
    .line 11
    const/4 v4, 0x5

    .line 12
    const/4 v5, 0x4

    .line 13
    const/4 v6, 0x3

    .line 14
    const/4 v7, 0x2

    .line 15
    const/4 v8, 0x1

    .line 16
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    iget-object v10, v0, Lq80/n;->j:Lq80/o;

    .line 19
    .line 20
    const/4 v11, 0x0

    .line 21
    const/4 v12, 0x0

    .line 22
    if-eqz v3, :cond_5

    .line 23
    .line 24
    if-eq v3, v8, :cond_4

    .line 25
    .line 26
    if-eq v3, v7, :cond_3

    .line 27
    .line 28
    if-eq v3, v6, :cond_2

    .line 29
    .line 30
    if-eq v3, v5, :cond_1

    .line 31
    .line 32
    if-ne v3, v4, :cond_0

    .line 33
    .line 34
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    return-object v9

    .line 38
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 39
    .line 40
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 41
    .line 42
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw v0

    .line 46
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    return-object v9

    .line 50
    :cond_2
    iget v11, v0, Lq80/n;->g:I

    .line 51
    .line 52
    iget v3, v0, Lq80/n;->f:I

    .line 53
    .line 54
    iget v6, v0, Lq80/n;->e:I

    .line 55
    .line 56
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    move-object/from16 v4, p1

    .line 60
    .line 61
    goto/16 :goto_6

    .line 62
    .line 63
    :cond_3
    iget v3, v0, Lq80/n;->f:I

    .line 64
    .line 65
    iget v7, v0, Lq80/n;->e:I

    .line 66
    .line 67
    iget-object v8, v0, Lq80/n;->d:Ljava/util/ArrayList;

    .line 68
    .line 69
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    move-object/from16 v3, p1

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    iget-object v3, v10, Lq80/o;->a:Lkf0/k;

    .line 83
    .line 84
    iput-object v1, v0, Lq80/n;->i:Ljava/lang/Object;

    .line 85
    .line 86
    iput v8, v0, Lq80/n;->h:I

    .line 87
    .line 88
    invoke-virtual {v3, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    if-ne v3, v2, :cond_6

    .line 93
    .line 94
    goto/16 :goto_8

    .line 95
    .line 96
    :cond_6
    :goto_0
    check-cast v3, Lss0/b;

    .line 97
    .line 98
    if-eqz v3, :cond_7

    .line 99
    .line 100
    sget-object v8, Lss0/e;->H1:Lss0/e;

    .line 101
    .line 102
    invoke-static {v3, v8}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 103
    .line 104
    .line 105
    move-result v8

    .line 106
    goto :goto_1

    .line 107
    :cond_7
    move v8, v11

    .line 108
    :goto_1
    if-eqz v3, :cond_8

    .line 109
    .line 110
    sget-object v13, Lss0/e;->r:Lss0/e;

    .line 111
    .line 112
    invoke-static {v3, v13}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 113
    .line 114
    .line 115
    move-result v3

    .line 116
    goto :goto_2

    .line 117
    :cond_8
    move v3, v11

    .line 118
    :goto_2
    new-instance v13, Ljava/util/ArrayList;

    .line 119
    .line 120
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 121
    .line 122
    .line 123
    if-eqz v8, :cond_9

    .line 124
    .line 125
    iget-object v14, v10, Lq80/o;->b:Lcr0/b;

    .line 126
    .line 127
    invoke-virtual {v13, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    :cond_9
    if-eqz v3, :cond_a

    .line 131
    .line 132
    iget-object v10, v10, Lq80/o;->c:Lf80/c;

    .line 133
    .line 134
    invoke-virtual {v13, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    :cond_a
    iput-object v1, v0, Lq80/n;->i:Ljava/lang/Object;

    .line 138
    .line 139
    iput-object v13, v0, Lq80/n;->d:Ljava/util/ArrayList;

    .line 140
    .line 141
    iput v8, v0, Lq80/n;->e:I

    .line 142
    .line 143
    iput v3, v0, Lq80/n;->f:I

    .line 144
    .line 145
    iput v7, v0, Lq80/n;->h:I

    .line 146
    .line 147
    sget-object v7, Lne0/d;->a:Lne0/d;

    .line 148
    .line 149
    invoke-interface {v1, v7, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v7

    .line 153
    if-ne v7, v2, :cond_b

    .line 154
    .line 155
    goto/16 :goto_8

    .line 156
    .line 157
    :cond_b
    move v7, v8

    .line 158
    move-object v8, v13

    .line 159
    :goto_3
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 160
    .line 161
    .line 162
    move-result-object v10

    .line 163
    invoke-static {v10}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 164
    .line 165
    .line 166
    move-result-object v10

    .line 167
    new-instance v13, Ljava/util/ArrayList;

    .line 168
    .line 169
    const/16 v14, 0xa

    .line 170
    .line 171
    invoke-static {v8, v14}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 172
    .line 173
    .line 174
    move-result v14

    .line 175
    invoke-direct {v13, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 176
    .line 177
    .line 178
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 179
    .line 180
    .line 181
    move-result-object v8

    .line 182
    :goto_4
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 183
    .line 184
    .line 185
    move-result v14

    .line 186
    if-eqz v14, :cond_c

    .line 187
    .line 188
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v14

    .line 192
    check-cast v14, Ltr0/d;

    .line 193
    .line 194
    new-instance v15, Ln00/f;

    .line 195
    .line 196
    const/16 v4, 0x11

    .line 197
    .line 198
    invoke-direct {v15, v14, v12, v4}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 199
    .line 200
    .line 201
    invoke-static {v10, v12, v15, v6}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 202
    .line 203
    .line 204
    move-result-object v4

    .line 205
    invoke-virtual {v13, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    const/4 v4, 0x5

    .line 209
    goto :goto_4

    .line 210
    :cond_c
    new-array v4, v11, [Lvy0/h0;

    .line 211
    .line 212
    invoke-virtual {v13, v4}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v4

    .line 216
    check-cast v4, [Lvy0/h0;

    .line 217
    .line 218
    array-length v8, v4

    .line 219
    invoke-static {v4, v8}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v4

    .line 223
    check-cast v4, [Lvy0/h0;

    .line 224
    .line 225
    iput-object v1, v0, Lq80/n;->i:Ljava/lang/Object;

    .line 226
    .line 227
    iput-object v12, v0, Lq80/n;->d:Ljava/util/ArrayList;

    .line 228
    .line 229
    iput v7, v0, Lq80/n;->e:I

    .line 230
    .line 231
    iput v3, v0, Lq80/n;->f:I

    .line 232
    .line 233
    iput v11, v0, Lq80/n;->g:I

    .line 234
    .line 235
    iput v6, v0, Lq80/n;->h:I

    .line 236
    .line 237
    array-length v6, v4

    .line 238
    if-nez v6, :cond_d

    .line 239
    .line 240
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 241
    .line 242
    goto :goto_5

    .line 243
    :cond_d
    new-instance v6, Lvy0/e;

    .line 244
    .line 245
    invoke-direct {v6, v4}, Lvy0/e;-><init>([Lvy0/h0;)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v6, v0}, Lvy0/e;->a(Lrx0/c;)Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v4

    .line 252
    :goto_5
    if-ne v4, v2, :cond_e

    .line 253
    .line 254
    goto :goto_8

    .line 255
    :cond_e
    move v6, v7

    .line 256
    :goto_6
    check-cast v4, Ljava/lang/Iterable;

    .line 257
    .line 258
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 259
    .line 260
    .line 261
    move-result-object v4

    .line 262
    :cond_f
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 263
    .line 264
    .line 265
    move-result v7

    .line 266
    if-eqz v7, :cond_10

    .line 267
    .line 268
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v7

    .line 272
    move-object v8, v7

    .line 273
    check-cast v8, Lne0/s;

    .line 274
    .line 275
    instance-of v8, v8, Lne0/c;

    .line 276
    .line 277
    if-eqz v8, :cond_f

    .line 278
    .line 279
    goto :goto_7

    .line 280
    :cond_10
    move-object v7, v12

    .line 281
    :goto_7
    check-cast v7, Lne0/s;

    .line 282
    .line 283
    if-eqz v7, :cond_11

    .line 284
    .line 285
    new-instance v16, Lne0/c;

    .line 286
    .line 287
    new-instance v4, Ljava/lang/IllegalStateException;

    .line 288
    .line 289
    const-string v8, "Unable to refresh Subscriptions."

    .line 290
    .line 291
    invoke-direct {v4, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    move-object/from16 v18, v7

    .line 295
    .line 296
    check-cast v18, Lne0/c;

    .line 297
    .line 298
    const/16 v20, 0x0

    .line 299
    .line 300
    const/16 v21, 0x1c

    .line 301
    .line 302
    const/16 v19, 0x0

    .line 303
    .line 304
    move-object/from16 v17, v4

    .line 305
    .line 306
    invoke-direct/range {v16 .. v21}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 307
    .line 308
    .line 309
    move-object/from16 v4, v16

    .line 310
    .line 311
    iput-object v1, v0, Lq80/n;->i:Ljava/lang/Object;

    .line 312
    .line 313
    iput-object v12, v0, Lq80/n;->d:Ljava/util/ArrayList;

    .line 314
    .line 315
    iput v6, v0, Lq80/n;->e:I

    .line 316
    .line 317
    iput v3, v0, Lq80/n;->f:I

    .line 318
    .line 319
    iput v11, v0, Lq80/n;->g:I

    .line 320
    .line 321
    iput v5, v0, Lq80/n;->h:I

    .line 322
    .line 323
    invoke-interface {v1, v4, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v0

    .line 327
    if-ne v0, v2, :cond_12

    .line 328
    .line 329
    goto :goto_8

    .line 330
    :cond_11
    new-instance v4, Lne0/e;

    .line 331
    .line 332
    invoke-direct {v4, v9}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    iput-object v12, v0, Lq80/n;->i:Ljava/lang/Object;

    .line 336
    .line 337
    iput-object v12, v0, Lq80/n;->d:Ljava/util/ArrayList;

    .line 338
    .line 339
    iput v6, v0, Lq80/n;->e:I

    .line 340
    .line 341
    iput v3, v0, Lq80/n;->f:I

    .line 342
    .line 343
    iput v11, v0, Lq80/n;->g:I

    .line 344
    .line 345
    const/4 v3, 0x5

    .line 346
    iput v3, v0, Lq80/n;->h:I

    .line 347
    .line 348
    invoke-interface {v1, v4, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v0

    .line 352
    if-ne v0, v2, :cond_12

    .line 353
    .line 354
    :goto_8
    return-object v2

    .line 355
    :cond_12
    return-object v9
.end method
