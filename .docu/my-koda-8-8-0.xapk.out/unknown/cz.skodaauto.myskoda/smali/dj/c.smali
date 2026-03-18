.class public final Ldj/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:[Ljava/lang/Integer;

.field public f:Ljava/lang/Object;

.field public g:I

.field public h:I

.field public i:I

.field public j:I

.field public synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ldj/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ldj/c;->l:Ljava/lang/Object;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Ldj/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ldj/c;

    .line 7
    .line 8
    iget-object p0, p0, Ldj/c;->l:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lqj/a;

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    invoke-direct {v0, p0, p2, v1}, Ldj/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Ldj/c;

    .line 20
    .line 21
    iget-object p0, p0, Ldj/c;->l:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lhj/a;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-direct {v0, p0, p2, v1}, Ldj/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_1
    new-instance v0, Ldj/c;

    .line 33
    .line 34
    iget-object p0, p0, Ldj/c;->l:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Ldj/g;

    .line 37
    .line 38
    const/4 v1, 0x0

    .line 39
    invoke-direct {v0, p0, p2, v1}, Ldj/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    iput-object p1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 43
    .line 44
    return-object v0

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ldj/c;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Ldj/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ldj/c;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ldj/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ldj/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ldj/c;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ldj/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ldj/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ldj/c;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ldj/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ldj/c;->d:I

    .line 4
    .line 5
    const-string v2, "response"

    .line 6
    .line 7
    iget-object v3, v0, Ldj/c;->l:Ljava/lang/Object;

    .line 8
    .line 9
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 10
    .line 11
    const/4 v6, 0x0

    .line 12
    const/4 v7, 0x0

    .line 13
    const/4 v8, 0x4

    .line 14
    const-string v11, "Kt"

    .line 15
    .line 16
    sget-object v12, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    const/4 v13, 0x1

    .line 19
    const/4 v14, 0x3

    .line 20
    const/4 v15, 0x2

    .line 21
    packed-switch v1, :pswitch_data_0

    .line 22
    .line 23
    .line 24
    iget-object v1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Lyy0/j;

    .line 27
    .line 28
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 29
    .line 30
    iget v4, v0, Ldj/c;->j:I

    .line 31
    .line 32
    if-eqz v4, :cond_4

    .line 33
    .line 34
    if-eq v4, v13, :cond_3

    .line 35
    .line 36
    if-eq v4, v15, :cond_2

    .line 37
    .line 38
    if-eq v4, v14, :cond_1

    .line 39
    .line 40
    if-ne v4, v8, :cond_0

    .line 41
    .line 42
    iget v4, v0, Ldj/c;->h:I

    .line 43
    .line 44
    iget v5, v0, Ldj/c;->g:I

    .line 45
    .line 46
    iget-object v7, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 47
    .line 48
    iget-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 49
    .line 50
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    move-object/from16 v19, v3

    .line 54
    .line 55
    move/from16 v18, v13

    .line 56
    .line 57
    goto/16 :goto_9

    .line 58
    .line 59
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_1
    iget v4, v0, Ldj/c;->i:I

    .line 66
    .line 67
    iget v5, v0, Ldj/c;->h:I

    .line 68
    .line 69
    iget v7, v0, Ldj/c;->g:I

    .line 70
    .line 71
    iget-object v8, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v8, Llx0/o;

    .line 74
    .line 75
    iget-object v10, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 76
    .line 77
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    move-object/from16 v18, v10

    .line 81
    .line 82
    move v10, v4

    .line 83
    move v4, v5

    .line 84
    move v5, v7

    .line 85
    move-object/from16 v7, v18

    .line 86
    .line 87
    move/from16 v18, v13

    .line 88
    .line 89
    goto/16 :goto_4

    .line 90
    .line 91
    :cond_2
    iget v4, v0, Ldj/c;->i:I

    .line 92
    .line 93
    iget v5, v0, Ldj/c;->h:I

    .line 94
    .line 95
    iget v7, v0, Ldj/c;->g:I

    .line 96
    .line 97
    iget-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 98
    .line 99
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    move v10, v4

    .line 103
    move-object/from16 v4, p1

    .line 104
    .line 105
    goto/16 :goto_3

    .line 106
    .line 107
    :cond_3
    iget v4, v0, Ldj/c;->i:I

    .line 108
    .line 109
    iget v5, v0, Ldj/c;->h:I

    .line 110
    .line 111
    iget v7, v0, Ldj/c;->g:I

    .line 112
    .line 113
    iget-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 114
    .line 115
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    sget-object v4, Lqj/b;->a:[Ljava/lang/Integer;

    .line 123
    .line 124
    move-object v8, v4

    .line 125
    move-object v5, v6

    .line 126
    const/16 v4, 0xa

    .line 127
    .line 128
    :goto_0
    if-ge v7, v4, :cond_12

    .line 129
    .line 130
    aget-object v10, v8, v7

    .line 131
    .line 132
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 133
    .line 134
    .line 135
    move-result v10

    .line 136
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 137
    .line 138
    .line 139
    move-result-object v16

    .line 140
    invoke-static/range {v16 .. v16}, Lvy0/e0;->A(Lpx0/g;)Z

    .line 141
    .line 142
    .line 143
    move-result v16

    .line 144
    if-eqz v16, :cond_11

    .line 145
    .line 146
    if-eqz v5, :cond_6

    .line 147
    .line 148
    iget-object v5, v5, Llx0/o;->d:Ljava/lang/Object;

    .line 149
    .line 150
    new-instance v9, Lri/c;

    .line 151
    .line 152
    invoke-direct {v9, v5}, Lri/c;-><init>(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    iput-object v1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 156
    .line 157
    iput-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 158
    .line 159
    iput-object v6, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 160
    .line 161
    iput v7, v0, Ldj/c;->g:I

    .line 162
    .line 163
    iput v4, v0, Ldj/c;->h:I

    .line 164
    .line 165
    iput v10, v0, Ldj/c;->i:I

    .line 166
    .line 167
    iput v13, v0, Ldj/c;->j:I

    .line 168
    .line 169
    invoke-interface {v1, v9, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v5

    .line 173
    if-ne v5, v2, :cond_5

    .line 174
    .line 175
    goto/16 :goto_8

    .line 176
    .line 177
    :cond_5
    move v5, v4

    .line 178
    move v4, v10

    .line 179
    :goto_1
    move v10, v4

    .line 180
    goto :goto_2

    .line 181
    :cond_6
    move v5, v4

    .line 182
    :goto_2
    move-object v4, v3

    .line 183
    check-cast v4, Lqj/a;

    .line 184
    .line 185
    iget-object v4, v4, Lqj/a;->a:Lo90/f;

    .line 186
    .line 187
    iput-object v1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 188
    .line 189
    iput-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 190
    .line 191
    iput-object v6, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 192
    .line 193
    iput v7, v0, Ldj/c;->g:I

    .line 194
    .line 195
    iput v5, v0, Ldj/c;->h:I

    .line 196
    .line 197
    iput v10, v0, Ldj/c;->i:I

    .line 198
    .line 199
    iput v15, v0, Ldj/c;->j:I

    .line 200
    .line 201
    invoke-virtual {v4, v0}, Lo90/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v4

    .line 205
    if-ne v4, v2, :cond_7

    .line 206
    .line 207
    goto/16 :goto_8

    .line 208
    .line 209
    :cond_7
    :goto_3
    check-cast v4, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 210
    .line 211
    invoke-static {v4}, Lkp/j0;->b(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v4

    .line 215
    instance-of v9, v4, Llx0/n;

    .line 216
    .line 217
    if-nez v9, :cond_8

    .line 218
    .line 219
    check-cast v4, Lrj/c;

    .line 220
    .line 221
    iget-boolean v4, v4, Lrj/c;->a:Z

    .line 222
    .line 223
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 224
    .line 225
    .line 226
    move-result-object v4

    .line 227
    :cond_8
    new-instance v9, Llx0/o;

    .line 228
    .line 229
    invoke-direct {v9, v4}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 230
    .line 231
    .line 232
    move/from16 v18, v13

    .line 233
    .line 234
    new-instance v13, Lri/a;

    .line 235
    .line 236
    invoke-direct {v13, v4}, Lri/a;-><init>(Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    iput-object v1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 240
    .line 241
    iput-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 242
    .line 243
    iput-object v9, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 244
    .line 245
    iput v7, v0, Ldj/c;->g:I

    .line 246
    .line 247
    iput v5, v0, Ldj/c;->h:I

    .line 248
    .line 249
    iput v10, v0, Ldj/c;->i:I

    .line 250
    .line 251
    iput v14, v0, Ldj/c;->j:I

    .line 252
    .line 253
    invoke-interface {v1, v13, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v4

    .line 257
    if-ne v4, v2, :cond_9

    .line 258
    .line 259
    goto/16 :goto_8

    .line 260
    .line 261
    :cond_9
    move v4, v5

    .line 262
    move v5, v7

    .line 263
    move-object v7, v8

    .line 264
    move-object v8, v9

    .line 265
    :goto_4
    iget-object v8, v8, Llx0/o;->d:Ljava/lang/Object;

    .line 266
    .line 267
    instance-of v9, v8, Llx0/n;

    .line 268
    .line 269
    if-nez v9, :cond_c

    .line 270
    .line 271
    check-cast v8, Ljava/lang/Boolean;

    .line 272
    .line 273
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 274
    .line 275
    .line 276
    new-instance v0, Ldj/a;

    .line 277
    .line 278
    invoke-direct {v0, v15}, Ldj/a;-><init>(I)V

    .line 279
    .line 280
    .line 281
    sget-object v2, Lgi/b;->e:Lgi/b;

    .line 282
    .line 283
    sget-object v3, Lgi/a;->e:Lgi/a;

    .line 284
    .line 285
    instance-of v4, v1, Ljava/lang/String;

    .line 286
    .line 287
    if-eqz v4, :cond_a

    .line 288
    .line 289
    check-cast v1, Ljava/lang/String;

    .line 290
    .line 291
    goto :goto_5

    .line 292
    :cond_a
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 293
    .line 294
    .line 295
    move-result-object v1

    .line 296
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 297
    .line 298
    .line 299
    move-result-object v1

    .line 300
    const/16 v4, 0x24

    .line 301
    .line 302
    invoke-static {v1, v4}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 303
    .line 304
    .line 305
    move-result-object v4

    .line 306
    const/16 v5, 0x2e

    .line 307
    .line 308
    invoke-static {v5, v4, v4}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object v4

    .line 312
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 313
    .line 314
    .line 315
    move-result v5

    .line 316
    if-nez v5, :cond_b

    .line 317
    .line 318
    goto :goto_5

    .line 319
    :cond_b
    invoke-static {v4, v11}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 320
    .line 321
    .line 322
    move-result-object v1

    .line 323
    :goto_5
    invoke-static {v1, v3, v2, v6, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 324
    .line 325
    .line 326
    goto/16 :goto_d

    .line 327
    .line 328
    :cond_c
    invoke-static {v8}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 329
    .line 330
    .line 331
    move-result-object v9

    .line 332
    if-eqz v9, :cond_10

    .line 333
    .line 334
    new-instance v9, Lac/g;

    .line 335
    .line 336
    const/16 v13, 0x9

    .line 337
    .line 338
    invoke-direct {v9, v10, v13}, Lac/g;-><init>(II)V

    .line 339
    .line 340
    .line 341
    sget-object v13, Lgi/b;->e:Lgi/b;

    .line 342
    .line 343
    sget-object v14, Lgi/a;->e:Lgi/a;

    .line 344
    .line 345
    instance-of v15, v1, Ljava/lang/String;

    .line 346
    .line 347
    if-eqz v15, :cond_d

    .line 348
    .line 349
    move-object v15, v1

    .line 350
    check-cast v15, Ljava/lang/String;

    .line 351
    .line 352
    move-object/from16 v19, v3

    .line 353
    .line 354
    move-object v3, v6

    .line 355
    goto :goto_7

    .line 356
    :cond_d
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 357
    .line 358
    .line 359
    move-result-object v15

    .line 360
    invoke-virtual {v15}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 361
    .line 362
    .line 363
    move-result-object v15

    .line 364
    move-object/from16 v19, v3

    .line 365
    .line 366
    const/16 v6, 0x24

    .line 367
    .line 368
    invoke-static {v15, v6}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 369
    .line 370
    .line 371
    move-result-object v3

    .line 372
    const/16 v6, 0x2e

    .line 373
    .line 374
    invoke-static {v6, v3, v3}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 375
    .line 376
    .line 377
    move-result-object v3

    .line 378
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 379
    .line 380
    .line 381
    move-result v6

    .line 382
    if-nez v6, :cond_e

    .line 383
    .line 384
    goto :goto_6

    .line 385
    :cond_e
    invoke-static {v3, v11}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 386
    .line 387
    .line 388
    move-result-object v3

    .line 389
    move-object v15, v3

    .line 390
    :goto_6
    const/4 v3, 0x0

    .line 391
    :goto_7
    invoke-static {v15, v14, v13, v3, v9}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 392
    .line 393
    .line 394
    sget v3, Lmy0/c;->g:I

    .line 395
    .line 396
    sget-object v3, Lmy0/e;->h:Lmy0/e;

    .line 397
    .line 398
    invoke-static {v10, v3}, Lmy0/h;->s(ILmy0/e;)J

    .line 399
    .line 400
    .line 401
    move-result-wide v13

    .line 402
    iput-object v1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 403
    .line 404
    iput-object v7, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 405
    .line 406
    iput-object v8, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 407
    .line 408
    iput v5, v0, Ldj/c;->g:I

    .line 409
    .line 410
    iput v4, v0, Ldj/c;->h:I

    .line 411
    .line 412
    iput v10, v0, Ldj/c;->i:I

    .line 413
    .line 414
    const/4 v3, 0x4

    .line 415
    iput v3, v0, Ldj/c;->j:I

    .line 416
    .line 417
    invoke-static {v13, v14, v0}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 418
    .line 419
    .line 420
    move-result-object v3

    .line 421
    if-ne v3, v2, :cond_f

    .line 422
    .line 423
    :goto_8
    move-object v12, v2

    .line 424
    goto :goto_d

    .line 425
    :cond_f
    move-object/from16 v22, v8

    .line 426
    .line 427
    move-object v8, v7

    .line 428
    move-object/from16 v7, v22

    .line 429
    .line 430
    :goto_9
    move-object v3, v8

    .line 431
    move-object v8, v7

    .line 432
    :goto_a
    move v7, v5

    .line 433
    goto :goto_b

    .line 434
    :cond_10
    move-object/from16 v19, v3

    .line 435
    .line 436
    move-object v3, v7

    .line 437
    goto :goto_a

    .line 438
    :goto_b
    new-instance v5, Llx0/o;

    .line 439
    .line 440
    invoke-direct {v5, v8}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 441
    .line 442
    .line 443
    move-object v8, v3

    .line 444
    goto :goto_c

    .line 445
    :cond_11
    move-object/from16 v19, v3

    .line 446
    .line 447
    move/from16 v18, v13

    .line 448
    .line 449
    :goto_c
    add-int/lit8 v7, v7, 0x1

    .line 450
    .line 451
    move/from16 v13, v18

    .line 452
    .line 453
    move-object/from16 v3, v19

    .line 454
    .line 455
    const/4 v6, 0x0

    .line 456
    const/4 v14, 0x3

    .line 457
    const/4 v15, 0x2

    .line 458
    goto/16 :goto_0

    .line 459
    .line 460
    :cond_12
    :goto_d
    return-object v12

    .line 461
    :pswitch_0
    move-object/from16 v19, v3

    .line 462
    .line 463
    move/from16 v18, v13

    .line 464
    .line 465
    move-object/from16 v3, v19

    .line 466
    .line 467
    check-cast v3, Lhj/a;

    .line 468
    .line 469
    iget-object v1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 470
    .line 471
    check-cast v1, Lyy0/j;

    .line 472
    .line 473
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 474
    .line 475
    iget v6, v0, Ldj/c;->j:I

    .line 476
    .line 477
    if-eqz v6, :cond_17

    .line 478
    .line 479
    move/from16 v8, v18

    .line 480
    .line 481
    if-eq v6, v8, :cond_16

    .line 482
    .line 483
    const/4 v7, 0x2

    .line 484
    if-eq v6, v7, :cond_15

    .line 485
    .line 486
    const/4 v7, 0x3

    .line 487
    if-eq v6, v7, :cond_14

    .line 488
    .line 489
    const/4 v7, 0x4

    .line 490
    if-ne v6, v7, :cond_13

    .line 491
    .line 492
    iget v5, v0, Ldj/c;->h:I

    .line 493
    .line 494
    iget v6, v0, Ldj/c;->g:I

    .line 495
    .line 496
    iget-object v7, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 497
    .line 498
    iget-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 499
    .line 500
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 501
    .line 502
    .line 503
    move-object/from16 v19, v3

    .line 504
    .line 505
    move-object/from16 v20, v12

    .line 506
    .line 507
    goto/16 :goto_18

    .line 508
    .line 509
    :cond_13
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 510
    .line 511
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 512
    .line 513
    .line 514
    throw v0

    .line 515
    :cond_14
    iget v5, v0, Ldj/c;->i:I

    .line 516
    .line 517
    iget v6, v0, Ldj/c;->h:I

    .line 518
    .line 519
    iget v7, v0, Ldj/c;->g:I

    .line 520
    .line 521
    iget-object v8, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 522
    .line 523
    check-cast v8, Llx0/o;

    .line 524
    .line 525
    iget-object v9, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 526
    .line 527
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 528
    .line 529
    .line 530
    move-object/from16 v22, v9

    .line 531
    .line 532
    move v9, v5

    .line 533
    move v5, v6

    .line 534
    move v6, v7

    .line 535
    move-object/from16 v7, v22

    .line 536
    .line 537
    goto/16 :goto_12

    .line 538
    .line 539
    :cond_15
    iget v5, v0, Ldj/c;->i:I

    .line 540
    .line 541
    iget v6, v0, Ldj/c;->h:I

    .line 542
    .line 543
    iget v7, v0, Ldj/c;->g:I

    .line 544
    .line 545
    iget-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 546
    .line 547
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 548
    .line 549
    .line 550
    move v9, v5

    .line 551
    move-object/from16 v5, p1

    .line 552
    .line 553
    goto/16 :goto_11

    .line 554
    .line 555
    :cond_16
    iget v5, v0, Ldj/c;->i:I

    .line 556
    .line 557
    iget v6, v0, Ldj/c;->h:I

    .line 558
    .line 559
    iget v7, v0, Ldj/c;->g:I

    .line 560
    .line 561
    iget-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 562
    .line 563
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 564
    .line 565
    .line 566
    goto :goto_f

    .line 567
    :cond_17
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 568
    .line 569
    .line 570
    sget-object v5, Lhj/b;->a:[Ljava/lang/Integer;

    .line 571
    .line 572
    move-object v8, v5

    .line 573
    const/16 v5, 0xa

    .line 574
    .line 575
    const/4 v6, 0x0

    .line 576
    :goto_e
    if-ge v7, v5, :cond_25

    .line 577
    .line 578
    aget-object v9, v8, v7

    .line 579
    .line 580
    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    .line 581
    .line 582
    .line 583
    move-result v9

    .line 584
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 585
    .line 586
    .line 587
    move-result-object v10

    .line 588
    invoke-static {v10}, Lvy0/e0;->A(Lpx0/g;)Z

    .line 589
    .line 590
    .line 591
    move-result v10

    .line 592
    if-eqz v10, :cond_24

    .line 593
    .line 594
    if-eqz v6, :cond_19

    .line 595
    .line 596
    iget-object v6, v6, Llx0/o;->d:Ljava/lang/Object;

    .line 597
    .line 598
    new-instance v10, Lri/c;

    .line 599
    .line 600
    invoke-direct {v10, v6}, Lri/c;-><init>(Ljava/lang/Object;)V

    .line 601
    .line 602
    .line 603
    iput-object v1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 604
    .line 605
    iput-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 606
    .line 607
    const/4 v6, 0x0

    .line 608
    iput-object v6, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 609
    .line 610
    iput v7, v0, Ldj/c;->g:I

    .line 611
    .line 612
    iput v5, v0, Ldj/c;->h:I

    .line 613
    .line 614
    iput v9, v0, Ldj/c;->i:I

    .line 615
    .line 616
    const/4 v6, 0x1

    .line 617
    iput v6, v0, Ldj/c;->j:I

    .line 618
    .line 619
    invoke-interface {v1, v10, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 620
    .line 621
    .line 622
    move-result-object v6

    .line 623
    if-ne v6, v4, :cond_18

    .line 624
    .line 625
    goto/16 :goto_17

    .line 626
    .line 627
    :cond_18
    move v6, v5

    .line 628
    move v5, v9

    .line 629
    :goto_f
    move v9, v5

    .line 630
    goto :goto_10

    .line 631
    :cond_19
    move v6, v5

    .line 632
    :goto_10
    iget-object v5, v3, Lhj/a;->a:Lag/c;

    .line 633
    .line 634
    iput-object v1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 635
    .line 636
    iput-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 637
    .line 638
    const/4 v10, 0x0

    .line 639
    iput-object v10, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 640
    .line 641
    iput v7, v0, Ldj/c;->g:I

    .line 642
    .line 643
    iput v6, v0, Ldj/c;->h:I

    .line 644
    .line 645
    iput v9, v0, Ldj/c;->i:I

    .line 646
    .line 647
    const/4 v10, 0x2

    .line 648
    iput v10, v0, Ldj/c;->j:I

    .line 649
    .line 650
    const-string v10, "DE"

    .line 651
    .line 652
    invoke-virtual {v5, v10, v0}, Lag/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 653
    .line 654
    .line 655
    move-result-object v5

    .line 656
    if-ne v5, v4, :cond_1a

    .line 657
    .line 658
    goto/16 :goto_17

    .line 659
    .line 660
    :cond_1a
    :goto_11
    check-cast v5, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 661
    .line 662
    invoke-static {v5}, Lkp/j0;->b(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Ljava/lang/Object;

    .line 663
    .line 664
    .line 665
    move-result-object v5

    .line 666
    instance-of v10, v5, Llx0/n;

    .line 667
    .line 668
    if-nez v10, :cond_1b

    .line 669
    .line 670
    check-cast v5, Lij/f;

    .line 671
    .line 672
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 673
    .line 674
    .line 675
    new-instance v10, Lgj/a;

    .line 676
    .line 677
    iget-object v5, v5, Lij/f;->a:Lij/c;

    .line 678
    .line 679
    iget-boolean v13, v5, Lij/c;->a:Z

    .line 680
    .line 681
    iget-boolean v14, v5, Lij/c;->b:Z

    .line 682
    .line 683
    iget-boolean v5, v5, Lij/c;->c:Z

    .line 684
    .line 685
    invoke-direct {v10, v13, v14, v5}, Lgj/a;-><init>(ZZZ)V

    .line 686
    .line 687
    .line 688
    move-object v5, v10

    .line 689
    :cond_1b
    new-instance v10, Llx0/o;

    .line 690
    .line 691
    invoke-direct {v10, v5}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 692
    .line 693
    .line 694
    new-instance v13, Lri/a;

    .line 695
    .line 696
    invoke-direct {v13, v5}, Lri/a;-><init>(Ljava/lang/Object;)V

    .line 697
    .line 698
    .line 699
    iput-object v1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 700
    .line 701
    iput-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 702
    .line 703
    iput-object v10, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 704
    .line 705
    iput v7, v0, Ldj/c;->g:I

    .line 706
    .line 707
    iput v6, v0, Ldj/c;->h:I

    .line 708
    .line 709
    iput v9, v0, Ldj/c;->i:I

    .line 710
    .line 711
    const/4 v5, 0x3

    .line 712
    iput v5, v0, Ldj/c;->j:I

    .line 713
    .line 714
    invoke-interface {v1, v13, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 715
    .line 716
    .line 717
    move-result-object v5

    .line 718
    if-ne v5, v4, :cond_1c

    .line 719
    .line 720
    goto/16 :goto_17

    .line 721
    .line 722
    :cond_1c
    move v5, v6

    .line 723
    move v6, v7

    .line 724
    move-object v7, v8

    .line 725
    move-object v8, v10

    .line 726
    :goto_12
    iget-object v8, v8, Llx0/o;->d:Ljava/lang/Object;

    .line 727
    .line 728
    instance-of v10, v8, Llx0/n;

    .line 729
    .line 730
    if-nez v10, :cond_1f

    .line 731
    .line 732
    check-cast v8, Lgj/a;

    .line 733
    .line 734
    new-instance v0, Ldj/a;

    .line 735
    .line 736
    const/4 v7, 0x2

    .line 737
    invoke-direct {v0, v7}, Ldj/a;-><init>(I)V

    .line 738
    .line 739
    .line 740
    sget-object v2, Lgi/b;->e:Lgi/b;

    .line 741
    .line 742
    sget-object v3, Lgi/a;->e:Lgi/a;

    .line 743
    .line 744
    instance-of v4, v1, Ljava/lang/String;

    .line 745
    .line 746
    if-eqz v4, :cond_1d

    .line 747
    .line 748
    check-cast v1, Ljava/lang/String;

    .line 749
    .line 750
    :goto_13
    const/4 v6, 0x0

    .line 751
    goto :goto_14

    .line 752
    :cond_1d
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 753
    .line 754
    .line 755
    move-result-object v1

    .line 756
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 757
    .line 758
    .line 759
    move-result-object v1

    .line 760
    const/16 v4, 0x24

    .line 761
    .line 762
    invoke-static {v1, v4}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 763
    .line 764
    .line 765
    move-result-object v4

    .line 766
    const/16 v5, 0x2e

    .line 767
    .line 768
    invoke-static {v5, v4, v4}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 769
    .line 770
    .line 771
    move-result-object v4

    .line 772
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 773
    .line 774
    .line 775
    move-result v5

    .line 776
    if-nez v5, :cond_1e

    .line 777
    .line 778
    goto :goto_13

    .line 779
    :cond_1e
    invoke-static {v4, v11}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 780
    .line 781
    .line 782
    move-result-object v1

    .line 783
    goto :goto_13

    .line 784
    :goto_14
    invoke-static {v1, v3, v2, v6, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 785
    .line 786
    .line 787
    goto/16 :goto_1d

    .line 788
    .line 789
    :cond_1f
    invoke-static {v8}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 790
    .line 791
    .line 792
    move-result-object v10

    .line 793
    if-eqz v10, :cond_23

    .line 794
    .line 795
    new-instance v10, Lac/g;

    .line 796
    .line 797
    const/4 v13, 0x3

    .line 798
    invoke-direct {v10, v9, v13}, Lac/g;-><init>(II)V

    .line 799
    .line 800
    .line 801
    sget-object v13, Lgi/b;->e:Lgi/b;

    .line 802
    .line 803
    sget-object v14, Lgi/a;->e:Lgi/a;

    .line 804
    .line 805
    instance-of v15, v1, Ljava/lang/String;

    .line 806
    .line 807
    if-eqz v15, :cond_20

    .line 808
    .line 809
    move-object v15, v1

    .line 810
    check-cast v15, Ljava/lang/String;

    .line 811
    .line 812
    move-object/from16 v19, v3

    .line 813
    .line 814
    move-object/from16 v20, v12

    .line 815
    .line 816
    :goto_15
    const/4 v3, 0x0

    .line 817
    goto :goto_16

    .line 818
    :cond_20
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 819
    .line 820
    .line 821
    move-result-object v15

    .line 822
    invoke-virtual {v15}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 823
    .line 824
    .line 825
    move-result-object v15

    .line 826
    move-object/from16 v19, v3

    .line 827
    .line 828
    move-object/from16 v20, v12

    .line 829
    .line 830
    const/16 v3, 0x24

    .line 831
    .line 832
    invoke-static {v15, v3}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 833
    .line 834
    .line 835
    move-result-object v12

    .line 836
    const/16 v3, 0x2e

    .line 837
    .line 838
    invoke-static {v3, v12, v12}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 839
    .line 840
    .line 841
    move-result-object v12

    .line 842
    invoke-virtual {v12}, Ljava/lang/String;->length()I

    .line 843
    .line 844
    .line 845
    move-result v3

    .line 846
    if-nez v3, :cond_21

    .line 847
    .line 848
    goto :goto_15

    .line 849
    :cond_21
    invoke-static {v12, v11}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 850
    .line 851
    .line 852
    move-result-object v3

    .line 853
    move-object v15, v3

    .line 854
    goto :goto_15

    .line 855
    :goto_16
    invoke-static {v15, v14, v13, v3, v10}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 856
    .line 857
    .line 858
    sget v3, Lmy0/c;->g:I

    .line 859
    .line 860
    sget-object v3, Lmy0/e;->h:Lmy0/e;

    .line 861
    .line 862
    invoke-static {v9, v3}, Lmy0/h;->s(ILmy0/e;)J

    .line 863
    .line 864
    .line 865
    move-result-wide v12

    .line 866
    iput-object v1, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 867
    .line 868
    iput-object v7, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 869
    .line 870
    iput-object v8, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 871
    .line 872
    iput v6, v0, Ldj/c;->g:I

    .line 873
    .line 874
    iput v5, v0, Ldj/c;->h:I

    .line 875
    .line 876
    iput v9, v0, Ldj/c;->i:I

    .line 877
    .line 878
    const/4 v3, 0x4

    .line 879
    iput v3, v0, Ldj/c;->j:I

    .line 880
    .line 881
    invoke-static {v12, v13, v0}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 882
    .line 883
    .line 884
    move-result-object v3

    .line 885
    if-ne v3, v4, :cond_22

    .line 886
    .line 887
    :goto_17
    move-object v12, v4

    .line 888
    goto :goto_1d

    .line 889
    :cond_22
    move-object/from16 v22, v8

    .line 890
    .line 891
    move-object v8, v7

    .line 892
    move-object/from16 v7, v22

    .line 893
    .line 894
    :goto_18
    move-object v3, v8

    .line 895
    move-object v8, v7

    .line 896
    :goto_19
    move v7, v6

    .line 897
    goto :goto_1a

    .line 898
    :cond_23
    move-object/from16 v19, v3

    .line 899
    .line 900
    move-object/from16 v20, v12

    .line 901
    .line 902
    move-object v3, v7

    .line 903
    goto :goto_19

    .line 904
    :goto_1a
    new-instance v6, Llx0/o;

    .line 905
    .line 906
    invoke-direct {v6, v8}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 907
    .line 908
    .line 909
    move-object v8, v3

    .line 910
    :goto_1b
    const/4 v3, 0x1

    .line 911
    goto :goto_1c

    .line 912
    :cond_24
    move-object/from16 v19, v3

    .line 913
    .line 914
    move-object/from16 v20, v12

    .line 915
    .line 916
    goto :goto_1b

    .line 917
    :goto_1c
    add-int/2addr v7, v3

    .line 918
    move-object/from16 v3, v19

    .line 919
    .line 920
    move-object/from16 v12, v20

    .line 921
    .line 922
    goto/16 :goto_e

    .line 923
    .line 924
    :cond_25
    move-object/from16 v20, v12

    .line 925
    .line 926
    :goto_1d
    return-object v12

    .line 927
    :pswitch_1
    move-object/from16 v19, v3

    .line 928
    .line 929
    move-object/from16 v20, v12

    .line 930
    .line 931
    move v3, v13

    .line 932
    move-object/from16 v1, v19

    .line 933
    .line 934
    check-cast v1, Ldj/g;

    .line 935
    .line 936
    iget-object v4, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 937
    .line 938
    check-cast v4, Lyy0/j;

    .line 939
    .line 940
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 941
    .line 942
    iget v8, v0, Ldj/c;->j:I

    .line 943
    .line 944
    if-eqz v8, :cond_2a

    .line 945
    .line 946
    if-eq v8, v3, :cond_29

    .line 947
    .line 948
    const/4 v7, 0x2

    .line 949
    if-eq v8, v7, :cond_28

    .line 950
    .line 951
    const/4 v7, 0x3

    .line 952
    if-eq v8, v7, :cond_27

    .line 953
    .line 954
    const/4 v3, 0x4

    .line 955
    if-ne v8, v3, :cond_26

    .line 956
    .line 957
    iget v3, v0, Ldj/c;->h:I

    .line 958
    .line 959
    iget v5, v0, Ldj/c;->g:I

    .line 960
    .line 961
    iget-object v7, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 962
    .line 963
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 964
    .line 965
    .line 966
    move-object/from16 v16, v1

    .line 967
    .line 968
    move-object/from16 v21, v2

    .line 969
    .line 970
    goto/16 :goto_31

    .line 971
    .line 972
    :cond_26
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 973
    .line 974
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 975
    .line 976
    .line 977
    throw v0

    .line 978
    :cond_27
    iget v3, v0, Ldj/c;->i:I

    .line 979
    .line 980
    iget v5, v0, Ldj/c;->h:I

    .line 981
    .line 982
    iget v7, v0, Ldj/c;->g:I

    .line 983
    .line 984
    iget-object v8, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 985
    .line 986
    check-cast v8, Llx0/o;

    .line 987
    .line 988
    iget-object v9, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 989
    .line 990
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 991
    .line 992
    .line 993
    move-object/from16 v16, v1

    .line 994
    .line 995
    move-object/from16 v21, v2

    .line 996
    .line 997
    move v1, v3

    .line 998
    move v3, v5

    .line 999
    move v5, v7

    .line 1000
    move-object v7, v9

    .line 1001
    const/4 v13, 0x3

    .line 1002
    goto/16 :goto_29

    .line 1003
    .line 1004
    :cond_28
    iget v3, v0, Ldj/c;->i:I

    .line 1005
    .line 1006
    iget v5, v0, Ldj/c;->h:I

    .line 1007
    .line 1008
    iget v7, v0, Ldj/c;->g:I

    .line 1009
    .line 1010
    iget-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 1011
    .line 1012
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1013
    .line 1014
    .line 1015
    move-object/from16 v9, p1

    .line 1016
    .line 1017
    goto/16 :goto_20

    .line 1018
    .line 1019
    :cond_29
    iget v3, v0, Ldj/c;->i:I

    .line 1020
    .line 1021
    iget v5, v0, Ldj/c;->h:I

    .line 1022
    .line 1023
    iget v7, v0, Ldj/c;->g:I

    .line 1024
    .line 1025
    iget-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 1026
    .line 1027
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1028
    .line 1029
    .line 1030
    goto :goto_1f

    .line 1031
    :cond_2a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1032
    .line 1033
    .line 1034
    sget-object v3, Ldj/h;->a:[Ljava/lang/Integer;

    .line 1035
    .line 1036
    move-object v8, v3

    .line 1037
    move-object v3, v4

    .line 1038
    const/16 v4, 0xa

    .line 1039
    .line 1040
    :goto_1e
    if-ge v7, v4, :cond_3b

    .line 1041
    .line 1042
    aget-object v5, v8, v7

    .line 1043
    .line 1044
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 1045
    .line 1046
    .line 1047
    move-result v5

    .line 1048
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 1049
    .line 1050
    .line 1051
    move-result-object v9

    .line 1052
    invoke-static {v9}, Lvy0/e0;->A(Lpx0/g;)Z

    .line 1053
    .line 1054
    .line 1055
    move-result v9

    .line 1056
    if-eqz v9, :cond_41

    .line 1057
    .line 1058
    iget-object v9, v1, Ldj/g;->c:Llx0/q;

    .line 1059
    .line 1060
    invoke-virtual {v9}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 1061
    .line 1062
    .line 1063
    move-result-object v9

    .line 1064
    check-cast v9, Lyy0/a2;

    .line 1065
    .line 1066
    invoke-interface {v9}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v9

    .line 1070
    check-cast v9, Lri/d;

    .line 1071
    .line 1072
    invoke-static {v9}, Lkp/i0;->c(Lri/d;)Llx0/o;

    .line 1073
    .line 1074
    .line 1075
    move-result-object v9

    .line 1076
    if-eqz v9, :cond_2b

    .line 1077
    .line 1078
    iget-object v9, v9, Llx0/o;->d:Ljava/lang/Object;

    .line 1079
    .line 1080
    new-instance v10, Lri/c;

    .line 1081
    .line 1082
    invoke-direct {v10, v9}, Lri/c;-><init>(Ljava/lang/Object;)V

    .line 1083
    .line 1084
    .line 1085
    iput-object v3, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 1086
    .line 1087
    iput-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 1088
    .line 1089
    const/4 v9, 0x0

    .line 1090
    iput-object v9, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 1091
    .line 1092
    iput v7, v0, Ldj/c;->g:I

    .line 1093
    .line 1094
    iput v4, v0, Ldj/c;->h:I

    .line 1095
    .line 1096
    iput v5, v0, Ldj/c;->i:I

    .line 1097
    .line 1098
    const/4 v9, 0x1

    .line 1099
    iput v9, v0, Ldj/c;->j:I

    .line 1100
    .line 1101
    invoke-interface {v3, v10, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1102
    .line 1103
    .line 1104
    move-result-object v9

    .line 1105
    if-ne v9, v6, :cond_2b

    .line 1106
    .line 1107
    goto/16 :goto_2f

    .line 1108
    .line 1109
    :cond_2b
    move/from16 v22, v4

    .line 1110
    .line 1111
    move-object v4, v3

    .line 1112
    move v3, v5

    .line 1113
    move/from16 v5, v22

    .line 1114
    .line 1115
    :goto_1f
    iget-object v9, v1, Ldj/g;->a:Lcz/j;

    .line 1116
    .line 1117
    iput-object v4, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 1118
    .line 1119
    iput-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 1120
    .line 1121
    const/4 v10, 0x0

    .line 1122
    iput-object v10, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 1123
    .line 1124
    iput v7, v0, Ldj/c;->g:I

    .line 1125
    .line 1126
    iput v5, v0, Ldj/c;->h:I

    .line 1127
    .line 1128
    iput v3, v0, Ldj/c;->i:I

    .line 1129
    .line 1130
    const/4 v10, 0x2

    .line 1131
    iput v10, v0, Ldj/c;->j:I

    .line 1132
    .line 1133
    invoke-virtual {v9, v0}, Lcz/j;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1134
    .line 1135
    .line 1136
    move-result-object v9

    .line 1137
    if-ne v9, v6, :cond_2c

    .line 1138
    .line 1139
    goto/16 :goto_2f

    .line 1140
    .line 1141
    :cond_2c
    :goto_20
    check-cast v9, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 1142
    .line 1143
    invoke-static {v9}, Lkp/j0;->b(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Ljava/lang/Object;

    .line 1144
    .line 1145
    .line 1146
    move-result-object v9

    .line 1147
    iget-object v10, v1, Ldj/g;->e:Ldj/i;

    .line 1148
    .line 1149
    instance-of v12, v9, Llx0/n;

    .line 1150
    .line 1151
    if-nez v12, :cond_37

    .line 1152
    .line 1153
    check-cast v9, Lej/c;

    .line 1154
    .line 1155
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1156
    .line 1157
    .line 1158
    invoke-static {v9, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1159
    .line 1160
    .line 1161
    iget-object v10, v9, Lej/c;->a:Ljava/util/List;

    .line 1162
    .line 1163
    check-cast v10, Ljava/lang/Iterable;

    .line 1164
    .line 1165
    new-instance v12, Ljava/util/ArrayList;

    .line 1166
    .line 1167
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 1168
    .line 1169
    .line 1170
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1171
    .line 1172
    .line 1173
    move-result-object v10

    .line 1174
    :goto_21
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 1175
    .line 1176
    .line 1177
    move-result v13

    .line 1178
    if-eqz v13, :cond_36

    .line 1179
    .line 1180
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1181
    .line 1182
    .line 1183
    move-result-object v13

    .line 1184
    check-cast v13, Ltb/w;

    .line 1185
    .line 1186
    iget-object v14, v13, Ltb/w;->d:Ljava/lang/String;

    .line 1187
    .line 1188
    invoke-virtual {v14}, Ljava/lang/String;->hashCode()I

    .line 1189
    .line 1190
    .line 1191
    move-result v15

    .line 1192
    move-object/from16 v16, v1

    .line 1193
    .line 1194
    const v1, -0x3ce218d7

    .line 1195
    .line 1196
    .line 1197
    if-eq v15, v1, :cond_31

    .line 1198
    .line 1199
    const v1, -0x12bedc78

    .line 1200
    .line 1201
    .line 1202
    if-eq v15, v1, :cond_2f

    .line 1203
    .line 1204
    const v1, 0x48784ad1

    .line 1205
    .line 1206
    .line 1207
    if-eq v15, v1, :cond_2d

    .line 1208
    .line 1209
    goto :goto_23

    .line 1210
    :cond_2d
    const-string v1, "legalnotice"

    .line 1211
    .line 1212
    invoke-virtual {v14, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1213
    .line 1214
    .line 1215
    move-result v1

    .line 1216
    if-nez v1, :cond_2e

    .line 1217
    .line 1218
    goto :goto_23

    .line 1219
    :cond_2e
    sget-object v1, Lcj/d;->f:Lcj/d;

    .line 1220
    .line 1221
    :goto_22
    move-object/from16 v21, v2

    .line 1222
    .line 1223
    move-object/from16 v19, v6

    .line 1224
    .line 1225
    move-object/from16 p1, v10

    .line 1226
    .line 1227
    goto :goto_26

    .line 1228
    :cond_2f
    const-string v1, "privacy"

    .line 1229
    .line 1230
    invoke-virtual {v14, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1231
    .line 1232
    .line 1233
    move-result v1

    .line 1234
    if-nez v1, :cond_30

    .line 1235
    .line 1236
    goto :goto_23

    .line 1237
    :cond_30
    sget-object v1, Lcj/d;->e:Lcj/d;

    .line 1238
    .line 1239
    goto :goto_22

    .line 1240
    :cond_31
    const-string v1, "termsofuse"

    .line 1241
    .line 1242
    invoke-virtual {v14, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1243
    .line 1244
    .line 1245
    move-result v1

    .line 1246
    if-nez v1, :cond_33

    .line 1247
    .line 1248
    :goto_23
    sget-object v1, Lgi/b;->h:Lgi/b;

    .line 1249
    .line 1250
    new-instance v14, La2/e;

    .line 1251
    .line 1252
    const/16 v15, 0x14

    .line 1253
    .line 1254
    invoke-direct {v14, v13, v15}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 1255
    .line 1256
    .line 1257
    sget-object v15, Lgi/a;->e:Lgi/a;

    .line 1258
    .line 1259
    const-class v19, Ldj/i;

    .line 1260
    .line 1261
    move-object/from16 v21, v2

    .line 1262
    .line 1263
    invoke-virtual/range {v19 .. v19}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 1264
    .line 1265
    .line 1266
    move-result-object v2

    .line 1267
    move-object/from16 v19, v6

    .line 1268
    .line 1269
    move-object/from16 p1, v10

    .line 1270
    .line 1271
    const/16 v10, 0x24

    .line 1272
    .line 1273
    invoke-static {v2, v10}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 1274
    .line 1275
    .line 1276
    move-result-object v6

    .line 1277
    const/16 v10, 0x2e

    .line 1278
    .line 1279
    invoke-static {v10, v6, v6}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1280
    .line 1281
    .line 1282
    move-result-object v6

    .line 1283
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 1284
    .line 1285
    .line 1286
    move-result v10

    .line 1287
    if-nez v10, :cond_32

    .line 1288
    .line 1289
    :goto_24
    const/4 v6, 0x0

    .line 1290
    goto :goto_25

    .line 1291
    :cond_32
    invoke-static {v6, v11}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1292
    .line 1293
    .line 1294
    move-result-object v2

    .line 1295
    goto :goto_24

    .line 1296
    :goto_25
    invoke-static {v2, v15, v1, v6, v14}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 1297
    .line 1298
    .line 1299
    const/4 v1, 0x0

    .line 1300
    goto :goto_26

    .line 1301
    :cond_33
    move-object/from16 v21, v2

    .line 1302
    .line 1303
    move-object/from16 v19, v6

    .line 1304
    .line 1305
    move-object/from16 p1, v10

    .line 1306
    .line 1307
    sget-object v1, Lcj/d;->d:Lcj/d;

    .line 1308
    .line 1309
    :goto_26
    if-eqz v1, :cond_34

    .line 1310
    .line 1311
    new-instance v2, Lcj/e;

    .line 1312
    .line 1313
    iget-object v6, v13, Ltb/w;->e:Ljava/lang/String;

    .line 1314
    .line 1315
    invoke-direct {v2, v1, v6}, Lcj/e;-><init>(Lcj/d;Ljava/lang/String;)V

    .line 1316
    .line 1317
    .line 1318
    goto :goto_27

    .line 1319
    :cond_34
    const/4 v2, 0x0

    .line 1320
    :goto_27
    if-eqz v2, :cond_35

    .line 1321
    .line 1322
    invoke-virtual {v12, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1323
    .line 1324
    .line 1325
    :cond_35
    move-object/from16 v10, p1

    .line 1326
    .line 1327
    move-object/from16 v1, v16

    .line 1328
    .line 1329
    move-object/from16 v6, v19

    .line 1330
    .line 1331
    move-object/from16 v2, v21

    .line 1332
    .line 1333
    goto/16 :goto_21

    .line 1334
    .line 1335
    :cond_36
    move-object/from16 v16, v1

    .line 1336
    .line 1337
    move-object/from16 v21, v2

    .line 1338
    .line 1339
    move-object/from16 v19, v6

    .line 1340
    .line 1341
    iget-object v1, v9, Lej/c;->b:Ljava/lang/String;

    .line 1342
    .line 1343
    new-instance v9, Lcj/c;

    .line 1344
    .line 1345
    invoke-direct {v9, v1, v12}, Lcj/c;-><init>(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 1346
    .line 1347
    .line 1348
    goto :goto_28

    .line 1349
    :cond_37
    move-object/from16 v16, v1

    .line 1350
    .line 1351
    move-object/from16 v21, v2

    .line 1352
    .line 1353
    move-object/from16 v19, v6

    .line 1354
    .line 1355
    :goto_28
    new-instance v1, Llx0/o;

    .line 1356
    .line 1357
    invoke-direct {v1, v9}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 1358
    .line 1359
    .line 1360
    new-instance v2, Lri/a;

    .line 1361
    .line 1362
    invoke-direct {v2, v9}, Lri/a;-><init>(Ljava/lang/Object;)V

    .line 1363
    .line 1364
    .line 1365
    iput-object v4, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 1366
    .line 1367
    iput-object v8, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 1368
    .line 1369
    iput-object v1, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 1370
    .line 1371
    iput v7, v0, Ldj/c;->g:I

    .line 1372
    .line 1373
    iput v5, v0, Ldj/c;->h:I

    .line 1374
    .line 1375
    iput v3, v0, Ldj/c;->i:I

    .line 1376
    .line 1377
    const/4 v13, 0x3

    .line 1378
    iput v13, v0, Ldj/c;->j:I

    .line 1379
    .line 1380
    invoke-interface {v4, v2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1381
    .line 1382
    .line 1383
    move-result-object v2

    .line 1384
    move-object/from16 v6, v19

    .line 1385
    .line 1386
    if-ne v2, v6, :cond_38

    .line 1387
    .line 1388
    goto/16 :goto_2f

    .line 1389
    .line 1390
    :cond_38
    move-object/from16 v22, v8

    .line 1391
    .line 1392
    move-object v8, v1

    .line 1393
    move v1, v3

    .line 1394
    move v3, v5

    .line 1395
    move v5, v7

    .line 1396
    move-object/from16 v7, v22

    .line 1397
    .line 1398
    :goto_29
    iget-object v2, v8, Llx0/o;->d:Ljava/lang/Object;

    .line 1399
    .line 1400
    instance-of v8, v2, Llx0/n;

    .line 1401
    .line 1402
    if-nez v8, :cond_3c

    .line 1403
    .line 1404
    check-cast v2, Lcj/c;

    .line 1405
    .line 1406
    new-instance v0, Ldj/a;

    .line 1407
    .line 1408
    const/4 v10, 0x2

    .line 1409
    invoke-direct {v0, v10}, Ldj/a;-><init>(I)V

    .line 1410
    .line 1411
    .line 1412
    sget-object v1, Lgi/b;->e:Lgi/b;

    .line 1413
    .line 1414
    sget-object v2, Lgi/a;->e:Lgi/a;

    .line 1415
    .line 1416
    instance-of v3, v4, Ljava/lang/String;

    .line 1417
    .line 1418
    if-eqz v3, :cond_39

    .line 1419
    .line 1420
    check-cast v4, Ljava/lang/String;

    .line 1421
    .line 1422
    :goto_2a
    const/4 v6, 0x0

    .line 1423
    goto :goto_2c

    .line 1424
    :cond_39
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1425
    .line 1426
    .line 1427
    move-result-object v3

    .line 1428
    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 1429
    .line 1430
    .line 1431
    move-result-object v3

    .line 1432
    const/16 v4, 0x24

    .line 1433
    .line 1434
    invoke-static {v3, v4}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 1435
    .line 1436
    .line 1437
    move-result-object v4

    .line 1438
    const/16 v5, 0x2e

    .line 1439
    .line 1440
    invoke-static {v5, v4, v4}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1441
    .line 1442
    .line 1443
    move-result-object v4

    .line 1444
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 1445
    .line 1446
    .line 1447
    move-result v5

    .line 1448
    if-nez v5, :cond_3a

    .line 1449
    .line 1450
    :goto_2b
    move-object v4, v3

    .line 1451
    goto :goto_2a

    .line 1452
    :cond_3a
    invoke-static {v4, v11}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1453
    .line 1454
    .line 1455
    move-result-object v3

    .line 1456
    goto :goto_2b

    .line 1457
    :goto_2c
    invoke-static {v4, v2, v1, v6, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 1458
    .line 1459
    .line 1460
    :cond_3b
    move-object/from16 v12, v20

    .line 1461
    .line 1462
    goto/16 :goto_33

    .line 1463
    .line 1464
    :cond_3c
    const/4 v10, 0x2

    .line 1465
    invoke-static {v2}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 1466
    .line 1467
    .line 1468
    move-result-object v8

    .line 1469
    if-eqz v8, :cond_40

    .line 1470
    .line 1471
    new-instance v8, Lac/g;

    .line 1472
    .line 1473
    const/4 v9, 0x1

    .line 1474
    invoke-direct {v8, v1, v9}, Lac/g;-><init>(II)V

    .line 1475
    .line 1476
    .line 1477
    sget-object v9, Lgi/b;->e:Lgi/b;

    .line 1478
    .line 1479
    sget-object v12, Lgi/a;->e:Lgi/a;

    .line 1480
    .line 1481
    instance-of v14, v4, Ljava/lang/String;

    .line 1482
    .line 1483
    if-eqz v14, :cond_3d

    .line 1484
    .line 1485
    move-object v14, v4

    .line 1486
    check-cast v14, Ljava/lang/String;

    .line 1487
    .line 1488
    const/16 v13, 0x2e

    .line 1489
    .line 1490
    const/16 v15, 0x24

    .line 1491
    .line 1492
    :goto_2d
    const/4 v10, 0x0

    .line 1493
    goto :goto_2e

    .line 1494
    :cond_3d
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1495
    .line 1496
    .line 1497
    move-result-object v14

    .line 1498
    invoke-virtual {v14}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 1499
    .line 1500
    .line 1501
    move-result-object v14

    .line 1502
    const/16 v15, 0x24

    .line 1503
    .line 1504
    invoke-static {v14, v15}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 1505
    .line 1506
    .line 1507
    move-result-object v10

    .line 1508
    const/16 v13, 0x2e

    .line 1509
    .line 1510
    invoke-static {v13, v10, v10}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1511
    .line 1512
    .line 1513
    move-result-object v10

    .line 1514
    invoke-virtual {v10}, Ljava/lang/String;->length()I

    .line 1515
    .line 1516
    .line 1517
    move-result v17

    .line 1518
    if-nez v17, :cond_3e

    .line 1519
    .line 1520
    goto :goto_2d

    .line 1521
    :cond_3e
    invoke-static {v10, v11}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1522
    .line 1523
    .line 1524
    move-result-object v10

    .line 1525
    move-object v14, v10

    .line 1526
    goto :goto_2d

    .line 1527
    :goto_2e
    invoke-static {v14, v12, v9, v10, v8}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 1528
    .line 1529
    .line 1530
    sget v8, Lmy0/c;->g:I

    .line 1531
    .line 1532
    sget-object v8, Lmy0/e;->h:Lmy0/e;

    .line 1533
    .line 1534
    invoke-static {v1, v8}, Lmy0/h;->s(ILmy0/e;)J

    .line 1535
    .line 1536
    .line 1537
    move-result-wide v8

    .line 1538
    iput-object v4, v0, Ldj/c;->k:Ljava/lang/Object;

    .line 1539
    .line 1540
    iput-object v7, v0, Ldj/c;->e:[Ljava/lang/Integer;

    .line 1541
    .line 1542
    iput-object v2, v0, Ldj/c;->f:Ljava/lang/Object;

    .line 1543
    .line 1544
    iput v5, v0, Ldj/c;->g:I

    .line 1545
    .line 1546
    iput v3, v0, Ldj/c;->h:I

    .line 1547
    .line 1548
    iput v1, v0, Ldj/c;->i:I

    .line 1549
    .line 1550
    const/4 v1, 0x4

    .line 1551
    iput v1, v0, Ldj/c;->j:I

    .line 1552
    .line 1553
    invoke-static {v8, v9, v0}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1554
    .line 1555
    .line 1556
    move-result-object v2

    .line 1557
    if-ne v2, v6, :cond_3f

    .line 1558
    .line 1559
    :goto_2f
    move-object v12, v6

    .line 1560
    goto :goto_33

    .line 1561
    :cond_3f
    :goto_30
    move-object v8, v4

    .line 1562
    move v4, v3

    .line 1563
    move-object v3, v8

    .line 1564
    move-object v8, v7

    .line 1565
    const/16 v18, 0x1

    .line 1566
    .line 1567
    move v7, v5

    .line 1568
    goto :goto_32

    .line 1569
    :cond_40
    :goto_31
    const/4 v1, 0x4

    .line 1570
    const/4 v10, 0x0

    .line 1571
    const/16 v13, 0x2e

    .line 1572
    .line 1573
    const/16 v15, 0x24

    .line 1574
    .line 1575
    goto :goto_30

    .line 1576
    :cond_41
    move-object/from16 v16, v1

    .line 1577
    .line 1578
    move-object/from16 v21, v2

    .line 1579
    .line 1580
    const/4 v1, 0x4

    .line 1581
    const/4 v10, 0x0

    .line 1582
    const/16 v13, 0x2e

    .line 1583
    .line 1584
    const/16 v15, 0x24

    .line 1585
    .line 1586
    const/16 v18, 0x1

    .line 1587
    .line 1588
    :goto_32
    add-int/lit8 v7, v7, 0x1

    .line 1589
    .line 1590
    move-object/from16 v1, v16

    .line 1591
    .line 1592
    move-object/from16 v2, v21

    .line 1593
    .line 1594
    goto/16 :goto_1e

    .line 1595
    .line 1596
    :goto_33
    return-object v12

    .line 1597
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
