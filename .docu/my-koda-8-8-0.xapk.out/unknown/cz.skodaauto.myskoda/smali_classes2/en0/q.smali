.class public final Len0/q;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/util/Iterator;

.field public f:Ljava/lang/Object;

.field public g:I

.field public h:I

.field public i:I

.field public final synthetic j:Ljava/lang/Object;

.field public k:Ljava/lang/Object;

.field public l:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Lme0/a;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Len0/q;->d:I

    iput-object p1, p0, Len0/q;->j:Ljava/lang/Object;

    iput-object p2, p0, Len0/q;->l:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Ljava/util/List;Lmj0/e;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Len0/q;->d:I

    .line 2
    iput-object p1, p0, Len0/q;->f:Ljava/lang/Object;

    iput-object p2, p0, Len0/q;->j:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Len0/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Len0/q;

    .line 7
    .line 8
    iget-object v1, p0, Len0/q;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ljava/util/List;

    .line 11
    .line 12
    iget-object p0, p0, Len0/q;->j:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lmj0/e;

    .line 15
    .line 16
    invoke-direct {v0, v1, p0, p1}, Len0/q;-><init>(Ljava/util/List;Lmj0/e;Lkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    new-instance v0, Len0/q;

    .line 21
    .line 22
    iget-object v1, p0, Len0/q;->j:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v1, Ljava/util/ArrayList;

    .line 25
    .line 26
    iget-object p0, p0, Len0/q;->l:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lif0/f0;

    .line 29
    .line 30
    const/4 v2, 0x1

    .line 31
    invoke-direct {v0, v1, p0, p1, v2}, Len0/q;-><init>(Ljava/util/ArrayList;Lme0/a;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    return-object v0

    .line 35
    :pswitch_1
    new-instance v0, Len0/q;

    .line 36
    .line 37
    iget-object v1, p0, Len0/q;->j:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v1, Ljava/util/ArrayList;

    .line 40
    .line 41
    iget-object p0, p0, Len0/q;->l:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Len0/s;

    .line 44
    .line 45
    const/4 v2, 0x0

    .line 46
    invoke-direct {v0, v1, p0, p1, v2}, Len0/q;-><init>(Ljava/util/ArrayList;Lme0/a;Lkotlin/coroutines/Continuation;I)V

    .line 47
    .line 48
    .line 49
    return-object v0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Len0/q;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Len0/q;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Len0/q;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Len0/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Len0/q;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Len0/q;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Len0/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Len0/q;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Len0/q;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Len0/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Len0/q;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Len0/q;->i:I

    .line 11
    .line 12
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    const/4 v5, 0x2

    .line 16
    const/4 v6, 0x1

    .line 17
    if-eqz v2, :cond_2

    .line 18
    .line 19
    if-eq v2, v6, :cond_1

    .line 20
    .line 21
    if-ne v2, v5, :cond_0

    .line 22
    .line 23
    iget v2, v0, Len0/q;->g:I

    .line 24
    .line 25
    iget-object v7, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 26
    .line 27
    iget-object v8, v0, Len0/q;->k:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v8, Lmj0/e;

    .line 30
    .line 31
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    move-object/from16 v19, v8

    .line 35
    .line 36
    move v8, v2

    .line 37
    move-object v2, v7

    .line 38
    move-object/from16 v7, v19

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 44
    .line 45
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw v0

    .line 49
    :cond_1
    iget v2, v0, Len0/q;->h:I

    .line 50
    .line 51
    iget v7, v0, Len0/q;->g:I

    .line 52
    .line 53
    iget-object v8, v0, Len0/q;->l:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v8, Lkj0/f;

    .line 56
    .line 57
    iget-object v9, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 58
    .line 59
    iget-object v10, v0, Len0/q;->k:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v10, Lmj0/e;

    .line 62
    .line 63
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    move v11, v7

    .line 67
    move v7, v2

    .line 68
    move v2, v11

    .line 69
    move-object v11, v10

    .line 70
    move-object/from16 v10, p1

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    iget-object v2, v0, Len0/q;->f:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v2, Ljava/util/List;

    .line 79
    .line 80
    check-cast v2, Ljava/lang/Iterable;

    .line 81
    .line 82
    iget-object v7, v0, Len0/q;->j:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v7, Lmj0/e;

    .line 85
    .line 86
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    move v8, v4

    .line 91
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 92
    .line 93
    .line 94
    move-result v9

    .line 95
    if-eqz v9, :cond_b

    .line 96
    .line 97
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v9

    .line 101
    check-cast v9, Lkj0/f;

    .line 102
    .line 103
    iget-object v10, v7, Lmj0/e;->a:Lti0/a;

    .line 104
    .line 105
    iput-object v7, v0, Len0/q;->k:Ljava/lang/Object;

    .line 106
    .line 107
    iput-object v2, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 108
    .line 109
    iput-object v9, v0, Len0/q;->l:Ljava/lang/Object;

    .line 110
    .line 111
    iput v8, v0, Len0/q;->g:I

    .line 112
    .line 113
    iput v4, v0, Len0/q;->h:I

    .line 114
    .line 115
    iput v6, v0, Len0/q;->i:I

    .line 116
    .line 117
    invoke-interface {v10, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v10

    .line 121
    if-ne v10, v1, :cond_3

    .line 122
    .line 123
    goto/16 :goto_5

    .line 124
    .line 125
    :cond_3
    move-object v11, v9

    .line 126
    move-object v9, v2

    .line 127
    move v2, v8

    .line 128
    move-object v8, v11

    .line 129
    move-object v11, v7

    .line 130
    move v7, v4

    .line 131
    :goto_1
    check-cast v10, Lmj0/a;

    .line 132
    .line 133
    const-string v12, "<this>"

    .line 134
    .line 135
    invoke-static {v8, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    iget-object v12, v8, Lkj0/f;->b:Lkj0/e;

    .line 139
    .line 140
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 141
    .line 142
    .line 143
    move-result v12

    .line 144
    if-eqz v12, :cond_8

    .line 145
    .line 146
    if-eq v12, v6, :cond_7

    .line 147
    .line 148
    if-eq v12, v5, :cond_6

    .line 149
    .line 150
    const/4 v13, 0x3

    .line 151
    if-eq v12, v13, :cond_5

    .line 152
    .line 153
    const/4 v13, 0x4

    .line 154
    if-ne v12, v13, :cond_4

    .line 155
    .line 156
    const-string v12, "E"

    .line 157
    .line 158
    :goto_2
    move-object/from16 v16, v12

    .line 159
    .line 160
    goto :goto_3

    .line 161
    :cond_4
    new-instance v0, La8/r0;

    .line 162
    .line 163
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 164
    .line 165
    .line 166
    throw v0

    .line 167
    :cond_5
    const-string v12, "W"

    .line 168
    .line 169
    goto :goto_2

    .line 170
    :cond_6
    const-string v12, "I"

    .line 171
    .line 172
    goto :goto_2

    .line 173
    :cond_7
    const-string v12, "D"

    .line 174
    .line 175
    goto :goto_2

    .line 176
    :cond_8
    const-string v12, "V"

    .line 177
    .line 178
    goto :goto_2

    .line 179
    :goto_3
    iget-object v12, v8, Lkj0/f;->c:Ljava/lang/String;

    .line 180
    .line 181
    iget-object v13, v8, Lkj0/f;->d:Ljava/lang/String;

    .line 182
    .line 183
    iget-object v15, v8, Lkj0/f;->a:Ljava/time/OffsetDateTime;

    .line 184
    .line 185
    move-object/from16 v18, v13

    .line 186
    .line 187
    new-instance v13, Lmj0/b;

    .line 188
    .line 189
    const/4 v14, 0x0

    .line 190
    move-object/from16 v17, v12

    .line 191
    .line 192
    invoke-direct/range {v13 .. v18}, Lmj0/b;-><init>(Ljava/lang/Long;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    iput-object v11, v0, Len0/q;->k:Ljava/lang/Object;

    .line 196
    .line 197
    iput-object v9, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 198
    .line 199
    const/4 v8, 0x0

    .line 200
    iput-object v8, v0, Len0/q;->l:Ljava/lang/Object;

    .line 201
    .line 202
    iput v2, v0, Len0/q;->g:I

    .line 203
    .line 204
    iput v7, v0, Len0/q;->h:I

    .line 205
    .line 206
    iput v5, v0, Len0/q;->i:I

    .line 207
    .line 208
    iget-object v7, v10, Lmj0/a;->a:Lla/u;

    .line 209
    .line 210
    new-instance v8, Ll2/v1;

    .line 211
    .line 212
    const/16 v12, 0x10

    .line 213
    .line 214
    invoke-direct {v8, v12, v10, v13}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    invoke-static {v0, v7, v4, v6, v8}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v7

    .line 221
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 222
    .line 223
    if-ne v7, v8, :cond_9

    .line 224
    .line 225
    goto :goto_4

    .line 226
    :cond_9
    move-object v7, v3

    .line 227
    :goto_4
    if-ne v7, v1, :cond_a

    .line 228
    .line 229
    goto :goto_5

    .line 230
    :cond_a
    move v8, v2

    .line 231
    move-object v2, v9

    .line 232
    move-object v7, v11

    .line 233
    goto/16 :goto_0

    .line 234
    .line 235
    :cond_b
    move-object v1, v3

    .line 236
    :goto_5
    return-object v1

    .line 237
    :pswitch_0
    iget-object v1, v0, Len0/q;->j:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v1, Ljava/util/ArrayList;

    .line 240
    .line 241
    iget-object v2, v0, Len0/q;->l:Ljava/lang/Object;

    .line 242
    .line 243
    check-cast v2, Lif0/f0;

    .line 244
    .line 245
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 246
    .line 247
    iget v4, v0, Len0/q;->i:I

    .line 248
    .line 249
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 250
    .line 251
    const/4 v6, 0x5

    .line 252
    const/4 v7, 0x4

    .line 253
    const/4 v8, 0x3

    .line 254
    const/4 v9, 0x2

    .line 255
    const/4 v10, 0x1

    .line 256
    const/4 v11, 0x0

    .line 257
    const/4 v12, 0x0

    .line 258
    if-eqz v4, :cond_11

    .line 259
    .line 260
    if-eq v4, v10, :cond_10

    .line 261
    .line 262
    if-eq v4, v9, :cond_f

    .line 263
    .line 264
    if-eq v4, v8, :cond_e

    .line 265
    .line 266
    if-eq v4, v7, :cond_d

    .line 267
    .line 268
    if-ne v4, v6, :cond_c

    .line 269
    .line 270
    iget v1, v0, Len0/q;->g:I

    .line 271
    .line 272
    iget-object v4, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 273
    .line 274
    iget-object v8, v0, Len0/q;->k:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast v8, Lif0/f0;

    .line 277
    .line 278
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 279
    .line 280
    .line 281
    move v9, v1

    .line 282
    move-object v1, v4

    .line 283
    move-object v4, v8

    .line 284
    move v8, v10

    .line 285
    goto/16 :goto_11

    .line 286
    .line 287
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 288
    .line 289
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 290
    .line 291
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    throw v0

    .line 295
    :cond_d
    iget v1, v0, Len0/q;->h:I

    .line 296
    .line 297
    iget v4, v0, Len0/q;->g:I

    .line 298
    .line 299
    iget-object v8, v0, Len0/q;->f:Ljava/lang/Object;

    .line 300
    .line 301
    check-cast v8, Ljava/lang/String;

    .line 302
    .line 303
    iget-object v9, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 304
    .line 305
    iget-object v13, v0, Len0/q;->k:Ljava/lang/Object;

    .line 306
    .line 307
    check-cast v13, Lif0/f0;

    .line 308
    .line 309
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 310
    .line 311
    .line 312
    move v10, v4

    .line 313
    move v4, v1

    .line 314
    move v1, v10

    .line 315
    move-object/from16 v10, p1

    .line 316
    .line 317
    goto/16 :goto_f

    .line 318
    .line 319
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 320
    .line 321
    .line 322
    move-object/from16 v4, p1

    .line 323
    .line 324
    goto :goto_8

    .line 325
    :cond_f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    move-object/from16 v4, p1

    .line 329
    .line 330
    goto :goto_7

    .line 331
    :cond_10
    iget v4, v0, Len0/q;->g:I

    .line 332
    .line 333
    iget-object v13, v0, Len0/q;->f:Ljava/lang/Object;

    .line 334
    .line 335
    check-cast v13, Ljava/lang/String;

    .line 336
    .line 337
    check-cast v13, Lss0/k;

    .line 338
    .line 339
    iget-object v13, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 340
    .line 341
    iget-object v14, v0, Len0/q;->k:Ljava/lang/Object;

    .line 342
    .line 343
    check-cast v14, Lif0/f0;

    .line 344
    .line 345
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 346
    .line 347
    .line 348
    goto :goto_6

    .line 349
    :cond_11
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 350
    .line 351
    .line 352
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 353
    .line 354
    .line 355
    move-result-object v4

    .line 356
    move-object v14, v2

    .line 357
    move-object v13, v4

    .line 358
    move v4, v11

    .line 359
    :cond_12
    :goto_6
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 360
    .line 361
    .line 362
    move-result v15

    .line 363
    if-eqz v15, :cond_13

    .line 364
    .line 365
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v15

    .line 369
    check-cast v15, Lss0/k;

    .line 370
    .line 371
    iput-object v14, v0, Len0/q;->k:Ljava/lang/Object;

    .line 372
    .line 373
    iput-object v13, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 374
    .line 375
    iput-object v12, v0, Len0/q;->f:Ljava/lang/Object;

    .line 376
    .line 377
    iput v4, v0, Len0/q;->g:I

    .line 378
    .line 379
    iput v11, v0, Len0/q;->h:I

    .line 380
    .line 381
    iput v10, v0, Len0/q;->i:I

    .line 382
    .line 383
    invoke-virtual {v14, v15, v0}, Lif0/f0;->f(Lss0/k;Lrx0/c;)Ljava/lang/Object;

    .line 384
    .line 385
    .line 386
    move-result-object v15

    .line 387
    if-ne v15, v3, :cond_12

    .line 388
    .line 389
    goto/16 :goto_12

    .line 390
    .line 391
    :cond_13
    iget-object v4, v2, Lif0/f0;->a:Lti0/a;

    .line 392
    .line 393
    iput-object v12, v0, Len0/q;->k:Ljava/lang/Object;

    .line 394
    .line 395
    iput-object v12, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 396
    .line 397
    iput-object v12, v0, Len0/q;->f:Ljava/lang/Object;

    .line 398
    .line 399
    iput v9, v0, Len0/q;->i:I

    .line 400
    .line 401
    invoke-interface {v4, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    move-result-object v4

    .line 405
    if-ne v4, v3, :cond_14

    .line 406
    .line 407
    goto/16 :goto_12

    .line 408
    .line 409
    :cond_14
    :goto_7
    check-cast v4, Lif0/m;

    .line 410
    .line 411
    iput v8, v0, Len0/q;->i:I

    .line 412
    .line 413
    iget-object v8, v4, Lif0/m;->a:Lla/u;

    .line 414
    .line 415
    new-instance v9, Lif0/k;

    .line 416
    .line 417
    const/4 v13, 0x0

    .line 418
    invoke-direct {v9, v4, v13}, Lif0/k;-><init>(Lif0/m;I)V

    .line 419
    .line 420
    .line 421
    invoke-static {v0, v8, v10, v10, v9}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 422
    .line 423
    .line 424
    move-result-object v4

    .line 425
    if-ne v4, v3, :cond_15

    .line 426
    .line 427
    goto/16 :goto_12

    .line 428
    .line 429
    :cond_15
    :goto_8
    check-cast v4, Ljava/lang/Iterable;

    .line 430
    .line 431
    new-instance v8, Ljava/util/ArrayList;

    .line 432
    .line 433
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 434
    .line 435
    .line 436
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 437
    .line 438
    .line 439
    move-result-object v4

    .line 440
    :goto_9
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 441
    .line 442
    .line 443
    move-result v9

    .line 444
    if-eqz v9, :cond_19

    .line 445
    .line 446
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 447
    .line 448
    .line 449
    move-result-object v9

    .line 450
    move-object v13, v9

    .line 451
    check-cast v13, Lif0/n;

    .line 452
    .line 453
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 454
    .line 455
    .line 456
    move-result v14

    .line 457
    if-eqz v14, :cond_16

    .line 458
    .line 459
    goto :goto_c

    .line 460
    :cond_16
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 461
    .line 462
    .line 463
    move-result-object v14

    .line 464
    :goto_a
    invoke-interface {v14}, Ljava/util/Iterator;->hasNext()Z

    .line 465
    .line 466
    .line 467
    move-result v15

    .line 468
    if-eqz v15, :cond_18

    .line 469
    .line 470
    invoke-interface {v14}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 471
    .line 472
    .line 473
    move-result-object v15

    .line 474
    check-cast v15, Lss0/k;

    .line 475
    .line 476
    iget-object v15, v15, Lss0/k;->a:Ljava/lang/String;

    .line 477
    .line 478
    iget-object v10, v13, Lif0/n;->a:Lif0/o;

    .line 479
    .line 480
    iget-object v10, v10, Lif0/o;->a:Ljava/lang/String;

    .line 481
    .line 482
    invoke-static {v15, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 483
    .line 484
    .line 485
    move-result v10

    .line 486
    if-eqz v10, :cond_17

    .line 487
    .line 488
    :goto_b
    const/4 v10, 0x1

    .line 489
    goto :goto_9

    .line 490
    :cond_17
    const/4 v10, 0x1

    .line 491
    goto :goto_a

    .line 492
    :cond_18
    :goto_c
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 493
    .line 494
    .line 495
    goto :goto_b

    .line 496
    :cond_19
    new-instance v1, Ljava/util/ArrayList;

    .line 497
    .line 498
    const/16 v4, 0xa

    .line 499
    .line 500
    invoke-static {v8, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 501
    .line 502
    .line 503
    move-result v4

    .line 504
    invoke-direct {v1, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 505
    .line 506
    .line 507
    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 508
    .line 509
    .line 510
    move-result-object v4

    .line 511
    :goto_d
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 512
    .line 513
    .line 514
    move-result v8

    .line 515
    if-eqz v8, :cond_1a

    .line 516
    .line 517
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 518
    .line 519
    .line 520
    move-result-object v8

    .line 521
    check-cast v8, Lif0/n;

    .line 522
    .line 523
    iget-object v8, v8, Lif0/n;->a:Lif0/o;

    .line 524
    .line 525
    iget-object v8, v8, Lif0/o;->a:Ljava/lang/String;

    .line 526
    .line 527
    invoke-virtual {v1, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 528
    .line 529
    .line 530
    goto :goto_d

    .line 531
    :cond_1a
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 532
    .line 533
    .line 534
    move-result-object v1

    .line 535
    move-object v4, v2

    .line 536
    move v8, v11

    .line 537
    :goto_e
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 538
    .line 539
    .line 540
    move-result v9

    .line 541
    if-eqz v9, :cond_1e

    .line 542
    .line 543
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 544
    .line 545
    .line 546
    move-result-object v9

    .line 547
    check-cast v9, Ljava/lang/String;

    .line 548
    .line 549
    iget-object v10, v4, Lif0/f0;->a:Lti0/a;

    .line 550
    .line 551
    iput-object v4, v0, Len0/q;->k:Ljava/lang/Object;

    .line 552
    .line 553
    iput-object v1, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 554
    .line 555
    iput-object v9, v0, Len0/q;->f:Ljava/lang/Object;

    .line 556
    .line 557
    iput v8, v0, Len0/q;->g:I

    .line 558
    .line 559
    iput v11, v0, Len0/q;->h:I

    .line 560
    .line 561
    iput v7, v0, Len0/q;->i:I

    .line 562
    .line 563
    invoke-interface {v10, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 564
    .line 565
    .line 566
    move-result-object v10

    .line 567
    if-ne v10, v3, :cond_1b

    .line 568
    .line 569
    goto :goto_12

    .line 570
    :cond_1b
    move-object v13, v9

    .line 571
    move-object v9, v1

    .line 572
    move v1, v8

    .line 573
    move-object v8, v13

    .line 574
    move-object v13, v4

    .line 575
    move v4, v11

    .line 576
    :goto_f
    check-cast v10, Lif0/m;

    .line 577
    .line 578
    iput-object v13, v0, Len0/q;->k:Ljava/lang/Object;

    .line 579
    .line 580
    iput-object v9, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 581
    .line 582
    iput-object v12, v0, Len0/q;->f:Ljava/lang/Object;

    .line 583
    .line 584
    iput v1, v0, Len0/q;->g:I

    .line 585
    .line 586
    iput v4, v0, Len0/q;->h:I

    .line 587
    .line 588
    iput v6, v0, Len0/q;->i:I

    .line 589
    .line 590
    iget-object v4, v10, Lif0/m;->a:Lla/u;

    .line 591
    .line 592
    new-instance v10, Lif0/d;

    .line 593
    .line 594
    const/4 v14, 0x2

    .line 595
    invoke-direct {v10, v8, v14}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 596
    .line 597
    .line 598
    const/4 v8, 0x1

    .line 599
    invoke-static {v0, v4, v11, v8, v10}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 600
    .line 601
    .line 602
    move-result-object v4

    .line 603
    sget-object v10, Lqx0/a;->d:Lqx0/a;

    .line 604
    .line 605
    if-ne v4, v10, :cond_1c

    .line 606
    .line 607
    goto :goto_10

    .line 608
    :cond_1c
    move-object v4, v5

    .line 609
    :goto_10
    if-ne v4, v3, :cond_1d

    .line 610
    .line 611
    goto :goto_12

    .line 612
    :cond_1d
    move-object v4, v9

    .line 613
    move v9, v1

    .line 614
    move-object v1, v4

    .line 615
    move-object v4, v13

    .line 616
    :goto_11
    move v8, v9

    .line 617
    goto :goto_e

    .line 618
    :cond_1e
    iget-object v0, v2, Lif0/f0;->g:Lwe0/a;

    .line 619
    .line 620
    check-cast v0, Lwe0/c;

    .line 621
    .line 622
    invoke-virtual {v0}, Lwe0/c;->c()V

    .line 623
    .line 624
    .line 625
    move-object v3, v5

    .line 626
    :goto_12
    return-object v3

    .line 627
    :pswitch_1
    iget-object v1, v0, Len0/q;->j:Ljava/lang/Object;

    .line 628
    .line 629
    check-cast v1, Ljava/util/ArrayList;

    .line 630
    .line 631
    iget-object v2, v0, Len0/q;->l:Ljava/lang/Object;

    .line 632
    .line 633
    check-cast v2, Len0/s;

    .line 634
    .line 635
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 636
    .line 637
    iget v4, v0, Len0/q;->i:I

    .line 638
    .line 639
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 640
    .line 641
    const/4 v6, 0x5

    .line 642
    const/4 v7, 0x4

    .line 643
    const/4 v8, 0x3

    .line 644
    const/4 v9, 0x2

    .line 645
    const/4 v10, 0x1

    .line 646
    const/4 v11, 0x0

    .line 647
    const/4 v12, 0x0

    .line 648
    if-eqz v4, :cond_24

    .line 649
    .line 650
    if-eq v4, v10, :cond_23

    .line 651
    .line 652
    if-eq v4, v9, :cond_22

    .line 653
    .line 654
    if-eq v4, v8, :cond_21

    .line 655
    .line 656
    if-eq v4, v7, :cond_20

    .line 657
    .line 658
    if-ne v4, v6, :cond_1f

    .line 659
    .line 660
    iget v1, v0, Len0/q;->g:I

    .line 661
    .line 662
    iget-object v4, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 663
    .line 664
    iget-object v8, v0, Len0/q;->k:Ljava/lang/Object;

    .line 665
    .line 666
    check-cast v8, Len0/s;

    .line 667
    .line 668
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 669
    .line 670
    .line 671
    move v9, v1

    .line 672
    move-object v1, v4

    .line 673
    move-object v4, v8

    .line 674
    move v8, v10

    .line 675
    goto/16 :goto_1e

    .line 676
    .line 677
    :cond_1f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 678
    .line 679
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 680
    .line 681
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 682
    .line 683
    .line 684
    throw v0

    .line 685
    :cond_20
    iget v1, v0, Len0/q;->h:I

    .line 686
    .line 687
    iget v4, v0, Len0/q;->g:I

    .line 688
    .line 689
    iget-object v8, v0, Len0/q;->f:Ljava/lang/Object;

    .line 690
    .line 691
    check-cast v8, Ljava/lang/String;

    .line 692
    .line 693
    iget-object v9, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 694
    .line 695
    iget-object v13, v0, Len0/q;->k:Ljava/lang/Object;

    .line 696
    .line 697
    check-cast v13, Len0/s;

    .line 698
    .line 699
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 700
    .line 701
    .line 702
    move v10, v4

    .line 703
    move v4, v1

    .line 704
    move v1, v10

    .line 705
    move-object/from16 v10, p1

    .line 706
    .line 707
    goto/16 :goto_1c

    .line 708
    .line 709
    :cond_21
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 710
    .line 711
    .line 712
    move-object/from16 v4, p1

    .line 713
    .line 714
    goto :goto_15

    .line 715
    :cond_22
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 716
    .line 717
    .line 718
    move-object/from16 v4, p1

    .line 719
    .line 720
    goto :goto_14

    .line 721
    :cond_23
    iget v4, v0, Len0/q;->g:I

    .line 722
    .line 723
    iget-object v13, v0, Len0/q;->f:Ljava/lang/Object;

    .line 724
    .line 725
    check-cast v13, Ljava/lang/String;

    .line 726
    .line 727
    check-cast v13, Lss0/u;

    .line 728
    .line 729
    iget-object v13, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 730
    .line 731
    iget-object v14, v0, Len0/q;->k:Ljava/lang/Object;

    .line 732
    .line 733
    check-cast v14, Len0/s;

    .line 734
    .line 735
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 736
    .line 737
    .line 738
    goto :goto_13

    .line 739
    :cond_24
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 740
    .line 741
    .line 742
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 743
    .line 744
    .line 745
    move-result-object v4

    .line 746
    move-object v14, v2

    .line 747
    move-object v13, v4

    .line 748
    move v4, v11

    .line 749
    :cond_25
    :goto_13
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 750
    .line 751
    .line 752
    move-result v15

    .line 753
    if-eqz v15, :cond_26

    .line 754
    .line 755
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 756
    .line 757
    .line 758
    move-result-object v15

    .line 759
    check-cast v15, Lss0/u;

    .line 760
    .line 761
    iput-object v14, v0, Len0/q;->k:Ljava/lang/Object;

    .line 762
    .line 763
    iput-object v13, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 764
    .line 765
    iput-object v12, v0, Len0/q;->f:Ljava/lang/Object;

    .line 766
    .line 767
    iput v4, v0, Len0/q;->g:I

    .line 768
    .line 769
    iput v11, v0, Len0/q;->h:I

    .line 770
    .line 771
    iput v10, v0, Len0/q;->i:I

    .line 772
    .line 773
    invoke-virtual {v14, v15, v0}, Len0/s;->d(Lss0/u;Lrx0/c;)Ljava/lang/Object;

    .line 774
    .line 775
    .line 776
    move-result-object v15

    .line 777
    if-ne v15, v3, :cond_25

    .line 778
    .line 779
    goto/16 :goto_1f

    .line 780
    .line 781
    :cond_26
    iget-object v4, v2, Len0/s;->a:Lti0/a;

    .line 782
    .line 783
    iput-object v12, v0, Len0/q;->k:Ljava/lang/Object;

    .line 784
    .line 785
    iput-object v12, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 786
    .line 787
    iput-object v12, v0, Len0/q;->f:Ljava/lang/Object;

    .line 788
    .line 789
    iput v9, v0, Len0/q;->i:I

    .line 790
    .line 791
    invoke-interface {v4, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 792
    .line 793
    .line 794
    move-result-object v4

    .line 795
    if-ne v4, v3, :cond_27

    .line 796
    .line 797
    goto/16 :goto_1f

    .line 798
    .line 799
    :cond_27
    :goto_14
    check-cast v4, Len0/g;

    .line 800
    .line 801
    iput v8, v0, Len0/q;->i:I

    .line 802
    .line 803
    iget-object v8, v4, Len0/g;->a:Lla/u;

    .line 804
    .line 805
    new-instance v9, Len0/f;

    .line 806
    .line 807
    const/4 v13, 0x1

    .line 808
    invoke-direct {v9, v4, v13}, Len0/f;-><init>(Len0/g;I)V

    .line 809
    .line 810
    .line 811
    invoke-static {v0, v8, v10, v10, v9}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 812
    .line 813
    .line 814
    move-result-object v4

    .line 815
    if-ne v4, v3, :cond_28

    .line 816
    .line 817
    goto/16 :goto_1f

    .line 818
    .line 819
    :cond_28
    :goto_15
    check-cast v4, Ljava/lang/Iterable;

    .line 820
    .line 821
    new-instance v8, Ljava/util/ArrayList;

    .line 822
    .line 823
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 824
    .line 825
    .line 826
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 827
    .line 828
    .line 829
    move-result-object v4

    .line 830
    :goto_16
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 831
    .line 832
    .line 833
    move-result v9

    .line 834
    if-eqz v9, :cond_2c

    .line 835
    .line 836
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 837
    .line 838
    .line 839
    move-result-object v9

    .line 840
    move-object v13, v9

    .line 841
    check-cast v13, Len0/h;

    .line 842
    .line 843
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 844
    .line 845
    .line 846
    move-result v14

    .line 847
    if-eqz v14, :cond_29

    .line 848
    .line 849
    goto :goto_19

    .line 850
    :cond_29
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 851
    .line 852
    .line 853
    move-result-object v14

    .line 854
    :goto_17
    invoke-interface {v14}, Ljava/util/Iterator;->hasNext()Z

    .line 855
    .line 856
    .line 857
    move-result v15

    .line 858
    if-eqz v15, :cond_2b

    .line 859
    .line 860
    invoke-interface {v14}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 861
    .line 862
    .line 863
    move-result-object v15

    .line 864
    check-cast v15, Lss0/u;

    .line 865
    .line 866
    iget-object v15, v15, Lss0/u;->a:Ljava/lang/String;

    .line 867
    .line 868
    iget-object v10, v13, Len0/h;->a:Len0/i;

    .line 869
    .line 870
    iget-object v10, v10, Len0/i;->a:Ljava/lang/String;

    .line 871
    .line 872
    invoke-static {v15, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 873
    .line 874
    .line 875
    move-result v10

    .line 876
    if-eqz v10, :cond_2a

    .line 877
    .line 878
    :goto_18
    const/4 v10, 0x1

    .line 879
    goto :goto_16

    .line 880
    :cond_2a
    const/4 v10, 0x1

    .line 881
    goto :goto_17

    .line 882
    :cond_2b
    :goto_19
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 883
    .line 884
    .line 885
    goto :goto_18

    .line 886
    :cond_2c
    new-instance v1, Ljava/util/ArrayList;

    .line 887
    .line 888
    const/16 v4, 0xa

    .line 889
    .line 890
    invoke-static {v8, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 891
    .line 892
    .line 893
    move-result v4

    .line 894
    invoke-direct {v1, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 895
    .line 896
    .line 897
    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 898
    .line 899
    .line 900
    move-result-object v4

    .line 901
    :goto_1a
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 902
    .line 903
    .line 904
    move-result v8

    .line 905
    if-eqz v8, :cond_2d

    .line 906
    .line 907
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 908
    .line 909
    .line 910
    move-result-object v8

    .line 911
    check-cast v8, Len0/h;

    .line 912
    .line 913
    iget-object v8, v8, Len0/h;->a:Len0/i;

    .line 914
    .line 915
    iget-object v8, v8, Len0/i;->a:Ljava/lang/String;

    .line 916
    .line 917
    invoke-virtual {v1, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 918
    .line 919
    .line 920
    goto :goto_1a

    .line 921
    :cond_2d
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 922
    .line 923
    .line 924
    move-result-object v1

    .line 925
    move-object v4, v2

    .line 926
    move v8, v11

    .line 927
    :goto_1b
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 928
    .line 929
    .line 930
    move-result v9

    .line 931
    if-eqz v9, :cond_31

    .line 932
    .line 933
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 934
    .line 935
    .line 936
    move-result-object v9

    .line 937
    check-cast v9, Ljava/lang/String;

    .line 938
    .line 939
    iget-object v10, v4, Len0/s;->a:Lti0/a;

    .line 940
    .line 941
    iput-object v4, v0, Len0/q;->k:Ljava/lang/Object;

    .line 942
    .line 943
    iput-object v1, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 944
    .line 945
    iput-object v9, v0, Len0/q;->f:Ljava/lang/Object;

    .line 946
    .line 947
    iput v8, v0, Len0/q;->g:I

    .line 948
    .line 949
    iput v11, v0, Len0/q;->h:I

    .line 950
    .line 951
    iput v7, v0, Len0/q;->i:I

    .line 952
    .line 953
    invoke-interface {v10, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 954
    .line 955
    .line 956
    move-result-object v10

    .line 957
    if-ne v10, v3, :cond_2e

    .line 958
    .line 959
    goto :goto_1f

    .line 960
    :cond_2e
    move-object v13, v9

    .line 961
    move-object v9, v1

    .line 962
    move v1, v8

    .line 963
    move-object v8, v13

    .line 964
    move-object v13, v4

    .line 965
    move v4, v11

    .line 966
    :goto_1c
    check-cast v10, Len0/g;

    .line 967
    .line 968
    iput-object v13, v0, Len0/q;->k:Ljava/lang/Object;

    .line 969
    .line 970
    iput-object v9, v0, Len0/q;->e:Ljava/util/Iterator;

    .line 971
    .line 972
    iput-object v12, v0, Len0/q;->f:Ljava/lang/Object;

    .line 973
    .line 974
    iput v1, v0, Len0/q;->g:I

    .line 975
    .line 976
    iput v4, v0, Len0/q;->h:I

    .line 977
    .line 978
    iput v6, v0, Len0/q;->i:I

    .line 979
    .line 980
    iget-object v4, v10, Len0/g;->a:Lla/u;

    .line 981
    .line 982
    new-instance v10, Lac0/r;

    .line 983
    .line 984
    const/16 v14, 0x8

    .line 985
    .line 986
    invoke-direct {v10, v8, v14}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 987
    .line 988
    .line 989
    const/4 v8, 0x1

    .line 990
    invoke-static {v0, v4, v11, v8, v10}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 991
    .line 992
    .line 993
    move-result-object v4

    .line 994
    sget-object v10, Lqx0/a;->d:Lqx0/a;

    .line 995
    .line 996
    if-ne v4, v10, :cond_2f

    .line 997
    .line 998
    goto :goto_1d

    .line 999
    :cond_2f
    move-object v4, v5

    .line 1000
    :goto_1d
    if-ne v4, v3, :cond_30

    .line 1001
    .line 1002
    goto :goto_1f

    .line 1003
    :cond_30
    move-object v4, v9

    .line 1004
    move v9, v1

    .line 1005
    move-object v1, v4

    .line 1006
    move-object v4, v13

    .line 1007
    :goto_1e
    move v8, v9

    .line 1008
    goto :goto_1b

    .line 1009
    :cond_31
    iget-object v0, v2, Len0/s;->e:Lwe0/a;

    .line 1010
    .line 1011
    check-cast v0, Lwe0/c;

    .line 1012
    .line 1013
    invoke-virtual {v0}, Lwe0/c;->c()V

    .line 1014
    .line 1015
    .line 1016
    move-object v3, v5

    .line 1017
    :goto_1f
    return-object v3

    .line 1018
    nop

    .line 1019
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
