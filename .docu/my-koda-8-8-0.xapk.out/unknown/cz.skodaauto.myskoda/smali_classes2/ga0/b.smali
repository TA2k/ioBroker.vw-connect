.class public final Lga0/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lga0/o;


# direct methods
.method public synthetic constructor <init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lga0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lga0/b;->g:Lga0/o;

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
    iget v0, p0, Lga0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lga0/b;

    .line 7
    .line 8
    iget-object p0, p0, Lga0/b;->g:Lga0/o;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lga0/b;-><init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lga0/b;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lga0/b;

    .line 18
    .line 19
    iget-object p0, p0, Lga0/b;->g:Lga0/o;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lga0/b;-><init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lga0/b;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lga0/b;

    .line 29
    .line 30
    iget-object p0, p0, Lga0/b;->g:Lga0/o;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    invoke-direct {v0, p0, p2, v1}, Lga0/b;-><init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lga0/b;->f:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lga0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lga0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lga0/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lga0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lga0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lga0/b;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lga0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Llf0/i;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lga0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lga0/b;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lga0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
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
    iget v1, v0, Lga0/b;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lga0/b;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lvy0/b0;

    .line 11
    .line 12
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v3, v0, Lga0/b;->e:I

    .line 15
    .line 16
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    const/4 v5, 0x2

    .line 19
    const/4 v6, 0x1

    .line 20
    const/4 v7, 0x0

    .line 21
    iget-object v8, v0, Lga0/b;->g:Lga0/o;

    .line 22
    .line 23
    if-eqz v3, :cond_3

    .line 24
    .line 25
    if-eq v3, v6, :cond_2

    .line 26
    .line 27
    if-ne v3, v5, :cond_1

    .line 28
    .line 29
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_0
    move-object v2, v4

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 37
    .line 38
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw v0

    .line 42
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    move-object/from16 v1, p1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    new-instance v3, Lga0/a;

    .line 52
    .line 53
    const/4 v9, 0x6

    .line 54
    invoke-direct {v3, v8, v9}, Lga0/a;-><init>(Lga0/o;I)V

    .line 55
    .line 56
    .line 57
    invoke-static {v1, v3}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 58
    .line 59
    .line 60
    iget-object v1, v8, Lga0/o;->q:Lrt0/y;

    .line 61
    .line 62
    iput-object v7, v0, Lga0/b;->f:Ljava/lang/Object;

    .line 63
    .line 64
    iput v6, v0, Lga0/b;->e:I

    .line 65
    .line 66
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v1, v0}, Lrt0/y;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    if-ne v1, v2, :cond_4

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_4
    :goto_0
    check-cast v1, Lne0/t;

    .line 77
    .line 78
    instance-of v3, v1, Lne0/e;

    .line 79
    .line 80
    if-eqz v3, :cond_5

    .line 81
    .line 82
    move-object v3, v1

    .line 83
    check-cast v3, Lne0/e;

    .line 84
    .line 85
    iget-object v3, v3, Lne0/e;->a:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v3, Llx0/b0;

    .line 88
    .line 89
    invoke-virtual {v8}, Lql0/j;->a()Lql0/h;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    move-object v9, v3

    .line 94
    check-cast v9, Lga0/i;

    .line 95
    .line 96
    const-string v3, "<this>"

    .line 97
    .line 98
    invoke-static {v9, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    sget-object v13, Lga0/e;->i:Lga0/e;

    .line 102
    .line 103
    const/16 v18, 0x0

    .line 104
    .line 105
    const/16 v19, 0x1b7

    .line 106
    .line 107
    const/4 v10, 0x0

    .line 108
    const/4 v11, 0x0

    .line 109
    const/4 v12, 0x0

    .line 110
    const/4 v14, 0x0

    .line 111
    const/4 v15, 0x0

    .line 112
    const/16 v16, 0x0

    .line 113
    .line 114
    const/16 v17, 0x0

    .line 115
    .line 116
    invoke-static/range {v9 .. v19}, Lga0/i;->a(Lga0/i;Lql0/g;ZLlf0/i;Lga0/e;Ljava/util/List;ZZZZI)Lga0/i;

    .line 117
    .line 118
    .line 119
    move-result-object v3

    .line 120
    invoke-virtual {v8, v3}, Lql0/j;->g(Lql0/h;)V

    .line 121
    .line 122
    .line 123
    :cond_5
    instance-of v3, v1, Lne0/c;

    .line 124
    .line 125
    if-eqz v3, :cond_0

    .line 126
    .line 127
    check-cast v1, Lne0/c;

    .line 128
    .line 129
    iput-object v7, v0, Lga0/b;->f:Ljava/lang/Object;

    .line 130
    .line 131
    iput v5, v0, Lga0/b;->e:I

    .line 132
    .line 133
    invoke-static {v8, v1, v0}, Lga0/o;->h(Lga0/o;Lne0/c;Lrx0/i;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    if-ne v0, v2, :cond_0

    .line 138
    .line 139
    :goto_1
    return-object v2

    .line 140
    :pswitch_0
    iget-object v1, v0, Lga0/b;->f:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v1, Lvy0/b0;

    .line 143
    .line 144
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 145
    .line 146
    iget v3, v0, Lga0/b;->e:I

    .line 147
    .line 148
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 149
    .line 150
    const/4 v5, 0x2

    .line 151
    const/4 v6, 0x1

    .line 152
    const/4 v7, 0x0

    .line 153
    iget-object v8, v0, Lga0/b;->g:Lga0/o;

    .line 154
    .line 155
    if-eqz v3, :cond_9

    .line 156
    .line 157
    if-eq v3, v6, :cond_8

    .line 158
    .line 159
    if-ne v3, v5, :cond_7

    .line 160
    .line 161
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    :cond_6
    move-object v2, v4

    .line 165
    goto :goto_3

    .line 166
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 167
    .line 168
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 169
    .line 170
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    throw v0

    .line 174
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    move-object/from16 v1, p1

    .line 178
    .line 179
    goto :goto_2

    .line 180
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    new-instance v3, Lga0/a;

    .line 184
    .line 185
    const/4 v9, 0x5

    .line 186
    invoke-direct {v3, v8, v9}, Lga0/a;-><init>(Lga0/o;I)V

    .line 187
    .line 188
    .line 189
    invoke-static {v1, v3}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 190
    .line 191
    .line 192
    iget-object v1, v8, Lga0/o;->p:Lrt0/m;

    .line 193
    .line 194
    iput-object v7, v0, Lga0/b;->f:Ljava/lang/Object;

    .line 195
    .line 196
    iput v6, v0, Lga0/b;->e:I

    .line 197
    .line 198
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 199
    .line 200
    .line 201
    invoke-virtual {v1, v0}, Lrt0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    if-ne v1, v2, :cond_a

    .line 206
    .line 207
    goto :goto_3

    .line 208
    :cond_a
    :goto_2
    check-cast v1, Lne0/t;

    .line 209
    .line 210
    instance-of v3, v1, Lne0/e;

    .line 211
    .line 212
    if-eqz v3, :cond_b

    .line 213
    .line 214
    move-object v3, v1

    .line 215
    check-cast v3, Lne0/e;

    .line 216
    .line 217
    iget-object v3, v3, Lne0/e;->a:Ljava/lang/Object;

    .line 218
    .line 219
    check-cast v3, Llx0/b0;

    .line 220
    .line 221
    invoke-virtual {v8}, Lql0/j;->a()Lql0/h;

    .line 222
    .line 223
    .line 224
    move-result-object v3

    .line 225
    move-object v9, v3

    .line 226
    check-cast v9, Lga0/i;

    .line 227
    .line 228
    const-string v3, "<this>"

    .line 229
    .line 230
    invoke-static {v9, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    sget-object v13, Lga0/e;->h:Lga0/e;

    .line 234
    .line 235
    const/16 v18, 0x0

    .line 236
    .line 237
    const/16 v19, 0x1b7

    .line 238
    .line 239
    const/4 v10, 0x0

    .line 240
    const/4 v11, 0x0

    .line 241
    const/4 v12, 0x0

    .line 242
    const/4 v14, 0x0

    .line 243
    const/4 v15, 0x0

    .line 244
    const/16 v16, 0x0

    .line 245
    .line 246
    const/16 v17, 0x0

    .line 247
    .line 248
    invoke-static/range {v9 .. v19}, Lga0/i;->a(Lga0/i;Lql0/g;ZLlf0/i;Lga0/e;Ljava/util/List;ZZZZI)Lga0/i;

    .line 249
    .line 250
    .line 251
    move-result-object v3

    .line 252
    invoke-virtual {v8, v3}, Lql0/j;->g(Lql0/h;)V

    .line 253
    .line 254
    .line 255
    :cond_b
    instance-of v3, v1, Lne0/c;

    .line 256
    .line 257
    if-eqz v3, :cond_6

    .line 258
    .line 259
    check-cast v1, Lne0/c;

    .line 260
    .line 261
    iput-object v7, v0, Lga0/b;->f:Ljava/lang/Object;

    .line 262
    .line 263
    iput v5, v0, Lga0/b;->e:I

    .line 264
    .line 265
    invoke-static {v8, v1, v0}, Lga0/o;->h(Lga0/o;Lne0/c;Lrx0/i;)Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object v0

    .line 269
    if-ne v0, v2, :cond_6

    .line 270
    .line 271
    :goto_3
    return-object v2

    .line 272
    :pswitch_1
    iget-object v1, v0, Lga0/b;->f:Ljava/lang/Object;

    .line 273
    .line 274
    move-object v5, v1

    .line 275
    check-cast v5, Llf0/i;

    .line 276
    .line 277
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 278
    .line 279
    iget v2, v0, Lga0/b;->e:I

    .line 280
    .line 281
    iget-object v13, v0, Lga0/b;->g:Lga0/o;

    .line 282
    .line 283
    const/4 v3, 0x2

    .line 284
    sget-object v14, Llx0/b0;->a:Llx0/b0;

    .line 285
    .line 286
    const/4 v15, 0x1

    .line 287
    if-eqz v2, :cond_f

    .line 288
    .line 289
    if-eq v2, v15, :cond_e

    .line 290
    .line 291
    if-ne v2, v3, :cond_d

    .line 292
    .line 293
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 294
    .line 295
    .line 296
    :cond_c
    move-object v1, v14

    .line 297
    goto/16 :goto_7

    .line 298
    .line 299
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 300
    .line 301
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 302
    .line 303
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 304
    .line 305
    .line 306
    throw v0

    .line 307
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 308
    .line 309
    .line 310
    move-object/from16 v2, p1

    .line 311
    .line 312
    goto :goto_4

    .line 313
    :cond_f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 314
    .line 315
    .line 316
    iget-object v2, v13, Lga0/o;->l:Lkf0/k;

    .line 317
    .line 318
    iput-object v5, v0, Lga0/b;->f:Ljava/lang/Object;

    .line 319
    .line 320
    iput v15, v0, Lga0/b;->e:I

    .line 321
    .line 322
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 323
    .line 324
    .line 325
    invoke-virtual {v2, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v2

    .line 329
    if-ne v2, v1, :cond_10

    .line 330
    .line 331
    goto :goto_7

    .line 332
    :cond_10
    :goto_4
    check-cast v2, Lss0/b;

    .line 333
    .line 334
    invoke-static {v2}, Lst0/o;->a(Lss0/b;)Z

    .line 335
    .line 336
    .line 337
    move-result v8

    .line 338
    const/4 v2, 0x0

    .line 339
    iput-object v2, v0, Lga0/b;->f:Ljava/lang/Object;

    .line 340
    .line 341
    iput v3, v0, Lga0/b;->e:I

    .line 342
    .line 343
    invoke-virtual {v13}, Lql0/j;->a()Lql0/h;

    .line 344
    .line 345
    .line 346
    move-result-object v3

    .line 347
    check-cast v3, Lga0/i;

    .line 348
    .line 349
    const/4 v11, 0x0

    .line 350
    const/16 v12, 0x1db

    .line 351
    .line 352
    move-object v4, v2

    .line 353
    move-object v2, v3

    .line 354
    const/4 v3, 0x0

    .line 355
    move-object v6, v4

    .line 356
    const/4 v4, 0x0

    .line 357
    move-object v7, v6

    .line 358
    const/4 v6, 0x0

    .line 359
    move-object v9, v7

    .line 360
    const/4 v7, 0x0

    .line 361
    move-object v10, v9

    .line 362
    const/4 v9, 0x0

    .line 363
    move-object/from16 v16, v10

    .line 364
    .line 365
    const/4 v10, 0x0

    .line 366
    invoke-static/range {v2 .. v12}, Lga0/i;->a(Lga0/i;Lql0/g;ZLlf0/i;Lga0/e;Ljava/util/List;ZZZZI)Lga0/i;

    .line 367
    .line 368
    .line 369
    move-result-object v2

    .line 370
    invoke-virtual {v13, v2}, Lql0/j;->g(Lql0/h;)V

    .line 371
    .line 372
    .line 373
    sget-object v2, Lga0/j;->a:[I

    .line 374
    .line 375
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 376
    .line 377
    .line 378
    move-result v3

    .line 379
    aget v2, v2, v3

    .line 380
    .line 381
    if-ne v2, v15, :cond_12

    .line 382
    .line 383
    new-instance v2, Le30/p;

    .line 384
    .line 385
    const/16 v3, 0x11

    .line 386
    .line 387
    const/4 v4, 0x0

    .line 388
    invoke-direct {v2, v13, v4, v3}, Le30/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 389
    .line 390
    .line 391
    invoke-static {v2, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v0

    .line 395
    if-ne v0, v1, :cond_11

    .line 396
    .line 397
    goto :goto_6

    .line 398
    :cond_11
    :goto_5
    move-object v0, v14

    .line 399
    goto :goto_6

    .line 400
    :cond_12
    invoke-virtual {v13}, Lql0/j;->a()Lql0/h;

    .line 401
    .line 402
    .line 403
    move-result-object v0

    .line 404
    move-object v2, v0

    .line 405
    check-cast v2, Lga0/i;

    .line 406
    .line 407
    const/4 v11, 0x0

    .line 408
    const/16 v12, 0x1fd

    .line 409
    .line 410
    const/4 v3, 0x0

    .line 411
    const/4 v4, 0x0

    .line 412
    const/4 v5, 0x0

    .line 413
    const/4 v6, 0x0

    .line 414
    const/4 v7, 0x0

    .line 415
    const/4 v8, 0x0

    .line 416
    const/4 v9, 0x0

    .line 417
    const/4 v10, 0x0

    .line 418
    invoke-static/range {v2 .. v12}, Lga0/i;->a(Lga0/i;Lql0/g;ZLlf0/i;Lga0/e;Ljava/util/List;ZZZZI)Lga0/i;

    .line 419
    .line 420
    .line 421
    move-result-object v0

    .line 422
    invoke-virtual {v13, v0}, Lql0/j;->g(Lql0/h;)V

    .line 423
    .line 424
    .line 425
    goto :goto_5

    .line 426
    :goto_6
    if-ne v0, v1, :cond_c

    .line 427
    .line 428
    :goto_7
    return-object v1

    .line 429
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
