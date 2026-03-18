.class public final Lga0/r;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lga0/h0;


# direct methods
.method public synthetic constructor <init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lga0/r;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lga0/r;->g:Lga0/h0;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lga0/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lga0/r;

    .line 7
    .line 8
    iget-object p0, p0, Lga0/r;->g:Lga0/h0;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    invoke-direct {v0, v1, p0, p2}, Lga0/r;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lga0/r;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lga0/r;

    .line 18
    .line 19
    iget-object p0, p0, Lga0/r;->g:Lga0/h0;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    invoke-direct {v0, v1, p0, p2}, Lga0/r;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lga0/r;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lga0/r;

    .line 29
    .line 30
    iget-object p0, p0, Lga0/r;->g:Lga0/h0;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    invoke-direct {v0, v1, p0, p2}, Lga0/r;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lga0/r;->f:Ljava/lang/Object;

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
    iget v0, p0, Lga0/r;->d:I

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
    invoke-virtual {p0, p1, p2}, Lga0/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lga0/r;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lga0/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lga0/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lga0/r;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lga0/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lss0/b;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lga0/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lga0/r;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lga0/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lga0/r;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lga0/r;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lvy0/b0;

    .line 11
    .line 12
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v3, v0, Lga0/r;->e:I

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
    iget-object v8, v0, Lga0/r;->g:Lga0/h0;

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
    new-instance v3, Lf2/h0;

    .line 52
    .line 53
    const/16 v9, 0x17

    .line 54
    .line 55
    invoke-direct {v3, v9}, Lf2/h0;-><init>(I)V

    .line 56
    .line 57
    .line 58
    invoke-static {v1, v3}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 59
    .line 60
    .line 61
    iget-object v1, v8, Lga0/h0;->u:Lrt0/y;

    .line 62
    .line 63
    iput-object v7, v0, Lga0/r;->f:Ljava/lang/Object;

    .line 64
    .line 65
    iput v6, v0, Lga0/r;->e:I

    .line 66
    .line 67
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v1, v0}, Lrt0/y;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    if-ne v1, v2, :cond_4

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_4
    :goto_0
    check-cast v1, Lne0/t;

    .line 78
    .line 79
    instance-of v3, v1, Lne0/e;

    .line 80
    .line 81
    if-eqz v3, :cond_5

    .line 82
    .line 83
    move-object v3, v1

    .line 84
    check-cast v3, Lne0/e;

    .line 85
    .line 86
    iget-object v3, v3, Lne0/e;->a:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v3, Llx0/b0;

    .line 89
    .line 90
    invoke-virtual {v8}, Lql0/j;->a()Lql0/h;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    check-cast v3, Lga0/v;

    .line 95
    .line 96
    invoke-static {v3}, Lkp/t8;->f(Lga0/v;)Lga0/v;

    .line 97
    .line 98
    .line 99
    move-result-object v3

    .line 100
    invoke-virtual {v8, v3}, Lql0/j;->g(Lql0/h;)V

    .line 101
    .line 102
    .line 103
    :cond_5
    instance-of v3, v1, Lne0/c;

    .line 104
    .line 105
    if-eqz v3, :cond_0

    .line 106
    .line 107
    check-cast v1, Lne0/c;

    .line 108
    .line 109
    iput-object v7, v0, Lga0/r;->f:Ljava/lang/Object;

    .line 110
    .line 111
    iput v5, v0, Lga0/r;->e:I

    .line 112
    .line 113
    invoke-static {v8, v1, v0}, Lga0/h0;->j(Lga0/h0;Lne0/c;Lrx0/i;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    if-ne v0, v2, :cond_0

    .line 118
    .line 119
    :goto_1
    return-object v2

    .line 120
    :pswitch_0
    iget-object v1, v0, Lga0/r;->f:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v1, Lvy0/b0;

    .line 123
    .line 124
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 125
    .line 126
    iget v3, v0, Lga0/r;->e:I

    .line 127
    .line 128
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 129
    .line 130
    const/4 v5, 0x2

    .line 131
    const/4 v6, 0x1

    .line 132
    const/4 v7, 0x0

    .line 133
    iget-object v8, v0, Lga0/r;->g:Lga0/h0;

    .line 134
    .line 135
    if-eqz v3, :cond_9

    .line 136
    .line 137
    if-eq v3, v6, :cond_8

    .line 138
    .line 139
    if-ne v3, v5, :cond_7

    .line 140
    .line 141
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    :cond_6
    move-object v2, v4

    .line 145
    goto :goto_3

    .line 146
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 147
    .line 148
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 149
    .line 150
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    throw v0

    .line 154
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    move-object/from16 v1, p1

    .line 158
    .line 159
    goto :goto_2

    .line 160
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    new-instance v3, Lf2/h0;

    .line 164
    .line 165
    const/16 v9, 0x16

    .line 166
    .line 167
    invoke-direct {v3, v9}, Lf2/h0;-><init>(I)V

    .line 168
    .line 169
    .line 170
    invoke-static {v1, v3}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 171
    .line 172
    .line 173
    iget-object v1, v8, Lga0/h0;->t:Lrt0/m;

    .line 174
    .line 175
    iput-object v7, v0, Lga0/r;->f:Ljava/lang/Object;

    .line 176
    .line 177
    iput v6, v0, Lga0/r;->e:I

    .line 178
    .line 179
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 180
    .line 181
    .line 182
    invoke-virtual {v1, v0}, Lrt0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v1

    .line 186
    if-ne v1, v2, :cond_a

    .line 187
    .line 188
    goto :goto_3

    .line 189
    :cond_a
    :goto_2
    check-cast v1, Lne0/t;

    .line 190
    .line 191
    instance-of v3, v1, Lne0/e;

    .line 192
    .line 193
    if-eqz v3, :cond_b

    .line 194
    .line 195
    move-object v3, v1

    .line 196
    check-cast v3, Lne0/e;

    .line 197
    .line 198
    iget-object v3, v3, Lne0/e;->a:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v3, Llx0/b0;

    .line 201
    .line 202
    invoke-virtual {v8}, Lql0/j;->a()Lql0/h;

    .line 203
    .line 204
    .line 205
    move-result-object v3

    .line 206
    check-cast v3, Lga0/v;

    .line 207
    .line 208
    invoke-static {v3}, Lkp/t8;->e(Lga0/v;)Lga0/v;

    .line 209
    .line 210
    .line 211
    move-result-object v3

    .line 212
    invoke-virtual {v8, v3}, Lql0/j;->g(Lql0/h;)V

    .line 213
    .line 214
    .line 215
    :cond_b
    instance-of v3, v1, Lne0/c;

    .line 216
    .line 217
    if-eqz v3, :cond_6

    .line 218
    .line 219
    check-cast v1, Lne0/c;

    .line 220
    .line 221
    iput-object v7, v0, Lga0/r;->f:Ljava/lang/Object;

    .line 222
    .line 223
    iput v5, v0, Lga0/r;->e:I

    .line 224
    .line 225
    invoke-static {v8, v1, v0}, Lga0/h0;->j(Lga0/h0;Lne0/c;Lrx0/i;)Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    if-ne v0, v2, :cond_6

    .line 230
    .line 231
    :goto_3
    return-object v2

    .line 232
    :pswitch_1
    iget-object v1, v0, Lga0/r;->f:Ljava/lang/Object;

    .line 233
    .line 234
    check-cast v1, Lss0/b;

    .line 235
    .line 236
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 237
    .line 238
    iget v3, v0, Lga0/r;->e:I

    .line 239
    .line 240
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 241
    .line 242
    const/4 v5, 0x1

    .line 243
    if-eqz v3, :cond_e

    .line 244
    .line 245
    if-ne v3, v5, :cond_d

    .line 246
    .line 247
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 248
    .line 249
    .line 250
    :cond_c
    move-object v2, v4

    .line 251
    goto :goto_6

    .line 252
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 253
    .line 254
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 255
    .line 256
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    throw v0

    .line 260
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 261
    .line 262
    .line 263
    const/4 v3, 0x0

    .line 264
    iput-object v3, v0, Lga0/r;->f:Ljava/lang/Object;

    .line 265
    .line 266
    iput v5, v0, Lga0/r;->e:I

    .line 267
    .line 268
    sget-object v5, Lss0/e;->G1:Lss0/e;

    .line 269
    .line 270
    invoke-static {v1, v5}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 271
    .line 272
    .line 273
    move-result-object v5

    .line 274
    sget-object v6, Llf0/i;->j:Llf0/i;

    .line 275
    .line 276
    iget-object v7, v0, Lga0/r;->g:Lga0/h0;

    .line 277
    .line 278
    if-eq v5, v6, :cond_11

    .line 279
    .line 280
    sget-object v5, Lss0/e;->d:Lss0/e;

    .line 281
    .line 282
    invoke-static {v1, v5}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 283
    .line 284
    .line 285
    move-result-object v5

    .line 286
    if-ne v5, v6, :cond_f

    .line 287
    .line 288
    goto :goto_4

    .line 289
    :cond_f
    invoke-virtual {v7}, Lql0/j;->a()Lql0/h;

    .line 290
    .line 291
    .line 292
    move-result-object v0

    .line 293
    move-object v8, v0

    .line 294
    check-cast v8, Lga0/v;

    .line 295
    .line 296
    const-string v0, "<this>"

    .line 297
    .line 298
    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    sget-object v10, Lga0/t;->h:Lga0/t;

    .line 302
    .line 303
    const/16 v22, 0x0

    .line 304
    .line 305
    const v23, 0xffb9

    .line 306
    .line 307
    .line 308
    const/4 v9, 0x0

    .line 309
    const/4 v11, 0x0

    .line 310
    const/4 v12, 0x0

    .line 311
    const/4 v13, 0x0

    .line 312
    const/4 v14, 0x0

    .line 313
    const/4 v15, 0x0

    .line 314
    const/16 v16, 0x0

    .line 315
    .line 316
    const/16 v17, 0x0

    .line 317
    .line 318
    const/16 v18, 0x0

    .line 319
    .line 320
    const/16 v19, 0x0

    .line 321
    .line 322
    const/16 v20, 0x0

    .line 323
    .line 324
    const/16 v21, 0x0

    .line 325
    .line 326
    invoke-static/range {v8 .. v23}, Lga0/v;->a(Lga0/v;Landroid/net/Uri;Lga0/t;ZZZZZLga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Ljava/time/OffsetDateTime;I)Lga0/v;

    .line 327
    .line 328
    .line 329
    move-result-object v0

    .line 330
    invoke-virtual {v7, v0}, Lql0/j;->g(Lql0/h;)V

    .line 331
    .line 332
    .line 333
    :cond_10
    move-object v0, v4

    .line 334
    goto :goto_5

    .line 335
    :cond_11
    :goto_4
    new-instance v5, Laa/s;

    .line 336
    .line 337
    const/16 v6, 0x8

    .line 338
    .line 339
    invoke-direct {v5, v6, v7, v1, v3}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 340
    .line 341
    .line 342
    invoke-static {v5, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object v0

    .line 346
    if-ne v0, v2, :cond_10

    .line 347
    .line 348
    :goto_5
    if-ne v0, v2, :cond_c

    .line 349
    .line 350
    :goto_6
    return-object v2

    .line 351
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
