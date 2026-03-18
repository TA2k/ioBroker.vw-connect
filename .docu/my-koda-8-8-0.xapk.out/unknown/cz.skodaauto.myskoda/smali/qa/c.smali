.class public final Lqa/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ljava/lang/Object;

.field public g:Z

.field public h:Z

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lqa/c;->d:I

    .line 1
    iput-object p2, p0, Lqa/c;->f:Ljava/lang/Object;

    iput-boolean p3, p0, Lqa/c;->g:Z

    iput-boolean p4, p0, Lqa/c;->h:Z

    iput-object p5, p0, Lqa/c;->i:Ljava/lang/Object;

    const/4 p2, 0x2

    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lla/u;ZZLay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lqa/c;->d:I

    .line 2
    iput-object p1, p0, Lqa/c;->f:Ljava/lang/Object;

    iput-boolean p2, p0, Lqa/c;->g:Z

    iput-boolean p3, p0, Lqa/c;->h:Z

    iput-object p4, p0, Lqa/c;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Ltz/n0;Lkf0/z;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lqa/c;->d:I

    .line 3
    iput-object p1, p0, Lqa/c;->f:Ljava/lang/Object;

    iput-object p2, p0, Lqa/c;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget p1, p0, Lqa/c;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lqa/c;

    .line 7
    .line 8
    iget-object v0, p0, Lqa/c;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Ltz/n0;

    .line 11
    .line 12
    iget-object p0, p0, Lqa/c;->i:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lkf0/z;

    .line 15
    .line 16
    invoke-direct {p1, v0, p0, p2}, Lqa/c;-><init>(Ltz/n0;Lkf0/z;Lkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    return-object p1

    .line 20
    :pswitch_0
    new-instance v1, Lqa/c;

    .line 21
    .line 22
    iget-object p1, p0, Lqa/c;->f:Ljava/lang/Object;

    .line 23
    .line 24
    move-object v3, p1

    .line 25
    check-cast v3, Lla/u;

    .line 26
    .line 27
    iget-boolean v4, p0, Lqa/c;->g:Z

    .line 28
    .line 29
    iget-boolean v5, p0, Lqa/c;->h:Z

    .line 30
    .line 31
    iget-object p0, p0, Lqa/c;->i:Ljava/lang/Object;

    .line 32
    .line 33
    move-object v6, p0

    .line 34
    check-cast v6, Lay0/k;

    .line 35
    .line 36
    move-object v2, p2

    .line 37
    invoke-direct/range {v1 .. v6}, Lqa/c;-><init>(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)V

    .line 38
    .line 39
    .line 40
    return-object v1

    .line 41
    :pswitch_1
    move-object v2, p2

    .line 42
    new-instance p1, Lqa/c;

    .line 43
    .line 44
    iget-object p2, p0, Lqa/c;->f:Ljava/lang/Object;

    .line 45
    .line 46
    move-object v3, p2

    .line 47
    check-cast v3, Lla/u;

    .line 48
    .line 49
    iget-boolean v4, p0, Lqa/c;->g:Z

    .line 50
    .line 51
    iget-boolean v5, p0, Lqa/c;->h:Z

    .line 52
    .line 53
    iget-object p0, p0, Lqa/c;->i:Ljava/lang/Object;

    .line 54
    .line 55
    move-object v6, p0

    .line 56
    check-cast v6, Lay0/k;

    .line 57
    .line 58
    move-object v7, v2

    .line 59
    move-object v2, p1

    .line 60
    invoke-direct/range {v2 .. v7}, Lqa/c;-><init>(Lla/u;ZZLay0/k;Lkotlin/coroutines/Continuation;)V

    .line 61
    .line 62
    .line 63
    return-object v2

    .line 64
    nop

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lqa/c;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lqa/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lqa/c;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lqa/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lqa/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lqa/c;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lqa/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lqa/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lqa/c;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lqa/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 38

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lqa/c;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    iget-object v3, v0, Lqa/c;->i:Ljava/lang/Object;

    .line 7
    .line 8
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 9
    .line 10
    const/4 v5, 0x1

    .line 11
    iget-object v6, v0, Lqa/c;->f:Ljava/lang/Object;

    .line 12
    .line 13
    packed-switch v1, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    check-cast v6, Ltz/n0;

    .line 17
    .line 18
    iget-object v1, v6, Ltz/n0;->D:Lhh0/a;

    .line 19
    .line 20
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    iget v8, v0, Lqa/c;->e:I

    .line 23
    .line 24
    const/4 v9, 0x4

    .line 25
    const/4 v10, 0x3

    .line 26
    const/4 v11, 0x2

    .line 27
    if-eqz v8, :cond_4

    .line 28
    .line 29
    if-eq v8, v5, :cond_3

    .line 30
    .line 31
    if-eq v8, v11, :cond_2

    .line 32
    .line 33
    if-eq v8, v10, :cond_1

    .line 34
    .line 35
    if-ne v8, v9, :cond_0

    .line 36
    .line 37
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto/16 :goto_4

    .line 41
    .line 42
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw v0

    .line 48
    :cond_1
    iget-boolean v1, v0, Lqa/c;->h:Z

    .line 49
    .line 50
    iget-boolean v4, v0, Lqa/c;->g:Z

    .line 51
    .line 52
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    move/from16 v32, v1

    .line 56
    .line 57
    move-object/from16 v1, p1

    .line 58
    .line 59
    :goto_0
    move/from16 v29, v4

    .line 60
    .line 61
    goto :goto_3

    .line 62
    :cond_2
    iget-boolean v4, v0, Lqa/c;->g:Z

    .line 63
    .line 64
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    move-object/from16 v5, p1

    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    move-object/from16 v4, p1

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    sget-object v4, Lih0/a;->k:Lih0/a;

    .line 80
    .line 81
    iput v5, v0, Lqa/c;->e:I

    .line 82
    .line 83
    invoke-virtual {v1, v4, v0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    if-ne v4, v7, :cond_5

    .line 88
    .line 89
    goto/16 :goto_5

    .line 90
    .line 91
    :cond_5
    :goto_1
    check-cast v4, Ljava/lang/Boolean;

    .line 92
    .line 93
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 94
    .line 95
    .line 96
    move-result v4

    .line 97
    sget-object v5, Lih0/a;->l:Lih0/a;

    .line 98
    .line 99
    iput-boolean v4, v0, Lqa/c;->g:Z

    .line 100
    .line 101
    iput v11, v0, Lqa/c;->e:I

    .line 102
    .line 103
    invoke-virtual {v1, v5, v0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    if-ne v5, v7, :cond_6

    .line 108
    .line 109
    goto/16 :goto_5

    .line 110
    .line 111
    :cond_6
    :goto_2
    check-cast v5, Ljava/lang/Boolean;

    .line 112
    .line 113
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 114
    .line 115
    .line 116
    move-result v5

    .line 117
    sget-object v8, Lih0/a;->i:Lih0/a;

    .line 118
    .line 119
    iput-boolean v4, v0, Lqa/c;->g:Z

    .line 120
    .line 121
    iput-boolean v5, v0, Lqa/c;->h:Z

    .line 122
    .line 123
    iput v10, v0, Lqa/c;->e:I

    .line 124
    .line 125
    invoke-virtual {v1, v8, v0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    if-ne v1, v7, :cond_7

    .line 130
    .line 131
    goto :goto_5

    .line 132
    :cond_7
    move/from16 v32, v5

    .line 133
    .line 134
    goto :goto_0

    .line 135
    :goto_3
    check-cast v1, Ljava/lang/Boolean;

    .line 136
    .line 137
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 138
    .line 139
    .line 140
    move-result v35

    .line 141
    sget v1, Ltz/n0;->J:I

    .line 142
    .line 143
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    move-object v10, v1

    .line 148
    check-cast v10, Ltz/f0;

    .line 149
    .line 150
    const/16 v36, 0x0

    .line 151
    .line 152
    const v37, 0xb6fffff

    .line 153
    .line 154
    .line 155
    const/4 v11, 0x0

    .line 156
    const/4 v12, 0x0

    .line 157
    const/4 v13, 0x0

    .line 158
    const/4 v14, 0x0

    .line 159
    const/4 v15, 0x0

    .line 160
    const/16 v16, 0x0

    .line 161
    .line 162
    const/16 v17, 0x0

    .line 163
    .line 164
    const/16 v18, 0x0

    .line 165
    .line 166
    const/16 v19, 0x0

    .line 167
    .line 168
    const/16 v20, 0x0

    .line 169
    .line 170
    const/16 v21, 0x0

    .line 171
    .line 172
    const/16 v22, 0x0

    .line 173
    .line 174
    const/16 v23, 0x0

    .line 175
    .line 176
    const/16 v24, 0x0

    .line 177
    .line 178
    const/16 v25, 0x0

    .line 179
    .line 180
    const/16 v26, 0x0

    .line 181
    .line 182
    const/16 v27, 0x0

    .line 183
    .line 184
    const/16 v28, 0x0

    .line 185
    .line 186
    const/16 v30, 0x0

    .line 187
    .line 188
    const/16 v31, 0x0

    .line 189
    .line 190
    const/16 v33, 0x0

    .line 191
    .line 192
    const/16 v34, 0x0

    .line 193
    .line 194
    invoke-static/range {v10 .. v37}, Ltz/f0;->a(Ltz/f0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ltz/e0;ZLtz/z;Ltz/x;Ltz/y;Llp/p0;Ltz/a0;Lne0/c;ZZZZZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;I)Ltz/f0;

    .line 195
    .line 196
    .line 197
    move-result-object v1

    .line 198
    move/from16 v4, v29

    .line 199
    .line 200
    move/from16 v5, v32

    .line 201
    .line 202
    invoke-virtual {v6, v1}, Lql0/j;->g(Lql0/h;)V

    .line 203
    .line 204
    .line 205
    check-cast v3, Lkf0/z;

    .line 206
    .line 207
    invoke-virtual {v3}, Lkf0/z;->invoke()Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    check-cast v1, Lyy0/i;

    .line 212
    .line 213
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 214
    .line 215
    const/4 v8, 0x5

    .line 216
    invoke-direct {v3, v6, v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;-><init>(Ljava/lang/Object;I)V

    .line 217
    .line 218
    .line 219
    invoke-static {v1, v3}, Lbb/j0;->b(Lyy0/i;Lay0/k;)Lne0/k;

    .line 220
    .line 221
    .line 222
    move-result-object v1

    .line 223
    new-instance v3, Ltz/u;

    .line 224
    .line 225
    const/4 v8, 0x0

    .line 226
    invoke-direct {v3, v6, v8, v2}, Ltz/u;-><init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V

    .line 227
    .line 228
    .line 229
    iput-boolean v4, v0, Lqa/c;->g:Z

    .line 230
    .line 231
    iput-boolean v5, v0, Lqa/c;->h:Z

    .line 232
    .line 233
    iput v9, v0, Lqa/c;->e:I

    .line 234
    .line 235
    invoke-static {v3, v0, v1}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    if-ne v0, v7, :cond_8

    .line 240
    .line 241
    goto :goto_5

    .line 242
    :cond_8
    :goto_4
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 243
    .line 244
    :goto_5
    return-object v7

    .line 245
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 246
    .line 247
    iget v2, v0, Lqa/c;->e:I

    .line 248
    .line 249
    if-eqz v2, :cond_a

    .line 250
    .line 251
    if-ne v2, v5, :cond_9

    .line 252
    .line 253
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 254
    .line 255
    .line 256
    move-object/from16 v0, p1

    .line 257
    .line 258
    goto :goto_6

    .line 259
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 260
    .line 261
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    throw v0

    .line 265
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    move-object v9, v6

    .line 269
    check-cast v9, Lla/u;

    .line 270
    .line 271
    iget-boolean v8, v0, Lqa/c;->g:Z

    .line 272
    .line 273
    iget-boolean v7, v0, Lqa/c;->h:Z

    .line 274
    .line 275
    new-instance v6, Lqa/b;

    .line 276
    .line 277
    move-object v11, v3

    .line 278
    check-cast v11, Lay0/k;

    .line 279
    .line 280
    const/4 v12, 0x1

    .line 281
    const/4 v10, 0x0

    .line 282
    invoke-direct/range {v6 .. v12}, Lqa/b;-><init>(ZZLla/u;Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 283
    .line 284
    .line 285
    iput v5, v0, Lqa/c;->e:I

    .line 286
    .line 287
    invoke-virtual {v9, v8, v6, v0}, Lla/u;->r(ZLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    if-ne v0, v1, :cond_b

    .line 292
    .line 293
    move-object v0, v1

    .line 294
    :cond_b
    :goto_6
    return-object v0

    .line 295
    :pswitch_1
    move-object v1, v6

    .line 296
    check-cast v1, Lla/u;

    .line 297
    .line 298
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 299
    .line 300
    iget v8, v0, Lqa/c;->e:I

    .line 301
    .line 302
    if-eqz v8, :cond_d

    .line 303
    .line 304
    if-ne v8, v5, :cond_c

    .line 305
    .line 306
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 307
    .line 308
    .line 309
    move-object/from16 v0, p1

    .line 310
    .line 311
    goto :goto_8

    .line 312
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 313
    .line 314
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 315
    .line 316
    .line 317
    throw v0

    .line 318
    :cond_d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 319
    .line 320
    .line 321
    invoke-virtual {v1}, Lla/u;->l()Z

    .line 322
    .line 323
    .line 324
    move-result v4

    .line 325
    if-eqz v4, :cond_e

    .line 326
    .line 327
    invoke-virtual {v1}, Lla/u;->m()Z

    .line 328
    .line 329
    .line 330
    move-result v1

    .line 331
    if-nez v1, :cond_f

    .line 332
    .line 333
    :cond_e
    iget-boolean v1, v0, Lqa/c;->g:Z

    .line 334
    .line 335
    if-eqz v1, :cond_f

    .line 336
    .line 337
    move v9, v5

    .line 338
    goto :goto_7

    .line 339
    :cond_f
    move v9, v2

    .line 340
    :goto_7
    move-object v11, v6

    .line 341
    check-cast v11, Lla/u;

    .line 342
    .line 343
    iget-boolean v10, v0, Lqa/c;->h:Z

    .line 344
    .line 345
    move-object v13, v3

    .line 346
    check-cast v13, Lay0/k;

    .line 347
    .line 348
    new-instance v8, Lqa/b;

    .line 349
    .line 350
    const/4 v12, 0x0

    .line 351
    const/4 v14, 0x0

    .line 352
    invoke-direct/range {v8 .. v14}, Lqa/b;-><init>(ZZLla/u;Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 353
    .line 354
    .line 355
    iput v5, v0, Lqa/c;->e:I

    .line 356
    .line 357
    invoke-virtual {v11, v10, v8, v0}, Lla/u;->r(ZLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 358
    .line 359
    .line 360
    move-result-object v0

    .line 361
    if-ne v0, v7, :cond_10

    .line 362
    .line 363
    move-object v0, v7

    .line 364
    :cond_10
    :goto_8
    return-object v0

    .line 365
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
