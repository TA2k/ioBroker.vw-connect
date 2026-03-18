.class public final Lr60/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lr60/l;


# direct methods
.method public synthetic constructor <init>(Lr60/l;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lr60/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lr60/k;->f:Lr60/l;

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
    .locals 1

    .line 1
    iget p1, p0, Lr60/k;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lr60/k;

    .line 7
    .line 8
    iget-object p0, p0, Lr60/k;->f:Lr60/l;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lr60/k;-><init>(Lr60/l;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lr60/k;

    .line 16
    .line 17
    iget-object p0, p0, Lr60/k;->f:Lr60/l;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lr60/k;-><init>(Lr60/l;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lr60/k;->d:I

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
    invoke-virtual {p0, p1, p2}, Lr60/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lr60/k;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lr60/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lr60/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lr60/k;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lr60/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lr60/k;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lr60/k;->e:I

    .line 11
    .line 12
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    const/4 v4, 0x2

    .line 15
    const/4 v5, 0x1

    .line 16
    iget-object v6, v0, Lr60/k;->f:Lr60/l;

    .line 17
    .line 18
    if-eqz v2, :cond_3

    .line 19
    .line 20
    if-eq v2, v5, :cond_2

    .line 21
    .line 22
    if-ne v2, v4, :cond_1

    .line 23
    .line 24
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    move-object v1, v3

    .line 28
    goto/16 :goto_8

    .line 29
    .line 30
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 33
    .line 34
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw v0

    .line 38
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    move-object/from16 v2, p1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    iget-object v2, v6, Lr60/l;->i:Lwr0/e;

    .line 48
    .line 49
    iput v5, v0, Lr60/k;->e:I

    .line 50
    .line 51
    invoke-virtual {v2, v3, v0}, Lwr0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    if-ne v2, v1, :cond_4

    .line 56
    .line 57
    goto/16 :goto_8

    .line 58
    .line 59
    :cond_4
    :goto_0
    check-cast v2, Lyr0/e;

    .line 60
    .line 61
    iget-object v5, v6, Lr60/l;->j:Lp60/h0;

    .line 62
    .line 63
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 64
    .line 65
    .line 66
    move-result-object v7

    .line 67
    check-cast v7, Lr60/i;

    .line 68
    .line 69
    const-string v8, ""

    .line 70
    .line 71
    if-eqz v2, :cond_6

    .line 72
    .line 73
    iget-object v9, v2, Lyr0/e;->c:Ljava/lang/String;

    .line 74
    .line 75
    if-nez v9, :cond_5

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_5
    move-object v12, v9

    .line 79
    goto :goto_2

    .line 80
    :cond_6
    :goto_1
    move-object v12, v8

    .line 81
    :goto_2
    if-eqz v2, :cond_8

    .line 82
    .line 83
    iget-object v9, v2, Lyr0/e;->d:Ljava/lang/String;

    .line 84
    .line 85
    if-nez v9, :cond_7

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_7
    move-object v13, v9

    .line 89
    goto :goto_4

    .line 90
    :cond_8
    :goto_3
    move-object v13, v8

    .line 91
    :goto_4
    if-eqz v2, :cond_a

    .line 92
    .line 93
    iget-object v2, v2, Lyr0/e;->b:Ljava/lang/String;

    .line 94
    .line 95
    if-nez v2, :cond_9

    .line 96
    .line 97
    goto :goto_5

    .line 98
    :cond_9
    move-object v8, v2

    .line 99
    :cond_a
    :goto_5
    new-instance v10, Lon0/b0;

    .line 100
    .line 101
    iget-object v2, v7, Lr60/i;->k:Lon0/q;

    .line 102
    .line 103
    if-eqz v2, :cond_c

    .line 104
    .line 105
    iget-object v2, v2, Lon0/q;->b:Ljava/lang/String;

    .line 106
    .line 107
    if-nez v2, :cond_b

    .line 108
    .line 109
    goto :goto_6

    .line 110
    :cond_b
    move-object v11, v2

    .line 111
    goto :goto_7

    .line 112
    :cond_c
    :goto_6
    move-object v11, v8

    .line 113
    :goto_7
    iget-object v14, v7, Lr60/i;->f:Ljava/lang/String;

    .line 114
    .line 115
    iget-object v15, v7, Lr60/i;->g:Ljava/lang/String;

    .line 116
    .line 117
    iget-object v2, v7, Lr60/i;->d:Ljava/lang/String;

    .line 118
    .line 119
    iget-object v8, v7, Lr60/i;->e:Ljava/lang/String;

    .line 120
    .line 121
    iget-object v7, v7, Lr60/i;->c:Ljava/lang/String;

    .line 122
    .line 123
    move-object/from16 v16, v2

    .line 124
    .line 125
    move-object/from16 v18, v7

    .line 126
    .line 127
    move-object/from16 v17, v8

    .line 128
    .line 129
    invoke-direct/range {v10 .. v18}, Lon0/b0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v5, v10}, Lp60/h0;->a(Lon0/b0;)Lam0/i;

    .line 133
    .line 134
    .line 135
    move-result-object v2

    .line 136
    new-instance v5, Lr60/h;

    .line 137
    .line 138
    const/4 v7, 0x1

    .line 139
    invoke-direct {v5, v6, v7}, Lr60/h;-><init>(Lr60/l;I)V

    .line 140
    .line 141
    .line 142
    iput v4, v0, Lr60/k;->e:I

    .line 143
    .line 144
    invoke-virtual {v2, v5, v0}, Lam0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    if-ne v0, v1, :cond_0

    .line 149
    .line 150
    :goto_8
    return-object v1

    .line 151
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 152
    .line 153
    iget v2, v0, Lr60/k;->e:I

    .line 154
    .line 155
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 156
    .line 157
    const/4 v4, 0x1

    .line 158
    iget-object v5, v0, Lr60/k;->f:Lr60/l;

    .line 159
    .line 160
    if-eqz v2, :cond_e

    .line 161
    .line 162
    if-ne v2, v4, :cond_d

    .line 163
    .line 164
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    move-object/from16 v0, p1

    .line 168
    .line 169
    goto :goto_9

    .line 170
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 171
    .line 172
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 173
    .line 174
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    throw v0

    .line 178
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    iget-object v2, v5, Lr60/l;->i:Lwr0/e;

    .line 182
    .line 183
    iput v4, v0, Lr60/k;->e:I

    .line 184
    .line 185
    invoke-virtual {v2, v3, v0}, Lwr0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    if-ne v0, v1, :cond_f

    .line 190
    .line 191
    goto/16 :goto_d

    .line 192
    .line 193
    :cond_f
    :goto_9
    check-cast v0, Lyr0/e;

    .line 194
    .line 195
    if-eqz v0, :cond_13

    .line 196
    .line 197
    iget-object v0, v0, Lyr0/e;->k:Lyr0/a;

    .line 198
    .line 199
    if-eqz v0, :cond_13

    .line 200
    .line 201
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    move-object v6, v1

    .line 206
    check-cast v6, Lr60/i;

    .line 207
    .line 208
    iget-object v1, v0, Lyr0/a;->c:Ljava/lang/String;

    .line 209
    .line 210
    const-string v2, ""

    .line 211
    .line 212
    if-nez v1, :cond_10

    .line 213
    .line 214
    move-object v9, v2

    .line 215
    goto :goto_a

    .line 216
    :cond_10
    move-object v9, v1

    .line 217
    :goto_a
    iget-object v1, v0, Lyr0/a;->d:Ljava/lang/String;

    .line 218
    .line 219
    if-nez v1, :cond_11

    .line 220
    .line 221
    move-object v10, v2

    .line 222
    goto :goto_b

    .line 223
    :cond_11
    move-object v10, v1

    .line 224
    :goto_b
    iget-object v1, v0, Lyr0/a;->e:Ljava/lang/String;

    .line 225
    .line 226
    if-nez v1, :cond_12

    .line 227
    .line 228
    move-object v11, v2

    .line 229
    goto :goto_c

    .line 230
    :cond_12
    move-object v11, v1

    .line 231
    :goto_c
    iget-object v12, v0, Lyr0/a;->b:Ljava/lang/String;

    .line 232
    .line 233
    iget-object v13, v0, Lyr0/a;->a:Ljava/lang/String;

    .line 234
    .line 235
    invoke-virtual {v5, v13}, Lr60/l;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v14

    .line 239
    const/16 v21, 0x0

    .line 240
    .line 241
    const/16 v22, 0x7f03

    .line 242
    .line 243
    const/4 v7, 0x0

    .line 244
    const/4 v8, 0x0

    .line 245
    const/4 v15, 0x0

    .line 246
    const/16 v16, 0x0

    .line 247
    .line 248
    const/16 v17, 0x0

    .line 249
    .line 250
    const/16 v18, 0x0

    .line 251
    .line 252
    const/16 v19, 0x0

    .line 253
    .line 254
    const/16 v20, 0x0

    .line 255
    .line 256
    invoke-static/range {v6 .. v22}, Lr60/i;->a(Lr60/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/ArrayList;Lql0/g;ZZI)Lr60/i;

    .line 257
    .line 258
    .line 259
    move-result-object v0

    .line 260
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 261
    .line 262
    .line 263
    :cond_13
    invoke-virtual {v5}, Lr60/l;->k()V

    .line 264
    .line 265
    .line 266
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    move-object v6, v0

    .line 271
    check-cast v6, Lr60/i;

    .line 272
    .line 273
    const/16 v21, 0x0

    .line 274
    .line 275
    const/16 v22, 0x7dff

    .line 276
    .line 277
    const/4 v7, 0x0

    .line 278
    const/4 v8, 0x0

    .line 279
    const/4 v9, 0x0

    .line 280
    const/4 v10, 0x0

    .line 281
    const/4 v11, 0x0

    .line 282
    const/4 v12, 0x0

    .line 283
    const/4 v13, 0x0

    .line 284
    const/4 v14, 0x0

    .line 285
    const/4 v15, 0x0

    .line 286
    const/16 v16, 0x0

    .line 287
    .line 288
    const/16 v17, 0x0

    .line 289
    .line 290
    const/16 v18, 0x0

    .line 291
    .line 292
    const/16 v19, 0x0

    .line 293
    .line 294
    const/16 v20, 0x0

    .line 295
    .line 296
    invoke-static/range {v6 .. v22}, Lr60/i;->a(Lr60/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLon0/q;Ljava/util/ArrayList;Lql0/g;ZZI)Lr60/i;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 301
    .line 302
    .line 303
    move-object v1, v3

    .line 304
    :goto_d
    return-object v1

    .line 305
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
