.class public final Lr80/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lr80/f;


# direct methods
.method public synthetic constructor <init>(Lr80/f;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lr80/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lr80/c;->f:Lr80/f;

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
    iget p1, p0, Lr80/c;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lr80/c;

    .line 7
    .line 8
    iget-object p0, p0, Lr80/c;->f:Lr80/f;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lr80/c;-><init>(Lr80/f;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lr80/c;

    .line 16
    .line 17
    iget-object p0, p0, Lr80/c;->f:Lr80/f;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lr80/c;-><init>(Lr80/f;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lr80/c;

    .line 25
    .line 26
    iget-object p0, p0, Lr80/c;->f:Lr80/f;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lr80/c;-><init>(Lr80/f;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lr80/c;

    .line 34
    .line 35
    iget-object p0, p0, Lr80/c;->f:Lr80/f;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lr80/c;-><init>(Lr80/f;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lr80/c;

    .line 43
    .line 44
    iget-object p0, p0, Lr80/c;->f:Lr80/f;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lr80/c;-><init>(Lr80/f;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lr80/c;->d:I

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
    invoke-virtual {p0, p1, p2}, Lr80/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lr80/c;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lr80/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lr80/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lr80/c;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lr80/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lr80/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lr80/c;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lr80/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lr80/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lr80/c;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lr80/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lr80/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lr80/c;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lr80/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
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
    iget v1, v0, Lr80/c;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lr80/c;->e:I

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v2, :cond_1

    .line 14
    .line 15
    if-ne v2, v3, :cond_0

    .line 16
    .line 17
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw v0

    .line 29
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object v2, v0, Lr80/c;->f:Lr80/f;

    .line 33
    .line 34
    iget-object v4, v2, Lr80/f;->o:Lq80/o;

    .line 35
    .line 36
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    check-cast v4, Lyy0/i;

    .line 41
    .line 42
    invoke-static {v4}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    new-instance v5, Lma0/c;

    .line 47
    .line 48
    const/16 v6, 0x1b

    .line 49
    .line 50
    invoke-direct {v5, v2, v6}, Lma0/c;-><init>(Ljava/lang/Object;I)V

    .line 51
    .line 52
    .line 53
    iput v3, v0, Lr80/c;->e:I

    .line 54
    .line 55
    invoke-virtual {v4, v5, v0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    if-ne v0, v1, :cond_2

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_2
    :goto_0
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    :goto_1
    return-object v1

    .line 65
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 66
    .line 67
    iget v2, v0, Lr80/c;->e:I

    .line 68
    .line 69
    const/4 v3, 0x1

    .line 70
    if-eqz v2, :cond_4

    .line 71
    .line 72
    if-ne v2, v3, :cond_3

    .line 73
    .line 74
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 79
    .line 80
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 81
    .line 82
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    throw v0

    .line 86
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    iget-object v2, v0, Lr80/c;->f:Lr80/f;

    .line 90
    .line 91
    iget-object v4, v2, Lr80/f;->n:Lq80/d;

    .line 92
    .line 93
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v4

    .line 97
    check-cast v4, Lyy0/i;

    .line 98
    .line 99
    new-instance v5, Lr80/d;

    .line 100
    .line 101
    const/4 v6, 0x2

    .line 102
    invoke-direct {v5, v2, v6}, Lr80/d;-><init>(Lr80/f;I)V

    .line 103
    .line 104
    .line 105
    iput v3, v0, Lr80/c;->e:I

    .line 106
    .line 107
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    if-ne v0, v1, :cond_5

    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_5
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    :goto_3
    return-object v1

    .line 117
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 118
    .line 119
    iget v2, v0, Lr80/c;->e:I

    .line 120
    .line 121
    const/4 v3, 0x1

    .line 122
    if-eqz v2, :cond_7

    .line 123
    .line 124
    if-ne v2, v3, :cond_6

    .line 125
    .line 126
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    goto :goto_4

    .line 130
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 131
    .line 132
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 133
    .line 134
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    throw v0

    .line 138
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    iget-object v2, v0, Lr80/c;->f:Lr80/f;

    .line 142
    .line 143
    iget-object v4, v2, Lr80/f;->m:Lq80/e;

    .line 144
    .line 145
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v4

    .line 149
    check-cast v4, Lyy0/i;

    .line 150
    .line 151
    new-instance v5, Lr80/d;

    .line 152
    .line 153
    const/4 v6, 0x1

    .line 154
    invoke-direct {v5, v2, v6}, Lr80/d;-><init>(Lr80/f;I)V

    .line 155
    .line 156
    .line 157
    iput v3, v0, Lr80/c;->e:I

    .line 158
    .line 159
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    if-ne v0, v1, :cond_8

    .line 164
    .line 165
    goto :goto_5

    .line 166
    :cond_8
    :goto_4
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 167
    .line 168
    :goto_5
    return-object v1

    .line 169
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 170
    .line 171
    iget v2, v0, Lr80/c;->e:I

    .line 172
    .line 173
    const/4 v3, 0x1

    .line 174
    if-eqz v2, :cond_a

    .line 175
    .line 176
    if-ne v2, v3, :cond_9

    .line 177
    .line 178
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    goto :goto_6

    .line 182
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 183
    .line 184
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 185
    .line 186
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    throw v0

    .line 190
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    iget-object v2, v0, Lr80/c;->f:Lr80/f;

    .line 194
    .line 195
    iget-object v4, v2, Lr80/f;->p:Lro0/k;

    .line 196
    .line 197
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v4

    .line 201
    check-cast v4, Lyy0/i;

    .line 202
    .line 203
    new-instance v5, Lr80/d;

    .line 204
    .line 205
    const/4 v6, 0x0

    .line 206
    invoke-direct {v5, v2, v6}, Lr80/d;-><init>(Lr80/f;I)V

    .line 207
    .line 208
    .line 209
    iput v3, v0, Lr80/c;->e:I

    .line 210
    .line 211
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v0

    .line 215
    if-ne v0, v1, :cond_b

    .line 216
    .line 217
    goto :goto_7

    .line 218
    :cond_b
    :goto_6
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 219
    .line 220
    :goto_7
    return-object v1

    .line 221
    :pswitch_3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 222
    .line 223
    iget v2, v0, Lr80/c;->e:I

    .line 224
    .line 225
    iget-object v3, v0, Lr80/c;->f:Lr80/f;

    .line 226
    .line 227
    const/4 v4, 0x1

    .line 228
    if-eqz v2, :cond_d

    .line 229
    .line 230
    if-ne v2, v4, :cond_c

    .line 231
    .line 232
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    move-object/from16 v0, p1

    .line 236
    .line 237
    goto :goto_8

    .line 238
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 239
    .line 240
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 241
    .line 242
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    throw v0

    .line 246
    :cond_d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    iget-object v2, v3, Lr80/f;->j:Lkf0/k;

    .line 250
    .line 251
    iput v4, v0, Lr80/c;->e:I

    .line 252
    .line 253
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 254
    .line 255
    .line 256
    invoke-virtual {v2, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v0

    .line 260
    if-ne v0, v1, :cond_e

    .line 261
    .line 262
    goto :goto_d

    .line 263
    :cond_e
    :goto_8
    check-cast v0, Lss0/b;

    .line 264
    .line 265
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 266
    .line 267
    .line 268
    move-result-object v1

    .line 269
    move-object v5, v1

    .line 270
    check-cast v5, Lr80/e;

    .line 271
    .line 272
    const/4 v1, 0x0

    .line 273
    if-eqz v0, :cond_f

    .line 274
    .line 275
    sget-object v2, Lss0/e;->H1:Lss0/e;

    .line 276
    .line 277
    invoke-static {v0, v2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 278
    .line 279
    .line 280
    move-result v2

    .line 281
    move v8, v2

    .line 282
    goto :goto_9

    .line 283
    :cond_f
    move v8, v1

    .line 284
    :goto_9
    if-eqz v0, :cond_10

    .line 285
    .line 286
    sget-object v2, Lss0/e;->r:Lss0/e;

    .line 287
    .line 288
    invoke-static {v0, v2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 289
    .line 290
    .line 291
    move-result v2

    .line 292
    move v9, v2

    .line 293
    goto :goto_a

    .line 294
    :cond_10
    move v9, v1

    .line 295
    :goto_a
    if-eqz v0, :cond_11

    .line 296
    .line 297
    sget-object v2, Lss0/e;->x:Lss0/e;

    .line 298
    .line 299
    invoke-static {v0, v2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 300
    .line 301
    .line 302
    move-result v2

    .line 303
    if-ne v2, v4, :cond_11

    .line 304
    .line 305
    move/from16 v17, v4

    .line 306
    .line 307
    goto :goto_b

    .line 308
    :cond_11
    move/from16 v17, v1

    .line 309
    .line 310
    :goto_b
    if-eqz v0, :cond_12

    .line 311
    .line 312
    sget-object v2, Lss0/e;->x:Lss0/e;

    .line 313
    .line 314
    invoke-static {v0, v2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 315
    .line 316
    .line 317
    move-result v2

    .line 318
    if-ne v2, v4, :cond_12

    .line 319
    .line 320
    sget-object v2, Lss0/e;->y:Lss0/e;

    .line 321
    .line 322
    invoke-static {v0, v2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 323
    .line 324
    .line 325
    move-result v0

    .line 326
    if-nez v0, :cond_12

    .line 327
    .line 328
    move v10, v4

    .line 329
    goto :goto_c

    .line 330
    :cond_12
    move v10, v1

    .line 331
    :goto_c
    const/16 v18, 0x0

    .line 332
    .line 333
    const/16 v19, 0x17e3

    .line 334
    .line 335
    const/4 v6, 0x0

    .line 336
    const/4 v7, 0x0

    .line 337
    const/4 v11, 0x0

    .line 338
    const/4 v12, 0x0

    .line 339
    const/4 v13, 0x0

    .line 340
    const/4 v14, 0x0

    .line 341
    const/4 v15, 0x0

    .line 342
    const/16 v16, 0x0

    .line 343
    .line 344
    invoke-static/range {v5 .. v19}, Lr80/e;->a(Lr80/e;Lql0/g;ZZZZZZZZZZZLjava/lang/String;I)Lr80/e;

    .line 345
    .line 346
    .line 347
    move-result-object v0

    .line 348
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 349
    .line 350
    .line 351
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 352
    .line 353
    :goto_d
    return-object v1

    .line 354
    nop

    .line 355
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
