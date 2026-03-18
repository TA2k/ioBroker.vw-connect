.class public final Ls10/z;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ls10/d0;


# direct methods
.method public synthetic constructor <init>(Ls10/d0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ls10/z;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ls10/z;->f:Ls10/d0;

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
    iget p1, p0, Ls10/z;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ls10/z;

    .line 7
    .line 8
    iget-object p0, p0, Ls10/z;->f:Ls10/d0;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ls10/z;-><init>(Ls10/d0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ls10/z;

    .line 16
    .line 17
    iget-object p0, p0, Ls10/z;->f:Ls10/d0;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ls10/z;-><init>(Ls10/d0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ls10/z;

    .line 25
    .line 26
    iget-object p0, p0, Ls10/z;->f:Ls10/d0;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ls10/z;-><init>(Ls10/d0;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Ls10/z;

    .line 34
    .line 35
    iget-object p0, p0, Ls10/z;->f:Ls10/d0;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Ls10/z;-><init>(Ls10/d0;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ls10/z;->d:I

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
    invoke-virtual {p0, p1, p2}, Ls10/z;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ls10/z;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ls10/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ls10/z;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ls10/z;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ls10/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ls10/z;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ls10/z;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ls10/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Ls10/z;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ls10/z;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ls10/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ls10/z;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Ls10/z;->e:I

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
    iget-object v2, v0, Ls10/z;->f:Ls10/d0;

    .line 33
    .line 34
    iget-object v4, v2, Ls10/d0;->j:Lkf0/b0;

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
    new-instance v5, Ls10/b0;

    .line 43
    .line 44
    const/4 v6, 0x1

    .line 45
    invoke-direct {v5, v2, v6}, Ls10/b0;-><init>(Ls10/d0;I)V

    .line 46
    .line 47
    .line 48
    iput v3, v0, Ls10/z;->e:I

    .line 49
    .line 50
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    if-ne v0, v1, :cond_2

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_2
    :goto_0
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 58
    .line 59
    :goto_1
    return-object v1

    .line 60
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 61
    .line 62
    iget v2, v0, Ls10/z;->e:I

    .line 63
    .line 64
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    const/4 v4, 0x2

    .line 67
    const/4 v5, 0x1

    .line 68
    iget-object v6, v0, Ls10/z;->f:Ls10/d0;

    .line 69
    .line 70
    if-eqz v2, :cond_6

    .line 71
    .line 72
    if-eq v2, v5, :cond_5

    .line 73
    .line 74
    if-ne v2, v4, :cond_4

    .line 75
    .line 76
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    :cond_3
    move-object v1, v3

    .line 80
    goto :goto_3

    .line 81
    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 82
    .line 83
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 84
    .line 85
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw v0

    .line 89
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    move-object/from16 v2, p1

    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_6
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    iget-object v2, v6, Ls10/d0;->p:Lcf0/e;

    .line 99
    .line 100
    iput v5, v0, Ls10/z;->e:I

    .line 101
    .line 102
    invoke-virtual {v2, v3, v0}, Lcf0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    if-ne v2, v1, :cond_7

    .line 107
    .line 108
    goto :goto_3

    .line 109
    :cond_7
    :goto_2
    check-cast v2, Ljava/lang/Boolean;

    .line 110
    .line 111
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 112
    .line 113
    .line 114
    move-result v14

    .line 115
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    move-object v7, v2

    .line 120
    check-cast v7, Ls10/c0;

    .line 121
    .line 122
    const/4 v15, 0x0

    .line 123
    const/16 v16, 0xbf

    .line 124
    .line 125
    const/4 v8, 0x0

    .line 126
    const/4 v9, 0x0

    .line 127
    const/4 v10, 0x0

    .line 128
    const/4 v11, 0x0

    .line 129
    const/4 v12, 0x0

    .line 130
    const/4 v13, 0x0

    .line 131
    invoke-static/range {v7 .. v16}, Ls10/c0;->a(Ls10/c0;Llf0/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZI)Ls10/c0;

    .line 132
    .line 133
    .line 134
    move-result-object v2

    .line 135
    invoke-virtual {v6, v2}, Lql0/j;->g(Lql0/h;)V

    .line 136
    .line 137
    .line 138
    if-eqz v14, :cond_3

    .line 139
    .line 140
    iget-object v2, v6, Ls10/d0;->o:Lq10/j;

    .line 141
    .line 142
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v2

    .line 146
    check-cast v2, Lyy0/i;

    .line 147
    .line 148
    new-instance v5, Ls10/b0;

    .line 149
    .line 150
    const/4 v7, 0x0

    .line 151
    invoke-direct {v5, v6, v7}, Ls10/b0;-><init>(Ls10/d0;I)V

    .line 152
    .line 153
    .line 154
    iput v4, v0, Ls10/z;->e:I

    .line 155
    .line 156
    invoke-interface {v2, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    if-ne v0, v1, :cond_3

    .line 161
    .line 162
    :goto_3
    return-object v1

    .line 163
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 164
    .line 165
    iget v2, v0, Ls10/z;->e:I

    .line 166
    .line 167
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 168
    .line 169
    const/4 v4, 0x1

    .line 170
    if-eqz v2, :cond_a

    .line 171
    .line 172
    if-ne v2, v4, :cond_9

    .line 173
    .line 174
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    :cond_8
    move-object v1, v3

    .line 178
    goto :goto_5

    .line 179
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 180
    .line 181
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 182
    .line 183
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    throw v0

    .line 187
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    iput v4, v0, Ls10/z;->e:I

    .line 191
    .line 192
    iget-object v2, v0, Ls10/z;->f:Ls10/d0;

    .line 193
    .line 194
    iget-object v4, v2, Ls10/d0;->l:Lq10/h;

    .line 195
    .line 196
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v4

    .line 200
    check-cast v4, Lyy0/i;

    .line 201
    .line 202
    new-instance v5, Lqa0/a;

    .line 203
    .line 204
    const/4 v6, 0x0

    .line 205
    const/16 v7, 0xc

    .line 206
    .line 207
    invoke-direct {v5, v6, v2, v7}, Lqa0/a;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 208
    .line 209
    .line 210
    invoke-static {v4, v5}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 211
    .line 212
    .line 213
    move-result-object v2

    .line 214
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    if-ne v0, v1, :cond_b

    .line 219
    .line 220
    goto :goto_4

    .line 221
    :cond_b
    move-object v0, v3

    .line 222
    :goto_4
    if-ne v0, v1, :cond_8

    .line 223
    .line 224
    :goto_5
    return-object v1

    .line 225
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 226
    .line 227
    iget v2, v0, Ls10/z;->e:I

    .line 228
    .line 229
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 230
    .line 231
    const/4 v4, 0x1

    .line 232
    if-eqz v2, :cond_e

    .line 233
    .line 234
    if-ne v2, v4, :cond_d

    .line 235
    .line 236
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    :cond_c
    move-object v1, v3

    .line 240
    goto :goto_7

    .line 241
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 242
    .line 243
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 244
    .line 245
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 246
    .line 247
    .line 248
    throw v0

    .line 249
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 250
    .line 251
    .line 252
    iput v4, v0, Ls10/z;->e:I

    .line 253
    .line 254
    iget-object v2, v0, Ls10/z;->f:Ls10/d0;

    .line 255
    .line 256
    iget-object v4, v2, Ls10/d0;->i:Lkf0/e0;

    .line 257
    .line 258
    sget-object v5, Lss0/e;->A:Lss0/e;

    .line 259
    .line 260
    invoke-virtual {v4, v5}, Lkf0/e0;->a(Lss0/e;)Lne0/k;

    .line 261
    .line 262
    .line 263
    move-result-object v4

    .line 264
    new-instance v5, Lr60/t;

    .line 265
    .line 266
    const/4 v6, 0x0

    .line 267
    const/16 v7, 0xa

    .line 268
    .line 269
    invoke-direct {v5, v2, v6, v7}, Lr60/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 270
    .line 271
    .line 272
    invoke-static {v5, v0, v4}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v0

    .line 276
    if-ne v0, v1, :cond_f

    .line 277
    .line 278
    goto :goto_6

    .line 279
    :cond_f
    move-object v0, v3

    .line 280
    :goto_6
    if-ne v0, v1, :cond_c

    .line 281
    .line 282
    :goto_7
    return-object v1

    .line 283
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
