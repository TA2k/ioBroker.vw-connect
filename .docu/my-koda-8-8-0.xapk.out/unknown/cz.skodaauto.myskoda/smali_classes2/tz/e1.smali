.class public final Ltz/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltz/h1;


# direct methods
.method public synthetic constructor <init>(Ltz/h1;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltz/e1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/e1;->e:Ltz/h1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Ltz/d1;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Ltz/d1;

    .line 11
    .line 12
    iget v3, v2, Ltz/d1;->h:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Ltz/d1;->h:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Ltz/d1;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Ltz/d1;-><init>(Ltz/e1;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Ltz/d1;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Ltz/d1;->h:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    if-eqz v4, :cond_2

    .line 39
    .line 40
    if-ne v4, v6, :cond_1

    .line 41
    .line 42
    iget-object v0, v2, Ltz/d1;->e:Lne0/s;

    .line 43
    .line 44
    iget-object v2, v2, Ltz/d1;->d:Ltz/h1;

    .line 45
    .line 46
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw v0

    .line 58
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iget-object v0, v0, Ltz/e1;->e:Ltz/h1;

    .line 62
    .line 63
    iget-object v1, v0, Ltz/h1;->j:Lqf0/g;

    .line 64
    .line 65
    iput-object v0, v2, Ltz/d1;->d:Ltz/h1;

    .line 66
    .line 67
    move-object/from16 v4, p1

    .line 68
    .line 69
    iput-object v4, v2, Ltz/d1;->e:Lne0/s;

    .line 70
    .line 71
    iput v6, v2, Ltz/d1;->h:I

    .line 72
    .line 73
    invoke-virtual {v1, v5, v2}, Lqf0/g;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    if-ne v1, v3, :cond_3

    .line 78
    .line 79
    return-object v3

    .line 80
    :cond_3
    move-object v2, v0

    .line 81
    move-object v0, v4

    .line 82
    :goto_1
    check-cast v1, Ljava/lang/Boolean;

    .line 83
    .line 84
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 85
    .line 86
    .line 87
    move-result v10

    .line 88
    iget-object v1, v2, Ltz/h1;->k:Lij0/a;

    .line 89
    .line 90
    instance-of v3, v0, Lne0/e;

    .line 91
    .line 92
    if-eqz v3, :cond_b

    .line 93
    .line 94
    check-cast v0, Lne0/e;

    .line 95
    .line 96
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, Lrd0/j;

    .line 99
    .line 100
    new-instance v3, Lqr0/l;

    .line 101
    .line 102
    if-eqz v0, :cond_4

    .line 103
    .line 104
    iget-object v4, v0, Lrd0/j;->c:Lrd0/v;

    .line 105
    .line 106
    if-eqz v4, :cond_4

    .line 107
    .line 108
    iget-object v4, v4, Lrd0/v;->d:Lqr0/l;

    .line 109
    .line 110
    if-eqz v4, :cond_4

    .line 111
    .line 112
    iget v4, v4, Lqr0/l;->d:I

    .line 113
    .line 114
    sget-object v7, Lrd0/v;->f:Lgy0/j;

    .line 115
    .line 116
    invoke-static {v4, v7}, Lkp/r9;->f(ILgy0/g;)I

    .line 117
    .line 118
    .line 119
    move-result v4

    .line 120
    :goto_2
    move v11, v4

    .line 121
    goto :goto_3

    .line 122
    :cond_4
    const/16 v4, 0x64

    .line 123
    .line 124
    goto :goto_2

    .line 125
    :goto_3
    invoke-direct {v3, v11}, Lqr0/l;-><init>(I)V

    .line 126
    .line 127
    .line 128
    const/4 v4, 0x0

    .line 129
    if-eqz v0, :cond_5

    .line 130
    .line 131
    iget-object v7, v0, Lrd0/j;->c:Lrd0/v;

    .line 132
    .line 133
    if-eqz v7, :cond_5

    .line 134
    .line 135
    iget-object v7, v7, Lrd0/v;->e:Lqr0/l;

    .line 136
    .line 137
    if-eqz v7, :cond_5

    .line 138
    .line 139
    iget v7, v7, Lqr0/l;->d:I

    .line 140
    .line 141
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 142
    .line 143
    .line 144
    move-result-object v7

    .line 145
    move-object v14, v7

    .line 146
    goto :goto_4

    .line 147
    :cond_5
    move-object v14, v4

    .line 148
    :goto_4
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 149
    .line 150
    .line 151
    move-result-object v7

    .line 152
    check-cast v7, Ltz/f1;

    .line 153
    .line 154
    invoke-static {v3}, Lkp/l6;->a(Lqr0/l;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v12

    .line 158
    if-eqz v0, :cond_6

    .line 159
    .line 160
    iget-object v3, v0, Lrd0/j;->a:Lrd0/a;

    .line 161
    .line 162
    goto :goto_5

    .line 163
    :cond_6
    move-object v3, v4

    .line 164
    :goto_5
    sget-object v8, Lrd0/a;->d:Lrd0/a;

    .line 165
    .line 166
    const/4 v9, 0x0

    .line 167
    if-ne v3, v8, :cond_7

    .line 168
    .line 169
    move v13, v6

    .line 170
    goto :goto_6

    .line 171
    :cond_7
    move v13, v9

    .line 172
    :goto_6
    if-eqz v0, :cond_8

    .line 173
    .line 174
    iget-object v4, v0, Lrd0/j;->a:Lrd0/a;

    .line 175
    .line 176
    :cond_8
    if-nez v4, :cond_9

    .line 177
    .line 178
    const/4 v0, -0x1

    .line 179
    goto :goto_7

    .line 180
    :cond_9
    sget-object v0, Ltz/g1;->a:[I

    .line 181
    .line 182
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 183
    .line 184
    .line 185
    move-result v3

    .line 186
    aget v0, v0, v3

    .line 187
    .line 188
    :goto_7
    if-ne v0, v6, :cond_a

    .line 189
    .line 190
    invoke-virtual {v2, v11, v14}, Ltz/h1;->h(ILjava/lang/Integer;)Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    :goto_8
    move-object v15, v0

    .line 195
    goto :goto_9

    .line 196
    :cond_a
    new-array v0, v9, [Ljava/lang/Object;

    .line 197
    .line 198
    check-cast v1, Ljj0/f;

    .line 199
    .line 200
    const v3, 0x7f120443

    .line 201
    .line 202
    .line 203
    invoke-virtual {v1, v3, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v0

    .line 207
    goto :goto_8

    .line 208
    :goto_9
    const/16 v16, 0x0

    .line 209
    .line 210
    const/16 v17, 0x220

    .line 211
    .line 212
    const/4 v8, 0x0

    .line 213
    const/4 v9, 0x0

    .line 214
    invoke-static/range {v7 .. v17}, Ltz/f1;->a(Ltz/f1;ZZZILjava/lang/String;ZLjava/lang/Integer;Ljava/lang/String;Lql0/g;I)Ltz/f1;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    goto :goto_a

    .line 219
    :cond_b
    instance-of v3, v0, Lne0/c;

    .line 220
    .line 221
    if-eqz v3, :cond_c

    .line 222
    .line 223
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 224
    .line 225
    .line 226
    move-result-object v3

    .line 227
    move-object v6, v3

    .line 228
    check-cast v6, Ltz/f1;

    .line 229
    .line 230
    check-cast v0, Lne0/c;

    .line 231
    .line 232
    invoke-static {v0, v1}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 233
    .line 234
    .line 235
    move-result-object v15

    .line 236
    invoke-static {v1}, Lkp/l6;->c(Lij0/a;)Ljava/lang/String;

    .line 237
    .line 238
    .line 239
    move-result-object v11

    .line 240
    const/4 v14, 0x0

    .line 241
    const/16 v16, 0xa4

    .line 242
    .line 243
    const/4 v7, 0x0

    .line 244
    const/4 v8, 0x1

    .line 245
    const/4 v9, 0x0

    .line 246
    const/4 v10, 0x0

    .line 247
    const/4 v12, 0x0

    .line 248
    const/4 v13, 0x0

    .line 249
    invoke-static/range {v6 .. v16}, Ltz/f1;->a(Ltz/f1;ZZZILjava/lang/String;ZLjava/lang/Integer;Ljava/lang/String;Lql0/g;I)Ltz/f1;

    .line 250
    .line 251
    .line 252
    move-result-object v0

    .line 253
    goto :goto_a

    .line 254
    :cond_c
    sget-object v3, Lne0/d;->a:Lne0/d;

    .line 255
    .line 256
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 257
    .line 258
    .line 259
    move-result v0

    .line 260
    if-eqz v0, :cond_d

    .line 261
    .line 262
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 263
    .line 264
    .line 265
    move-result-object v0

    .line 266
    move-object v6, v0

    .line 267
    check-cast v6, Ltz/f1;

    .line 268
    .line 269
    invoke-static {v1}, Lkp/l6;->c(Lij0/a;)Ljava/lang/String;

    .line 270
    .line 271
    .line 272
    move-result-object v11

    .line 273
    const/4 v15, 0x0

    .line 274
    const/16 v16, 0x2ac

    .line 275
    .line 276
    const/4 v7, 0x1

    .line 277
    const/4 v8, 0x0

    .line 278
    const/4 v9, 0x0

    .line 279
    const/4 v10, 0x0

    .line 280
    const/4 v12, 0x0

    .line 281
    const/4 v13, 0x0

    .line 282
    const/4 v14, 0x0

    .line 283
    invoke-static/range {v6 .. v16}, Ltz/f1;->a(Ltz/f1;ZZZILjava/lang/String;ZLjava/lang/Integer;Ljava/lang/String;Lql0/g;I)Ltz/f1;

    .line 284
    .line 285
    .line 286
    move-result-object v0

    .line 287
    :goto_a
    invoke-virtual {v2, v0}, Lql0/j;->g(Lql0/h;)V

    .line 288
    .line 289
    .line 290
    return-object v5

    .line 291
    :cond_d
    new-instance v0, La8/r0;

    .line 292
    .line 293
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 294
    .line 295
    .line 296
    throw v0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Ltz/e1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/t;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/c;

    .line 9
    .line 10
    iget-object p0, p0, Ltz/e1;->e:Ltz/h1;

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    move-object v0, p2

    .line 19
    check-cast v0, Ltz/f1;

    .line 20
    .line 21
    check-cast p1, Lne0/c;

    .line 22
    .line 23
    iget-object p2, p0, Ltz/h1;->k:Lij0/a;

    .line 24
    .line 25
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 26
    .line 27
    .line 28
    move-result-object v9

    .line 29
    const/16 v10, 0x1ff

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    const/4 v2, 0x0

    .line 33
    const/4 v3, 0x0

    .line 34
    const/4 v4, 0x0

    .line 35
    const/4 v5, 0x0

    .line 36
    const/4 v6, 0x0

    .line 37
    const/4 v7, 0x0

    .line 38
    const/4 v8, 0x0

    .line 39
    invoke-static/range {v0 .. v10}, Ltz/f1;->a(Ltz/f1;ZZZILjava/lang/String;ZLjava/lang/Integer;Ljava/lang/String;Lql0/g;I)Ltz/f1;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    instance-of p1, p1, Lne0/e;

    .line 48
    .line 49
    if-eqz p1, :cond_1

    .line 50
    .line 51
    iget-object p0, p0, Ltz/h1;->i:Ltr0/b;

    .line 52
    .line 53
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object p0

    .line 59
    :cond_1
    new-instance p0, La8/r0;

    .line 60
    .line 61
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 66
    .line 67
    invoke-virtual {p0, p1, p2}, Ltz/e1;->b(Lne0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
