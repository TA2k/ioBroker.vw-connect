.class public final Lpp0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Lnp0/c;

.field public final c:Lpp0/l0;

.field public final d:Lfg0/d;

.field public final e:Lpp0/c0;


# direct methods
.method public constructor <init>(Lkf0/o;Lnp0/c;Lpp0/l0;Lfg0/d;Lpp0/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/e;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lpp0/e;->b:Lnp0/c;

    .line 7
    .line 8
    iput-object p3, p0, Lpp0/e;->c:Lpp0/l0;

    .line 9
    .line 10
    iput-object p4, p0, Lpp0/e;->d:Lfg0/d;

    .line 11
    .line 12
    iput-object p5, p0, Lpp0/e;->e:Lpp0/c0;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lpp0/c;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lpp0/e;->b(Lpp0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lpp0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    instance-of v3, v2, Lpp0/d;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lpp0/d;

    .line 13
    .line 14
    iget v4, v3, Lpp0/d;->k:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lpp0/d;->k:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lpp0/d;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Lpp0/d;-><init>(Lpp0/e;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lpp0/d;->i:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lpp0/d;->k:I

    .line 36
    .line 37
    const/4 v6, 0x3

    .line 38
    const/4 v7, 0x2

    .line 39
    const/4 v8, 0x1

    .line 40
    const/4 v9, 0x0

    .line 41
    if-eqz v5, :cond_4

    .line 42
    .line 43
    if-eq v5, v8, :cond_3

    .line 44
    .line 45
    if-eq v5, v7, :cond_2

    .line 46
    .line 47
    if-ne v5, v6, :cond_1

    .line 48
    .line 49
    iget-object v1, v3, Lpp0/d;->h:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v4, v3, Lpp0/d;->g:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v4, Lqp0/q;

    .line 54
    .line 55
    iget-object v5, v3, Lpp0/d;->f:Ljava/lang/String;

    .line 56
    .line 57
    iget-object v3, v3, Lpp0/d;->e:Lnp0/c;

    .line 58
    .line 59
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    move-object v12, v3

    .line 63
    move-object v13, v4

    .line 64
    :goto_1
    move-object/from16 v16, v1

    .line 65
    .line 66
    move-object v15, v5

    .line 67
    goto/16 :goto_6

    .line 68
    .line 69
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 72
    .line 73
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw v0

    .line 77
    :cond_2
    iget-object v1, v3, Lpp0/d;->g:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v1, Lxj0/f;

    .line 80
    .line 81
    iget-object v5, v3, Lpp0/d;->f:Ljava/lang/String;

    .line 82
    .line 83
    iget-object v7, v3, Lpp0/d;->e:Lnp0/c;

    .line 84
    .line 85
    iget-object v8, v3, Lpp0/d;->d:Lpp0/c;

    .line 86
    .line 87
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    goto/16 :goto_4

    .line 91
    .line 92
    :cond_3
    iget-object v1, v3, Lpp0/d;->f:Ljava/lang/String;

    .line 93
    .line 94
    iget-object v5, v3, Lpp0/d;->e:Lnp0/c;

    .line 95
    .line 96
    iget-object v8, v3, Lpp0/d;->d:Lpp0/c;

    .line 97
    .line 98
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    move-object v10, v5

    .line 102
    move-object v5, v2

    .line 103
    move-object v2, v1

    .line 104
    move-object v1, v8

    .line 105
    goto :goto_2

    .line 106
    :cond_4
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    iget-object v2, v1, Lpp0/c;->a:Ljava/lang/String;

    .line 110
    .line 111
    iget-object v5, v0, Lpp0/e;->d:Lfg0/d;

    .line 112
    .line 113
    invoke-virtual {v5}, Lfg0/d;->invoke()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v5

    .line 117
    check-cast v5, Lyy0/i;

    .line 118
    .line 119
    iput-object v1, v3, Lpp0/d;->d:Lpp0/c;

    .line 120
    .line 121
    iget-object v10, v0, Lpp0/e;->b:Lnp0/c;

    .line 122
    .line 123
    iput-object v10, v3, Lpp0/d;->e:Lnp0/c;

    .line 124
    .line 125
    iput-object v2, v3, Lpp0/d;->f:Ljava/lang/String;

    .line 126
    .line 127
    iput v8, v3, Lpp0/d;->k:I

    .line 128
    .line 129
    invoke-static {v5, v3}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v5

    .line 133
    if-ne v5, v4, :cond_5

    .line 134
    .line 135
    goto :goto_5

    .line 136
    :cond_5
    :goto_2
    check-cast v5, Lgg0/a;

    .line 137
    .line 138
    if-eqz v5, :cond_6

    .line 139
    .line 140
    new-instance v8, Lxj0/f;

    .line 141
    .line 142
    iget-wide v11, v5, Lgg0/a;->a:D

    .line 143
    .line 144
    iget-wide v13, v5, Lgg0/a;->b:D

    .line 145
    .line 146
    invoke-direct {v8, v11, v12, v13, v14}, Lxj0/f;-><init>(DD)V

    .line 147
    .line 148
    .line 149
    goto :goto_3

    .line 150
    :cond_6
    move-object v8, v9

    .line 151
    :goto_3
    iget-object v5, v0, Lpp0/e;->c:Lpp0/l0;

    .line 152
    .line 153
    invoke-virtual {v5}, Lpp0/l0;->invoke()Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v5

    .line 157
    check-cast v5, Lyy0/i;

    .line 158
    .line 159
    iput-object v1, v3, Lpp0/d;->d:Lpp0/c;

    .line 160
    .line 161
    iput-object v10, v3, Lpp0/d;->e:Lnp0/c;

    .line 162
    .line 163
    iput-object v2, v3, Lpp0/d;->f:Ljava/lang/String;

    .line 164
    .line 165
    iput-object v8, v3, Lpp0/d;->g:Ljava/lang/Object;

    .line 166
    .line 167
    iput v7, v3, Lpp0/d;->k:I

    .line 168
    .line 169
    invoke-static {v5, v3}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v5

    .line 173
    if-ne v5, v4, :cond_7

    .line 174
    .line 175
    goto :goto_5

    .line 176
    :cond_7
    move-object v7, v8

    .line 177
    move-object v8, v1

    .line 178
    move-object v1, v7

    .line 179
    move-object v7, v5

    .line 180
    move-object v5, v2

    .line 181
    move-object v2, v7

    .line 182
    move-object v7, v10

    .line 183
    :goto_4
    check-cast v2, Lqp0/r;

    .line 184
    .line 185
    new-instance v10, Lqp0/q;

    .line 186
    .line 187
    invoke-direct {v10, v1, v2}, Lqp0/q;-><init>(Lxj0/f;Lqp0/r;)V

    .line 188
    .line 189
    .line 190
    iget-object v1, v8, Lpp0/c;->b:Ljava/lang/String;

    .line 191
    .line 192
    iput-object v9, v3, Lpp0/d;->d:Lpp0/c;

    .line 193
    .line 194
    iput-object v7, v3, Lpp0/d;->e:Lnp0/c;

    .line 195
    .line 196
    iput-object v5, v3, Lpp0/d;->f:Ljava/lang/String;

    .line 197
    .line 198
    iput-object v10, v3, Lpp0/d;->g:Ljava/lang/Object;

    .line 199
    .line 200
    iput-object v1, v3, Lpp0/d;->h:Ljava/lang/String;

    .line 201
    .line 202
    iput v6, v3, Lpp0/d;->k:I

    .line 203
    .line 204
    iget-object v2, v0, Lpp0/e;->a:Lkf0/o;

    .line 205
    .line 206
    invoke-virtual {v2, v3}, Lkf0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v2

    .line 210
    if-ne v2, v4, :cond_8

    .line 211
    .line 212
    :goto_5
    return-object v4

    .line 213
    :cond_8
    move-object v12, v7

    .line 214
    move-object v13, v10

    .line 215
    goto/16 :goto_1

    .line 216
    .line 217
    :goto_6
    check-cast v2, Lne0/t;

    .line 218
    .line 219
    instance-of v1, v2, Lne0/c;

    .line 220
    .line 221
    if-eqz v1, :cond_9

    .line 222
    .line 223
    move-object v1, v9

    .line 224
    goto :goto_7

    .line 225
    :cond_9
    instance-of v1, v2, Lne0/e;

    .line 226
    .line 227
    if-eqz v1, :cond_b

    .line 228
    .line 229
    check-cast v2, Lne0/e;

    .line 230
    .line 231
    iget-object v1, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 232
    .line 233
    :goto_7
    check-cast v1, Lss0/j0;

    .line 234
    .line 235
    if-eqz v1, :cond_a

    .line 236
    .line 237
    iget-object v1, v1, Lss0/j0;->d:Ljava/lang/String;

    .line 238
    .line 239
    move-object v14, v1

    .line 240
    goto :goto_8

    .line 241
    :cond_a
    move-object v14, v9

    .line 242
    :goto_8
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 243
    .line 244
    .line 245
    const-string v1, "userInput"

    .line 246
    .line 247
    invoke-static {v15, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    const-string v1, "routePlannerRequest"

    .line 251
    .line 252
    invoke-static {v13, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    iget-object v1, v12, Lnp0/c;->a:Lxl0/f;

    .line 256
    .line 257
    new-instance v11, Li70/s;

    .line 258
    .line 259
    const/16 v17, 0x0

    .line 260
    .line 261
    invoke-direct/range {v11 .. v17}, Li70/s;-><init>(Lnp0/c;Lqp0/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 262
    .line 263
    .line 264
    new-instance v2, Lnh/i;

    .line 265
    .line 266
    const/4 v3, 0x4

    .line 267
    invoke-direct {v2, v3}, Lnh/i;-><init>(I)V

    .line 268
    .line 269
    .line 270
    invoke-virtual {v1, v11, v2, v9}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 271
    .line 272
    .line 273
    move-result-object v1

    .line 274
    new-instance v2, Lm70/f1;

    .line 275
    .line 276
    const/16 v3, 0x8

    .line 277
    .line 278
    invoke-direct {v2, v0, v9, v3}, Lm70/f1;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 279
    .line 280
    .line 281
    new-instance v3, Lne0/n;

    .line 282
    .line 283
    invoke-direct {v3, v2, v1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 284
    .line 285
    .line 286
    new-instance v1, Lbv0/d;

    .line 287
    .line 288
    const/16 v2, 0xc

    .line 289
    .line 290
    invoke-direct {v1, v0, v9, v2}, Lbv0/d;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 291
    .line 292
    .line 293
    new-instance v2, Lyy0/x;

    .line 294
    .line 295
    invoke-direct {v2, v3, v1}, Lyy0/x;-><init>(Lyy0/i;Lay0/o;)V

    .line 296
    .line 297
    .line 298
    new-instance v1, Lnz/g;

    .line 299
    .line 300
    const/4 v3, 0x6

    .line 301
    invoke-direct {v1, v0, v9, v3}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 302
    .line 303
    .line 304
    invoke-static {v1, v2}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 305
    .line 306
    .line 307
    move-result-object v0

    .line 308
    return-object v0

    .line 309
    :cond_b
    new-instance v0, La8/r0;

    .line 310
    .line 311
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 312
    .line 313
    .line 314
    throw v0
.end method
