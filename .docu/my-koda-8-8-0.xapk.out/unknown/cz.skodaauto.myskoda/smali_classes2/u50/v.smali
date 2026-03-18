.class public final Lu50/v;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Lne0/t;

.field public e:Lu50/w;

.field public f:I

.field public g:I

.field public h:I

.field public synthetic i:Ljava/lang/Object;

.field public final synthetic j:Lu50/w;


# direct methods
.method public constructor <init>(Lu50/w;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lu50/v;->j:Lu50/w;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    new-instance v0, Lu50/v;

    .line 2
    .line 3
    iget-object p0, p0, Lu50/v;->j:Lu50/w;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Lu50/v;-><init>(Lu50/w;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iput-object p1, v0, Lu50/v;->i:Ljava/lang/Object;

    .line 9
    .line 10
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lu50/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lu50/v;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lu50/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lu50/v;->i:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lvy0/b0;

    .line 6
    .line 7
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v3, v0, Lu50/v;->h:I

    .line 10
    .line 11
    const/4 v4, 0x3

    .line 12
    iget-object v5, v0, Lu50/v;->j:Lu50/w;

    .line 13
    .line 14
    const/4 v6, 0x2

    .line 15
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    const/4 v8, 0x1

    .line 18
    const/4 v9, 0x0

    .line 19
    if-eqz v3, :cond_3

    .line 20
    .line 21
    if-eq v3, v8, :cond_2

    .line 22
    .line 23
    if-eq v3, v6, :cond_1

    .line 24
    .line 25
    if-ne v3, v4, :cond_0

    .line 26
    .line 27
    iget-object v0, v0, Lu50/v;->e:Lu50/w;

    .line 28
    .line 29
    check-cast v0, Lss0/d0;

    .line 30
    .line 31
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    return-object v7

    .line 35
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 36
    .line 37
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 38
    .line 39
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw v0

    .line 43
    :cond_1
    iget v1, v0, Lu50/v;->g:I

    .line 44
    .line 45
    iget v3, v0, Lu50/v;->f:I

    .line 46
    .line 47
    iget-object v5, v0, Lu50/v;->e:Lu50/w;

    .line 48
    .line 49
    iget-object v6, v0, Lu50/v;->d:Lne0/t;

    .line 50
    .line 51
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    move v11, v1

    .line 55
    move-object/from16 v1, p1

    .line 56
    .line 57
    goto/16 :goto_1

    .line 58
    .line 59
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    move-object/from16 v3, p1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iget-object v3, v5, Lu50/w;->h:Lrs0/b;

    .line 69
    .line 70
    iput-object v1, v0, Lu50/v;->i:Ljava/lang/Object;

    .line 71
    .line 72
    iput v8, v0, Lu50/v;->h:I

    .line 73
    .line 74
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v3, v0}, Lrs0/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    if-ne v3, v2, :cond_4

    .line 82
    .line 83
    goto/16 :goto_4

    .line 84
    .line 85
    :cond_4
    :goto_0
    check-cast v3, Lne0/t;

    .line 86
    .line 87
    instance-of v10, v3, Lne0/c;

    .line 88
    .line 89
    const/4 v11, 0x0

    .line 90
    if-eqz v10, :cond_5

    .line 91
    .line 92
    move-object v10, v3

    .line 93
    check-cast v10, Lne0/c;

    .line 94
    .line 95
    new-instance v12, Lu41/u;

    .line 96
    .line 97
    const/4 v13, 0x1

    .line 98
    invoke-direct {v12, v13}, Lu41/u;-><init>(I)V

    .line 99
    .line 100
    .line 101
    invoke-static {v9, v1, v12}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 102
    .line 103
    .line 104
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 105
    .line 106
    .line 107
    move-result-object v12

    .line 108
    check-cast v12, Lu50/t;

    .line 109
    .line 110
    iget-object v13, v5, Lu50/w;->l:Lij0/a;

    .line 111
    .line 112
    invoke-static {v10, v13}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 113
    .line 114
    .line 115
    move-result-object v10

    .line 116
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 117
    .line 118
    .line 119
    new-instance v12, Lu50/t;

    .line 120
    .line 121
    invoke-direct {v12, v10, v11}, Lu50/t;-><init>(Lql0/g;Z)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v5, v12}, Lql0/j;->g(Lql0/h;)V

    .line 125
    .line 126
    .line 127
    :cond_5
    instance-of v10, v3, Lne0/e;

    .line 128
    .line 129
    if-eqz v10, :cond_b

    .line 130
    .line 131
    move-object v10, v3

    .line 132
    check-cast v10, Lne0/e;

    .line 133
    .line 134
    iget-object v10, v10, Lne0/e;->a:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v10, Lss0/d0;

    .line 137
    .line 138
    instance-of v12, v10, Lss0/g;

    .line 139
    .line 140
    if-eqz v12, :cond_6

    .line 141
    .line 142
    new-instance v0, Lky/s;

    .line 143
    .line 144
    const/4 v2, 0x2

    .line 145
    invoke-direct {v0, v10, v2}, Lky/s;-><init>(Lss0/d0;I)V

    .line 146
    .line 147
    .line 148
    invoke-static {v9, v1, v0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 149
    .line 150
    .line 151
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    check-cast v0, Lu50/t;

    .line 156
    .line 157
    iget-object v12, v5, Lu50/w;->l:Lij0/a;

    .line 158
    .line 159
    new-array v1, v11, [Ljava/lang/Object;

    .line 160
    .line 161
    move-object v2, v12

    .line 162
    check-cast v2, Ljj0/f;

    .line 163
    .line 164
    const v3, 0x7f1202be

    .line 165
    .line 166
    .line 167
    invoke-virtual {v2, v3, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v13

    .line 171
    iget-object v1, v5, Lu50/w;->l:Lij0/a;

    .line 172
    .line 173
    new-array v2, v11, [Ljava/lang/Object;

    .line 174
    .line 175
    check-cast v1, Ljj0/f;

    .line 176
    .line 177
    const v3, 0x7f1202bc

    .line 178
    .line 179
    .line 180
    invoke-virtual {v1, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object v14

    .line 184
    const v2, 0x7f12038c

    .line 185
    .line 186
    .line 187
    new-array v3, v11, [Ljava/lang/Object;

    .line 188
    .line 189
    invoke-virtual {v1, v2, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v15

    .line 193
    const/16 v16, 0x0

    .line 194
    .line 195
    const/16 v17, 0x70

    .line 196
    .line 197
    invoke-static/range {v12 .. v17}, Ljp/rf;->a(Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lql0/g;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 202
    .line 203
    .line 204
    new-instance v0, Lu50/t;

    .line 205
    .line 206
    invoke-direct {v0, v1, v11}, Lu50/t;-><init>(Lql0/g;Z)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 210
    .line 211
    .line 212
    return-object v7

    .line 213
    :cond_6
    instance-of v1, v10, Lss0/j0;

    .line 214
    .line 215
    if-eqz v1, :cond_a

    .line 216
    .line 217
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 218
    .line 219
    .line 220
    move-result-object v1

    .line 221
    check-cast v1, Lu50/t;

    .line 222
    .line 223
    invoke-static {v1, v8}, Lu50/t;->a(Lu50/t;Z)Lu50/t;

    .line 224
    .line 225
    .line 226
    move-result-object v1

    .line 227
    invoke-virtual {v5, v1}, Lql0/j;->g(Lql0/h;)V

    .line 228
    .line 229
    .line 230
    iget-object v1, v5, Lu50/w;->i:Ls50/c;

    .line 231
    .line 232
    check-cast v10, Lss0/j0;

    .line 233
    .line 234
    iget-object v8, v10, Lss0/j0;->d:Ljava/lang/String;

    .line 235
    .line 236
    iput-object v9, v0, Lu50/v;->i:Ljava/lang/Object;

    .line 237
    .line 238
    iput-object v3, v0, Lu50/v;->d:Lne0/t;

    .line 239
    .line 240
    iput-object v5, v0, Lu50/v;->e:Lu50/w;

    .line 241
    .line 242
    iput v11, v0, Lu50/v;->f:I

    .line 243
    .line 244
    iput v11, v0, Lu50/v;->g:I

    .line 245
    .line 246
    iput v6, v0, Lu50/v;->h:I

    .line 247
    .line 248
    iget-object v1, v1, Ls50/c;->a:Lp50/d;

    .line 249
    .line 250
    invoke-virtual {v1, v8, v0}, Lp50/d;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v1

    .line 254
    if-ne v1, v2, :cond_7

    .line 255
    .line 256
    goto :goto_4

    .line 257
    :cond_7
    move-object v6, v3

    .line 258
    move v3, v11

    .line 259
    :goto_1
    check-cast v1, Lyy0/i;

    .line 260
    .line 261
    iput-object v9, v0, Lu50/v;->i:Ljava/lang/Object;

    .line 262
    .line 263
    iput-object v6, v0, Lu50/v;->d:Lne0/t;

    .line 264
    .line 265
    iput-object v9, v0, Lu50/v;->e:Lu50/w;

    .line 266
    .line 267
    iput v3, v0, Lu50/v;->f:I

    .line 268
    .line 269
    iput v11, v0, Lu50/v;->g:I

    .line 270
    .line 271
    iput v4, v0, Lu50/v;->h:I

    .line 272
    .line 273
    new-instance v3, Lqg/l;

    .line 274
    .line 275
    const/16 v4, 0x12

    .line 276
    .line 277
    sget-object v6, Lzy0/q;->d:Lzy0/q;

    .line 278
    .line 279
    invoke-direct {v3, v4, v6, v5}, Lqg/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 280
    .line 281
    .line 282
    invoke-interface {v1, v3, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object v0

    .line 286
    if-ne v0, v2, :cond_8

    .line 287
    .line 288
    goto :goto_2

    .line 289
    :cond_8
    move-object v0, v7

    .line 290
    :goto_2
    if-ne v0, v2, :cond_9

    .line 291
    .line 292
    goto :goto_3

    .line 293
    :cond_9
    move-object v0, v7

    .line 294
    :goto_3
    if-ne v0, v2, :cond_b

    .line 295
    .line 296
    :goto_4
    return-object v2

    .line 297
    :cond_a
    new-instance v0, La8/r0;

    .line 298
    .line 299
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 300
    .line 301
    .line 302
    throw v0

    .line 303
    :cond_b
    return-object v7
.end method
