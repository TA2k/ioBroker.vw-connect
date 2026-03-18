.class public final Lh2/p0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc1/c;

.field public final synthetic g:F

.field public final synthetic h:Z

.field public final synthetic i:Li1/k;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lc1/c;FZLjava/lang/Object;Li1/k;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p7, p0, Lh2/p0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/p0;->f:Lc1/c;

    .line 4
    .line 5
    iput p2, p0, Lh2/p0;->g:F

    .line 6
    .line 7
    iput-boolean p3, p0, Lh2/p0;->h:Z

    .line 8
    .line 9
    iput-object p4, p0, Lh2/p0;->j:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p5, p0, Lh2/p0;->i:Li1/k;

    .line 12
    .line 13
    const/4 p1, 0x2

    .line 14
    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 9

    .line 1
    iget p1, p0, Lh2/p0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lh2/p0;

    .line 7
    .line 8
    iget-object p1, p0, Lh2/p0;->j:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v4, p1

    .line 11
    check-cast v4, Lh2/x0;

    .line 12
    .line 13
    iget-object v5, p0, Lh2/p0;->i:Li1/k;

    .line 14
    .line 15
    const/4 v7, 0x1

    .line 16
    iget-object v1, p0, Lh2/p0;->f:Lc1/c;

    .line 17
    .line 18
    iget v2, p0, Lh2/p0;->g:F

    .line 19
    .line 20
    iget-boolean v3, p0, Lh2/p0;->h:Z

    .line 21
    .line 22
    move-object v6, p2

    .line 23
    invoke-direct/range {v0 .. v7}, Lh2/p0;-><init>(Lc1/c;FZLjava/lang/Object;Li1/k;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :pswitch_0
    move-object v6, p2

    .line 28
    new-instance v1, Lh2/p0;

    .line 29
    .line 30
    iget-object p1, p0, Lh2/p0;->j:Ljava/lang/Object;

    .line 31
    .line 32
    move-object v5, p1

    .line 33
    check-cast v5, Lh2/q0;

    .line 34
    .line 35
    move-object v7, v6

    .line 36
    iget-object v6, p0, Lh2/p0;->i:Li1/k;

    .line 37
    .line 38
    const/4 v8, 0x0

    .line 39
    iget-object v2, p0, Lh2/p0;->f:Lc1/c;

    .line 40
    .line 41
    iget v3, p0, Lh2/p0;->g:F

    .line 42
    .line 43
    iget-boolean v4, p0, Lh2/p0;->h:Z

    .line 44
    .line 45
    invoke-direct/range {v1 .. v8}, Lh2/p0;-><init>(Lc1/c;FZLjava/lang/Object;Li1/k;Lkotlin/coroutines/Continuation;I)V

    .line 46
    .line 47
    .line 48
    return-object v1

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lh2/p0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh2/p0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh2/p0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh2/p0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh2/p0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh2/p0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh2/p0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 8

    .line 1
    iget v0, p0, Lh2/p0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/p0;->j:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lh2/x0;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Lh2/p0;->e:I

    .line 13
    .line 14
    const/4 v3, 0x2

    .line 15
    const/4 v4, 0x1

    .line 16
    if-eqz v2, :cond_2

    .line 17
    .line 18
    if-eq v2, v4, :cond_1

    .line 19
    .line 20
    if-ne v2, v3, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    :goto_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    goto/16 :goto_2

    .line 35
    .line 36
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iget-object p1, p0, Lh2/p0;->f:Lc1/c;

    .line 40
    .line 41
    iget-object v2, p1, Lc1/c;->e:Ll2/j1;

    .line 42
    .line 43
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    check-cast v2, Lt4/f;

    .line 48
    .line 49
    iget v2, v2, Lt4/f;->d:F

    .line 50
    .line 51
    iget v5, p0, Lh2/p0;->g:F

    .line 52
    .line 53
    invoke-static {v2, v5}, Lt4/f;->a(FF)Z

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    if-nez v2, :cond_8

    .line 58
    .line 59
    iget-boolean v2, p0, Lh2/p0;->h:Z

    .line 60
    .line 61
    if-nez v2, :cond_3

    .line 62
    .line 63
    new-instance v0, Lt4/f;

    .line 64
    .line 65
    invoke-direct {v0, v5}, Lt4/f;-><init>(F)V

    .line 66
    .line 67
    .line 68
    iput v4, p0, Lh2/p0;->e:I

    .line 69
    .line 70
    invoke-virtual {p1, v0, p0}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    if-ne p0, v1, :cond_8

    .line 75
    .line 76
    goto :goto_3

    .line 77
    :cond_3
    iget-object v2, p1, Lc1/c;->e:Ll2/j1;

    .line 78
    .line 79
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    check-cast v2, Lt4/f;

    .line 84
    .line 85
    iget v2, v2, Lt4/f;->d:F

    .line 86
    .line 87
    iget v4, v0, Lh2/x0;->b:F

    .line 88
    .line 89
    invoke-static {v2, v4}, Lt4/f;->a(FF)Z

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    if-eqz v4, :cond_4

    .line 94
    .line 95
    new-instance v0, Li1/n;

    .line 96
    .line 97
    const-wide/16 v6, 0x0

    .line 98
    .line 99
    invoke-direct {v0, v6, v7}, Li1/n;-><init>(J)V

    .line 100
    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_4
    iget v4, v0, Lh2/x0;->d:F

    .line 104
    .line 105
    invoke-static {v2, v4}, Lt4/f;->a(FF)Z

    .line 106
    .line 107
    .line 108
    move-result v4

    .line 109
    if-eqz v4, :cond_5

    .line 110
    .line 111
    new-instance v0, Li1/i;

    .line 112
    .line 113
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 114
    .line 115
    .line 116
    goto :goto_1

    .line 117
    :cond_5
    iget v4, v0, Lh2/x0;->c:F

    .line 118
    .line 119
    invoke-static {v2, v4}, Lt4/f;->a(FF)Z

    .line 120
    .line 121
    .line 122
    move-result v4

    .line 123
    if-eqz v4, :cond_6

    .line 124
    .line 125
    new-instance v0, Li1/e;

    .line 126
    .line 127
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 128
    .line 129
    .line 130
    goto :goto_1

    .line 131
    :cond_6
    iget v0, v0, Lh2/x0;->e:F

    .line 132
    .line 133
    invoke-static {v2, v0}, Lt4/f;->a(FF)Z

    .line 134
    .line 135
    .line 136
    move-result v0

    .line 137
    if-eqz v0, :cond_7

    .line 138
    .line 139
    new-instance v0, Li1/b;

    .line 140
    .line 141
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 142
    .line 143
    .line 144
    goto :goto_1

    .line 145
    :cond_7
    const/4 v0, 0x0

    .line 146
    :goto_1
    iput v3, p0, Lh2/p0;->e:I

    .line 147
    .line 148
    iget-object v2, p0, Lh2/p0;->i:Li1/k;

    .line 149
    .line 150
    invoke-static {p1, v5, v0, v2, p0}, Li2/k0;->a(Lc1/c;FLi1/k;Li1/k;Lrx0/i;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    if-ne p0, v1, :cond_8

    .line 155
    .line 156
    goto :goto_3

    .line 157
    :cond_8
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 158
    .line 159
    :goto_3
    return-object v1

    .line 160
    :pswitch_0
    iget-object v0, p0, Lh2/p0;->j:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast v0, Lh2/q0;

    .line 163
    .line 164
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 165
    .line 166
    iget v2, p0, Lh2/p0;->e:I

    .line 167
    .line 168
    const/4 v3, 0x2

    .line 169
    const/4 v4, 0x1

    .line 170
    if-eqz v2, :cond_b

    .line 171
    .line 172
    if-eq v2, v4, :cond_a

    .line 173
    .line 174
    if-ne v2, v3, :cond_9

    .line 175
    .line 176
    goto :goto_4

    .line 177
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 178
    .line 179
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 180
    .line 181
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    throw p0

    .line 185
    :cond_a
    :goto_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    goto :goto_6

    .line 189
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    iget-object p1, p0, Lh2/p0;->f:Lc1/c;

    .line 193
    .line 194
    iget-object v2, p1, Lc1/c;->e:Ll2/j1;

    .line 195
    .line 196
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v2

    .line 200
    check-cast v2, Lt4/f;

    .line 201
    .line 202
    iget v2, v2, Lt4/f;->d:F

    .line 203
    .line 204
    iget v5, p0, Lh2/p0;->g:F

    .line 205
    .line 206
    invoke-static {v2, v5}, Lt4/f;->a(FF)Z

    .line 207
    .line 208
    .line 209
    move-result v2

    .line 210
    if-nez v2, :cond_10

    .line 211
    .line 212
    iget-boolean v2, p0, Lh2/p0;->h:Z

    .line 213
    .line 214
    if-nez v2, :cond_c

    .line 215
    .line 216
    new-instance v0, Lt4/f;

    .line 217
    .line 218
    invoke-direct {v0, v5}, Lt4/f;-><init>(F)V

    .line 219
    .line 220
    .line 221
    iput v4, p0, Lh2/p0;->e:I

    .line 222
    .line 223
    invoke-virtual {p1, v0, p0}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    if-ne p0, v1, :cond_10

    .line 228
    .line 229
    goto :goto_7

    .line 230
    :cond_c
    iget-object v2, p1, Lc1/c;->e:Ll2/j1;

    .line 231
    .line 232
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v2

    .line 236
    check-cast v2, Lt4/f;

    .line 237
    .line 238
    iget v2, v2, Lt4/f;->d:F

    .line 239
    .line 240
    iget v4, v0, Lh2/q0;->b:F

    .line 241
    .line 242
    invoke-static {v2, v4}, Lt4/f;->a(FF)Z

    .line 243
    .line 244
    .line 245
    move-result v4

    .line 246
    if-eqz v4, :cond_d

    .line 247
    .line 248
    new-instance v0, Li1/n;

    .line 249
    .line 250
    const-wide/16 v6, 0x0

    .line 251
    .line 252
    invoke-direct {v0, v6, v7}, Li1/n;-><init>(J)V

    .line 253
    .line 254
    .line 255
    goto :goto_5

    .line 256
    :cond_d
    iget v4, v0, Lh2/q0;->d:F

    .line 257
    .line 258
    invoke-static {v2, v4}, Lt4/f;->a(FF)Z

    .line 259
    .line 260
    .line 261
    move-result v4

    .line 262
    if-eqz v4, :cond_e

    .line 263
    .line 264
    new-instance v0, Li1/i;

    .line 265
    .line 266
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 267
    .line 268
    .line 269
    goto :goto_5

    .line 270
    :cond_e
    iget v0, v0, Lh2/q0;->c:F

    .line 271
    .line 272
    invoke-static {v2, v0}, Lt4/f;->a(FF)Z

    .line 273
    .line 274
    .line 275
    move-result v0

    .line 276
    if-eqz v0, :cond_f

    .line 277
    .line 278
    new-instance v0, Li1/e;

    .line 279
    .line 280
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 281
    .line 282
    .line 283
    goto :goto_5

    .line 284
    :cond_f
    const/4 v0, 0x0

    .line 285
    :goto_5
    iput v3, p0, Lh2/p0;->e:I

    .line 286
    .line 287
    iget-object v2, p0, Lh2/p0;->i:Li1/k;

    .line 288
    .line 289
    invoke-static {p1, v5, v0, v2, p0}, Li2/k0;->a(Lc1/c;FLi1/k;Li1/k;Lrx0/i;)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object p0

    .line 293
    if-ne p0, v1, :cond_10

    .line 294
    .line 295
    goto :goto_7

    .line 296
    :cond_10
    :goto_6
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 297
    .line 298
    :goto_7
    return-object v1

    .line 299
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
