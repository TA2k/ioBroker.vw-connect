.class public final Lg1/c0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:Lkotlin/jvm/internal/c0;

.field public f:I

.field public final synthetic g:F

.field public final synthetic h:Lg1/e2;

.field public i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public constructor <init>(FLg1/d0;Lg1/e2;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lg1/c0;->d:I

    .line 1
    iput p1, p0, Lg1/c0;->g:F

    iput-object p2, p0, Lg1/c0;->j:Ljava/lang/Object;

    iput-object p3, p0, Lg1/c0;->h:Lg1/e2;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lh1/g;FLay0/k;Lg1/e2;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lg1/c0;->d:I

    .line 2
    iput-object p1, p0, Lg1/c0;->i:Ljava/lang/Object;

    iput p2, p0, Lg1/c0;->g:F

    iput-object p3, p0, Lg1/c0;->j:Ljava/lang/Object;

    iput-object p4, p0, Lg1/c0;->h:Lg1/e2;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6

    .line 1
    iget p1, p0, Lg1/c0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lg1/c0;

    .line 7
    .line 8
    iget-object p1, p0, Lg1/c0;->i:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lh1/g;

    .line 12
    .line 13
    iget-object p1, p0, Lg1/c0;->j:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, p1

    .line 16
    check-cast v3, Lay0/k;

    .line 17
    .line 18
    iget-object v4, p0, Lg1/c0;->h:Lg1/e2;

    .line 19
    .line 20
    iget v2, p0, Lg1/c0;->g:F

    .line 21
    .line 22
    move-object v5, p2

    .line 23
    invoke-direct/range {v0 .. v5}, Lg1/c0;-><init>(Lh1/g;FLay0/k;Lg1/e2;Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :pswitch_0
    move-object v5, p2

    .line 28
    new-instance p1, Lg1/c0;

    .line 29
    .line 30
    iget-object p2, p0, Lg1/c0;->j:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p2, Lg1/d0;

    .line 33
    .line 34
    iget-object v0, p0, Lg1/c0;->h:Lg1/e2;

    .line 35
    .line 36
    iget p0, p0, Lg1/c0;->g:F

    .line 37
    .line 38
    invoke-direct {p1, p0, p2, v0, v5}, Lg1/c0;-><init>(FLg1/d0;Lg1/e2;Lkotlin/coroutines/Continuation;)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lg1/c0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lg1/c0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg1/c0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg1/c0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lg1/c0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lg1/c0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lg1/c0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 12

    .line 1
    iget v0, p0, Lg1/c0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lg1/c0;->j:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v6, v0

    .line 9
    check-cast v6, Lay0/k;

    .line 10
    .line 11
    iget-object v0, p0, Lg1/c0;->i:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lh1/g;

    .line 14
    .line 15
    iget-object v7, v0, Lh1/g;->a:Lh1/l;

    .line 16
    .line 17
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 18
    .line 19
    iget v1, p0, Lg1/c0;->f:I

    .line 20
    .line 21
    const/4 v9, 0x0

    .line 22
    const/4 v10, 0x2

    .line 23
    const/4 v2, 0x1

    .line 24
    if-eqz v1, :cond_2

    .line 25
    .line 26
    if-eq v1, v2, :cond_1

    .line 27
    .line 28
    if-ne v1, v10, :cond_0

    .line 29
    .line 30
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    move-object v0, p1

    .line 34
    goto/16 :goto_2

    .line 35
    .line 36
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw v0

    .line 44
    :cond_1
    iget-object v1, p0, Lg1/c0;->e:Lkotlin/jvm/internal/c0;

    .line 45
    .line 46
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    move-object v11, v1

    .line 50
    move-object v1, p1

    .line 51
    goto :goto_0

    .line 52
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iget-object v1, v0, Lh1/g;->b:Lc1/u;

    .line 56
    .line 57
    iget v3, p0, Lg1/c0;->g:F

    .line 58
    .line 59
    invoke-static {v1, v9, v3}, Lc1/d;->k(Lc1/u;FF)F

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    invoke-interface {v7, v3, v1}, Lh1/l;->j(FF)F

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    .line 68
    .line 69
    .line 70
    move-result v4

    .line 71
    if-eqz v4, :cond_3

    .line 72
    .line 73
    const-string v4, "calculateApproachOffset returned NaN. Please use a valid value."

    .line 74
    .line 75
    invoke-static {v4}, Lj1/b;->c(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    :cond_3
    new-instance v11, Lkotlin/jvm/internal/c0;

    .line 79
    .line 80
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 81
    .line 82
    .line 83
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    invoke-static {v3}, Ljava/lang/Math;->signum(F)F

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    mul-float/2addr v3, v1

    .line 92
    iput v3, v11, Lkotlin/jvm/internal/c0;->d:F

    .line 93
    .line 94
    new-instance v1, Ljava/lang/Float;

    .line 95
    .line 96
    invoke-direct {v1, v3}, Ljava/lang/Float;-><init>(F)V

    .line 97
    .line 98
    .line 99
    invoke-interface {v6, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    iget v1, v11, Lkotlin/jvm/internal/c0;->d:F

    .line 103
    .line 104
    new-instance v4, Lh1/d;

    .line 105
    .line 106
    const/4 v3, 0x0

    .line 107
    invoke-direct {v4, v11, v6, v3}, Lh1/d;-><init>(Lkotlin/jvm/internal/c0;Lay0/k;I)V

    .line 108
    .line 109
    .line 110
    iput-object v11, p0, Lg1/c0;->e:Lkotlin/jvm/internal/c0;

    .line 111
    .line 112
    iput v2, p0, Lg1/c0;->f:I

    .line 113
    .line 114
    move v2, v1

    .line 115
    iget-object v1, p0, Lg1/c0;->h:Lg1/e2;

    .line 116
    .line 117
    iget v3, p0, Lg1/c0;->g:F

    .line 118
    .line 119
    move-object v5, p0

    .line 120
    invoke-static/range {v0 .. v5}, Lh1/g;->b(Lh1/g;Lg1/e2;FFLh1/d;Lrx0/c;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    if-ne v1, v8, :cond_4

    .line 125
    .line 126
    goto :goto_1

    .line 127
    :cond_4
    :goto_0
    check-cast v1, Lc1/k;

    .line 128
    .line 129
    invoke-virtual {v1}, Lc1/k;->a()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    check-cast v2, Ljava/lang/Number;

    .line 134
    .line 135
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 136
    .line 137
    .line 138
    move-result v2

    .line 139
    invoke-interface {v7, v2}, Lh1/l;->g(F)F

    .line 140
    .line 141
    .line 142
    move-result v2

    .line 143
    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    .line 144
    .line 145
    .line 146
    move-result v3

    .line 147
    if-eqz v3, :cond_5

    .line 148
    .line 149
    const-string v3, "calculateSnapOffset returned NaN. Please use a valid value."

    .line 150
    .line 151
    invoke-static {v3}, Lj1/b;->c(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    :cond_5
    iput v2, v11, Lkotlin/jvm/internal/c0;->d:F

    .line 155
    .line 156
    const/16 v3, 0x1e

    .line 157
    .line 158
    invoke-static {v1, v9, v9, v3}, Lc1/d;->m(Lc1/k;FFI)Lc1/k;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    iget-object v4, v0, Lh1/g;->c:Lc1/j;

    .line 163
    .line 164
    new-instance v0, Lh1/d;

    .line 165
    .line 166
    const/4 v1, 0x1

    .line 167
    invoke-direct {v0, v11, v6, v1}, Lh1/d;-><init>(Lkotlin/jvm/internal/c0;Lay0/k;I)V

    .line 168
    .line 169
    .line 170
    const/4 v1, 0x0

    .line 171
    iput-object v1, p0, Lg1/c0;->e:Lkotlin/jvm/internal/c0;

    .line 172
    .line 173
    iput v10, p0, Lg1/c0;->f:I

    .line 174
    .line 175
    move-object v1, v0

    .line 176
    iget-object v0, p0, Lg1/c0;->h:Lg1/e2;

    .line 177
    .line 178
    move-object v5, v1

    .line 179
    move v1, v2

    .line 180
    move-object v6, p0

    .line 181
    invoke-static/range {v0 .. v6}, Lh1/k;->b(Lg1/e2;FFLc1/k;Lc1/j;Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    if-ne v0, v8, :cond_6

    .line 186
    .line 187
    :goto_1
    move-object v0, v8

    .line 188
    :cond_6
    :goto_2
    return-object v0

    .line 189
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 190
    .line 191
    iget v1, p0, Lg1/c0;->f:I

    .line 192
    .line 193
    const/4 v2, 0x1

    .line 194
    if-eqz v1, :cond_8

    .line 195
    .line 196
    if-ne v1, v2, :cond_7

    .line 197
    .line 198
    iget-object v0, p0, Lg1/c0;->i:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v0, Lc1/k;

    .line 201
    .line 202
    iget-object v1, p0, Lg1/c0;->e:Lkotlin/jvm/internal/c0;

    .line 203
    .line 204
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_1

    .line 205
    .line 206
    .line 207
    goto :goto_3

    .line 208
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 209
    .line 210
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 211
    .line 212
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    throw v0

    .line 216
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    iget v1, p0, Lg1/c0;->g:F

    .line 220
    .line 221
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 222
    .line 223
    .line 224
    move-result v3

    .line 225
    const/high16 v4, 0x3f800000    # 1.0f

    .line 226
    .line 227
    cmpl-float v3, v3, v4

    .line 228
    .line 229
    if-lez v3, :cond_a

    .line 230
    .line 231
    new-instance v3, Lkotlin/jvm/internal/c0;

    .line 232
    .line 233
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 234
    .line 235
    .line 236
    iput v1, v3, Lkotlin/jvm/internal/c0;->d:F

    .line 237
    .line 238
    new-instance v4, Lkotlin/jvm/internal/c0;

    .line 239
    .line 240
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 241
    .line 242
    .line 243
    const/4 v6, 0x0

    .line 244
    const/16 v7, 0x1c

    .line 245
    .line 246
    invoke-static {v6, v1, v7}, Lc1/d;->b(FFI)Lc1/k;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    :try_start_1
    iget-object v6, p0, Lg1/c0;->j:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v6, Lg1/d0;

    .line 253
    .line 254
    iget-object v7, v6, Lg1/d0;->a:Lc1/u;

    .line 255
    .line 256
    iget-object v8, p0, Lg1/c0;->h:Lg1/e2;

    .line 257
    .line 258
    new-instance v9, Laa/o;

    .line 259
    .line 260
    invoke-direct {v9, v4, v8, v3, v6}, Laa/o;-><init>(Lkotlin/jvm/internal/c0;Lg1/e2;Lkotlin/jvm/internal/c0;Lg1/d0;)V

    .line 261
    .line 262
    .line 263
    iput-object v3, p0, Lg1/c0;->e:Lkotlin/jvm/internal/c0;

    .line 264
    .line 265
    iput-object v1, p0, Lg1/c0;->i:Ljava/lang/Object;

    .line 266
    .line 267
    iput v2, p0, Lg1/c0;->f:I

    .line 268
    .line 269
    const/4 v2, 0x0

    .line 270
    invoke-static {v1, v7, v2, v9, p0}, Lc1/d;->f(Lc1/k;Lc1/u;ZLay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v1
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    .line 274
    if-ne v1, v0, :cond_9

    .line 275
    .line 276
    goto :goto_4

    .line 277
    :cond_9
    move-object v1, v3

    .line 278
    goto :goto_3

    .line 279
    :catch_0
    move-object v0, v1

    .line 280
    move-object v1, v3

    .line 281
    :catch_1
    invoke-virtual {v0}, Lc1/k;->a()Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object v0

    .line 285
    check-cast v0, Ljava/lang/Number;

    .line 286
    .line 287
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 288
    .line 289
    .line 290
    move-result v0

    .line 291
    iput v0, v1, Lkotlin/jvm/internal/c0;->d:F

    .line 292
    .line 293
    :goto_3
    iget v1, v1, Lkotlin/jvm/internal/c0;->d:F

    .line 294
    .line 295
    :cond_a
    new-instance v0, Ljava/lang/Float;

    .line 296
    .line 297
    invoke-direct {v0, v1}, Ljava/lang/Float;-><init>(F)V

    .line 298
    .line 299
    .line 300
    :goto_4
    return-object v0

    .line 301
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
