.class public final Lza0/n;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lyl/l;

.field public final synthetic h:Lmm/g;

.field public final synthetic i:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lyl/l;Lmm/g;Ll2/b1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Lza0/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lza0/n;->g:Lyl/l;

    .line 4
    .line 5
    iput-object p2, p0, Lza0/n;->h:Lmm/g;

    .line 6
    .line 7
    iput-object p3, p0, Lza0/n;->i:Ll2/b1;

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget v0, p0, Lza0/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lza0/n;

    .line 7
    .line 8
    iget-object v4, p0, Lza0/n;->i:Ll2/b1;

    .line 9
    .line 10
    const/4 v6, 0x2

    .line 11
    iget-object v2, p0, Lza0/n;->g:Lyl/l;

    .line 12
    .line 13
    iget-object v3, p0, Lza0/n;->h:Lmm/g;

    .line 14
    .line 15
    move-object v5, p2

    .line 16
    invoke-direct/range {v1 .. v6}, Lza0/n;-><init>(Lyl/l;Lmm/g;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    iput-object p1, v1, Lza0/n;->f:Ljava/lang/Object;

    .line 20
    .line 21
    return-object v1

    .line 22
    :pswitch_0
    move-object v6, p2

    .line 23
    new-instance v2, Lza0/n;

    .line 24
    .line 25
    iget-object v5, p0, Lza0/n;->i:Ll2/b1;

    .line 26
    .line 27
    const/4 v7, 0x1

    .line 28
    iget-object v3, p0, Lza0/n;->g:Lyl/l;

    .line 29
    .line 30
    iget-object v4, p0, Lza0/n;->h:Lmm/g;

    .line 31
    .line 32
    invoke-direct/range {v2 .. v7}, Lza0/n;-><init>(Lyl/l;Lmm/g;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    iput-object p1, v2, Lza0/n;->f:Ljava/lang/Object;

    .line 36
    .line 37
    return-object v2

    .line 38
    :pswitch_1
    move-object v6, p2

    .line 39
    new-instance v2, Lza0/n;

    .line 40
    .line 41
    iget-object v5, p0, Lza0/n;->i:Ll2/b1;

    .line 42
    .line 43
    const/4 v7, 0x0

    .line 44
    iget-object v3, p0, Lza0/n;->g:Lyl/l;

    .line 45
    .line 46
    iget-object v4, p0, Lza0/n;->h:Lmm/g;

    .line 47
    .line 48
    invoke-direct/range {v2 .. v7}, Lza0/n;-><init>(Lyl/l;Lmm/g;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 49
    .line 50
    .line 51
    iput-object p1, v2, Lza0/n;->f:Ljava/lang/Object;

    .line 52
    .line 53
    return-object v2

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lza0/n;->d:I

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
    invoke-virtual {p0, p1, p2}, Lza0/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lza0/n;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lza0/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lza0/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lza0/n;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lza0/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lza0/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lza0/n;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lza0/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 4

    .line 1
    iget v0, p0, Lza0/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lza0/n;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvy0/b0;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Lza0/n;->e:I

    .line 13
    .line 14
    const/4 v3, 0x1

    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    if-ne v2, v3, :cond_0

    .line 18
    .line 19
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iput-object v0, p0, Lza0/n;->f:Ljava/lang/Object;

    .line 35
    .line 36
    iput v3, p0, Lza0/n;->e:I

    .line 37
    .line 38
    iget-object p1, p0, Lza0/n;->g:Lyl/l;

    .line 39
    .line 40
    check-cast p1, Lyl/r;

    .line 41
    .line 42
    iget-object v2, p0, Lza0/n;->h:Lmm/g;

    .line 43
    .line 44
    invoke-virtual {p1, v2, p0}, Lyl/r;->b(Lmm/g;Lrx0/c;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    if-ne p1, v1, :cond_2

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    :goto_0
    check-cast p1, Lmm/j;

    .line 52
    .line 53
    instance-of v1, p1, Lmm/c;

    .line 54
    .line 55
    if-eqz v1, :cond_3

    .line 56
    .line 57
    new-instance p0, Lza0/m;

    .line 58
    .line 59
    check-cast p1, Lmm/c;

    .line 60
    .line 61
    const/4 v1, 0x2

    .line 62
    invoke-direct {p0, p1, v1}, Lza0/m;-><init>(Lmm/c;I)V

    .line 63
    .line 64
    .line 65
    const/4 p1, 0x0

    .line 66
    invoke-static {p1, v0, p0}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_3
    instance-of v0, p1, Lmm/p;

    .line 71
    .line 72
    if-eqz v0, :cond_4

    .line 73
    .line 74
    check-cast p1, Lmm/p;

    .line 75
    .line 76
    iget-object p1, p1, Lmm/p;->a:Lyl/j;

    .line 77
    .line 78
    invoke-static {p1}, Lyl/m;->i(Lyl/j;)Landroid/graphics/Bitmap;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    new-instance v0, Ly6/f;

    .line 83
    .line 84
    invoke-direct {v0, p1}, Ly6/f;-><init>(Landroid/graphics/Bitmap;)V

    .line 85
    .line 86
    .line 87
    iget-object p0, p0, Lza0/n;->i:Ll2/b1;

    .line 88
    .line 89
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    :goto_1
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    :goto_2
    return-object v1

    .line 95
    :cond_4
    new-instance p0, La8/r0;

    .line 96
    .line 97
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 98
    .line 99
    .line 100
    throw p0

    .line 101
    :pswitch_0
    iget-object v0, p0, Lza0/n;->f:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast v0, Lvy0/b0;

    .line 104
    .line 105
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 106
    .line 107
    iget v2, p0, Lza0/n;->e:I

    .line 108
    .line 109
    const/4 v3, 0x1

    .line 110
    if-eqz v2, :cond_6

    .line 111
    .line 112
    if-ne v2, v3, :cond_5

    .line 113
    .line 114
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    goto :goto_3

    .line 118
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 119
    .line 120
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 121
    .line 122
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    throw p0

    .line 126
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    iput-object v0, p0, Lza0/n;->f:Ljava/lang/Object;

    .line 130
    .line 131
    iput v3, p0, Lza0/n;->e:I

    .line 132
    .line 133
    iget-object p1, p0, Lza0/n;->g:Lyl/l;

    .line 134
    .line 135
    check-cast p1, Lyl/r;

    .line 136
    .line 137
    iget-object v2, p0, Lza0/n;->h:Lmm/g;

    .line 138
    .line 139
    invoke-virtual {p1, v2, p0}, Lyl/r;->b(Lmm/g;Lrx0/c;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    if-ne p1, v1, :cond_7

    .line 144
    .line 145
    goto :goto_5

    .line 146
    :cond_7
    :goto_3
    check-cast p1, Lmm/j;

    .line 147
    .line 148
    instance-of v1, p1, Lmm/c;

    .line 149
    .line 150
    if-eqz v1, :cond_8

    .line 151
    .line 152
    new-instance p0, Lza0/m;

    .line 153
    .line 154
    check-cast p1, Lmm/c;

    .line 155
    .line 156
    const/4 v1, 0x1

    .line 157
    invoke-direct {p0, p1, v1}, Lza0/m;-><init>(Lmm/c;I)V

    .line 158
    .line 159
    .line 160
    const/4 p1, 0x0

    .line 161
    invoke-static {p1, v0, p0}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 162
    .line 163
    .line 164
    goto :goto_4

    .line 165
    :cond_8
    instance-of v0, p1, Lmm/p;

    .line 166
    .line 167
    if-eqz v0, :cond_9

    .line 168
    .line 169
    check-cast p1, Lmm/p;

    .line 170
    .line 171
    iget-object p1, p1, Lmm/p;->a:Lyl/j;

    .line 172
    .line 173
    invoke-static {p1}, Lyl/m;->i(Lyl/j;)Landroid/graphics/Bitmap;

    .line 174
    .line 175
    .line 176
    move-result-object p1

    .line 177
    new-instance v0, Ly6/f;

    .line 178
    .line 179
    invoke-direct {v0, p1}, Ly6/f;-><init>(Landroid/graphics/Bitmap;)V

    .line 180
    .line 181
    .line 182
    iget-object p0, p0, Lza0/n;->i:Ll2/b1;

    .line 183
    .line 184
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    :goto_4
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 188
    .line 189
    :goto_5
    return-object v1

    .line 190
    :cond_9
    new-instance p0, La8/r0;

    .line 191
    .line 192
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 193
    .line 194
    .line 195
    throw p0

    .line 196
    :pswitch_1
    iget-object v0, p0, Lza0/n;->f:Ljava/lang/Object;

    .line 197
    .line 198
    check-cast v0, Lvy0/b0;

    .line 199
    .line 200
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 201
    .line 202
    iget v2, p0, Lza0/n;->e:I

    .line 203
    .line 204
    const/4 v3, 0x1

    .line 205
    if-eqz v2, :cond_b

    .line 206
    .line 207
    if-ne v2, v3, :cond_a

    .line 208
    .line 209
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 210
    .line 211
    .line 212
    goto :goto_6

    .line 213
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 214
    .line 215
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 216
    .line 217
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    throw p0

    .line 221
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    iput-object v0, p0, Lza0/n;->f:Ljava/lang/Object;

    .line 225
    .line 226
    iput v3, p0, Lza0/n;->e:I

    .line 227
    .line 228
    iget-object p1, p0, Lza0/n;->g:Lyl/l;

    .line 229
    .line 230
    check-cast p1, Lyl/r;

    .line 231
    .line 232
    iget-object v2, p0, Lza0/n;->h:Lmm/g;

    .line 233
    .line 234
    invoke-virtual {p1, v2, p0}, Lyl/r;->b(Lmm/g;Lrx0/c;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object p1

    .line 238
    if-ne p1, v1, :cond_c

    .line 239
    .line 240
    goto :goto_8

    .line 241
    :cond_c
    :goto_6
    check-cast p1, Lmm/j;

    .line 242
    .line 243
    instance-of v1, p1, Lmm/c;

    .line 244
    .line 245
    if-eqz v1, :cond_d

    .line 246
    .line 247
    new-instance p0, Lza0/m;

    .line 248
    .line 249
    check-cast p1, Lmm/c;

    .line 250
    .line 251
    const/4 v1, 0x0

    .line 252
    invoke-direct {p0, p1, v1}, Lza0/m;-><init>(Lmm/c;I)V

    .line 253
    .line 254
    .line 255
    const/4 p1, 0x0

    .line 256
    invoke-static {p1, v0, p0}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 257
    .line 258
    .line 259
    goto :goto_7

    .line 260
    :cond_d
    instance-of v0, p1, Lmm/p;

    .line 261
    .line 262
    if-eqz v0, :cond_e

    .line 263
    .line 264
    check-cast p1, Lmm/p;

    .line 265
    .line 266
    iget-object p1, p1, Lmm/p;->a:Lyl/j;

    .line 267
    .line 268
    invoke-static {p1}, Lyl/m;->i(Lyl/j;)Landroid/graphics/Bitmap;

    .line 269
    .line 270
    .line 271
    move-result-object p1

    .line 272
    new-instance v0, Ly6/f;

    .line 273
    .line 274
    invoke-direct {v0, p1}, Ly6/f;-><init>(Landroid/graphics/Bitmap;)V

    .line 275
    .line 276
    .line 277
    iget-object p0, p0, Lza0/n;->i:Ll2/b1;

    .line 278
    .line 279
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 280
    .line 281
    .line 282
    :goto_7
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 283
    .line 284
    :goto_8
    return-object v1

    .line 285
    :cond_e
    new-instance p0, La8/r0;

    .line 286
    .line 287
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 288
    .line 289
    .line 290
    throw p0

    .line 291
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
