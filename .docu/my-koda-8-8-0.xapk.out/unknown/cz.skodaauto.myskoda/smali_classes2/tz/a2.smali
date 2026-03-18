.class public final Ltz/a2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ltz/i2;


# direct methods
.method public synthetic constructor <init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltz/a2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/a2;->f:Ltz/i2;

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
    iget p1, p0, Ltz/a2;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ltz/a2;

    .line 7
    .line 8
    iget-object p0, p0, Ltz/a2;->f:Ltz/i2;

    .line 9
    .line 10
    const/4 v0, 0x5

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ltz/a2;-><init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ltz/a2;

    .line 16
    .line 17
    iget-object p0, p0, Ltz/a2;->f:Ltz/i2;

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ltz/a2;-><init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ltz/a2;

    .line 25
    .line 26
    iget-object p0, p0, Ltz/a2;->f:Ltz/i2;

    .line 27
    .line 28
    const/4 v0, 0x3

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ltz/a2;-><init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Ltz/a2;

    .line 34
    .line 35
    iget-object p0, p0, Ltz/a2;->f:Ltz/i2;

    .line 36
    .line 37
    const/4 v0, 0x2

    .line 38
    invoke-direct {p1, p0, p2, v0}, Ltz/a2;-><init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Ltz/a2;

    .line 43
    .line 44
    iget-object p0, p0, Ltz/a2;->f:Ltz/i2;

    .line 45
    .line 46
    const/4 v0, 0x1

    .line 47
    invoke-direct {p1, p0, p2, v0}, Ltz/a2;-><init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_4
    new-instance p1, Ltz/a2;

    .line 52
    .line 53
    iget-object p0, p0, Ltz/a2;->f:Ltz/i2;

    .line 54
    .line 55
    const/4 v0, 0x0

    .line 56
    invoke-direct {p1, p0, p2, v0}, Ltz/a2;-><init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    return-object p1

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltz/a2;->d:I

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
    invoke-virtual {p0, p1, p2}, Ltz/a2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltz/a2;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ltz/a2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ltz/a2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ltz/a2;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ltz/a2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ltz/a2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ltz/a2;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ltz/a2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Ltz/a2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ltz/a2;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ltz/a2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Ltz/a2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ltz/a2;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Ltz/a2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Ltz/a2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Ltz/a2;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Ltz/a2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    nop

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Ltz/a2;->d:I

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x0

    .line 6
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    iget-object v5, p0, Ltz/a2;->f:Ltz/i2;

    .line 9
    .line 10
    const-string v6, "call to \'resume\' before \'invoke\' with coroutine"

    .line 11
    .line 12
    const/4 v7, 0x1

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    iget v8, p0, Ltz/a2;->e:I

    .line 19
    .line 20
    if-eqz v8, :cond_1

    .line 21
    .line 22
    if-ne v8, v7, :cond_0

    .line 23
    .line 24
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    invoke-direct {p0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object p1, v5, Ltz/i2;->u:Lrq0/f;

    .line 38
    .line 39
    new-instance v6, Lsq0/c;

    .line 40
    .line 41
    iget-object v5, v5, Ltz/i2;->h:Lij0/a;

    .line 42
    .line 43
    new-array v8, v3, [Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v5, Ljj0/f;

    .line 46
    .line 47
    const v9, 0x7f120f9f

    .line 48
    .line 49
    .line 50
    invoke-virtual {v5, v9, v8}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    invoke-direct {v6, v1, v5, v2, v2}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iput v7, p0, Ltz/a2;->e:I

    .line 58
    .line 59
    invoke-virtual {p1, v6, v3, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    if-ne p0, v0, :cond_2

    .line 64
    .line 65
    move-object v4, v0

    .line 66
    :cond_2
    :goto_0
    return-object v4

    .line 67
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 68
    .line 69
    iget v1, p0, Ltz/a2;->e:I

    .line 70
    .line 71
    if-eqz v1, :cond_4

    .line 72
    .line 73
    if-ne v1, v7, :cond_3

    .line 74
    .line 75
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 80
    .line 81
    invoke-direct {p0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    iget-object p1, v5, Ltz/i2;->j:Ltn0/b;

    .line 89
    .line 90
    sget-object v1, Lun0/a;->e:Lun0/a;

    .line 91
    .line 92
    iput v7, p0, Ltz/a2;->e:I

    .line 93
    .line 94
    invoke-virtual {p1, v1, p0}, Ltn0/b;->b(Lun0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    if-ne p1, v0, :cond_5

    .line 99
    .line 100
    move-object v4, v0

    .line 101
    goto :goto_2

    .line 102
    :cond_5
    :goto_1
    check-cast p1, Lun0/b;

    .line 103
    .line 104
    iget-boolean p0, p1, Lun0/b;->b:Z

    .line 105
    .line 106
    if-eqz p0, :cond_6

    .line 107
    .line 108
    iget-object p0, v5, Ltz/i2;->p:Lfg0/e;

    .line 109
    .line 110
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    :cond_6
    :goto_2
    return-object v4

    .line 114
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 115
    .line 116
    iget v1, p0, Ltz/a2;->e:I

    .line 117
    .line 118
    const/4 v2, 0x2

    .line 119
    if-eqz v1, :cond_9

    .line 120
    .line 121
    if-eq v1, v7, :cond_8

    .line 122
    .line 123
    if-ne v1, v2, :cond_7

    .line 124
    .line 125
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    goto :goto_5

    .line 129
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 130
    .line 131
    invoke-direct {p0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    throw p0

    .line 135
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    goto :goto_3

    .line 139
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    iget-object p1, v5, Ltz/i2;->r:Lgl0/e;

    .line 143
    .line 144
    sget-object v1, Ltz/i2;->v:Lhl0/b;

    .line 145
    .line 146
    iput v7, p0, Ltz/a2;->e:I

    .line 147
    .line 148
    invoke-virtual {p1, v1, p0}, Lgl0/e;->b(Lhl0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    if-ne p1, v0, :cond_a

    .line 153
    .line 154
    goto :goto_4

    .line 155
    :cond_a
    :goto_3
    check-cast p1, Lhl0/i;

    .line 156
    .line 157
    if-eqz p1, :cond_b

    .line 158
    .line 159
    iput v2, p0, Ltz/a2;->e:I

    .line 160
    .line 161
    invoke-static {v5, p1, p0}, Ltz/i2;->h(Ltz/i2;Lhl0/i;Lrx0/c;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    if-ne p0, v0, :cond_b

    .line 166
    .line 167
    :goto_4
    move-object v4, v0

    .line 168
    :cond_b
    :goto_5
    return-object v4

    .line 169
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 170
    .line 171
    iget v8, p0, Ltz/a2;->e:I

    .line 172
    .line 173
    if-eqz v8, :cond_d

    .line 174
    .line 175
    if-ne v8, v7, :cond_c

    .line 176
    .line 177
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    goto :goto_6

    .line 181
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 182
    .line 183
    invoke-direct {p0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    throw p0

    .line 187
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    iget-object p1, v5, Ltz/i2;->k:Lwj0/k;

    .line 191
    .line 192
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object p1

    .line 196
    check-cast p1, Lyy0/i;

    .line 197
    .line 198
    new-instance v6, Llb0/y;

    .line 199
    .line 200
    const/16 v8, 0xe

    .line 201
    .line 202
    invoke-direct {v6, v8, p1, v5}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 203
    .line 204
    .line 205
    new-instance p1, Ltz/b2;

    .line 206
    .line 207
    invoke-direct {p1, v5, v2, v3}, Ltz/b2;-><init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V

    .line 208
    .line 209
    .line 210
    new-instance v3, Lne0/n;

    .line 211
    .line 212
    const/4 v8, 0x5

    .line 213
    invoke-direct {v3, v6, p1, v8}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 214
    .line 215
    .line 216
    new-instance p1, Llb0/y;

    .line 217
    .line 218
    const/16 v6, 0xf

    .line 219
    .line 220
    invoke-direct {p1, v6, v3, v5}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    new-instance v3, Lm70/f1;

    .line 224
    .line 225
    const/16 v6, 0x16

    .line 226
    .line 227
    invoke-direct {v3, v5, v2, v6}, Lm70/f1;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 228
    .line 229
    .line 230
    new-instance v6, Lne0/n;

    .line 231
    .line 232
    invoke-direct {v6, p1, v3, v8}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 233
    .line 234
    .line 235
    sget p1, Lmy0/c;->g:I

    .line 236
    .line 237
    const/16 p1, 0xc8

    .line 238
    .line 239
    sget-object v3, Lmy0/e;->g:Lmy0/e;

    .line 240
    .line 241
    invoke-static {p1, v3}, Lmy0/h;->s(ILmy0/e;)J

    .line 242
    .line 243
    .line 244
    move-result-wide v8

    .line 245
    invoke-static {v8, v9}, Lvy0/e0;->O(J)J

    .line 246
    .line 247
    .line 248
    move-result-wide v8

    .line 249
    invoke-static {v6, v8, v9}, Lyy0/u;->o(Lyy0/i;J)Lyy0/i;

    .line 250
    .line 251
    .line 252
    move-result-object p1

    .line 253
    new-instance v3, Lqa0/a;

    .line 254
    .line 255
    const/16 v6, 0x10

    .line 256
    .line 257
    invoke-direct {v3, v2, v5, v6}, Lqa0/a;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 258
    .line 259
    .line 260
    invoke-static {p1, v3}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 261
    .line 262
    .line 263
    move-result-object p1

    .line 264
    new-instance v3, Lq10/k;

    .line 265
    .line 266
    const/16 v6, 0xb

    .line 267
    .line 268
    invoke-direct {v3, v5, v2, v6}, Lq10/k;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 269
    .line 270
    .line 271
    new-instance v6, Lgb0/z;

    .line 272
    .line 273
    invoke-direct {v6, v3, v2}, Lgb0/z;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 274
    .line 275
    .line 276
    invoke-static {p1, v6}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 277
    .line 278
    .line 279
    move-result-object p1

    .line 280
    new-instance v3, Lal0/j0;

    .line 281
    .line 282
    invoke-direct {v3, p1, v1}, Lal0/j0;-><init>(Lzy0/j;I)V

    .line 283
    .line 284
    .line 285
    new-instance p1, Ltz/b2;

    .line 286
    .line 287
    invoke-direct {p1, v5, v2, v7}, Ltz/b2;-><init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V

    .line 288
    .line 289
    .line 290
    iput v7, p0, Ltz/a2;->e:I

    .line 291
    .line 292
    invoke-static {p1, p0, v3}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object p0

    .line 296
    if-ne p0, v0, :cond_e

    .line 297
    .line 298
    move-object v4, v0

    .line 299
    :cond_e
    :goto_6
    return-object v4

    .line 300
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 301
    .line 302
    iget v1, p0, Ltz/a2;->e:I

    .line 303
    .line 304
    if-eqz v1, :cond_10

    .line 305
    .line 306
    if-ne v1, v7, :cond_f

    .line 307
    .line 308
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    goto :goto_7

    .line 312
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 313
    .line 314
    invoke-direct {p0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 315
    .line 316
    .line 317
    throw p0

    .line 318
    :cond_10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 319
    .line 320
    .line 321
    iget-object p1, v5, Ltz/i2;->m:Lqd0/h0;

    .line 322
    .line 323
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object p1

    .line 327
    check-cast p1, Lyy0/i;

    .line 328
    .line 329
    new-instance v1, Ltz/z1;

    .line 330
    .line 331
    invoke-direct {v1, v5, v7}, Ltz/z1;-><init>(Ltz/i2;I)V

    .line 332
    .line 333
    .line 334
    iput v7, p0, Ltz/a2;->e:I

    .line 335
    .line 336
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    move-result-object p0

    .line 340
    if-ne p0, v0, :cond_11

    .line 341
    .line 342
    move-object v4, v0

    .line 343
    :cond_11
    :goto_7
    return-object v4

    .line 344
    :pswitch_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 345
    .line 346
    iget v1, p0, Ltz/a2;->e:I

    .line 347
    .line 348
    if-eqz v1, :cond_13

    .line 349
    .line 350
    if-ne v1, v7, :cond_12

    .line 351
    .line 352
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 353
    .line 354
    .line 355
    goto :goto_8

    .line 356
    :cond_12
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 357
    .line 358
    invoke-direct {p0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 359
    .line 360
    .line 361
    throw p0

    .line 362
    :cond_13
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 363
    .line 364
    .line 365
    iget-object p1, v5, Ltz/i2;->l:Lrz/n;

    .line 366
    .line 367
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 368
    .line 369
    .line 370
    move-result-object p1

    .line 371
    check-cast p1, Lyy0/i;

    .line 372
    .line 373
    new-instance v1, Ltz/z1;

    .line 374
    .line 375
    invoke-direct {v1, v5, v3}, Ltz/z1;-><init>(Ltz/i2;I)V

    .line 376
    .line 377
    .line 378
    iput v7, p0, Ltz/a2;->e:I

    .line 379
    .line 380
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 381
    .line 382
    .line 383
    move-result-object p0

    .line 384
    if-ne p0, v0, :cond_14

    .line 385
    .line 386
    move-object v4, v0

    .line 387
    :cond_14
    :goto_8
    return-object v4

    .line 388
    nop

    .line 389
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
