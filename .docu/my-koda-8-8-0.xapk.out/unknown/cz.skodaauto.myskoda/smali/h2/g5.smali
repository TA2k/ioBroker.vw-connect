.class public final Lh2/g5;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh2/h5;


# direct methods
.method public synthetic constructor <init>(Lh2/h5;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/g5;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/g5;->f:Lh2/h5;

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
    iget p1, p0, Lh2/g5;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh2/g5;

    .line 7
    .line 8
    iget-object p0, p0, Lh2/g5;->f:Lh2/h5;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lh2/g5;-><init>(Lh2/h5;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lh2/g5;

    .line 16
    .line 17
    iget-object p0, p0, Lh2/g5;->f:Lh2/h5;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lh2/g5;-><init>(Lh2/h5;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lh2/g5;

    .line 25
    .line 26
    iget-object p0, p0, Lh2/g5;->f:Lh2/h5;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lh2/g5;-><init>(Lh2/h5;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lh2/g5;

    .line 34
    .line 35
    iget-object p0, p0, Lh2/g5;->f:Lh2/h5;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lh2/g5;-><init>(Lh2/h5;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lh2/g5;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh2/g5;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh2/g5;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh2/g5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh2/g5;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh2/g5;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh2/g5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lh2/g5;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lh2/g5;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lh2/g5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lh2/g5;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lh2/g5;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lh2/g5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 11

    .line 1
    iget v0, p0, Lh2/g5;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lh2/g5;->f:Lh2/h5;

    .line 4
    .line 5
    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    .line 6
    .line 7
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    const/4 v4, 0x1

    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    iget v5, p0, Lh2/g5;->e:I

    .line 16
    .line 17
    if-eqz v5, :cond_1

    .line 18
    .line 19
    if-ne v5, v4, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    iput v4, p0, Lh2/g5;->e:I

    .line 35
    .line 36
    invoke-static {v1, p0}, Lh2/h5;->a1(Lh2/h5;Lrx0/i;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-object v3, v0

    .line 40
    :goto_0
    return-object v3

    .line 41
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 42
    .line 43
    iget v5, p0, Lh2/g5;->e:I

    .line 44
    .line 45
    if-eqz v5, :cond_3

    .line 46
    .line 47
    if-ne v5, v4, :cond_2

    .line 48
    .line 49
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput v4, p0, Lh2/g5;->e:I

    .line 63
    .line 64
    invoke-static {v1, p0}, Lh2/h5;->a1(Lh2/h5;Lrx0/i;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-object v3, v0

    .line 68
    :goto_1
    return-object v3

    .line 69
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 70
    .line 71
    iget v5, p0, Lh2/g5;->e:I

    .line 72
    .line 73
    if-eqz v5, :cond_5

    .line 74
    .line 75
    if-ne v5, v4, :cond_4

    .line 76
    .line 77
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    goto :goto_5

    .line 81
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 82
    .line 83
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw p0

    .line 87
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    move v5, v4

    .line 91
    iget-object v4, v1, Lh2/h5;->D:Lc1/c;

    .line 92
    .line 93
    iget-boolean p1, v1, Lh2/h5;->y:Z

    .line 94
    .line 95
    if-eqz p1, :cond_6

    .line 96
    .line 97
    iget-boolean p1, v1, Lh2/h5;->t:Z

    .line 98
    .line 99
    if-eqz p1, :cond_6

    .line 100
    .line 101
    iget p1, v1, Lh2/h5;->w:F

    .line 102
    .line 103
    :goto_2
    move v6, v5

    .line 104
    goto :goto_3

    .line 105
    :cond_6
    iget p1, v1, Lh2/h5;->x:F

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :goto_3
    new-instance v5, Lt4/f;

    .line 109
    .line 110
    invoke-direct {v5, p1}, Lt4/f;-><init>(F)V

    .line 111
    .line 112
    .line 113
    iget-boolean p1, v1, Lh2/h5;->t:Z

    .line 114
    .line 115
    if-eqz p1, :cond_7

    .line 116
    .line 117
    sget-object p1, Lh2/l5;->a:Ll2/u2;

    .line 118
    .line 119
    invoke-static {v1, p1}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    check-cast p1, Lh2/n6;

    .line 124
    .line 125
    sget-object v1, Lk2/w;->e:Lk2/w;

    .line 126
    .line 127
    invoke-static {p1, v1}, Lh2/r;->z(Lh2/n6;Lk2/w;)Lc1/f1;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    goto :goto_4

    .line 132
    :cond_7
    invoke-static {}, Lc1/d;->s()Lc1/d1;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    :goto_4
    iput v6, p0, Lh2/g5;->e:I

    .line 137
    .line 138
    const/4 v7, 0x0

    .line 139
    const/4 v8, 0x0

    .line 140
    const/16 v10, 0xc

    .line 141
    .line 142
    move-object v9, p0

    .line 143
    move-object v6, p1

    .line 144
    invoke-static/range {v4 .. v10}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    if-ne p0, v0, :cond_8

    .line 149
    .line 150
    move-object v3, v0

    .line 151
    :cond_8
    :goto_5
    return-object v3

    .line 152
    :pswitch_2
    move-object v9, p0

    .line 153
    move v6, v4

    .line 154
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 155
    .line 156
    iget v0, v9, Lh2/g5;->e:I

    .line 157
    .line 158
    if-eqz v0, :cond_a

    .line 159
    .line 160
    if-ne v0, v6, :cond_9

    .line 161
    .line 162
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    goto :goto_7

    .line 166
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 167
    .line 168
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    throw p0

    .line 172
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    iget-object v4, v1, Lh2/h5;->B:Lc1/c;

    .line 176
    .line 177
    if-eqz v4, :cond_e

    .line 178
    .line 179
    iget-object p1, v1, Lh2/h5;->A:Lh2/eb;

    .line 180
    .line 181
    if-nez p1, :cond_b

    .line 182
    .line 183
    sget-object p1, Lh2/hb;->a:Lh2/hb;

    .line 184
    .line 185
    sget-object p1, Lh2/g1;->a:Ll2/u2;

    .line 186
    .line 187
    invoke-static {v1, p1}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object p1

    .line 191
    check-cast p1, Lh2/f1;

    .line 192
    .line 193
    sget-object v0, Le2/e1;->a:Ll2/e0;

    .line 194
    .line 195
    invoke-static {v1, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    check-cast v0, Le2/d1;

    .line 200
    .line 201
    invoke-static {p1, v0}, Lh2/hb;->f(Lh2/f1;Le2/d1;)Lh2/eb;

    .line 202
    .line 203
    .line 204
    move-result-object p1

    .line 205
    :cond_b
    iget-boolean v0, v1, Lh2/h5;->t:Z

    .line 206
    .line 207
    iget-boolean v2, v1, Lh2/h5;->u:Z

    .line 208
    .line 209
    iget-boolean v5, v1, Lh2/h5;->y:Z

    .line 210
    .line 211
    invoke-virtual {p1, v0, v2, v5}, Lh2/eb;->c(ZZZ)J

    .line 212
    .line 213
    .line 214
    move-result-wide v7

    .line 215
    new-instance v5, Le3/s;

    .line 216
    .line 217
    invoke-direct {v5, v7, v8}, Le3/s;-><init>(J)V

    .line 218
    .line 219
    .line 220
    iget-boolean p1, v1, Lh2/h5;->t:Z

    .line 221
    .line 222
    if-eqz p1, :cond_c

    .line 223
    .line 224
    sget-object p1, Lh2/l5;->a:Ll2/u2;

    .line 225
    .line 226
    invoke-static {v1, p1}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object p1

    .line 230
    check-cast p1, Lh2/n6;

    .line 231
    .line 232
    sget-object v0, Lk2/w;->g:Lk2/w;

    .line 233
    .line 234
    invoke-static {p1, v0}, Lh2/r;->z(Lh2/n6;Lk2/w;)Lc1/f1;

    .line 235
    .line 236
    .line 237
    move-result-object p1

    .line 238
    goto :goto_6

    .line 239
    :cond_c
    invoke-static {}, Lc1/d;->s()Lc1/d1;

    .line 240
    .line 241
    .line 242
    move-result-object p1

    .line 243
    :goto_6
    iput v6, v9, Lh2/g5;->e:I

    .line 244
    .line 245
    const/4 v7, 0x0

    .line 246
    const/4 v8, 0x0

    .line 247
    const/16 v10, 0xc

    .line 248
    .line 249
    move-object v6, p1

    .line 250
    invoke-static/range {v4 .. v10}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object p1

    .line 254
    if-ne p1, p0, :cond_d

    .line 255
    .line 256
    move-object v3, p0

    .line 257
    goto :goto_8

    .line 258
    :cond_d
    :goto_7
    check-cast p1, Lc1/h;

    .line 259
    .line 260
    :cond_e
    :goto_8
    return-object v3

    .line 261
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
