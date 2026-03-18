.class public final Lkn/t;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lkn/c0;

.field public final synthetic g:I

.field public final synthetic h:Z

.field public final synthetic i:Lvy0/b0;

.field public final synthetic j:Lc1/c;


# direct methods
.method public synthetic constructor <init>(Lkn/c0;IZLvy0/b0;Lc1/c;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p7, p0, Lkn/t;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lkn/t;->f:Lkn/c0;

    .line 4
    .line 5
    iput p2, p0, Lkn/t;->g:I

    .line 6
    .line 7
    iput-boolean p3, p0, Lkn/t;->h:Z

    .line 8
    .line 9
    iput-object p4, p0, Lkn/t;->i:Lvy0/b0;

    .line 10
    .line 11
    iput-object p5, p0, Lkn/t;->j:Lc1/c;

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
    iget p1, p0, Lkn/t;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lkn/t;

    .line 7
    .line 8
    iget-object v5, p0, Lkn/t;->j:Lc1/c;

    .line 9
    .line 10
    const/4 v7, 0x1

    .line 11
    iget-object v1, p0, Lkn/t;->f:Lkn/c0;

    .line 12
    .line 13
    iget v2, p0, Lkn/t;->g:I

    .line 14
    .line 15
    iget-boolean v3, p0, Lkn/t;->h:Z

    .line 16
    .line 17
    iget-object v4, p0, Lkn/t;->i:Lvy0/b0;

    .line 18
    .line 19
    move-object v6, p2

    .line 20
    invoke-direct/range {v0 .. v7}, Lkn/t;-><init>(Lkn/c0;IZLvy0/b0;Lc1/c;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object v0

    .line 24
    :pswitch_0
    move-object v6, p2

    .line 25
    new-instance v1, Lkn/t;

    .line 26
    .line 27
    move-object v7, v6

    .line 28
    iget-object v6, p0, Lkn/t;->j:Lc1/c;

    .line 29
    .line 30
    const/4 v8, 0x0

    .line 31
    iget-object v2, p0, Lkn/t;->f:Lkn/c0;

    .line 32
    .line 33
    iget v3, p0, Lkn/t;->g:I

    .line 34
    .line 35
    iget-boolean v4, p0, Lkn/t;->h:Z

    .line 36
    .line 37
    iget-object v5, p0, Lkn/t;->i:Lvy0/b0;

    .line 38
    .line 39
    invoke-direct/range {v1 .. v8}, Lkn/t;-><init>(Lkn/c0;IZLvy0/b0;Lc1/c;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    return-object v1

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lkn/t;->d:I

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
    invoke-virtual {p0, p1, p2}, Lkn/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lkn/t;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lkn/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lkn/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lkn/t;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lkn/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 11

    .line 1
    iget v0, p0, Lkn/t;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lkn/t;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    iget-boolean v3, p0, Lkn/t;->h:Z

    .line 13
    .line 14
    iget-object v4, p0, Lkn/t;->f:Lkn/c0;

    .line 15
    .line 16
    const/4 v5, 0x4

    .line 17
    const/4 v6, 0x3

    .line 18
    const/4 v7, 0x2

    .line 19
    const/4 v8, 0x1

    .line 20
    if-eqz v1, :cond_3

    .line 21
    .line 22
    if-eq v1, v8, :cond_2

    .line 23
    .line 24
    if-eq v1, v7, :cond_1

    .line 25
    .line 26
    if-eq v1, v6, :cond_1

    .line 27
    .line 28
    if-ne v1, v5, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_1
    :goto_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    xor-int/lit8 p1, v3, 0x1

    .line 51
    .line 52
    iput v8, p0, Lkn/t;->e:I

    .line 53
    .line 54
    iget v1, p0, Lkn/t;->g:I

    .line 55
    .line 56
    int-to-float v1, v1

    .line 57
    invoke-virtual {v4, v1, p1, p0}, Lkn/c0;->l(FZLrx0/c;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-ne p1, v0, :cond_4

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_4
    move-object p1, v2

    .line 65
    :goto_1
    if-ne p1, v0, :cond_5

    .line 66
    .line 67
    goto :goto_4

    .line 68
    :cond_5
    :goto_2
    iget-object p1, p0, Lkn/t;->j:Lc1/c;

    .line 69
    .line 70
    if-eqz v3, :cond_7

    .line 71
    .line 72
    iget-object v1, v4, Lkn/c0;->k:Lc1/j;

    .line 73
    .line 74
    iget-object v3, p0, Lkn/t;->i:Lvy0/b0;

    .line 75
    .line 76
    const/4 v5, 0x0

    .line 77
    if-eqz v1, :cond_6

    .line 78
    .line 79
    new-instance v9, Lkn/s;

    .line 80
    .line 81
    const/4 v10, 0x1

    .line 82
    invoke-direct {v9, p1, v1, v5, v10}, Lkn/s;-><init>(Lc1/c;Lc1/j;Lkotlin/coroutines/Continuation;I)V

    .line 83
    .line 84
    .line 85
    invoke-static {v3, v5, v5, v9, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 86
    .line 87
    .line 88
    iput v7, p0, Lkn/t;->e:I

    .line 89
    .line 90
    invoke-static {v4, v1, p0, v8}, Lkn/c0;->k(Lkn/c0;Lc1/j;Lrx0/i;I)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    if-ne p0, v0, :cond_8

    .line 95
    .line 96
    goto :goto_4

    .line 97
    :cond_6
    new-instance v1, Lh2/e6;

    .line 98
    .line 99
    const/4 v7, 0x5

    .line 100
    invoke-direct {v1, p1, v5, v7}, Lh2/e6;-><init>(Lc1/c;Lkotlin/coroutines/Continuation;I)V

    .line 101
    .line 102
    .line 103
    invoke-static {v3, v5, v5, v1, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 104
    .line 105
    .line 106
    iput v6, p0, Lkn/t;->e:I

    .line 107
    .line 108
    invoke-static {v4, v5, p0, v6}, Lkn/c0;->k(Lkn/c0;Lc1/j;Lrx0/i;I)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    if-ne p0, v0, :cond_8

    .line 113
    .line 114
    goto :goto_4

    .line 115
    :cond_7
    new-instance v1, Ljava/lang/Float;

    .line 116
    .line 117
    const/high16 v3, 0x3f800000    # 1.0f

    .line 118
    .line 119
    invoke-direct {v1, v3}, Ljava/lang/Float;-><init>(F)V

    .line 120
    .line 121
    .line 122
    iput v5, p0, Lkn/t;->e:I

    .line 123
    .line 124
    invoke-virtual {p1, v1, p0}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    if-ne p0, v0, :cond_8

    .line 129
    .line 130
    goto :goto_4

    .line 131
    :cond_8
    :goto_3
    move-object v0, v2

    .line 132
    :goto_4
    return-object v0

    .line 133
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 134
    .line 135
    iget v1, p0, Lkn/t;->e:I

    .line 136
    .line 137
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 138
    .line 139
    iget-boolean v3, p0, Lkn/t;->h:Z

    .line 140
    .line 141
    iget-object v4, p0, Lkn/t;->f:Lkn/c0;

    .line 142
    .line 143
    const/4 v5, 0x4

    .line 144
    const/4 v6, 0x3

    .line 145
    const/4 v7, 0x2

    .line 146
    const/4 v8, 0x1

    .line 147
    if-eqz v1, :cond_c

    .line 148
    .line 149
    if-eq v1, v8, :cond_b

    .line 150
    .line 151
    if-eq v1, v7, :cond_a

    .line 152
    .line 153
    if-eq v1, v6, :cond_a

    .line 154
    .line 155
    if-ne v1, v5, :cond_9

    .line 156
    .line 157
    goto :goto_5

    .line 158
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 159
    .line 160
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 161
    .line 162
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    throw p0

    .line 166
    :cond_a
    :goto_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    goto :goto_8

    .line 170
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    goto :goto_7

    .line 174
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    xor-int/lit8 p1, v3, 0x1

    .line 178
    .line 179
    iput v8, p0, Lkn/t;->e:I

    .line 180
    .line 181
    iget v1, p0, Lkn/t;->g:I

    .line 182
    .line 183
    int-to-float v1, v1

    .line 184
    invoke-virtual {v4, v1, p1, p0}, Lkn/c0;->l(FZLrx0/c;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    if-ne p1, v0, :cond_d

    .line 189
    .line 190
    goto :goto_6

    .line 191
    :cond_d
    move-object p1, v2

    .line 192
    :goto_6
    if-ne p1, v0, :cond_e

    .line 193
    .line 194
    goto :goto_9

    .line 195
    :cond_e
    :goto_7
    iget-object p1, p0, Lkn/t;->j:Lc1/c;

    .line 196
    .line 197
    if-eqz v3, :cond_10

    .line 198
    .line 199
    iget-object v1, v4, Lkn/c0;->j:Lc1/j;

    .line 200
    .line 201
    iget-object v3, p0, Lkn/t;->i:Lvy0/b0;

    .line 202
    .line 203
    const/4 v5, 0x0

    .line 204
    if-eqz v1, :cond_f

    .line 205
    .line 206
    new-instance v9, Lkn/s;

    .line 207
    .line 208
    const/4 v10, 0x0

    .line 209
    invoke-direct {v9, p1, v1, v5, v10}, Lkn/s;-><init>(Lc1/c;Lc1/j;Lkotlin/coroutines/Continuation;I)V

    .line 210
    .line 211
    .line 212
    invoke-static {v3, v5, v5, v9, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 213
    .line 214
    .line 215
    iput v7, p0, Lkn/t;->e:I

    .line 216
    .line 217
    invoke-static {v4, v1, p0, v8}, Lkn/c0;->f(Lkn/c0;Lc1/j;Lrx0/i;I)Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    if-ne p0, v0, :cond_11

    .line 222
    .line 223
    goto :goto_9

    .line 224
    :cond_f
    new-instance v1, Lh2/e6;

    .line 225
    .line 226
    const/4 v7, 0x4

    .line 227
    invoke-direct {v1, p1, v5, v7}, Lh2/e6;-><init>(Lc1/c;Lkotlin/coroutines/Continuation;I)V

    .line 228
    .line 229
    .line 230
    invoke-static {v3, v5, v5, v1, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 231
    .line 232
    .line 233
    iput v6, p0, Lkn/t;->e:I

    .line 234
    .line 235
    invoke-static {v4, v5, p0, v6}, Lkn/c0;->f(Lkn/c0;Lc1/j;Lrx0/i;I)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object p0

    .line 239
    if-ne p0, v0, :cond_11

    .line 240
    .line 241
    goto :goto_9

    .line 242
    :cond_10
    new-instance v1, Ljava/lang/Float;

    .line 243
    .line 244
    const/high16 v3, 0x3f800000    # 1.0f

    .line 245
    .line 246
    invoke-direct {v1, v3}, Ljava/lang/Float;-><init>(F)V

    .line 247
    .line 248
    .line 249
    iput v5, p0, Lkn/t;->e:I

    .line 250
    .line 251
    invoke-virtual {p1, v1, p0}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    if-ne p0, v0, :cond_11

    .line 256
    .line 257
    goto :goto_9

    .line 258
    :cond_11
    :goto_8
    move-object v0, v2

    .line 259
    :goto_9
    return-object v0

    .line 260
    nop

    .line 261
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
