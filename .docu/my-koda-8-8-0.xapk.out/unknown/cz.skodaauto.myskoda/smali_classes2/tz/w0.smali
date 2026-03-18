.class public final Ltz/w0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ltz/b1;


# direct methods
.method public synthetic constructor <init>(Ltz/b1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltz/w0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/w0;->f:Ltz/b1;

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
    iget p1, p0, Ltz/w0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ltz/w0;

    .line 7
    .line 8
    iget-object p0, p0, Ltz/w0;->f:Ltz/b1;

    .line 9
    .line 10
    const/4 v0, 0x6

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ltz/w0;-><init>(Ltz/b1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ltz/w0;

    .line 16
    .line 17
    iget-object p0, p0, Ltz/w0;->f:Ltz/b1;

    .line 18
    .line 19
    const/4 v0, 0x5

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ltz/w0;-><init>(Ltz/b1;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ltz/w0;

    .line 25
    .line 26
    iget-object p0, p0, Ltz/w0;->f:Ltz/b1;

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ltz/w0;-><init>(Ltz/b1;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Ltz/w0;

    .line 34
    .line 35
    iget-object p0, p0, Ltz/w0;->f:Ltz/b1;

    .line 36
    .line 37
    const/4 v0, 0x3

    .line 38
    invoke-direct {p1, p0, p2, v0}, Ltz/w0;-><init>(Ltz/b1;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Ltz/w0;

    .line 43
    .line 44
    iget-object p0, p0, Ltz/w0;->f:Ltz/b1;

    .line 45
    .line 46
    const/4 v0, 0x2

    .line 47
    invoke-direct {p1, p0, p2, v0}, Ltz/w0;-><init>(Ltz/b1;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_4
    new-instance p1, Ltz/w0;

    .line 52
    .line 53
    iget-object p0, p0, Ltz/w0;->f:Ltz/b1;

    .line 54
    .line 55
    const/4 v0, 0x1

    .line 56
    invoke-direct {p1, p0, p2, v0}, Ltz/w0;-><init>(Ltz/b1;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    return-object p1

    .line 60
    :pswitch_5
    new-instance p1, Ltz/w0;

    .line 61
    .line 62
    iget-object p0, p0, Ltz/w0;->f:Ltz/b1;

    .line 63
    .line 64
    const/4 v0, 0x0

    .line 65
    invoke-direct {p1, p0, p2, v0}, Ltz/w0;-><init>(Ltz/b1;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    return-object p1

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
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
    iget v0, p0, Ltz/w0;->d:I

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
    invoke-virtual {p0, p1, p2}, Ltz/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltz/w0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ltz/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ltz/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ltz/w0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ltz/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ltz/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ltz/w0;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ltz/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Ltz/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ltz/w0;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ltz/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Ltz/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ltz/w0;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Ltz/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Ltz/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Ltz/w0;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Ltz/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :pswitch_5
    invoke-virtual {p0, p1, p2}, Ltz/w0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Ltz/w0;

    .line 93
    .line 94
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    invoke-virtual {p0, p1}, Ltz/w0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0

    .line 101
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Ltz/w0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ltz/w0;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Ltz/w0;->f:Ltz/b1;

    .line 31
    .line 32
    iget-object v1, p1, Ltz/b1;->t:Lrq0/f;

    .line 33
    .line 34
    new-instance v3, Lsq0/c;

    .line 35
    .line 36
    iget-object p1, p1, Ltz/b1;->u:Lij0/a;

    .line 37
    .line 38
    const/4 v4, 0x0

    .line 39
    new-array v5, v4, [Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p1, Ljj0/f;

    .line 42
    .line 43
    const v6, 0x7f120412

    .line 44
    .line 45
    .line 46
    invoke-virtual {p1, v6, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    const/4 v5, 0x6

    .line 51
    const/4 v6, 0x0

    .line 52
    invoke-direct {v3, v5, p1, v6, v6}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    iput v2, p0, Ltz/w0;->e:I

    .line 56
    .line 57
    invoke-virtual {v1, v3, v4, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    if-ne p0, v0, :cond_2

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    :goto_1
    return-object v0

    .line 67
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 68
    .line 69
    iget v1, p0, Ltz/w0;->e:I

    .line 70
    .line 71
    const/4 v2, 0x1

    .line 72
    if-eqz v1, :cond_4

    .line 73
    .line 74
    if-ne v1, v2, :cond_3

    .line 75
    .line 76
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 81
    .line 82
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 83
    .line 84
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    iget-object p1, p0, Ltz/w0;->f:Ltz/b1;

    .line 92
    .line 93
    iget-object v1, p1, Ltz/b1;->t:Lrq0/f;

    .line 94
    .line 95
    new-instance v3, Lsq0/c;

    .line 96
    .line 97
    iget-object p1, p1, Ltz/b1;->u:Lij0/a;

    .line 98
    .line 99
    const/4 v4, 0x0

    .line 100
    new-array v5, v4, [Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p1, Ljj0/f;

    .line 103
    .line 104
    const v6, 0x7f120411

    .line 105
    .line 106
    .line 107
    invoke-virtual {p1, v6, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    const/4 v5, 0x6

    .line 112
    const/4 v6, 0x0

    .line 113
    invoke-direct {v3, v5, p1, v6, v6}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    iput v2, p0, Ltz/w0;->e:I

    .line 117
    .line 118
    invoke-virtual {v1, v3, v4, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    if-ne p0, v0, :cond_5

    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 126
    .line 127
    :goto_3
    return-object v0

    .line 128
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 129
    .line 130
    iget v1, p0, Ltz/w0;->e:I

    .line 131
    .line 132
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 133
    .line 134
    const/4 v3, 0x1

    .line 135
    if-eqz v1, :cond_8

    .line 136
    .line 137
    if-ne v1, v3, :cond_7

    .line 138
    .line 139
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    :cond_6
    move-object v0, v2

    .line 143
    goto :goto_4

    .line 144
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 145
    .line 146
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 147
    .line 148
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    throw p0

    .line 152
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    iget-object p1, p0, Ltz/w0;->f:Ltz/b1;

    .line 156
    .line 157
    iget-object p1, p1, Ltz/b1;->s:Lqd0/v0;

    .line 158
    .line 159
    iput v3, p0, Ltz/w0;->e:I

    .line 160
    .line 161
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 162
    .line 163
    .line 164
    invoke-virtual {p1, p0}, Lqd0/v0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    if-ne p0, v0, :cond_6

    .line 169
    .line 170
    :goto_4
    return-object v0

    .line 171
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 172
    .line 173
    iget v1, p0, Ltz/w0;->e:I

    .line 174
    .line 175
    const/4 v2, 0x1

    .line 176
    if-eqz v1, :cond_a

    .line 177
    .line 178
    if-ne v1, v2, :cond_9

    .line 179
    .line 180
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    goto :goto_5

    .line 184
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 185
    .line 186
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 187
    .line 188
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    throw p0

    .line 192
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    iget-object p1, p0, Ltz/w0;->f:Ltz/b1;

    .line 196
    .line 197
    iget-object p1, p1, Ltz/b1;->t:Lrq0/f;

    .line 198
    .line 199
    new-instance v1, Lsq0/c;

    .line 200
    .line 201
    const/4 v3, 0x0

    .line 202
    const/4 v4, 0x2

    .line 203
    const v5, 0x7f120414

    .line 204
    .line 205
    .line 206
    invoke-direct {v1, v5, v4, v3}, Lsq0/c;-><init>(IILjava/lang/Integer;)V

    .line 207
    .line 208
    .line 209
    iput v2, p0, Ltz/w0;->e:I

    .line 210
    .line 211
    const/4 v2, 0x0

    .line 212
    invoke-virtual {p1, v1, v2, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    if-ne p0, v0, :cond_b

    .line 217
    .line 218
    goto :goto_6

    .line 219
    :cond_b
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 220
    .line 221
    :goto_6
    return-object v0

    .line 222
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 223
    .line 224
    iget v1, p0, Ltz/w0;->e:I

    .line 225
    .line 226
    const/4 v2, 0x1

    .line 227
    if-eqz v1, :cond_d

    .line 228
    .line 229
    if-ne v1, v2, :cond_c

    .line 230
    .line 231
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    goto :goto_7

    .line 235
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 236
    .line 237
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 238
    .line 239
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    throw p0

    .line 243
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 244
    .line 245
    .line 246
    iget-object v5, p0, Ltz/w0;->f:Ltz/b1;

    .line 247
    .line 248
    iget-object p1, v5, Ltz/b1;->n:Lqd0/g0;

    .line 249
    .line 250
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object p1

    .line 254
    check-cast p1, Lyy0/i;

    .line 255
    .line 256
    new-instance v3, La50/d;

    .line 257
    .line 258
    const/4 v9, 0x4

    .line 259
    const/16 v10, 0x17

    .line 260
    .line 261
    const/4 v4, 0x2

    .line 262
    const-class v6, Ltz/b1;

    .line 263
    .line 264
    const-string v7, "onChargingHistory"

    .line 265
    .line 266
    const-string v8, "onChargingHistory(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 267
    .line 268
    invoke-direct/range {v3 .. v10}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 269
    .line 270
    .line 271
    iput v2, p0, Ltz/w0;->e:I

    .line 272
    .line 273
    invoke-static {v3, p0, p1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object p0

    .line 277
    if-ne p0, v0, :cond_e

    .line 278
    .line 279
    goto :goto_8

    .line 280
    :cond_e
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 281
    .line 282
    :goto_8
    return-object v0

    .line 283
    :pswitch_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 284
    .line 285
    iget v1, p0, Ltz/w0;->e:I

    .line 286
    .line 287
    const/4 v2, 0x1

    .line 288
    if-eqz v1, :cond_10

    .line 289
    .line 290
    if-ne v1, v2, :cond_f

    .line 291
    .line 292
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 293
    .line 294
    .line 295
    goto :goto_9

    .line 296
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 297
    .line 298
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 299
    .line 300
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    throw p0

    .line 304
    :cond_10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 305
    .line 306
    .line 307
    iget-object v5, p0, Ltz/w0;->f:Ltz/b1;

    .line 308
    .line 309
    iget-object p1, v5, Ltz/b1;->o:Lqd0/f0;

    .line 310
    .line 311
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object p1

    .line 315
    check-cast p1, Lyy0/i;

    .line 316
    .line 317
    new-instance v3, La50/d;

    .line 318
    .line 319
    const/4 v9, 0x4

    .line 320
    const/16 v10, 0x16

    .line 321
    .line 322
    const/4 v4, 0x2

    .line 323
    const-class v6, Ltz/b1;

    .line 324
    .line 325
    const-string v7, "onChargingHistoryFilter"

    .line 326
    .line 327
    const-string v8, "onChargingHistoryFilter(Lcz/skodaauto/myskoda/library/charging/model/ChargingHistoryFilter;)V"

    .line 328
    .line 329
    invoke-direct/range {v3 .. v10}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 330
    .line 331
    .line 332
    iput v2, p0, Ltz/w0;->e:I

    .line 333
    .line 334
    invoke-static {v3, p0, p1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object p0

    .line 338
    if-ne p0, v0, :cond_11

    .line 339
    .line 340
    goto :goto_a

    .line 341
    :cond_11
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 342
    .line 343
    :goto_a
    return-object v0

    .line 344
    :pswitch_5
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 345
    .line 346
    iget v1, p0, Ltz/w0;->e:I

    .line 347
    .line 348
    const/4 v2, 0x1

    .line 349
    if-eqz v1, :cond_13

    .line 350
    .line 351
    if-ne v1, v2, :cond_12

    .line 352
    .line 353
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 354
    .line 355
    .line 356
    goto :goto_b

    .line 357
    :cond_12
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 358
    .line 359
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 360
    .line 361
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 362
    .line 363
    .line 364
    throw p0

    .line 365
    :cond_13
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 366
    .line 367
    .line 368
    iput v2, p0, Ltz/w0;->e:I

    .line 369
    .line 370
    iget-object p1, p0, Ltz/w0;->f:Ltz/b1;

    .line 371
    .line 372
    invoke-static {p1, p0}, Ltz/b1;->h(Ltz/b1;Lrx0/c;)Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object p0

    .line 376
    if-ne p0, v0, :cond_14

    .line 377
    .line 378
    goto :goto_c

    .line 379
    :cond_14
    :goto_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 380
    .line 381
    :goto_c
    return-object v0

    .line 382
    nop

    .line 383
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
