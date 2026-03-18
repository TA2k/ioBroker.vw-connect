.class public final Li40/c0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lp1/v;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lp1/v;Lay0/k;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Li40/c0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/c0;->f:Lp1/v;

    .line 4
    .line 5
    iput-object p2, p0, Li40/c0;->g:Lay0/k;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Li40/c0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Li40/c0;

    .line 7
    .line 8
    iget-object v0, p0, Li40/c0;->g:Lay0/k;

    .line 9
    .line 10
    const/4 v1, 0x5

    .line 11
    iget-object p0, p0, Li40/c0;->f:Lp1/v;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Li40/c0;-><init>(Lp1/v;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Li40/c0;

    .line 18
    .line 19
    iget-object v0, p0, Li40/c0;->g:Lay0/k;

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    iget-object p0, p0, Li40/c0;->f:Lp1/v;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Li40/c0;-><init>(Lp1/v;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    :pswitch_1
    new-instance p1, Li40/c0;

    .line 29
    .line 30
    iget-object v0, p0, Li40/c0;->g:Lay0/k;

    .line 31
    .line 32
    const/4 v1, 0x3

    .line 33
    iget-object p0, p0, Li40/c0;->f:Lp1/v;

    .line 34
    .line 35
    invoke-direct {p1, p0, v0, p2, v1}, Li40/c0;-><init>(Lp1/v;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object p1

    .line 39
    :pswitch_2
    new-instance p1, Li40/c0;

    .line 40
    .line 41
    iget-object v0, p0, Li40/c0;->g:Lay0/k;

    .line 42
    .line 43
    const/4 v1, 0x2

    .line 44
    iget-object p0, p0, Li40/c0;->f:Lp1/v;

    .line 45
    .line 46
    invoke-direct {p1, p0, v0, p2, v1}, Li40/c0;-><init>(Lp1/v;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 47
    .line 48
    .line 49
    return-object p1

    .line 50
    :pswitch_3
    new-instance p1, Li40/c0;

    .line 51
    .line 52
    iget-object v0, p0, Li40/c0;->g:Lay0/k;

    .line 53
    .line 54
    const/4 v1, 0x1

    .line 55
    iget-object p0, p0, Li40/c0;->f:Lp1/v;

    .line 56
    .line 57
    invoke-direct {p1, p0, v0, p2, v1}, Li40/c0;-><init>(Lp1/v;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 58
    .line 59
    .line 60
    return-object p1

    .line 61
    :pswitch_4
    new-instance p1, Li40/c0;

    .line 62
    .line 63
    iget-object v0, p0, Li40/c0;->g:Lay0/k;

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    iget-object p0, p0, Li40/c0;->f:Lp1/v;

    .line 67
    .line 68
    invoke-direct {p1, p0, v0, p2, v1}, Li40/c0;-><init>(Lp1/v;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 69
    .line 70
    .line 71
    return-object p1

    .line 72
    nop

    .line 73
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
    iget v0, p0, Li40/c0;->d:I

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
    invoke-virtual {p0, p1, p2}, Li40/c0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Li40/c0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Li40/c0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Li40/c0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Li40/c0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Li40/c0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Li40/c0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Li40/c0;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Li40/c0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Li40/c0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Li40/c0;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Li40/c0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Li40/c0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Li40/c0;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Li40/c0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Li40/c0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Li40/c0;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Li40/c0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 5

    .line 1
    iget v0, p0, Li40/c0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Li40/c0;->e:I

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
    new-instance p1, Li40/a0;

    .line 31
    .line 32
    const/16 v1, 0x8

    .line 33
    .line 34
    iget-object v3, p0, Li40/c0;->f:Lp1/v;

    .line 35
    .line 36
    invoke-direct {p1, v3, v1}, Li40/a0;-><init>(Lp1/v;I)V

    .line 37
    .line 38
    .line 39
    invoke-static {p1}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    new-instance v1, Li40/b0;

    .line 44
    .line 45
    iget-object v3, p0, Li40/c0;->g:Lay0/k;

    .line 46
    .line 47
    const/4 v4, 0x6

    .line 48
    invoke-direct {v1, v4, v3}, Li40/b0;-><init>(ILay0/k;)V

    .line 49
    .line 50
    .line 51
    iput v2, p0, Li40/c0;->e:I

    .line 52
    .line 53
    invoke-virtual {p1, v1, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    if-ne p0, v0, :cond_2

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    :goto_1
    return-object v0

    .line 63
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 64
    .line 65
    iget v1, p0, Li40/c0;->e:I

    .line 66
    .line 67
    const/4 v2, 0x1

    .line 68
    if-eqz v1, :cond_4

    .line 69
    .line 70
    if-ne v1, v2, :cond_3

    .line 71
    .line 72
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 77
    .line 78
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 79
    .line 80
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p0

    .line 84
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    new-instance p1, Li40/a0;

    .line 88
    .line 89
    const/4 v1, 0x7

    .line 90
    iget-object v3, p0, Li40/c0;->f:Lp1/v;

    .line 91
    .line 92
    invoke-direct {p1, v3, v1}, Li40/a0;-><init>(Lp1/v;I)V

    .line 93
    .line 94
    .line 95
    invoke-static {p1}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    new-instance v1, Li40/b0;

    .line 100
    .line 101
    iget-object v3, p0, Li40/c0;->g:Lay0/k;

    .line 102
    .line 103
    const/4 v4, 0x4

    .line 104
    invoke-direct {v1, v4, v3}, Li40/b0;-><init>(ILay0/k;)V

    .line 105
    .line 106
    .line 107
    iput v2, p0, Li40/c0;->e:I

    .line 108
    .line 109
    invoke-virtual {p1, v1, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    if-ne p0, v0, :cond_5

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 117
    .line 118
    :goto_3
    return-object v0

    .line 119
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 120
    .line 121
    iget v1, p0, Li40/c0;->e:I

    .line 122
    .line 123
    const/4 v2, 0x0

    .line 124
    const/4 v3, 0x1

    .line 125
    if-eqz v1, :cond_7

    .line 126
    .line 127
    if-ne v1, v3, :cond_6

    .line 128
    .line 129
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 134
    .line 135
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 136
    .line 137
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    throw p0

    .line 141
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    iput v3, p0, Li40/c0;->e:I

    .line 145
    .line 146
    iget-object p1, p0, Li40/c0;->f:Lp1/v;

    .line 147
    .line 148
    invoke-static {p1, v2, p0}, Lp1/v;->g(Lp1/v;ILrx0/i;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    if-ne p1, v0, :cond_8

    .line 153
    .line 154
    goto :goto_5

    .line 155
    :cond_8
    :goto_4
    new-instance p1, Ljava/lang/Integer;

    .line 156
    .line 157
    invoke-direct {p1, v2}, Ljava/lang/Integer;-><init>(I)V

    .line 158
    .line 159
    .line 160
    iget-object p0, p0, Li40/c0;->g:Lay0/k;

    .line 161
    .line 162
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    :goto_5
    return-object v0

    .line 168
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 169
    .line 170
    iget v1, p0, Li40/c0;->e:I

    .line 171
    .line 172
    const/4 v2, 0x1

    .line 173
    if-eqz v1, :cond_a

    .line 174
    .line 175
    if-ne v1, v2, :cond_9

    .line 176
    .line 177
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    goto :goto_6

    .line 181
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 182
    .line 183
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 184
    .line 185
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    throw p0

    .line 189
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    new-instance p1, Li40/a0;

    .line 193
    .line 194
    const/4 v1, 0x2

    .line 195
    iget-object v3, p0, Li40/c0;->f:Lp1/v;

    .line 196
    .line 197
    invoke-direct {p1, v3, v1}, Li40/a0;-><init>(Lp1/v;I)V

    .line 198
    .line 199
    .line 200
    invoke-static {p1}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    const-wide/16 v3, 0x12c

    .line 205
    .line 206
    invoke-static {p1, v3, v4}, Lyy0/u;->o(Lyy0/i;J)Lyy0/i;

    .line 207
    .line 208
    .line 209
    move-result-object p1

    .line 210
    new-instance v1, Li40/b0;

    .line 211
    .line 212
    iget-object v3, p0, Li40/c0;->g:Lay0/k;

    .line 213
    .line 214
    const/4 v4, 0x2

    .line 215
    invoke-direct {v1, v4, v3}, Li40/b0;-><init>(ILay0/k;)V

    .line 216
    .line 217
    .line 218
    iput v2, p0, Li40/c0;->e:I

    .line 219
    .line 220
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    if-ne p0, v0, :cond_b

    .line 225
    .line 226
    goto :goto_7

    .line 227
    :cond_b
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 228
    .line 229
    :goto_7
    return-object v0

    .line 230
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 231
    .line 232
    iget v1, p0, Li40/c0;->e:I

    .line 233
    .line 234
    const/4 v2, 0x1

    .line 235
    if-eqz v1, :cond_d

    .line 236
    .line 237
    if-ne v1, v2, :cond_c

    .line 238
    .line 239
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 240
    .line 241
    .line 242
    goto :goto_8

    .line 243
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 244
    .line 245
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 246
    .line 247
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    throw p0

    .line 251
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 252
    .line 253
    .line 254
    new-instance p1, Li40/a0;

    .line 255
    .line 256
    const/4 v1, 0x1

    .line 257
    iget-object v3, p0, Li40/c0;->f:Lp1/v;

    .line 258
    .line 259
    invoke-direct {p1, v3, v1}, Li40/a0;-><init>(Lp1/v;I)V

    .line 260
    .line 261
    .line 262
    invoke-static {p1}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 263
    .line 264
    .line 265
    move-result-object p1

    .line 266
    new-instance v1, Li40/b0;

    .line 267
    .line 268
    iget-object v3, p0, Li40/c0;->g:Lay0/k;

    .line 269
    .line 270
    const/4 v4, 0x1

    .line 271
    invoke-direct {v1, v4, v3}, Li40/b0;-><init>(ILay0/k;)V

    .line 272
    .line 273
    .line 274
    iput v2, p0, Li40/c0;->e:I

    .line 275
    .line 276
    invoke-virtual {p1, v1, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object p0

    .line 280
    if-ne p0, v0, :cond_e

    .line 281
    .line 282
    goto :goto_9

    .line 283
    :cond_e
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 284
    .line 285
    :goto_9
    return-object v0

    .line 286
    :pswitch_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 287
    .line 288
    iget v1, p0, Li40/c0;->e:I

    .line 289
    .line 290
    const/4 v2, 0x1

    .line 291
    if-eqz v1, :cond_10

    .line 292
    .line 293
    if-ne v1, v2, :cond_f

    .line 294
    .line 295
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    goto :goto_a

    .line 299
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 300
    .line 301
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 302
    .line 303
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 304
    .line 305
    .line 306
    throw p0

    .line 307
    :cond_10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 308
    .line 309
    .line 310
    new-instance p1, Li40/a0;

    .line 311
    .line 312
    const/4 v1, 0x0

    .line 313
    iget-object v3, p0, Li40/c0;->f:Lp1/v;

    .line 314
    .line 315
    invoke-direct {p1, v3, v1}, Li40/a0;-><init>(Lp1/v;I)V

    .line 316
    .line 317
    .line 318
    invoke-static {p1}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 319
    .line 320
    .line 321
    move-result-object p1

    .line 322
    new-instance v1, Li40/b0;

    .line 323
    .line 324
    iget-object v3, p0, Li40/c0;->g:Lay0/k;

    .line 325
    .line 326
    const/4 v4, 0x0

    .line 327
    invoke-direct {v1, v4, v3}, Li40/b0;-><init>(ILay0/k;)V

    .line 328
    .line 329
    .line 330
    iput v2, p0, Li40/c0;->e:I

    .line 331
    .line 332
    invoke-virtual {p1, v1, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object p0

    .line 336
    if-ne p0, v0, :cond_11

    .line 337
    .line 338
    goto :goto_b

    .line 339
    :cond_11
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 340
    .line 341
    :goto_b
    return-object v0

    .line 342
    nop

    .line 343
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
