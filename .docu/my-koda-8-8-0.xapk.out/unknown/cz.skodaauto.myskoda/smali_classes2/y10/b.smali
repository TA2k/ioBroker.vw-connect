.class public final Ly10/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ly10/g;


# direct methods
.method public synthetic constructor <init>(Ly10/g;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ly10/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly10/b;->f:Ly10/g;

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
    iget p1, p0, Ly10/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ly10/b;

    .line 7
    .line 8
    iget-object p0, p0, Ly10/b;->f:Ly10/g;

    .line 9
    .line 10
    const/4 v0, 0x6

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ly10/b;-><init>(Ly10/g;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ly10/b;

    .line 16
    .line 17
    iget-object p0, p0, Ly10/b;->f:Ly10/g;

    .line 18
    .line 19
    const/4 v0, 0x5

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ly10/b;-><init>(Ly10/g;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ly10/b;

    .line 25
    .line 26
    iget-object p0, p0, Ly10/b;->f:Ly10/g;

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ly10/b;-><init>(Ly10/g;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Ly10/b;

    .line 34
    .line 35
    iget-object p0, p0, Ly10/b;->f:Ly10/g;

    .line 36
    .line 37
    const/4 v0, 0x3

    .line 38
    invoke-direct {p1, p0, p2, v0}, Ly10/b;-><init>(Ly10/g;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Ly10/b;

    .line 43
    .line 44
    iget-object p0, p0, Ly10/b;->f:Ly10/g;

    .line 45
    .line 46
    const/4 v0, 0x2

    .line 47
    invoke-direct {p1, p0, p2, v0}, Ly10/b;-><init>(Ly10/g;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_4
    new-instance p1, Ly10/b;

    .line 52
    .line 53
    iget-object p0, p0, Ly10/b;->f:Ly10/g;

    .line 54
    .line 55
    const/4 v0, 0x1

    .line 56
    invoke-direct {p1, p0, p2, v0}, Ly10/b;-><init>(Ly10/g;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    return-object p1

    .line 60
    :pswitch_5
    new-instance p1, Ly10/b;

    .line 61
    .line 62
    iget-object p0, p0, Ly10/b;->f:Ly10/g;

    .line 63
    .line 64
    const/4 v0, 0x0

    .line 65
    invoke-direct {p1, p0, p2, v0}, Ly10/b;-><init>(Ly10/g;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ly10/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Ly10/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ly10/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ly10/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ly10/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ly10/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ly10/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ly10/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ly10/b;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ly10/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Ly10/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ly10/b;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ly10/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Ly10/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ly10/b;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Ly10/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Ly10/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Ly10/b;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Ly10/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :pswitch_5
    invoke-virtual {p0, p1, p2}, Ly10/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Ly10/b;

    .line 93
    .line 94
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    invoke-virtual {p0, p1}, Ly10/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Ly10/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ly10/b;->e:I

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
    iget-object p1, p0, Ly10/b;->f:Ly10/g;

    .line 31
    .line 32
    iget-object v1, p1, Ly10/g;->k:Lhq0/h;

    .line 33
    .line 34
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    check-cast p1, Ly10/e;

    .line 39
    .line 40
    iget-object p1, p1, Ly10/e;->d:Ljava/lang/String;

    .line 41
    .line 42
    iput v2, p0, Ly10/b;->e:I

    .line 43
    .line 44
    invoke-virtual {v1, p1, p0}, Lhq0/h;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    if-ne p0, v0, :cond_2

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 52
    .line 53
    :goto_1
    return-object v0

    .line 54
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 55
    .line 56
    iget v1, p0, Ly10/b;->e:I

    .line 57
    .line 58
    const/4 v2, 0x1

    .line 59
    if-eqz v1, :cond_4

    .line 60
    .line 61
    if-ne v1, v2, :cond_3

    .line 62
    .line 63
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 68
    .line 69
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 70
    .line 71
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw p0

    .line 75
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    iget-object p1, p0, Ly10/b;->f:Ly10/g;

    .line 79
    .line 80
    iget-object p1, p1, Ly10/g;->p:Llp0/d;

    .line 81
    .line 82
    iput v2, p0, Ly10/b;->e:I

    .line 83
    .line 84
    const/4 v1, 0x0

    .line 85
    invoke-virtual {p1, v1, p0}, Llp0/d;->b(Lmp0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    if-ne p0, v0, :cond_5

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    :goto_3
    return-object v0

    .line 95
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 96
    .line 97
    iget v1, p0, Ly10/b;->e:I

    .line 98
    .line 99
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    iget-object v3, p0, Ly10/b;->f:Ly10/g;

    .line 102
    .line 103
    const/4 v4, 0x2

    .line 104
    const/4 v5, 0x1

    .line 105
    if-eqz v1, :cond_9

    .line 106
    .line 107
    if-eq v1, v5, :cond_8

    .line 108
    .line 109
    if-ne v1, v4, :cond_7

    .line 110
    .line 111
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    :cond_6
    move-object v0, v2

    .line 115
    goto :goto_5

    .line 116
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 117
    .line 118
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 119
    .line 120
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw p0

    .line 124
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    goto :goto_4

    .line 128
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    iget-object p1, v3, Ly10/g;->i:Lw10/e;

    .line 132
    .line 133
    iput v5, p0, Ly10/b;->e:I

    .line 134
    .line 135
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 136
    .line 137
    .line 138
    invoke-virtual {p1, p0}, Lw10/e;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    if-ne p1, v0, :cond_a

    .line 143
    .line 144
    goto :goto_5

    .line 145
    :cond_a
    :goto_4
    iput v4, p0, Ly10/b;->e:I

    .line 146
    .line 147
    invoke-static {v3, p0}, Ly10/g;->h(Ly10/g;Lrx0/c;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    if-ne p0, v0, :cond_6

    .line 152
    .line 153
    :goto_5
    return-object v0

    .line 154
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 155
    .line 156
    iget v1, p0, Ly10/b;->e:I

    .line 157
    .line 158
    const/4 v2, 0x1

    .line 159
    if-eqz v1, :cond_c

    .line 160
    .line 161
    if-ne v1, v2, :cond_b

    .line 162
    .line 163
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    goto :goto_6

    .line 167
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 168
    .line 169
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 170
    .line 171
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    throw p0

    .line 175
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    iget-object p1, p0, Ly10/b;->f:Ly10/g;

    .line 179
    .line 180
    iget-object v1, p1, Ly10/g;->l:Lhq0/c;

    .line 181
    .line 182
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 183
    .line 184
    .line 185
    move-result-object p1

    .line 186
    check-cast p1, Ly10/e;

    .line 187
    .line 188
    iget-object p1, p1, Ly10/e;->d:Ljava/lang/String;

    .line 189
    .line 190
    iput v2, p0, Ly10/b;->e:I

    .line 191
    .line 192
    invoke-virtual {v1, p1, p0}, Lhq0/c;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    if-ne p0, v0, :cond_d

    .line 197
    .line 198
    goto :goto_7

    .line 199
    :cond_d
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 200
    .line 201
    :goto_7
    return-object v0

    .line 202
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 203
    .line 204
    iget v1, p0, Ly10/b;->e:I

    .line 205
    .line 206
    const/4 v2, 0x1

    .line 207
    if-eqz v1, :cond_f

    .line 208
    .line 209
    if-ne v1, v2, :cond_e

    .line 210
    .line 211
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    goto :goto_8

    .line 215
    :cond_e
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 216
    .line 217
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 218
    .line 219
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    throw p0

    .line 223
    :cond_f
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    iget-object p1, p0, Ly10/b;->f:Ly10/g;

    .line 227
    .line 228
    iget-object v1, p1, Ly10/g;->r:Lwr0/i;

    .line 229
    .line 230
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    check-cast v1, Lyy0/i;

    .line 235
    .line 236
    new-instance v3, Ly10/a;

    .line 237
    .line 238
    const/4 v4, 0x1

    .line 239
    invoke-direct {v3, p1, v4}, Ly10/a;-><init>(Ly10/g;I)V

    .line 240
    .line 241
    .line 242
    iput v2, p0, Ly10/b;->e:I

    .line 243
    .line 244
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object p0

    .line 248
    if-ne p0, v0, :cond_10

    .line 249
    .line 250
    goto :goto_9

    .line 251
    :cond_10
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 252
    .line 253
    :goto_9
    return-object v0

    .line 254
    :pswitch_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 255
    .line 256
    iget v1, p0, Ly10/b;->e:I

    .line 257
    .line 258
    const/4 v2, 0x1

    .line 259
    if-eqz v1, :cond_12

    .line 260
    .line 261
    if-ne v1, v2, :cond_11

    .line 262
    .line 263
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    goto :goto_a

    .line 267
    :cond_11
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 268
    .line 269
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 270
    .line 271
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    throw p0

    .line 275
    :cond_12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 276
    .line 277
    .line 278
    iput v2, p0, Ly10/b;->e:I

    .line 279
    .line 280
    iget-object p1, p0, Ly10/b;->f:Ly10/g;

    .line 281
    .line 282
    invoke-static {p1, p0}, Ly10/g;->h(Ly10/g;Lrx0/c;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object p0

    .line 286
    if-ne p0, v0, :cond_13

    .line 287
    .line 288
    goto :goto_b

    .line 289
    :cond_13
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 290
    .line 291
    :goto_b
    return-object v0

    .line 292
    :pswitch_5
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 293
    .line 294
    iget v1, p0, Ly10/b;->e:I

    .line 295
    .line 296
    const/4 v2, 0x1

    .line 297
    if-eqz v1, :cond_15

    .line 298
    .line 299
    if-ne v1, v2, :cond_14

    .line 300
    .line 301
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 302
    .line 303
    .line 304
    goto :goto_c

    .line 305
    :cond_14
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 306
    .line 307
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 308
    .line 309
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    throw p0

    .line 313
    :cond_15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 314
    .line 315
    .line 316
    iget-object p1, p0, Ly10/b;->f:Ly10/g;

    .line 317
    .line 318
    iget-object v1, p1, Ly10/g;->o:Llp0/b;

    .line 319
    .line 320
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object v1

    .line 324
    check-cast v1, Lyy0/i;

    .line 325
    .line 326
    new-instance v3, Ly10/a;

    .line 327
    .line 328
    const/4 v4, 0x0

    .line 329
    invoke-direct {v3, p1, v4}, Ly10/a;-><init>(Ly10/g;I)V

    .line 330
    .line 331
    .line 332
    iput v2, p0, Ly10/b;->e:I

    .line 333
    .line 334
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object p0

    .line 338
    if-ne p0, v0, :cond_16

    .line 339
    .line 340
    goto :goto_d

    .line 341
    :cond_16
    :goto_c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 342
    .line 343
    :goto_d
    return-object v0

    .line 344
    nop

    .line 345
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
