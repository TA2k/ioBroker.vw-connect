.class public final Lim/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lrx0/i;


# direct methods
.method public constructor <init>(Lay0/n;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lim/k;->d:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lrx0/i;

    .line 7
    .line 8
    iput-object p1, p0, Lim/k;->g:Lrx0/i;

    .line 9
    .line 10
    const/4 p1, 0x2

    .line 11
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    check-cast p1, Lrx0/i;

    .line 16
    .line 17
    iput-object p1, p0, Lim/k;->g:Lrx0/i;

    .line 18
    .line 19
    const/4 p1, 0x2

    .line 20
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :pswitch_1
    check-cast p1, Lrx0/i;

    .line 25
    .line 26
    iput-object p1, p0, Lim/k;->g:Lrx0/i;

    .line 27
    .line 28
    const/4 p1, 0x2

    .line 29
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :pswitch_2
    check-cast p1, Lrx0/i;

    .line 34
    .line 35
    iput-object p1, p0, Lim/k;->g:Lrx0/i;

    .line 36
    .line 37
    const/4 p1, 0x2

    .line 38
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :pswitch_3
    check-cast p1, Lrx0/i;

    .line 43
    .line 44
    iput-object p1, p0, Lim/k;->g:Lrx0/i;

    .line 45
    .line 46
    const/4 p1, 0x2

    .line 47
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lim/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lim/k;

    .line 7
    .line 8
    iget-object p0, p0, Lim/k;->g:Lrx0/i;

    .line 9
    .line 10
    const/4 v1, 0x4

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lim/k;-><init>(Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lim/k;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lim/k;

    .line 18
    .line 19
    iget-object p0, p0, Lim/k;->g:Lrx0/i;

    .line 20
    .line 21
    const/4 v1, 0x3

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lim/k;-><init>(Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lim/k;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lim/k;

    .line 29
    .line 30
    iget-object p0, p0, Lim/k;->g:Lrx0/i;

    .line 31
    .line 32
    const/4 v1, 0x2

    .line 33
    invoke-direct {v0, p0, p2, v1}, Lim/k;-><init>(Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lim/k;->f:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_2
    new-instance v0, Lim/k;

    .line 40
    .line 41
    iget-object p0, p0, Lim/k;->g:Lrx0/i;

    .line 42
    .line 43
    const/4 v1, 0x1

    .line 44
    invoke-direct {v0, p0, p2, v1}, Lim/k;-><init>(Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    iput-object p1, v0, Lim/k;->f:Ljava/lang/Object;

    .line 48
    .line 49
    return-object v0

    .line 50
    :pswitch_3
    new-instance v0, Lim/k;

    .line 51
    .line 52
    iget-object p0, p0, Lim/k;->g:Lrx0/i;

    .line 53
    .line 54
    const/4 v1, 0x0

    .line 55
    invoke-direct {v0, p0, p2, v1}, Lim/k;-><init>(Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 56
    .line 57
    .line 58
    iput-object p1, v0, Lim/k;->f:Ljava/lang/Object;

    .line 59
    .line 60
    return-object v0

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lim/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lq6/b;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lim/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lim/k;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lim/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lim/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lim/k;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lim/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lne0/s;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lim/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lim/k;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lim/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p1, Lvy0/b0;

    .line 58
    .line 59
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2}, Lim/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lim/k;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lim/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_3
    check-cast p1, Lim/r;

    .line 75
    .line 76
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 77
    .line 78
    invoke-virtual {p0, p1, p2}, Lim/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Lim/k;

    .line 83
    .line 84
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    invoke-virtual {p0, p1}, Lim/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lim/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lim/k;->e:I

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
    iget-object p0, p0, Lim/k;->f:Ljava/lang/Object;

    .line 16
    .line 17
    move-object v0, p0

    .line 18
    check-cast v0, Lq6/b;

    .line 19
    .line 20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iget-object p1, p0, Lim/k;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p1, Lq6/b;

    .line 38
    .line 39
    invoke-virtual {p1}, Lq6/b;->g()Lq6/b;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    iput-object p1, p0, Lim/k;->f:Ljava/lang/Object;

    .line 44
    .line 45
    iput v2, p0, Lim/k;->e:I

    .line 46
    .line 47
    iget-object v1, p0, Lim/k;->g:Lrx0/i;

    .line 48
    .line 49
    invoke-interface {v1, p1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    if-ne p0, v0, :cond_2

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    move-object v0, p1

    .line 57
    :goto_0
    return-object v0

    .line 58
    :pswitch_0
    iget-object v0, p0, Lim/k;->f:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Lne0/s;

    .line 61
    .line 62
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 63
    .line 64
    iget v2, p0, Lim/k;->e:I

    .line 65
    .line 66
    const/4 v3, 0x1

    .line 67
    if-eqz v2, :cond_4

    .line 68
    .line 69
    if-ne v2, v3, :cond_3

    .line 70
    .line 71
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 76
    .line 77
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 78
    .line 79
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw p0

    .line 83
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    instance-of p1, v0, Lne0/e;

    .line 87
    .line 88
    if-eqz p1, :cond_5

    .line 89
    .line 90
    check-cast v0, Lne0/e;

    .line 91
    .line 92
    iget-object p1, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 93
    .line 94
    const/4 v0, 0x0

    .line 95
    iput-object v0, p0, Lim/k;->f:Ljava/lang/Object;

    .line 96
    .line 97
    iput v3, p0, Lim/k;->e:I

    .line 98
    .line 99
    iget-object v0, p0, Lim/k;->g:Lrx0/i;

    .line 100
    .line 101
    invoke-interface {v0, p1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    if-ne p0, v1, :cond_5

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_5
    :goto_1
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    :goto_2
    return-object v1

    .line 111
    :pswitch_1
    iget-object v0, p0, Lim/k;->f:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v0, Lne0/s;

    .line 114
    .line 115
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 116
    .line 117
    iget v2, p0, Lim/k;->e:I

    .line 118
    .line 119
    const/4 v3, 0x1

    .line 120
    if-eqz v2, :cond_7

    .line 121
    .line 122
    if-ne v2, v3, :cond_6

    .line 123
    .line 124
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    goto :goto_3

    .line 128
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 129
    .line 130
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 131
    .line 132
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    throw p0

    .line 136
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    instance-of p1, v0, Lne0/c;

    .line 140
    .line 141
    if-eqz p1, :cond_8

    .line 142
    .line 143
    const/4 p1, 0x0

    .line 144
    iput-object p1, p0, Lim/k;->f:Ljava/lang/Object;

    .line 145
    .line 146
    iput v3, p0, Lim/k;->e:I

    .line 147
    .line 148
    iget-object p1, p0, Lim/k;->g:Lrx0/i;

    .line 149
    .line 150
    invoke-interface {p1, v0, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    if-ne p0, v1, :cond_8

    .line 155
    .line 156
    goto :goto_4

    .line 157
    :cond_8
    :goto_3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 158
    .line 159
    :goto_4
    return-object v1

    .line 160
    :pswitch_2
    iget-object v0, p0, Lim/k;->f:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast v0, Lvy0/b0;

    .line 163
    .line 164
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 165
    .line 166
    iget v2, p0, Lim/k;->e:I

    .line 167
    .line 168
    const/4 v3, 0x1

    .line 169
    if-eqz v2, :cond_a

    .line 170
    .line 171
    if-ne v2, v3, :cond_9

    .line 172
    .line 173
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    goto :goto_5

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    const/4 p1, 0x0

    .line 189
    iput-object p1, p0, Lim/k;->f:Ljava/lang/Object;

    .line 190
    .line 191
    iput v3, p0, Lim/k;->e:I

    .line 192
    .line 193
    iget-object p1, p0, Lim/k;->g:Lrx0/i;

    .line 194
    .line 195
    invoke-interface {p1, v0, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object p1

    .line 199
    if-ne p1, v1, :cond_b

    .line 200
    .line 201
    move-object p1, v1

    .line 202
    :cond_b
    :goto_5
    return-object p1

    .line 203
    :pswitch_3
    iget-object v0, p0, Lim/k;->f:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v0, Lim/r;

    .line 206
    .line 207
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 208
    .line 209
    iget v2, p0, Lim/k;->e:I

    .line 210
    .line 211
    const/4 v3, 0x1

    .line 212
    if-eqz v2, :cond_d

    .line 213
    .line 214
    if-ne v2, v3, :cond_c

    .line 215
    .line 216
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    goto :goto_7

    .line 220
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 221
    .line 222
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 223
    .line 224
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    throw p0

    .line 228
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    iget p1, v0, Lim/r;->a:I

    .line 232
    .line 233
    const/16 v2, 0xc8

    .line 234
    .line 235
    if-gt v2, p1, :cond_e

    .line 236
    .line 237
    const/16 v2, 0x12c

    .line 238
    .line 239
    if-ge p1, v2, :cond_e

    .line 240
    .line 241
    goto :goto_6

    .line 242
    :cond_e
    const/16 v2, 0x130

    .line 243
    .line 244
    if-ne p1, v2, :cond_10

    .line 245
    .line 246
    :goto_6
    const/4 p1, 0x0

    .line 247
    iput-object p1, p0, Lim/k;->f:Ljava/lang/Object;

    .line 248
    .line 249
    iput v3, p0, Lim/k;->e:I

    .line 250
    .line 251
    iget-object p1, p0, Lim/k;->g:Lrx0/i;

    .line 252
    .line 253
    invoke-interface {p1, v0, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object p1

    .line 257
    if-ne p1, v1, :cond_f

    .line 258
    .line 259
    move-object p1, v1

    .line 260
    :cond_f
    :goto_7
    return-object p1

    .line 261
    :cond_10
    new-instance p0, La8/r0;

    .line 262
    .line 263
    new-instance p1, Ljava/lang/StringBuilder;

    .line 264
    .line 265
    const-string v1, "HTTP "

    .line 266
    .line 267
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    iget v0, v0, Lim/r;->a:I

    .line 271
    .line 272
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 273
    .line 274
    .line 275
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object p1

    .line 279
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    throw p0

    .line 283
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
