.class public final Laa/j0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:F

.field public f:I

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(FLc1/c1;Lz9/k;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Laa/j0;->d:I

    .line 1
    iput p1, p0, Laa/j0;->e:F

    iput-object p2, p0, Laa/j0;->g:Ljava/lang/Object;

    iput-object p3, p0, Laa/j0;->h:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lc1/w1;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Laa/j0;->d:I

    .line 2
    iput-object p1, p0, Laa/j0;->h:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lvv0/d;FLc1/j;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Laa/j0;->d:I

    .line 3
    iput-object p1, p0, Laa/j0;->g:Ljava/lang/Object;

    iput p2, p0, Laa/j0;->e:F

    iput-object p3, p0, Laa/j0;->h:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lz40/j;Lkotlin/jvm/internal/b0;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Laa/j0;->d:I

    .line 4
    iput-object p1, p0, Laa/j0;->g:Ljava/lang/Object;

    iput-object p2, p0, Laa/j0;->h:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Laa/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Laa/j0;

    .line 7
    .line 8
    iget-object v1, p0, Laa/j0;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lz40/j;

    .line 11
    .line 12
    iget-object p0, p0, Laa/j0;->h:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lkotlin/jvm/internal/b0;

    .line 15
    .line 16
    invoke-direct {v0, v1, p0, p2}, Laa/j0;-><init>(Lz40/j;Lkotlin/jvm/internal/b0;Lkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    check-cast p1, Ljava/lang/Number;

    .line 20
    .line 21
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    iput p0, v0, Laa/j0;->e:F

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_0
    new-instance p1, Laa/j0;

    .line 29
    .line 30
    iget-object v0, p0, Laa/j0;->g:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v0, Lvv0/d;

    .line 33
    .line 34
    iget v1, p0, Laa/j0;->e:F

    .line 35
    .line 36
    iget-object p0, p0, Laa/j0;->h:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Lc1/j;

    .line 39
    .line 40
    invoke-direct {p1, v0, v1, p0, p2}, Laa/j0;-><init>(Lvv0/d;FLc1/j;Lkotlin/coroutines/Continuation;)V

    .line 41
    .line 42
    .line 43
    return-object p1

    .line 44
    :pswitch_1
    new-instance v0, Laa/j0;

    .line 45
    .line 46
    iget-object p0, p0, Laa/j0;->h:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast p0, Lc1/w1;

    .line 49
    .line 50
    invoke-direct {v0, p0, p2}, Laa/j0;-><init>(Lc1/w1;Lkotlin/coroutines/Continuation;)V

    .line 51
    .line 52
    .line 53
    iput-object p1, v0, Laa/j0;->g:Ljava/lang/Object;

    .line 54
    .line 55
    return-object v0

    .line 56
    :pswitch_2
    new-instance p1, Laa/j0;

    .line 57
    .line 58
    iget v0, p0, Laa/j0;->e:F

    .line 59
    .line 60
    iget-object v1, p0, Laa/j0;->g:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v1, Lc1/c1;

    .line 63
    .line 64
    iget-object p0, p0, Laa/j0;->h:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast p0, Lz9/k;

    .line 67
    .line 68
    invoke-direct {p1, v0, v1, p0, p2}, Laa/j0;-><init>(FLc1/c1;Lz9/k;Lkotlin/coroutines/Continuation;)V

    .line 69
    .line 70
    .line 71
    return-object p1

    .line 72
    nop

    .line 73
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
    iget v0, p0, Laa/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 13
    .line 14
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {p0, p1, p2}, Laa/j0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Laa/j0;

    .line 23
    .line 24
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    invoke-virtual {p0, p1}, Laa/j0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_0
    check-cast p1, Lvy0/b0;

    .line 32
    .line 33
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 34
    .line 35
    invoke-virtual {p0, p1, p2}, Laa/j0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    check-cast p0, Laa/j0;

    .line 40
    .line 41
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {p0, p1}, Laa/j0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_1
    check-cast p1, Lvy0/b0;

    .line 49
    .line 50
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 51
    .line 52
    invoke-virtual {p0, p1, p2}, Laa/j0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    check-cast p0, Laa/j0;

    .line 57
    .line 58
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    invoke-virtual {p0, p1}, Laa/j0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    .line 65
    :pswitch_2
    check-cast p1, Lvy0/b0;

    .line 66
    .line 67
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 68
    .line 69
    invoke-virtual {p0, p1, p2}, Laa/j0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    check-cast p0, Laa/j0;

    .line 74
    .line 75
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    invoke-virtual {p0, p1}, Laa/j0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0

    .line 82
    nop

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Laa/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Laa/j0;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lkotlin/jvm/internal/b0;

    .line 9
    .line 10
    iget-object v1, p0, Laa/j0;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lz40/j;

    .line 13
    .line 14
    iget v2, p0, Laa/j0;->e:F

    .line 15
    .line 16
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    iget v4, p0, Laa/j0;->f:I

    .line 19
    .line 20
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    const/4 v6, 0x1

    .line 23
    if-eqz v4, :cond_2

    .line 24
    .line 25
    if-ne v4, v6, :cond_1

    .line 26
    .line 27
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    :goto_0
    move-object v3, v5

    .line 31
    goto :goto_2

    .line 32
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 35
    .line 36
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    const/high16 p1, 0x41100000    # 9.0f

    .line 44
    .line 45
    cmpl-float p1, v2, p1

    .line 46
    .line 47
    if-ltz p1, :cond_3

    .line 48
    .line 49
    iput-boolean v6, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_3
    if-ltz p1, :cond_4

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_4
    iget-boolean p1, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 56
    .line 57
    if-eqz p1, :cond_0

    .line 58
    .line 59
    const/4 p1, 0x0

    .line 60
    iput-boolean p1, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 61
    .line 62
    iput v2, p0, Laa/j0;->e:F

    .line 63
    .line 64
    iput v6, p0, Laa/j0;->f:I

    .line 65
    .line 66
    iget-object v0, v1, Lz40/j;->c:Lrq0/f;

    .line 67
    .line 68
    new-instance v1, Lsq0/c;

    .line 69
    .line 70
    const/4 v2, 0x0

    .line 71
    const/4 v4, 0x6

    .line 72
    const v6, 0x7f120607

    .line 73
    .line 74
    .line 75
    invoke-direct {v1, v6, v4, v2}, Lsq0/c;-><init>(IILjava/lang/Integer;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0, v1, p1, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    if-ne p0, v3, :cond_5

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_5
    move-object p0, v5

    .line 86
    :goto_1
    if-ne p0, v3, :cond_0

    .line 87
    .line 88
    :goto_2
    return-object v3

    .line 89
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 90
    .line 91
    iget v1, p0, Laa/j0;->f:I

    .line 92
    .line 93
    const/4 v2, 0x1

    .line 94
    if-eqz v1, :cond_7

    .line 95
    .line 96
    if-ne v1, v2, :cond_6

    .line 97
    .line 98
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    goto :goto_3

    .line 102
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 103
    .line 104
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 105
    .line 106
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    throw p0

    .line 110
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    iget-object p1, p0, Laa/j0;->g:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast p1, Lvv0/d;

    .line 116
    .line 117
    iget-object p1, p1, Lvv0/d;->c:Ljava/lang/Object;

    .line 118
    .line 119
    move-object v3, p1

    .line 120
    check-cast v3, Lc1/c;

    .line 121
    .line 122
    iget p1, p0, Laa/j0;->e:F

    .line 123
    .line 124
    new-instance v4, Ljava/lang/Float;

    .line 125
    .line 126
    invoke-direct {v4, p1}, Ljava/lang/Float;-><init>(F)V

    .line 127
    .line 128
    .line 129
    iget-object p1, p0, Laa/j0;->h:Ljava/lang/Object;

    .line 130
    .line 131
    move-object v5, p1

    .line 132
    check-cast v5, Lc1/j;

    .line 133
    .line 134
    iput v2, p0, Laa/j0;->f:I

    .line 135
    .line 136
    const/4 v6, 0x0

    .line 137
    const/4 v7, 0x0

    .line 138
    const/16 v9, 0xc

    .line 139
    .line 140
    move-object v8, p0

    .line 141
    invoke-static/range {v3 .. v9}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    if-ne p0, v0, :cond_8

    .line 146
    .line 147
    goto :goto_4

    .line 148
    :cond_8
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 149
    .line 150
    :goto_4
    return-object v0

    .line 151
    :pswitch_1
    move-object v8, p0

    .line 152
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 153
    .line 154
    iget v0, v8, Laa/j0;->f:I

    .line 155
    .line 156
    const/4 v1, 0x1

    .line 157
    if-eqz v0, :cond_a

    .line 158
    .line 159
    if-ne v0, v1, :cond_9

    .line 160
    .line 161
    iget v0, v8, Laa/j0;->e:F

    .line 162
    .line 163
    iget-object v2, v8, Laa/j0;->g:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast v2, Lvy0/b0;

    .line 166
    .line 167
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    goto :goto_5

    .line 171
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 172
    .line 173
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 174
    .line 175
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    throw p0

    .line 179
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 180
    .line 181
    .line 182
    iget-object p1, v8, Laa/j0;->g:Ljava/lang/Object;

    .line 183
    .line 184
    check-cast p1, Lvy0/b0;

    .line 185
    .line 186
    invoke-interface {p1}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    invoke-static {v0}, Lc1/d;->p(Lpx0/g;)F

    .line 191
    .line 192
    .line 193
    move-result v0

    .line 194
    move-object v2, p1

    .line 195
    :cond_b
    :goto_5
    invoke-static {v2}, Lvy0/e0;->B(Lvy0/b0;)Z

    .line 196
    .line 197
    .line 198
    move-result p1

    .line 199
    if-eqz p1, :cond_c

    .line 200
    .line 201
    iget-object p1, v8, Laa/j0;->h:Ljava/lang/Object;

    .line 202
    .line 203
    check-cast p1, Lc1/w1;

    .line 204
    .line 205
    new-instance v3, Lc1/u1;

    .line 206
    .line 207
    invoke-direct {v3, p1, v0}, Lc1/u1;-><init>(Lc1/w1;F)V

    .line 208
    .line 209
    .line 210
    iput-object v2, v8, Laa/j0;->g:Ljava/lang/Object;

    .line 211
    .line 212
    iput v0, v8, Laa/j0;->e:F

    .line 213
    .line 214
    iput v1, v8, Laa/j0;->f:I

    .line 215
    .line 216
    invoke-interface {v8}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 217
    .line 218
    .line 219
    move-result-object p1

    .line 220
    invoke-static {p1}, Ll2/b;->k(Lpx0/g;)Ll2/y0;

    .line 221
    .line 222
    .line 223
    move-result-object p1

    .line 224
    invoke-interface {p1, v3, v8}, Ll2/y0;->q(Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object p1

    .line 228
    if-ne p1, p0, :cond_b

    .line 229
    .line 230
    goto :goto_6

    .line 231
    :cond_c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 232
    .line 233
    :goto_6
    return-object p0

    .line 234
    :pswitch_2
    move-object v8, p0

    .line 235
    iget-object p0, v8, Laa/j0;->g:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast p0, Lc1/c1;

    .line 238
    .line 239
    iget v0, v8, Laa/j0;->e:F

    .line 240
    .line 241
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 242
    .line 243
    iget v2, v8, Laa/j0;->f:I

    .line 244
    .line 245
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 246
    .line 247
    const/4 v4, 0x0

    .line 248
    const/4 v5, 0x2

    .line 249
    const/4 v6, 0x1

    .line 250
    if-eqz v2, :cond_10

    .line 251
    .line 252
    if-eq v2, v6, :cond_f

    .line 253
    .line 254
    if-ne v2, v5, :cond_e

    .line 255
    .line 256
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 257
    .line 258
    .line 259
    :cond_d
    move-object v1, v3

    .line 260
    goto :goto_a

    .line 261
    :cond_e
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 262
    .line 263
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 264
    .line 265
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 266
    .line 267
    .line 268
    throw p0

    .line 269
    :cond_f
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 270
    .line 271
    .line 272
    goto :goto_7

    .line 273
    :cond_10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 274
    .line 275
    .line 276
    cmpl-float p1, v0, v4

    .line 277
    .line 278
    if-lez p1, :cond_11

    .line 279
    .line 280
    iput v6, v8, Laa/j0;->f:I

    .line 281
    .line 282
    iget-object p1, p0, Lc1/c1;->f:Ll2/j1;

    .line 283
    .line 284
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object p1

    .line 288
    invoke-virtual {p0, v0, p1, v8}, Lc1/c1;->i0(FLjava/lang/Object;Lrx0/i;)Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object p1

    .line 292
    if-ne p1, v1, :cond_11

    .line 293
    .line 294
    goto :goto_a

    .line 295
    :cond_11
    :goto_7
    cmpg-float p1, v0, v4

    .line 296
    .line 297
    if-nez p1, :cond_d

    .line 298
    .line 299
    iget-object p1, v8, Laa/j0;->h:Ljava/lang/Object;

    .line 300
    .line 301
    check-cast p1, Lz9/k;

    .line 302
    .line 303
    iput v5, v8, Laa/j0;->f:I

    .line 304
    .line 305
    iget-object v0, p0, Lc1/c1;->i:Lc1/w1;

    .line 306
    .line 307
    if-nez v0, :cond_13

    .line 308
    .line 309
    :cond_12
    :goto_8
    move-object p0, v3

    .line 310
    goto :goto_9

    .line 311
    :cond_13
    iget-object v2, p0, Lc1/c1;->g:Ll2/j1;

    .line 312
    .line 313
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v2

    .line 317
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 318
    .line 319
    .line 320
    move-result v2

    .line 321
    if-eqz v2, :cond_14

    .line 322
    .line 323
    iget-object v2, p0, Lc1/c1;->f:Ll2/j1;

    .line 324
    .line 325
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v2

    .line 329
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 330
    .line 331
    .line 332
    move-result v2

    .line 333
    if-eqz v2, :cond_14

    .line 334
    .line 335
    goto :goto_8

    .line 336
    :cond_14
    iget-object v2, p0, Lc1/c1;->o:Lc1/r0;

    .line 337
    .line 338
    new-instance v4, Lc1/w0;

    .line 339
    .line 340
    const/4 v5, 0x0

    .line 341
    invoke-direct {v4, p0, p1, v0, v5}, Lc1/w0;-><init>(Lc1/c1;Ljava/lang/Object;Lc1/w1;Lkotlin/coroutines/Continuation;)V

    .line 342
    .line 343
    .line 344
    invoke-static {v2, v4, v8}, Lc1/r0;->a(Lc1/r0;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    move-result-object p0

    .line 348
    if-ne p0, v1, :cond_12

    .line 349
    .line 350
    :goto_9
    if-ne p0, v1, :cond_d

    .line 351
    .line 352
    :goto_a
    return-object v1

    .line 353
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
