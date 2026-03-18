.class public final Lhg/n;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:I

.field public final synthetic g:Z

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Landroidx/lifecycle/b1;ZILkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Lhg/n;->d:I

    iput-object p1, p0, Lhg/n;->h:Ljava/lang/Object;

    iput-boolean p2, p0, Lhg/n;->g:Z

    iput p3, p0, Lhg/n;->f:I

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(ZLm1/t;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lhg/n;->d:I

    .line 2
    iput-boolean p1, p0, Lhg/n;->g:Z

    iput-object p2, p0, Lhg/n;->h:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget v0, p0, Lhg/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lhg/n;

    .line 7
    .line 8
    iget-object p1, p0, Lhg/n;->h:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, p1

    .line 11
    check-cast v2, Lx31/n;

    .line 12
    .line 13
    iget v4, p0, Lhg/n;->f:I

    .line 14
    .line 15
    const/4 v6, 0x2

    .line 16
    iget-boolean v3, p0, Lhg/n;->g:Z

    .line 17
    .line 18
    move-object v5, p2

    .line 19
    invoke-direct/range {v1 .. v6}, Lhg/n;-><init>(Landroidx/lifecycle/b1;ZILkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    return-object v1

    .line 23
    :pswitch_0
    move-object v5, p2

    .line 24
    new-instance p2, Lhg/n;

    .line 25
    .line 26
    iget-object v0, p0, Lhg/n;->h:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Lm1/t;

    .line 29
    .line 30
    iget-boolean p0, p0, Lhg/n;->g:Z

    .line 31
    .line 32
    invoke-direct {p2, p0, v0, v5}, Lhg/n;-><init>(ZLm1/t;Lkotlin/coroutines/Continuation;)V

    .line 33
    .line 34
    .line 35
    check-cast p1, Ljava/lang/Number;

    .line 36
    .line 37
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    iput p0, p2, Lhg/n;->f:I

    .line 42
    .line 43
    return-object p2

    .line 44
    :pswitch_1
    move-object v5, p2

    .line 45
    new-instance v2, Lhg/n;

    .line 46
    .line 47
    iget-object p1, p0, Lhg/n;->h:Ljava/lang/Object;

    .line 48
    .line 49
    move-object v3, p1

    .line 50
    check-cast v3, Lhg/x;

    .line 51
    .line 52
    move-object v6, v5

    .line 53
    iget v5, p0, Lhg/n;->f:I

    .line 54
    .line 55
    const/4 v7, 0x0

    .line 56
    iget-boolean v4, p0, Lhg/n;->g:Z

    .line 57
    .line 58
    invoke-direct/range {v2 .. v7}, Lhg/n;-><init>(Landroidx/lifecycle/b1;ZILkotlin/coroutines/Continuation;I)V

    .line 59
    .line 60
    .line 61
    return-object v2

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lhg/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lhg/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lhg/n;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lhg/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    .line 24
    .line 25
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 30
    .line 31
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p0, p1, p2}, Lhg/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    check-cast p0, Lhg/n;

    .line 40
    .line 41
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {p0, p1}, Lhg/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lhg/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    check-cast p0, Lhg/n;

    .line 57
    .line 58
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    invoke-virtual {p0, p1}, Lhg/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lhg/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lhg/n;->e:I

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
    goto :goto_1

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
    iget-object p1, p0, Lhg/n;->h:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p1, Lx31/n;

    .line 33
    .line 34
    iget-object p1, p1, Lx31/n;->k:Lk31/j;

    .line 35
    .line 36
    iget v1, p0, Lhg/n;->f:I

    .line 37
    .line 38
    new-instance v3, Ljava/lang/Integer;

    .line 39
    .line 40
    invoke-direct {v3, v1}, Ljava/lang/Integer;-><init>(I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    const/4 v4, -0x1

    .line 48
    const/4 v5, 0x0

    .line 49
    if-le v1, v4, :cond_2

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    move-object v3, v5

    .line 53
    :goto_0
    new-instance v1, Lk31/i;

    .line 54
    .line 55
    iget-boolean v4, p0, Lhg/n;->g:Z

    .line 56
    .line 57
    invoke-direct {v1, v4, v3}, Lk31/i;-><init>(ZLjava/lang/Integer;)V

    .line 58
    .line 59
    .line 60
    iput v2, p0, Lhg/n;->e:I

    .line 61
    .line 62
    iget-object v2, p1, Lk31/j;->b:Lvy0/x;

    .line 63
    .line 64
    new-instance v3, Lif0/d0;

    .line 65
    .line 66
    const/16 v4, 0x1d

    .line 67
    .line 68
    invoke-direct {v3, v4, v1, p1, v5}, Lif0/d0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 69
    .line 70
    .line 71
    invoke-static {v2, v3, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-ne p1, v0, :cond_3

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_3
    :goto_1
    check-cast p1, Lo41/c;

    .line 79
    .line 80
    invoke-static {p1}, Ljp/nb;->b(Lo41/c;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    move-object v0, p0

    .line 85
    check-cast v0, Ljava/util/List;

    .line 86
    .line 87
    if-nez v0, :cond_4

    .line 88
    .line 89
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 90
    .line 91
    :cond_4
    :goto_2
    return-object v0

    .line 92
    :pswitch_0
    iget v0, p0, Lhg/n;->f:I

    .line 93
    .line 94
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 95
    .line 96
    iget v2, p0, Lhg/n;->e:I

    .line 97
    .line 98
    const/4 v3, 0x1

    .line 99
    if-eqz v2, :cond_6

    .line 100
    .line 101
    if-ne v2, v3, :cond_5

    .line 102
    .line 103
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 108
    .line 109
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 110
    .line 111
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw p0

    .line 115
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    iget-boolean p1, p0, Lhg/n;->g:Z

    .line 119
    .line 120
    if-eqz p1, :cond_7

    .line 121
    .line 122
    if-lez v0, :cond_7

    .line 123
    .line 124
    iget-object p1, p0, Lhg/n;->h:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast p1, Lm1/t;

    .line 127
    .line 128
    add-int/lit8 v2, v0, -0x1

    .line 129
    .line 130
    iput v0, p0, Lhg/n;->f:I

    .line 131
    .line 132
    iput v3, p0, Lhg/n;->e:I

    .line 133
    .line 134
    invoke-static {p1, v2, p0}, Lm1/t;->f(Lm1/t;ILrx0/i;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    if-ne p0, v1, :cond_7

    .line 139
    .line 140
    goto :goto_4

    .line 141
    :cond_7
    :goto_3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 142
    .line 143
    :goto_4
    return-object v1

    .line 144
    :pswitch_1
    iget-object v0, p0, Lhg/n;->h:Ljava/lang/Object;

    .line 145
    .line 146
    move-object v4, v0

    .line 147
    check-cast v4, Lhg/x;

    .line 148
    .line 149
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 150
    .line 151
    iget v1, p0, Lhg/n;->e:I

    .line 152
    .line 153
    const/4 v2, 0x1

    .line 154
    if-eqz v1, :cond_9

    .line 155
    .line 156
    if-ne v1, v2, :cond_8

    .line 157
    .line 158
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    goto :goto_5

    .line 162
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 163
    .line 164
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 165
    .line 166
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    throw p0

    .line 170
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    new-instance p1, Leg/l;

    .line 174
    .line 175
    iget-object v1, v4, Lhg/x;->j:Ljava/lang/String;

    .line 176
    .line 177
    invoke-direct {p1, v1}, Leg/l;-><init>(Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    iget-object v1, v4, Lhg/x;->h:Lag/c;

    .line 181
    .line 182
    iput v2, p0, Lhg/n;->e:I

    .line 183
    .line 184
    invoke-virtual {v1, p1, p0}, Lag/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    if-ne p1, v0, :cond_a

    .line 189
    .line 190
    goto :goto_7

    .line 191
    :cond_a
    :goto_5
    check-cast p1, Llx0/o;

    .line 192
    .line 193
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 194
    .line 195
    instance-of v0, p1, Llx0/n;

    .line 196
    .line 197
    if-nez v0, :cond_b

    .line 198
    .line 199
    move-object v0, p1

    .line 200
    check-cast v0, Leg/o;

    .line 201
    .line 202
    const/4 v1, 0x0

    .line 203
    invoke-static {v4, v0, v1}, Lhg/x;->a(Lhg/x;Leg/o;Z)V

    .line 204
    .line 205
    .line 206
    :cond_b
    iget v5, p0, Lhg/n;->f:I

    .line 207
    .line 208
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 209
    .line 210
    .line 211
    move-result-object p1

    .line 212
    if-eqz p1, :cond_d

    .line 213
    .line 214
    iget-boolean p0, p0, Lhg/n;->g:Z

    .line 215
    .line 216
    if-nez p0, :cond_c

    .line 217
    .line 218
    iget-object p0, v4, Lhg/x;->k:Lyy0/c2;

    .line 219
    .line 220
    sget-object v0, Lhg/g;->a:Lhg/g;

    .line 221
    .line 222
    invoke-static {p0, p1, v0}, Lhg/x;->g(Lyy0/c2;Ljava/lang/Throwable;Lhg/j;)V

    .line 223
    .line 224
    .line 225
    goto :goto_6

    .line 226
    :cond_c
    const/4 p0, 0x3

    .line 227
    if-ge v5, p0, :cond_d

    .line 228
    .line 229
    const-wide/16 v0, 0x1388

    .line 230
    .line 231
    long-to-double v0, v0

    .line 232
    const-wide/high16 v2, 0x4000000000000000L    # 2.0

    .line 233
    .line 234
    int-to-double v6, v5

    .line 235
    invoke-static {v2, v3, v6, v7}, Ljava/lang/Math;->pow(DD)D

    .line 236
    .line 237
    .line 238
    move-result-wide v2

    .line 239
    mul-double/2addr v2, v0

    .line 240
    double-to-long v2, v2

    .line 241
    invoke-static {v4}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 242
    .line 243
    .line 244
    move-result-object p1

    .line 245
    new-instance v1, Lhg/o;

    .line 246
    .line 247
    const/4 v6, 0x0

    .line 248
    invoke-direct/range {v1 .. v6}, Lhg/o;-><init>(JLhg/x;ILkotlin/coroutines/Continuation;)V

    .line 249
    .line 250
    .line 251
    const/4 v0, 0x0

    .line 252
    invoke-static {p1, v0, v0, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 253
    .line 254
    .line 255
    :cond_d
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 256
    .line 257
    :goto_7
    return-object v0

    .line 258
    nop

    .line 259
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
