.class public final Lkn/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lkn/c0;


# direct methods
.method public synthetic constructor <init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lkn/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lkn/d;->f:Lkn/c0;

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
    iget p1, p0, Lkn/d;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lkn/d;

    .line 7
    .line 8
    iget-object p0, p0, Lkn/d;->f:Lkn/c0;

    .line 9
    .line 10
    const/4 v0, 0x7

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lkn/d;

    .line 16
    .line 17
    iget-object p0, p0, Lkn/d;->f:Lkn/c0;

    .line 18
    .line 19
    const/4 v0, 0x6

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lkn/d;

    .line 25
    .line 26
    iget-object p0, p0, Lkn/d;->f:Lkn/c0;

    .line 27
    .line 28
    const/4 v0, 0x5

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lkn/d;

    .line 34
    .line 35
    iget-object p0, p0, Lkn/d;->f:Lkn/c0;

    .line 36
    .line 37
    const/4 v0, 0x4

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lkn/d;

    .line 43
    .line 44
    iget-object p0, p0, Lkn/d;->f:Lkn/c0;

    .line 45
    .line 46
    const/4 v0, 0x3

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_4
    new-instance p1, Lkn/d;

    .line 52
    .line 53
    iget-object p0, p0, Lkn/d;->f:Lkn/c0;

    .line 54
    .line 55
    const/4 v0, 0x2

    .line 56
    invoke-direct {p1, p0, p2, v0}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    return-object p1

    .line 60
    :pswitch_5
    new-instance p1, Lkn/d;

    .line 61
    .line 62
    iget-object p0, p0, Lkn/d;->f:Lkn/c0;

    .line 63
    .line 64
    const/4 v0, 0x1

    .line 65
    invoke-direct {p1, p0, p2, v0}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    return-object p1

    .line 69
    :pswitch_6
    new-instance p1, Lkn/d;

    .line 70
    .line 71
    iget-object p0, p0, Lkn/d;->f:Lkn/c0;

    .line 72
    .line 73
    const/4 v0, 0x0

    .line 74
    invoke-direct {p1, p0, p2, v0}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 75
    .line 76
    .line 77
    return-object p1

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
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
    iget v0, p0, Lkn/d;->d:I

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
    invoke-virtual {p0, p1, p2}, Lkn/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lkn/d;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lkn/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lkn/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lkn/d;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lkn/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lkn/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lkn/d;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lkn/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lkn/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lkn/d;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lkn/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lkn/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lkn/d;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lkn/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Lkn/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Lkn/d;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Lkn/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :pswitch_5
    invoke-virtual {p0, p1, p2}, Lkn/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Lkn/d;

    .line 93
    .line 94
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    invoke-virtual {p0, p1}, Lkn/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0

    .line 101
    :pswitch_6
    invoke-virtual {p0, p1, p2}, Lkn/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    check-cast p0, Lkn/d;

    .line 106
    .line 107
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    invoke-virtual {p0, p1}, Lkn/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    return-object p0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lkn/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lkn/d;->e:I

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
    iput v2, p0, Lkn/d;->e:I

    .line 31
    .line 32
    iget-object p1, p0, Lkn/d;->f:Lkn/c0;

    .line 33
    .line 34
    invoke-static {p1, p0}, Lkn/c0;->d(Lkn/c0;Lrx0/i;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    if-ne p0, v0, :cond_2

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    :goto_1
    return-object v0

    .line 44
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 45
    .line 46
    iget v1, p0, Lkn/d;->e:I

    .line 47
    .line 48
    const/4 v2, 0x1

    .line 49
    if-eqz v1, :cond_4

    .line 50
    .line 51
    if-ne v1, v2, :cond_3

    .line 52
    .line 53
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iput v2, p0, Lkn/d;->e:I

    .line 69
    .line 70
    iget-object p1, p0, Lkn/d;->f:Lkn/c0;

    .line 71
    .line 72
    invoke-static {p1, p0}, Lkn/c0;->d(Lkn/c0;Lrx0/i;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    if-ne p0, v0, :cond_5

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    :goto_3
    return-object v0

    .line 82
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 83
    .line 84
    iget v1, p0, Lkn/d;->e:I

    .line 85
    .line 86
    const/4 v2, 0x1

    .line 87
    if-eqz v1, :cond_7

    .line 88
    .line 89
    if-ne v1, v2, :cond_6

    .line 90
    .line 91
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    goto :goto_4

    .line 95
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 96
    .line 97
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 98
    .line 99
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw p0

    .line 103
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    iput v2, p0, Lkn/d;->e:I

    .line 107
    .line 108
    iget-object p1, p0, Lkn/d;->f:Lkn/c0;

    .line 109
    .line 110
    const/4 v1, 0x0

    .line 111
    const/4 v2, 0x3

    .line 112
    invoke-static {p1, v1, p0, v2}, Lkn/c0;->f(Lkn/c0;Lc1/j;Lrx0/i;I)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    if-ne p0, v0, :cond_8

    .line 117
    .line 118
    goto :goto_5

    .line 119
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 120
    .line 121
    :goto_5
    return-object v0

    .line 122
    :pswitch_2
    iget-object v0, p0, Lkn/d;->f:Lkn/c0;

    .line 123
    .line 124
    iget-object v1, v0, Lkn/c0;->h:Ll2/f1;

    .line 125
    .line 126
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 127
    .line 128
    iget v3, p0, Lkn/d;->e:I

    .line 129
    .line 130
    const/4 v4, 0x3

    .line 131
    const/4 v5, 0x2

    .line 132
    const/4 v6, 0x1

    .line 133
    if-eqz v3, :cond_b

    .line 134
    .line 135
    if-eq v3, v6, :cond_a

    .line 136
    .line 137
    if-eq v3, v5, :cond_a

    .line 138
    .line 139
    if-ne v3, v4, :cond_9

    .line 140
    .line 141
    goto :goto_6

    .line 142
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 143
    .line 144
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 145
    .line 146
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    throw p0

    .line 150
    :cond_a
    :goto_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    goto/16 :goto_9

    .line 154
    .line 155
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    iget-object p1, v0, Lkn/c0;->f:Lc1/c;

    .line 159
    .line 160
    iget v3, v0, Lkn/c0;->p:F

    .line 161
    .line 162
    const v7, 0x469c4000    # 20000.0f

    .line 163
    .line 164
    .line 165
    cmpl-float v3, v3, v7

    .line 166
    .line 167
    if-ltz v3, :cond_c

    .line 168
    .line 169
    sget-object p1, Lkn/f0;->f:Lkn/f0;

    .line 170
    .line 171
    goto/16 :goto_8

    .line 172
    .line 173
    :cond_c
    invoke-virtual {p1}, Lc1/c;->d()Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v3

    .line 177
    check-cast v3, Ljava/lang/Number;

    .line 178
    .line 179
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 180
    .line 181
    .line 182
    move-result v3

    .line 183
    iget v7, v0, Lkn/c0;->p:F

    .line 184
    .line 185
    const/high16 v8, 0x447a0000    # 1000.0f

    .line 186
    .line 187
    cmpl-float v7, v7, v8

    .line 188
    .line 189
    if-ltz v7, :cond_12

    .line 190
    .line 191
    invoke-virtual {v0}, Lkn/c0;->i()Lkn/f0;

    .line 192
    .line 193
    .line 194
    move-result-object v7

    .line 195
    sget-object v8, Lkn/f0;->d:Lkn/f0;

    .line 196
    .line 197
    if-eq v7, v8, :cond_e

    .line 198
    .line 199
    iget-object v7, v0, Lkn/c0;->s:Ll2/j1;

    .line 200
    .line 201
    invoke-virtual {v7}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v7

    .line 205
    check-cast v7, Lkn/v;

    .line 206
    .line 207
    sget-object v8, Lkn/v;->f:Lkn/v;

    .line 208
    .line 209
    if-ne v7, v8, :cond_d

    .line 210
    .line 211
    goto :goto_7

    .line 212
    :cond_d
    invoke-virtual {v0}, Lkn/c0;->i()Lkn/f0;

    .line 213
    .line 214
    .line 215
    move-result-object v3

    .line 216
    sget-object v7, Lkn/f0;->e:Lkn/f0;

    .line 217
    .line 218
    if-ne v3, v7, :cond_12

    .line 219
    .line 220
    sget-object p1, Lkn/f0;->f:Lkn/f0;

    .line 221
    .line 222
    goto/16 :goto_8

    .line 223
    .line 224
    :cond_e
    :goto_7
    invoke-virtual {v0}, Lkn/c0;->n()Z

    .line 225
    .line 226
    .line 227
    move-result v7

    .line 228
    if-eqz v7, :cond_11

    .line 229
    .line 230
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 231
    .line 232
    .line 233
    move-result v7

    .line 234
    cmpl-float v7, v3, v7

    .line 235
    .line 236
    if-gez v7, :cond_10

    .line 237
    .line 238
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 239
    .line 240
    .line 241
    move-result v7

    .line 242
    const v8, 0x3f333333    # 0.7f

    .line 243
    .line 244
    .line 245
    mul-float/2addr v7, v8

    .line 246
    cmpl-float v7, v3, v7

    .line 247
    .line 248
    if-lez v7, :cond_f

    .line 249
    .line 250
    iget v7, v0, Lkn/c0;->p:F

    .line 251
    .line 252
    const/high16 v8, 0x44fa0000    # 2000.0f

    .line 253
    .line 254
    cmpl-float v7, v7, v8

    .line 255
    .line 256
    if-gez v7, :cond_10

    .line 257
    .line 258
    :cond_f
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 259
    .line 260
    .line 261
    move-result v7

    .line 262
    const/high16 v8, 0x3f000000    # 0.5f

    .line 263
    .line 264
    mul-float/2addr v7, v8

    .line 265
    cmpl-float v3, v3, v7

    .line 266
    .line 267
    if-lez v3, :cond_12

    .line 268
    .line 269
    iget v3, v0, Lkn/c0;->p:F

    .line 270
    .line 271
    const v7, 0x453b8000    # 3000.0f

    .line 272
    .line 273
    .line 274
    cmpl-float v3, v3, v7

    .line 275
    .line 276
    if-ltz v3, :cond_12

    .line 277
    .line 278
    :cond_10
    sget-object p1, Lkn/f0;->f:Lkn/f0;

    .line 279
    .line 280
    goto :goto_8

    .line 281
    :cond_11
    sget-object p1, Lkn/f0;->e:Lkn/f0;

    .line 282
    .line 283
    goto :goto_8

    .line 284
    :cond_12
    iget v3, v0, Lkn/c0;->p:F

    .line 285
    .line 286
    const/high16 v7, -0x3b860000    # -1000.0f

    .line 287
    .line 288
    cmpg-float v3, v3, v7

    .line 289
    .line 290
    if-gtz v3, :cond_13

    .line 291
    .line 292
    sget-object p1, Lkn/f0;->d:Lkn/f0;

    .line 293
    .line 294
    goto :goto_8

    .line 295
    :cond_13
    invoke-virtual {v0}, Lkn/c0;->n()Z

    .line 296
    .line 297
    .line 298
    move-result v3

    .line 299
    if-eqz v3, :cond_15

    .line 300
    .line 301
    invoke-virtual {p1}, Lc1/c;->d()Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object p1

    .line 305
    check-cast p1, Ljava/lang/Number;

    .line 306
    .line 307
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 308
    .line 309
    .line 310
    move-result p1

    .line 311
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 312
    .line 313
    .line 314
    move-result v1

    .line 315
    cmpl-float p1, p1, v1

    .line 316
    .line 317
    if-ltz p1, :cond_14

    .line 318
    .line 319
    sget-object p1, Lkn/f0;->f:Lkn/f0;

    .line 320
    .line 321
    goto :goto_8

    .line 322
    :cond_14
    sget-object p1, Lkn/f0;->d:Lkn/f0;

    .line 323
    .line 324
    goto :goto_8

    .line 325
    :cond_15
    invoke-virtual {v0}, Lkn/c0;->h()F

    .line 326
    .line 327
    .line 328
    move-result v1

    .line 329
    iget-object v3, v0, Lkn/c0;->c:Ll2/g1;

    .line 330
    .line 331
    invoke-virtual {v3}, Ll2/g1;->o()I

    .line 332
    .line 333
    .line 334
    move-result v3

    .line 335
    int-to-float v3, v3

    .line 336
    sub-float/2addr v3, v1

    .line 337
    const/high16 v7, 0x40000000    # 2.0f

    .line 338
    .line 339
    div-float v7, v3, v7

    .line 340
    .line 341
    sub-float v7, v3, v7

    .line 342
    .line 343
    const/high16 v8, 0x40200000    # 2.5f

    .line 344
    .line 345
    div-float/2addr v1, v8

    .line 346
    add-float/2addr v1, v3

    .line 347
    invoke-virtual {p1}, Lc1/c;->d()Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object v3

    .line 351
    check-cast v3, Ljava/lang/Number;

    .line 352
    .line 353
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 354
    .line 355
    .line 356
    move-result v3

    .line 357
    cmpg-float v8, v7, v3

    .line 358
    .line 359
    if-gtz v8, :cond_16

    .line 360
    .line 361
    cmpg-float v1, v3, v1

    .line 362
    .line 363
    if-gtz v1, :cond_16

    .line 364
    .line 365
    sget-object p1, Lkn/f0;->e:Lkn/f0;

    .line 366
    .line 367
    goto :goto_8

    .line 368
    :cond_16
    invoke-virtual {p1}, Lc1/c;->d()Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object p1

    .line 372
    check-cast p1, Ljava/lang/Number;

    .line 373
    .line 374
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 375
    .line 376
    .line 377
    move-result p1

    .line 378
    cmpg-float p1, p1, v7

    .line 379
    .line 380
    if-gez p1, :cond_17

    .line 381
    .line 382
    sget-object p1, Lkn/f0;->d:Lkn/f0;

    .line 383
    .line 384
    goto :goto_8

    .line 385
    :cond_17
    sget-object p1, Lkn/f0;->f:Lkn/f0;

    .line 386
    .line 387
    :goto_8
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 388
    .line 389
    .line 390
    move-result p1

    .line 391
    const/4 v1, 0x7

    .line 392
    const/4 v3, 0x0

    .line 393
    const/4 v7, 0x0

    .line 394
    if-eqz p1, :cond_1a

    .line 395
    .line 396
    if-eq p1, v6, :cond_19

    .line 397
    .line 398
    if-eq p1, v5, :cond_18

    .line 399
    .line 400
    goto :goto_9

    .line 401
    :cond_18
    iput v5, p0, Lkn/d;->e:I

    .line 402
    .line 403
    invoke-static {v0, p0}, Lkn/c0;->d(Lkn/c0;Lrx0/i;)Ljava/lang/Object;

    .line 404
    .line 405
    .line 406
    move-result-object p0

    .line 407
    if-ne p0, v2, :cond_1b

    .line 408
    .line 409
    goto :goto_a

    .line 410
    :cond_19
    invoke-static {v7, v7, v3, v1}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 411
    .line 412
    .line 413
    move-result-object p1

    .line 414
    iput v4, p0, Lkn/d;->e:I

    .line 415
    .line 416
    invoke-static {v0, p1, p0, v6}, Lkn/c0;->k(Lkn/c0;Lc1/j;Lrx0/i;I)Ljava/lang/Object;

    .line 417
    .line 418
    .line 419
    move-result-object p0

    .line 420
    if-ne p0, v2, :cond_1b

    .line 421
    .line 422
    goto :goto_a

    .line 423
    :cond_1a
    invoke-static {v7, v7, v3, v1}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 424
    .line 425
    .line 426
    move-result-object p1

    .line 427
    iput v6, p0, Lkn/d;->e:I

    .line 428
    .line 429
    invoke-static {v0, p1, p0, v6}, Lkn/c0;->f(Lkn/c0;Lc1/j;Lrx0/i;I)Ljava/lang/Object;

    .line 430
    .line 431
    .line 432
    move-result-object p0

    .line 433
    if-ne p0, v2, :cond_1b

    .line 434
    .line 435
    goto :goto_a

    .line 436
    :cond_1b
    :goto_9
    iget-object p0, v0, Lkn/c0;->q:Lh6/j;

    .line 437
    .line 438
    invoke-virtual {p0}, Lh6/j;->g()V

    .line 439
    .line 440
    .line 441
    const p1, 0x7f7fffff    # Float.MAX_VALUE

    .line 442
    .line 443
    .line 444
    invoke-static {p1, p1}, Lkp/g9;->a(FF)J

    .line 445
    .line 446
    .line 447
    move-result-wide v1

    .line 448
    invoke-virtual {p0, v1, v2}, Lh6/j;->e(J)J

    .line 449
    .line 450
    .line 451
    move-result-wide p0

    .line 452
    invoke-static {p0, p1}, Lt4/q;->c(J)F

    .line 453
    .line 454
    .line 455
    move-result p0

    .line 456
    iput p0, v0, Lkn/c0;->p:F

    .line 457
    .line 458
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 459
    .line 460
    :goto_a
    return-object v2

    .line 461
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 462
    .line 463
    iget v1, p0, Lkn/d;->e:I

    .line 464
    .line 465
    const/4 v2, 0x1

    .line 466
    if-eqz v1, :cond_1d

    .line 467
    .line 468
    if-ne v1, v2, :cond_1c

    .line 469
    .line 470
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 471
    .line 472
    .line 473
    goto :goto_b

    .line 474
    :cond_1c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 475
    .line 476
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 477
    .line 478
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 479
    .line 480
    .line 481
    throw p0

    .line 482
    :cond_1d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 483
    .line 484
    .line 485
    iput v2, p0, Lkn/d;->e:I

    .line 486
    .line 487
    iget-object p1, p0, Lkn/d;->f:Lkn/c0;

    .line 488
    .line 489
    invoke-static {p1, p0}, Lkn/c0;->d(Lkn/c0;Lrx0/i;)Ljava/lang/Object;

    .line 490
    .line 491
    .line 492
    move-result-object p0

    .line 493
    if-ne p0, v0, :cond_1e

    .line 494
    .line 495
    goto :goto_c

    .line 496
    :cond_1e
    :goto_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 497
    .line 498
    :goto_c
    return-object v0

    .line 499
    :pswitch_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 500
    .line 501
    iget v1, p0, Lkn/d;->e:I

    .line 502
    .line 503
    const/4 v2, 0x1

    .line 504
    if-eqz v1, :cond_20

    .line 505
    .line 506
    if-ne v1, v2, :cond_1f

    .line 507
    .line 508
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 509
    .line 510
    .line 511
    goto :goto_d

    .line 512
    :cond_1f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 513
    .line 514
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 515
    .line 516
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 517
    .line 518
    .line 519
    throw p0

    .line 520
    :cond_20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 521
    .line 522
    .line 523
    iput v2, p0, Lkn/d;->e:I

    .line 524
    .line 525
    iget-object p1, p0, Lkn/d;->f:Lkn/c0;

    .line 526
    .line 527
    invoke-virtual {p1, p0}, Lkn/c0;->o(Lrx0/c;)Ljava/lang/Object;

    .line 528
    .line 529
    .line 530
    move-result-object p0

    .line 531
    if-ne p0, v0, :cond_21

    .line 532
    .line 533
    goto :goto_e

    .line 534
    :cond_21
    :goto_d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 535
    .line 536
    :goto_e
    return-object v0

    .line 537
    :pswitch_5
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 538
    .line 539
    iget v1, p0, Lkn/d;->e:I

    .line 540
    .line 541
    const/4 v2, 0x1

    .line 542
    if-eqz v1, :cond_23

    .line 543
    .line 544
    if-ne v1, v2, :cond_22

    .line 545
    .line 546
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 547
    .line 548
    .line 549
    goto :goto_f

    .line 550
    :cond_22
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 551
    .line 552
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 553
    .line 554
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 555
    .line 556
    .line 557
    throw p0

    .line 558
    :cond_23
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 559
    .line 560
    .line 561
    iput v2, p0, Lkn/d;->e:I

    .line 562
    .line 563
    iget-object p1, p0, Lkn/d;->f:Lkn/c0;

    .line 564
    .line 565
    invoke-static {p1, p0}, Lkn/c0;->d(Lkn/c0;Lrx0/i;)Ljava/lang/Object;

    .line 566
    .line 567
    .line 568
    move-result-object p0

    .line 569
    if-ne p0, v0, :cond_24

    .line 570
    .line 571
    goto :goto_10

    .line 572
    :cond_24
    :goto_f
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 573
    .line 574
    :goto_10
    return-object v0

    .line 575
    :pswitch_6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 576
    .line 577
    iget v1, p0, Lkn/d;->e:I

    .line 578
    .line 579
    const/4 v2, 0x1

    .line 580
    if-eqz v1, :cond_26

    .line 581
    .line 582
    if-ne v1, v2, :cond_25

    .line 583
    .line 584
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 585
    .line 586
    .line 587
    goto :goto_11

    .line 588
    :cond_25
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 589
    .line 590
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 591
    .line 592
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 593
    .line 594
    .line 595
    throw p0

    .line 596
    :cond_26
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 597
    .line 598
    .line 599
    iput v2, p0, Lkn/d;->e:I

    .line 600
    .line 601
    iget-object p1, p0, Lkn/d;->f:Lkn/c0;

    .line 602
    .line 603
    const/4 v1, 0x0

    .line 604
    const/4 v2, 0x3

    .line 605
    invoke-static {p1, v1, p0, v2}, Lkn/c0;->k(Lkn/c0;Lc1/j;Lrx0/i;I)Ljava/lang/Object;

    .line 606
    .line 607
    .line 608
    move-result-object p0

    .line 609
    if-ne p0, v0, :cond_27

    .line 610
    .line 611
    goto :goto_12

    .line 612
    :cond_27
    :goto_11
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 613
    .line 614
    :goto_12
    return-object v0

    .line 615
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
