.class public final Lo1/r;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lo1/t;


# direct methods
.method public synthetic constructor <init>(Lo1/t;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lo1/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lo1/r;->f:Lo1/t;

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
    iget p1, p0, Lo1/r;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lo1/r;

    .line 7
    .line 8
    iget-object p0, p0, Lo1/r;->f:Lo1/t;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lo1/r;-><init>(Lo1/t;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lo1/r;

    .line 16
    .line 17
    iget-object p0, p0, Lo1/r;->f:Lo1/t;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lo1/r;-><init>(Lo1/t;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lo1/r;

    .line 25
    .line 26
    iget-object p0, p0, Lo1/r;->f:Lo1/t;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lo1/r;-><init>(Lo1/t;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lo1/r;

    .line 34
    .line 35
    iget-object p0, p0, Lo1/r;->f:Lo1/t;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lo1/r;-><init>(Lo1/t;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lo1/r;

    .line 43
    .line 44
    iget-object p0, p0, Lo1/r;->f:Lo1/t;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lo1/r;-><init>(Lo1/t;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
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
    iget v0, p0, Lo1/r;->d:I

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
    invoke-virtual {p0, p1, p2}, Lo1/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lo1/r;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lo1/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lo1/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lo1/r;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lo1/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lo1/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lo1/r;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lo1/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lo1/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lo1/r;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lo1/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lo1/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lo1/r;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lo1/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lo1/r;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Lo1/r;->f:Lo1/t;

    .line 6
    .line 7
    const-string v3, "call to \'resume\' before \'invoke\' with coroutine"

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
    iget v5, p0, Lo1/r;->e:I

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
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    iget-object p1, v2, Lo1/t;->p:Lc1/c;

    .line 35
    .line 36
    iput v4, p0, Lo1/r;->e:I

    .line 37
    .line 38
    invoke-virtual {p1, p0}, Lc1/c;->g(Lrx0/c;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    if-ne p0, v0, :cond_2

    .line 43
    .line 44
    move-object v1, v0

    .line 45
    :cond_2
    :goto_0
    return-object v1

    .line 46
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 47
    .line 48
    iget v5, p0, Lo1/r;->e:I

    .line 49
    .line 50
    if-eqz v5, :cond_4

    .line 51
    .line 52
    if-ne v5, v4, :cond_3

    .line 53
    .line 54
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 59
    .line 60
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw p0

    .line 64
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iget-object p1, v2, Lo1/t;->p:Lc1/c;

    .line 68
    .line 69
    iput v4, p0, Lo1/r;->e:I

    .line 70
    .line 71
    invoke-virtual {p1, p0}, Lc1/c;->g(Lrx0/c;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    if-ne p0, v0, :cond_5

    .line 76
    .line 77
    move-object v1, v0

    .line 78
    :cond_5
    :goto_1
    return-object v1

    .line 79
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 80
    .line 81
    iget v5, p0, Lo1/r;->e:I

    .line 82
    .line 83
    if-eqz v5, :cond_7

    .line 84
    .line 85
    if-ne v5, v4, :cond_6

    .line 86
    .line 87
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 92
    .line 93
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    iget-object p1, v2, Lo1/t;->o:Lc1/c;

    .line 101
    .line 102
    iput v4, p0, Lo1/r;->e:I

    .line 103
    .line 104
    invoke-virtual {p1, p0}, Lc1/c;->g(Lrx0/c;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    if-ne p0, v0, :cond_8

    .line 109
    .line 110
    move-object v1, v0

    .line 111
    :cond_8
    :goto_2
    return-object v1

    .line 112
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 113
    .line 114
    iget v5, p0, Lo1/r;->e:I

    .line 115
    .line 116
    const-wide/16 v6, 0x0

    .line 117
    .line 118
    if-eqz v5, :cond_a

    .line 119
    .line 120
    if-ne v5, v4, :cond_9

    .line 121
    .line 122
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    goto :goto_3

    .line 126
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 127
    .line 128
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    throw p0

    .line 132
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    iget-object p1, v2, Lo1/t;->o:Lc1/c;

    .line 136
    .line 137
    new-instance v3, Lt4/j;

    .line 138
    .line 139
    invoke-direct {v3, v6, v7}, Lt4/j;-><init>(J)V

    .line 140
    .line 141
    .line 142
    iput v4, p0, Lo1/r;->e:I

    .line 143
    .line 144
    invoke-virtual {p1, v3, p0}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    if-ne p0, v0, :cond_b

    .line 149
    .line 150
    move-object v1, v0

    .line 151
    goto :goto_4

    .line 152
    :cond_b
    :goto_3
    sget p0, Lo1/t;->t:I

    .line 153
    .line 154
    invoke-virtual {v2, v6, v7}, Lo1/t;->g(J)V

    .line 155
    .line 156
    .line 157
    const/4 p0, 0x0

    .line 158
    invoke-virtual {v2, p0}, Lo1/t;->f(Z)V

    .line 159
    .line 160
    .line 161
    :goto_4
    return-object v1

    .line 162
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 163
    .line 164
    iget v5, p0, Lo1/r;->e:I

    .line 165
    .line 166
    if-eqz v5, :cond_d

    .line 167
    .line 168
    if-ne v5, v4, :cond_c

    .line 169
    .line 170
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    goto :goto_5

    .line 174
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 175
    .line 176
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    throw p0

    .line 180
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    iget-object p1, v2, Lo1/t;->p:Lc1/c;

    .line 184
    .line 185
    new-instance v2, Ljava/lang/Float;

    .line 186
    .line 187
    const/high16 v3, 0x3f800000    # 1.0f

    .line 188
    .line 189
    invoke-direct {v2, v3}, Ljava/lang/Float;-><init>(F)V

    .line 190
    .line 191
    .line 192
    iput v4, p0, Lo1/r;->e:I

    .line 193
    .line 194
    invoke-virtual {p1, v2, p0}, Lc1/c;->f(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    if-ne p0, v0, :cond_e

    .line 199
    .line 200
    move-object v1, v0

    .line 201
    :cond_e
    :goto_5
    return-object v1

    .line 202
    nop

    .line 203
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
