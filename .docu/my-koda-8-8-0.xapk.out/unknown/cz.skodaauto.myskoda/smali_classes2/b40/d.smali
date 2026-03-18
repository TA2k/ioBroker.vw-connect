.class public final Lb40/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lb40/g;


# direct methods
.method public synthetic constructor <init>(Lb40/g;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lb40/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lb40/d;->f:Lb40/g;

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
    iget p1, p0, Lb40/d;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lb40/d;

    .line 7
    .line 8
    iget-object p0, p0, Lb40/d;->f:Lb40/g;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lb40/d;-><init>(Lb40/g;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lb40/d;

    .line 16
    .line 17
    iget-object p0, p0, Lb40/d;->f:Lb40/g;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lb40/d;-><init>(Lb40/g;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lb40/d;

    .line 25
    .line 26
    iget-object p0, p0, Lb40/d;->f:Lb40/g;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lb40/d;-><init>(Lb40/g;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lb40/d;

    .line 34
    .line 35
    iget-object p0, p0, Lb40/d;->f:Lb40/g;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lb40/d;-><init>(Lb40/g;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lb40/d;->d:I

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
    invoke-virtual {p0, p1, p2}, Lb40/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lb40/d;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lb40/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lb40/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lb40/d;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lb40/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lb40/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lb40/d;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lb40/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lb40/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lb40/d;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lb40/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Lb40/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lb40/d;->e:I

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
    iget-object p1, p0, Lb40/d;->f:Lb40/g;

    .line 31
    .line 32
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Lb40/e;

    .line 37
    .line 38
    const/4 v3, 0x0

    .line 39
    invoke-static {v1, v3, v3, v2}, Lb40/e;->a(Lb40/e;Lae0/a;Lql0/g;I)Lb40/e;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-virtual {p1, v1}, Lql0/j;->g(Lql0/h;)V

    .line 44
    .line 45
    .line 46
    iput v2, p0, Lb40/d;->e:I

    .line 47
    .line 48
    invoke-static {p1, p0}, Lb40/g;->h(Lb40/g;Lrx0/c;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    if-ne p0, v0, :cond_2

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    :goto_1
    return-object v0

    .line 58
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 59
    .line 60
    iget v1, p0, Lb40/d;->e:I

    .line 61
    .line 62
    const/4 v2, 0x1

    .line 63
    if-eqz v1, :cond_4

    .line 64
    .line 65
    if-ne v1, v2, :cond_3

    .line 66
    .line 67
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 72
    .line 73
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 74
    .line 75
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw p0

    .line 79
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    iget-object p1, p0, Lb40/d;->f:Lb40/g;

    .line 83
    .line 84
    iget-object p1, p1, Lb40/g;->j:Lkc0/t0;

    .line 85
    .line 86
    iput v2, p0, Lb40/d;->e:I

    .line 87
    .line 88
    invoke-virtual {p1, p0}, Lkc0/t0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    if-ne p0, v0, :cond_5

    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 96
    .line 97
    :goto_3
    return-object v0

    .line 98
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 99
    .line 100
    iget v1, p0, Lb40/d;->e:I

    .line 101
    .line 102
    const/4 v2, 0x1

    .line 103
    if-eqz v1, :cond_7

    .line 104
    .line 105
    if-ne v1, v2, :cond_6

    .line 106
    .line 107
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    goto :goto_4

    .line 111
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 112
    .line 113
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 114
    .line 115
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    throw p0

    .line 119
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    iput v2, p0, Lb40/d;->e:I

    .line 123
    .line 124
    iget-object p1, p0, Lb40/d;->f:Lb40/g;

    .line 125
    .line 126
    invoke-static {p1, p0}, Lb40/g;->h(Lb40/g;Lrx0/c;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    if-ne p0, v0, :cond_8

    .line 131
    .line 132
    goto :goto_5

    .line 133
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 134
    .line 135
    :goto_5
    return-object v0

    .line 136
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 137
    .line 138
    iget v1, p0, Lb40/d;->e:I

    .line 139
    .line 140
    const/4 v2, 0x1

    .line 141
    if-eqz v1, :cond_a

    .line 142
    .line 143
    if-ne v1, v2, :cond_9

    .line 144
    .line 145
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    goto :goto_6

    .line 149
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 150
    .line 151
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 152
    .line 153
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    throw p0

    .line 157
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    iget-object p1, p0, Lb40/d;->f:Lb40/g;

    .line 161
    .line 162
    iget-object v1, p1, Lb40/g;->h:Lzd0/b;

    .line 163
    .line 164
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v1

    .line 168
    check-cast v1, Lyy0/i;

    .line 169
    .line 170
    new-instance v3, La60/f;

    .line 171
    .line 172
    const/4 v4, 0x0

    .line 173
    const/16 v5, 0x9

    .line 174
    .line 175
    invoke-direct {v3, p1, v4, v5}, La60/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 176
    .line 177
    .line 178
    iput v2, p0, Lb40/d;->e:I

    .line 179
    .line 180
    invoke-static {v3, p0, v1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    if-ne p0, v0, :cond_b

    .line 185
    .line 186
    goto :goto_7

    .line 187
    :cond_b
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 188
    .line 189
    :goto_7
    return-object v0

    .line 190
    nop

    .line 191
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
