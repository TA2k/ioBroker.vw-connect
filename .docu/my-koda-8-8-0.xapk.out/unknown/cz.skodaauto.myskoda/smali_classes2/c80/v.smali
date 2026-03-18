.class public final Lc80/v;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc80/y;


# direct methods
.method public synthetic constructor <init>(Lc80/y;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc80/v;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc80/v;->f:Lc80/y;

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
    iget p1, p0, Lc80/v;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lc80/v;

    .line 7
    .line 8
    iget-object p0, p0, Lc80/v;->f:Lc80/y;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lc80/v;-><init>(Lc80/y;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lc80/v;

    .line 16
    .line 17
    iget-object p0, p0, Lc80/v;->f:Lc80/y;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lc80/v;-><init>(Lc80/y;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lc80/v;

    .line 25
    .line 26
    iget-object p0, p0, Lc80/v;->f:Lc80/y;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lc80/v;-><init>(Lc80/y;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lc80/v;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc80/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc80/v;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc80/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc80/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lc80/v;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lc80/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lc80/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lc80/v;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lc80/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lc80/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lc80/v;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Lc80/v;->f:Lc80/y;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v3, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, v2, Lc80/y;->k:Lwq0/y;

    .line 33
    .line 34
    iput v3, p0, Lc80/v;->e:I

    .line 35
    .line 36
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1, p0}, Lwq0/y;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    if-ne p0, v0, :cond_2

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_2
    :goto_0
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    move-object v3, p0

    .line 51
    check-cast v3, Lc80/w;

    .line 52
    .line 53
    const/4 v8, 0x0

    .line 54
    const/16 v9, 0x2f

    .line 55
    .line 56
    const/4 v4, 0x0

    .line 57
    const/4 v5, 0x0

    .line 58
    const/4 v6, 0x0

    .line 59
    const/4 v7, 0x0

    .line 60
    invoke-static/range {v3 .. v9}, Lc80/w;->a(Lc80/w;Lql0/g;ZZLjava/lang/String;ZI)Lc80/w;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 65
    .line 66
    .line 67
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    :goto_1
    return-object v0

    .line 70
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 71
    .line 72
    iget v1, p0, Lc80/v;->e:I

    .line 73
    .line 74
    iget-object v2, p0, Lc80/v;->f:Lc80/y;

    .line 75
    .line 76
    const/4 v3, 0x1

    .line 77
    if-eqz v1, :cond_4

    .line 78
    .line 79
    if-ne v1, v3, :cond_3

    .line 80
    .line 81
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 86
    .line 87
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 88
    .line 89
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    iget-object p1, v2, Lc80/y;->k:Lwq0/y;

    .line 97
    .line 98
    iput v3, p0, Lc80/v;->e:I

    .line 99
    .line 100
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    invoke-virtual {p1, p0}, Lwq0/y;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    if-ne p0, v0, :cond_5

    .line 108
    .line 109
    goto :goto_3

    .line 110
    :cond_5
    :goto_2
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    move-object v3, p0

    .line 115
    check-cast v3, Lc80/w;

    .line 116
    .line 117
    const/4 v8, 0x0

    .line 118
    const/16 v9, 0xf

    .line 119
    .line 120
    const/4 v4, 0x0

    .line 121
    const/4 v5, 0x0

    .line 122
    const/4 v6, 0x0

    .line 123
    const/4 v7, 0x0

    .line 124
    invoke-static/range {v3 .. v9}, Lc80/w;->a(Lc80/w;Lql0/g;ZZLjava/lang/String;ZI)Lc80/w;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 129
    .line 130
    .line 131
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    :goto_3
    return-object v0

    .line 134
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 135
    .line 136
    iget v1, p0, Lc80/v;->e:I

    .line 137
    .line 138
    const/4 v2, 0x1

    .line 139
    if-eqz v1, :cond_7

    .line 140
    .line 141
    if-ne v1, v2, :cond_6

    .line 142
    .line 143
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    goto :goto_4

    .line 147
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 148
    .line 149
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 150
    .line 151
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    throw p0

    .line 155
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    iget-object p1, p0, Lc80/v;->f:Lc80/y;

    .line 159
    .line 160
    iget-object v1, p1, Lc80/y;->h:Lwq0/i0;

    .line 161
    .line 162
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    check-cast v1, Lyy0/i;

    .line 167
    .line 168
    new-instance v3, Lac0/e;

    .line 169
    .line 170
    const/16 v4, 0xb

    .line 171
    .line 172
    invoke-direct {v3, p1, v4}, Lac0/e;-><init>(Ljava/lang/Object;I)V

    .line 173
    .line 174
    .line 175
    iput v2, p0, Lc80/v;->e:I

    .line 176
    .line 177
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    if-ne p0, v0, :cond_8

    .line 182
    .line 183
    goto :goto_5

    .line 184
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 185
    .line 186
    :goto_5
    return-object v0

    .line 187
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
