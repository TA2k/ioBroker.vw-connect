.class public final Lwk0/m0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lwk0/p0;


# direct methods
.method public synthetic constructor <init>(Lwk0/p0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lwk0/m0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lwk0/m0;->f:Lwk0/p0;

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
    iget p1, p0, Lwk0/m0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lwk0/m0;

    .line 7
    .line 8
    iget-object p0, p0, Lwk0/m0;->f:Lwk0/p0;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lwk0/m0;-><init>(Lwk0/p0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lwk0/m0;

    .line 16
    .line 17
    iget-object p0, p0, Lwk0/m0;->f:Lwk0/p0;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lwk0/m0;-><init>(Lwk0/p0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lwk0/m0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lwk0/m0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lwk0/m0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lwk0/m0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lwk0/m0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lwk0/m0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lwk0/m0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lwk0/m0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lwk0/m0;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    const/4 v3, 0x3

    .line 13
    const/4 v4, 0x2

    .line 14
    const/4 v5, 0x1

    .line 15
    iget-object v6, p0, Lwk0/m0;->f:Lwk0/p0;

    .line 16
    .line 17
    if-eqz v1, :cond_4

    .line 18
    .line 19
    if-eq v1, v5, :cond_3

    .line 20
    .line 21
    if-eq v1, v4, :cond_2

    .line 22
    .line 23
    if-ne v1, v3, :cond_1

    .line 24
    .line 25
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    move-object v0, v2

    .line 29
    goto :goto_2

    .line 30
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    iget-object p1, v6, Lwk0/p0;->h:Luk0/b0;

    .line 50
    .line 51
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    check-cast p1, Lyy0/i;

    .line 56
    .line 57
    new-instance v1, Lrz/k;

    .line 58
    .line 59
    const/16 v7, 0xd

    .line 60
    .line 61
    invoke-direct {v1, p1, v7}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 62
    .line 63
    .line 64
    iput v5, p0, Lwk0/m0;->e:I

    .line 65
    .line 66
    invoke-static {v1, p0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-ne p1, v0, :cond_5

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_5
    :goto_0
    check-cast p1, Lne0/e;

    .line 74
    .line 75
    if-eqz p1, :cond_0

    .line 76
    .line 77
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p1, Lvk0/j0;

    .line 80
    .line 81
    if-eqz p1, :cond_0

    .line 82
    .line 83
    invoke-interface {p1}, Lvk0/j0;->f()Lvk0/y;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    if-eqz p1, :cond_0

    .line 88
    .line 89
    iget-object p1, p1, Lvk0/y;->a:Ljava/lang/String;

    .line 90
    .line 91
    if-eqz p1, :cond_0

    .line 92
    .line 93
    iget-object v1, v6, Lwk0/p0;->k:Luk0/p0;

    .line 94
    .line 95
    iput v4, p0, Lwk0/m0;->e:I

    .line 96
    .line 97
    invoke-virtual {v1, p1, p0}, Luk0/p0;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    if-ne p1, v0, :cond_6

    .line 102
    .line 103
    goto :goto_2

    .line 104
    :cond_6
    :goto_1
    check-cast p1, Lyy0/i;

    .line 105
    .line 106
    new-instance v1, Ls90/a;

    .line 107
    .line 108
    const/16 v4, 0x15

    .line 109
    .line 110
    invoke-direct {v1, v6, v4}, Ls90/a;-><init>(Ljava/lang/Object;I)V

    .line 111
    .line 112
    .line 113
    iput v3, p0, Lwk0/m0;->e:I

    .line 114
    .line 115
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    if-ne p0, v0, :cond_0

    .line 120
    .line 121
    :goto_2
    return-object v0

    .line 122
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 123
    .line 124
    iget v1, p0, Lwk0/m0;->e:I

    .line 125
    .line 126
    iget-object v2, p0, Lwk0/m0;->f:Lwk0/p0;

    .line 127
    .line 128
    const/4 v3, 0x1

    .line 129
    if-eqz v1, :cond_8

    .line 130
    .line 131
    if-ne v1, v3, :cond_7

    .line 132
    .line 133
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 138
    .line 139
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 140
    .line 141
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    throw p0

    .line 145
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    iget-object p1, v2, Lwk0/p0;->h:Luk0/b0;

    .line 149
    .line 150
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    check-cast p1, Lyy0/i;

    .line 155
    .line 156
    new-instance v1, Lrz/k;

    .line 157
    .line 158
    const/16 v4, 0xc

    .line 159
    .line 160
    invoke-direct {v1, p1, v4}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 161
    .line 162
    .line 163
    iput v3, p0, Lwk0/m0;->e:I

    .line 164
    .line 165
    invoke-static {v1, p0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    if-ne p1, v0, :cond_9

    .line 170
    .line 171
    goto :goto_4

    .line 172
    :cond_9
    :goto_3
    check-cast p1, Lne0/e;

    .line 173
    .line 174
    if-eqz p1, :cond_a

    .line 175
    .line 176
    iget-object p0, v2, Lwk0/p0;->i:Luk0/g0;

    .line 177
    .line 178
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 179
    .line 180
    check-cast p1, Lvk0/j0;

    .line 181
    .line 182
    invoke-virtual {p0, p1}, Luk0/g0;->a(Lvk0/j0;)V

    .line 183
    .line 184
    .line 185
    :cond_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 186
    .line 187
    :goto_4
    return-object v0

    .line 188
    nop

    .line 189
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
