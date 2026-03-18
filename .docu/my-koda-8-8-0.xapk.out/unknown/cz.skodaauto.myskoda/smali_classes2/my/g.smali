.class public final Lmy/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lmy/t;


# direct methods
.method public synthetic constructor <init>(Lmy/t;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lmy/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lmy/g;->f:Lmy/t;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lmy/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lmy/g;

    .line 7
    .line 8
    iget-object p0, p0, Lmy/g;->f:Lmy/t;

    .line 9
    .line 10
    const/4 v1, 0x3

    .line 11
    invoke-direct {v0, p0, p1, v1}, Lmy/g;-><init>(Lmy/t;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object v0

    .line 15
    :pswitch_0
    new-instance v0, Lmy/g;

    .line 16
    .line 17
    iget-object p0, p0, Lmy/g;->f:Lmy/t;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, p0, p1, v1}, Lmy/g;-><init>(Lmy/t;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object v0

    .line 24
    :pswitch_1
    new-instance v0, Lmy/g;

    .line 25
    .line 26
    iget-object p0, p0, Lmy/g;->f:Lmy/t;

    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    invoke-direct {v0, p0, p1, v1}, Lmy/g;-><init>(Lmy/t;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object v0

    .line 33
    :pswitch_2
    new-instance v0, Lmy/g;

    .line 34
    .line 35
    iget-object p0, p0, Lmy/g;->f:Lmy/t;

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    invoke-direct {v0, p0, p1, v1}, Lmy/g;-><init>(Lmy/t;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object v0

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

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lmy/g;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lmy/g;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lmy/g;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lmy/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Lmy/g;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lmy/g;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lmy/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Lmy/g;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Lmy/g;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Lmy/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_2
    invoke-virtual {p0, p1}, Lmy/g;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Lmy/g;

    .line 52
    .line 53
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    invoke-virtual {p0, p1}, Lmy/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lmy/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lmy/g;->e:I

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
    iget-object p1, p0, Lmy/g;->f:Lmy/t;

    .line 31
    .line 32
    iget-object v1, p1, Lmy/t;->C:Lks0/q;

    .line 33
    .line 34
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    check-cast v1, Lyy0/i;

    .line 39
    .line 40
    new-instance v3, Lmy/h;

    .line 41
    .line 42
    const/4 v4, 0x0

    .line 43
    invoke-direct {v3, p1, v4}, Lmy/h;-><init>(Lmy/t;I)V

    .line 44
    .line 45
    .line 46
    iput v2, p0, Lmy/g;->e:I

    .line 47
    .line 48
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    iget v1, p0, Lmy/g;->e:I

    .line 61
    .line 62
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    const/4 v3, 0x1

    .line 65
    if-eqz v1, :cond_5

    .line 66
    .line 67
    if-ne v1, v3, :cond_4

    .line 68
    .line 69
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    :cond_3
    move-object v0, v2

    .line 73
    goto :goto_2

    .line 74
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 75
    .line 76
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 77
    .line 78
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    iget-object p1, p0, Lmy/g;->f:Lmy/t;

    .line 86
    .line 87
    iget-object p1, p1, Lmy/t;->y:Lcc0/d;

    .line 88
    .line 89
    iput v3, p0, Lmy/g;->e:I

    .line 90
    .line 91
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    invoke-virtual {p1, p0}, Lcc0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    if-ne p0, v0, :cond_3

    .line 99
    .line 100
    :goto_2
    return-object v0

    .line 101
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 102
    .line 103
    iget v1, p0, Lmy/g;->e:I

    .line 104
    .line 105
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    const/4 v3, 0x1

    .line 108
    if-eqz v1, :cond_8

    .line 109
    .line 110
    if-ne v1, v3, :cond_7

    .line 111
    .line 112
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    :cond_6
    move-object v0, v2

    .line 116
    goto :goto_3

    .line 117
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 118
    .line 119
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 120
    .line 121
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    throw p0

    .line 125
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    iget-object p1, p0, Lmy/g;->f:Lmy/t;

    .line 129
    .line 130
    iget-object p1, p1, Lmy/t;->x:Lky/q;

    .line 131
    .line 132
    iput v3, p0, Lmy/g;->e:I

    .line 133
    .line 134
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 135
    .line 136
    .line 137
    invoke-virtual {p1, p0}, Lky/q;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    if-ne p0, v0, :cond_6

    .line 142
    .line 143
    :goto_3
    return-object v0

    .line 144
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 145
    .line 146
    iget v1, p0, Lmy/g;->e:I

    .line 147
    .line 148
    const/4 v2, 0x1

    .line 149
    if-eqz v1, :cond_a

    .line 150
    .line 151
    if-ne v1, v2, :cond_9

    .line 152
    .line 153
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    goto :goto_4

    .line 157
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 158
    .line 159
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 160
    .line 161
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    throw p0

    .line 165
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    iget-object p1, p0, Lmy/g;->f:Lmy/t;

    .line 169
    .line 170
    iget-object v1, p1, Lmy/t;->o:Lkf0/y;

    .line 171
    .line 172
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    check-cast v1, Lyy0/i;

    .line 177
    .line 178
    new-instance v3, Lh50/y0;

    .line 179
    .line 180
    const/4 v4, 0x7

    .line 181
    invoke-direct {v3, p1, v4}, Lh50/y0;-><init>(Ljava/lang/Object;I)V

    .line 182
    .line 183
    .line 184
    iput v2, p0, Lmy/g;->e:I

    .line 185
    .line 186
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    if-ne p0, v0, :cond_b

    .line 191
    .line 192
    goto :goto_5

    .line 193
    :cond_b
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 194
    .line 195
    :goto_5
    return-object v0

    .line 196
    nop

    .line 197
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
