.class public final Lbq0/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lbq0/a;->d:I

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lbq0/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch p0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    new-instance p0, Lbq0/a;

    .line 11
    .line 12
    const/4 v0, 0x3

    .line 13
    const/4 v1, 0x2

    .line 14
    invoke-direct {p0, v0, p3, v1}, Lbq0/a;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lbq0/a;->f:Lyy0/j;

    .line 18
    .line 19
    iput-object p2, p0, Lbq0/a;->g:Ljava/lang/Object;

    .line 20
    .line 21
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lbq0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :pswitch_0
    new-instance p0, Lbq0/a;

    .line 29
    .line 30
    const/4 v0, 0x3

    .line 31
    const/4 v1, 0x1

    .line 32
    invoke-direct {p0, v0, p3, v1}, Lbq0/a;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    iput-object p1, p0, Lbq0/a;->f:Lyy0/j;

    .line 36
    .line 37
    iput-object p2, p0, Lbq0/a;->g:Ljava/lang/Object;

    .line 38
    .line 39
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    invoke-virtual {p0, p1}, Lbq0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :pswitch_1
    new-instance p0, Lbq0/a;

    .line 47
    .line 48
    const/4 v0, 0x3

    .line 49
    const/4 v1, 0x0

    .line 50
    invoke-direct {p0, v0, p3, v1}, Lbq0/a;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 51
    .line 52
    .line 53
    iput-object p1, p0, Lbq0/a;->f:Lyy0/j;

    .line 54
    .line 55
    iput-object p2, p0, Lbq0/a;->g:Ljava/lang/Object;

    .line 56
    .line 57
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 58
    .line 59
    invoke-virtual {p0, p1}, Lbq0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    nop

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lbq0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lbq0/a;->e:I

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
    iget-object p1, p0, Lbq0/a;->f:Lyy0/j;

    .line 31
    .line 32
    iget-object v1, p0, Lbq0/a;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lyy0/i;

    .line 35
    .line 36
    const/4 v3, 0x0

    .line 37
    iput-object v3, p0, Lbq0/a;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object v3, p0, Lbq0/a;->g:Ljava/lang/Object;

    .line 40
    .line 41
    iput v2, p0, Lbq0/a;->e:I

    .line 42
    .line 43
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    if-ne p0, v0, :cond_2

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    :goto_1
    return-object v0

    .line 53
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 54
    .line 55
    iget v1, p0, Lbq0/a;->e:I

    .line 56
    .line 57
    const/4 v2, 0x1

    .line 58
    if-eqz v1, :cond_4

    .line 59
    .line 60
    if-ne v1, v2, :cond_3

    .line 61
    .line 62
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 69
    .line 70
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw p0

    .line 74
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iget-object p1, p0, Lbq0/a;->f:Lyy0/j;

    .line 78
    .line 79
    iget-object v1, p0, Lbq0/a;->g:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v1, Ljava/lang/Long;

    .line 82
    .line 83
    new-instance v3, Lc00/p1;

    .line 84
    .line 85
    const/4 v4, 0x0

    .line 86
    invoke-direct {v3, v1, v4}, Lc00/p1;-><init>(Ljava/lang/Long;Lkotlin/coroutines/Continuation;)V

    .line 87
    .line 88
    .line 89
    new-instance v1, Lyy0/m1;

    .line 90
    .line 91
    invoke-direct {v1, v3}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 92
    .line 93
    .line 94
    iput-object v4, p0, Lbq0/a;->f:Lyy0/j;

    .line 95
    .line 96
    iput-object v4, p0, Lbq0/a;->g:Ljava/lang/Object;

    .line 97
    .line 98
    iput v2, p0, Lbq0/a;->e:I

    .line 99
    .line 100
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    if-ne p0, v0, :cond_5

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    :goto_3
    return-object v0

    .line 110
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 111
    .line 112
    iget v1, p0, Lbq0/a;->e:I

    .line 113
    .line 114
    const/4 v2, 0x1

    .line 115
    if-eqz v1, :cond_7

    .line 116
    .line 117
    if-ne v1, v2, :cond_6

    .line 118
    .line 119
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    goto :goto_5

    .line 123
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 124
    .line 125
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 126
    .line 127
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw p0

    .line 131
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    iget-object p1, p0, Lbq0/a;->f:Lyy0/j;

    .line 135
    .line 136
    iget-object v1, p0, Lbq0/a;->g:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v1, Lne0/s;

    .line 139
    .line 140
    instance-of v3, v1, Lne0/e;

    .line 141
    .line 142
    if-eqz v3, :cond_8

    .line 143
    .line 144
    check-cast v1, Lne0/e;

    .line 145
    .line 146
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v1, Lcq0/m;

    .line 149
    .line 150
    new-instance v3, Lne0/e;

    .line 151
    .line 152
    iget-object v1, v1, Lcq0/m;->b:Lcq0/n;

    .line 153
    .line 154
    invoke-direct {v3, v1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    new-instance v1, Lyy0/m;

    .line 158
    .line 159
    const/4 v4, 0x0

    .line 160
    invoke-direct {v1, v3, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 161
    .line 162
    .line 163
    goto :goto_4

    .line 164
    :cond_8
    instance-of v3, v1, Lne0/c;

    .line 165
    .line 166
    if-eqz v3, :cond_9

    .line 167
    .line 168
    new-instance v3, Lyy0/m;

    .line 169
    .line 170
    const/4 v4, 0x0

    .line 171
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 172
    .line 173
    .line 174
    move-object v1, v3

    .line 175
    goto :goto_4

    .line 176
    :cond_9
    instance-of v1, v1, Lne0/d;

    .line 177
    .line 178
    if-eqz v1, :cond_b

    .line 179
    .line 180
    new-instance v1, Lyy0/m;

    .line 181
    .line 182
    const/4 v3, 0x0

    .line 183
    sget-object v4, Lne0/d;->a:Lne0/d;

    .line 184
    .line 185
    invoke-direct {v1, v4, v3}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 186
    .line 187
    .line 188
    :goto_4
    const/4 v3, 0x0

    .line 189
    iput-object v3, p0, Lbq0/a;->f:Lyy0/j;

    .line 190
    .line 191
    iput-object v3, p0, Lbq0/a;->g:Ljava/lang/Object;

    .line 192
    .line 193
    iput v2, p0, Lbq0/a;->e:I

    .line 194
    .line 195
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    if-ne p0, v0, :cond_a

    .line 200
    .line 201
    goto :goto_6

    .line 202
    :cond_a
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 203
    .line 204
    :goto_6
    return-object v0

    .line 205
    :cond_b
    new-instance p0, La8/r0;

    .line 206
    .line 207
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 208
    .line 209
    .line 210
    throw p0

    .line 211
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
