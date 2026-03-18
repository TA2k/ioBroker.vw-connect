.class public final Lyd/s;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lyd/u;


# direct methods
.method public synthetic constructor <init>(Lyd/u;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lyd/s;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyd/s;->f:Lyd/u;

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
    iget p1, p0, Lyd/s;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lyd/s;

    .line 7
    .line 8
    iget-object p0, p0, Lyd/s;->f:Lyd/u;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lyd/s;-><init>(Lyd/u;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lyd/s;

    .line 16
    .line 17
    iget-object p0, p0, Lyd/s;->f:Lyd/u;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lyd/s;-><init>(Lyd/u;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lyd/s;->d:I

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
    invoke-virtual {p0, p1, p2}, Lyd/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lyd/s;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lyd/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lyd/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lyd/s;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lyd/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Lyd/s;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lyd/s;->f:Lyd/u;

    .line 7
    .line 8
    iget-object v1, v0, Lyd/u;->i:Lyy0/c2;

    .line 9
    .line 10
    iget-object v2, v0, Lyd/u;->k:Lyy0/c2;

    .line 11
    .line 12
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v4, p0, Lyd/s;->e:I

    .line 15
    .line 16
    const/4 v5, 0x1

    .line 17
    if-eqz v4, :cond_1

    .line 18
    .line 19
    if-ne v4, v5, :cond_0

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
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, v0, Lyd/u;->e:Lwp0/c;

    .line 37
    .line 38
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    iput v5, p0, Lyd/s;->e:I

    .line 43
    .line 44
    invoke-virtual {p1, v4, p0}, Lwp0/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    if-ne p1, v3, :cond_2

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_2
    :goto_0
    check-cast p1, Llx0/o;

    .line 52
    .line 53
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 54
    .line 55
    instance-of p1, p0, Llx0/n;

    .line 56
    .line 57
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 58
    .line 59
    const/4 v4, 0x0

    .line 60
    if-nez p1, :cond_3

    .line 61
    .line 62
    move-object p1, p0

    .line 63
    check-cast p1, Lvd/l;

    .line 64
    .line 65
    iget-object v0, v0, Lyd/u;->j:Lyy0/c2;

    .line 66
    .line 67
    invoke-virtual {v0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    new-instance p1, Llx0/o;

    .line 71
    .line 72
    invoke-direct {p1, v3}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v1, v4, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    const-string p1, ""

    .line 85
    .line 86
    invoke-virtual {v2, v4, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    :cond_3
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    if-eqz p0, :cond_4

    .line 94
    .line 95
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    new-instance p1, Llx0/o;

    .line 100
    .line 101
    invoke-direct {p1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    .line 106
    .line 107
    invoke-virtual {v1, v4, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    :cond_4
    :goto_1
    return-object v3

    .line 111
    :pswitch_0
    iget-object v0, p0, Lyd/s;->f:Lyd/u;

    .line 112
    .line 113
    iget-object v1, v0, Lyd/u;->i:Lyy0/c2;

    .line 114
    .line 115
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 116
    .line 117
    iget v3, p0, Lyd/s;->e:I

    .line 118
    .line 119
    const/4 v4, 0x1

    .line 120
    if-eqz v3, :cond_6

    .line 121
    .line 122
    if-ne v3, v4, :cond_5

    .line 123
    .line 124
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_5
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
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    iget-object p1, v0, Lyd/u;->d:Lus0/a;

    .line 140
    .line 141
    iput v4, p0, Lyd/s;->e:I

    .line 142
    .line 143
    invoke-virtual {p1, p0}, Lus0/a;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    if-ne p1, v2, :cond_7

    .line 148
    .line 149
    goto :goto_3

    .line 150
    :cond_7
    :goto_2
    check-cast p1, Llx0/o;

    .line 151
    .line 152
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 153
    .line 154
    instance-of p1, p0, Llx0/n;

    .line 155
    .line 156
    const/4 v2, 0x0

    .line 157
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 158
    .line 159
    if-nez p1, :cond_8

    .line 160
    .line 161
    move-object p1, p0

    .line 162
    check-cast p1, Lvd/l;

    .line 163
    .line 164
    iget-object v0, v0, Lyd/u;->j:Lyy0/c2;

    .line 165
    .line 166
    invoke-virtual {v0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    new-instance p1, Llx0/o;

    .line 170
    .line 171
    invoke-direct {p1, v3}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 175
    .line 176
    .line 177
    invoke-virtual {v1, v2, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    :cond_8
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    if-eqz p0, :cond_9

    .line 185
    .line 186
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    new-instance p1, Llx0/o;

    .line 191
    .line 192
    invoke-direct {p1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 196
    .line 197
    .line 198
    invoke-virtual {v1, v2, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    :cond_9
    move-object v2, v3

    .line 202
    :goto_3
    return-object v2

    .line 203
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
