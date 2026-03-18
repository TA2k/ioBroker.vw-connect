.class public final Lyy0/e1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:[Ljava/lang/Object;

.field public final synthetic h:Lrx0/i;


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Lay0/p;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lyy0/e1;->d:I

    .line 1
    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lyy0/e1;->h:Lrx0/i;

    const/4 p2, 0x3

    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lkotlin/coroutines/Continuation;Lay0/q;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lyy0/e1;->d:I

    .line 2
    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lyy0/e1;->h:Lrx0/i;

    const/4 p2, 0x3

    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lkotlin/coroutines/Continuation;Lay0/r;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lyy0/e1;->d:I

    .line 3
    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lyy0/e1;->h:Lrx0/i;

    const/4 p2, 0x3

    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lyy0/e1;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p2, [Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance v0, Lyy0/e1;

    .line 13
    .line 14
    iget-object p0, p0, Lyy0/e1;->h:Lrx0/i;

    .line 15
    .line 16
    invoke-direct {v0, p3, p0}, Lyy0/e1;-><init>(Lkotlin/coroutines/Continuation;Lay0/q;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, v0, Lyy0/e1;->f:Lyy0/j;

    .line 20
    .line 21
    iput-object p2, v0, Lyy0/e1;->g:[Ljava/lang/Object;

    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Lyy0/e1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_0
    new-instance v0, Lyy0/e1;

    .line 31
    .line 32
    iget-object p0, p0, Lyy0/e1;->h:Lrx0/i;

    .line 33
    .line 34
    invoke-direct {v0, p3, p0}, Lyy0/e1;-><init>(Lkotlin/coroutines/Continuation;Lay0/r;)V

    .line 35
    .line 36
    .line 37
    iput-object p1, v0, Lyy0/e1;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object p2, v0, Lyy0/e1;->g:[Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lyy0/e1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_1
    new-instance v0, Lyy0/e1;

    .line 49
    .line 50
    iget-object p0, p0, Lyy0/e1;->h:Lrx0/i;

    .line 51
    .line 52
    invoke-direct {v0, p3, p0}, Lyy0/e1;-><init>(Lkotlin/coroutines/Continuation;Lay0/p;)V

    .line 53
    .line 54
    .line 55
    iput-object p1, v0, Lyy0/e1;->f:Lyy0/j;

    .line 56
    .line 57
    iput-object p2, v0, Lyy0/e1;->g:[Ljava/lang/Object;

    .line 58
    .line 59
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    invoke-virtual {v0, p0}, Lyy0/e1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lyy0/e1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lyy0/e1;->e:I

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
    move p1, v2

    .line 31
    iget-object v2, p0, Lyy0/e1;->f:Lyy0/j;

    .line 32
    .line 33
    iget-object v1, p0, Lyy0/e1;->g:[Ljava/lang/Object;

    .line 34
    .line 35
    const/4 v3, 0x0

    .line 36
    aget-object v3, v1, v3

    .line 37
    .line 38
    aget-object v4, v1, p1

    .line 39
    .line 40
    const/4 v5, 0x2

    .line 41
    aget-object v5, v1, v5

    .line 42
    .line 43
    iput p1, p0, Lyy0/e1;->e:I

    .line 44
    .line 45
    iget-object v1, p0, Lyy0/e1;->h:Lrx0/i;

    .line 46
    .line 47
    move-object v6, p0

    .line 48
    invoke-interface/range {v1 .. v6}, Lay0/q;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

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
    move-object v6, p0

    .line 59
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 60
    .line 61
    iget v0, v6, Lyy0/e1;->e:I

    .line 62
    .line 63
    const/4 v8, 0x2

    .line 64
    const/4 v1, 0x1

    .line 65
    if-eqz v0, :cond_5

    .line 66
    .line 67
    if-eq v0, v1, :cond_4

    .line 68
    .line 69
    if-ne v0, v8, :cond_3

    .line 70
    .line 71
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 76
    .line 77
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 78
    .line 79
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw p0

    .line 83
    :cond_4
    iget-object v0, v6, Lyy0/e1;->f:Lyy0/j;

    .line 84
    .line 85
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    iget-object v0, v6, Lyy0/e1;->f:Lyy0/j;

    .line 93
    .line 94
    iget-object p1, v6, Lyy0/e1;->g:[Ljava/lang/Object;

    .line 95
    .line 96
    const/4 v2, 0x0

    .line 97
    aget-object v2, p1, v2

    .line 98
    .line 99
    aget-object v3, p1, v1

    .line 100
    .line 101
    aget-object v4, p1, v8

    .line 102
    .line 103
    const/4 v5, 0x3

    .line 104
    aget-object v5, p1, v5

    .line 105
    .line 106
    const/4 v7, 0x4

    .line 107
    aget-object p1, p1, v7

    .line 108
    .line 109
    iput-object v0, v6, Lyy0/e1;->f:Lyy0/j;

    .line 110
    .line 111
    iput v1, v6, Lyy0/e1;->e:I

    .line 112
    .line 113
    iget-object v1, v6, Lyy0/e1;->h:Lrx0/i;

    .line 114
    .line 115
    move-object v7, v6

    .line 116
    move-object v6, p1

    .line 117
    invoke-interface/range {v1 .. v7}, Lay0/r;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    move-object v6, v7

    .line 122
    if-ne p1, p0, :cond_6

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_6
    :goto_2
    const/4 v1, 0x0

    .line 126
    iput-object v1, v6, Lyy0/e1;->f:Lyy0/j;

    .line 127
    .line 128
    iput v8, v6, Lyy0/e1;->e:I

    .line 129
    .line 130
    invoke-interface {v0, p1, v6}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    if-ne p1, p0, :cond_7

    .line 135
    .line 136
    goto :goto_4

    .line 137
    :cond_7
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 138
    .line 139
    :goto_4
    return-object p0

    .line 140
    :pswitch_1
    move-object v6, p0

    .line 141
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 142
    .line 143
    iget v0, v6, Lyy0/e1;->e:I

    .line 144
    .line 145
    const/4 v1, 0x2

    .line 146
    const/4 v2, 0x1

    .line 147
    if-eqz v0, :cond_a

    .line 148
    .line 149
    if-eq v0, v2, :cond_9

    .line 150
    .line 151
    if-ne v0, v1, :cond_8

    .line 152
    .line 153
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    goto :goto_6

    .line 157
    :cond_8
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
    :cond_9
    iget-object v0, v6, Lyy0/e1;->f:Lyy0/j;

    .line 166
    .line 167
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    goto :goto_5

    .line 171
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    iget-object v0, v6, Lyy0/e1;->f:Lyy0/j;

    .line 175
    .line 176
    iget-object p1, v6, Lyy0/e1;->g:[Ljava/lang/Object;

    .line 177
    .line 178
    const/4 v3, 0x0

    .line 179
    aget-object v3, p1, v3

    .line 180
    .line 181
    aget-object v4, p1, v2

    .line 182
    .line 183
    aget-object p1, p1, v1

    .line 184
    .line 185
    iput-object v0, v6, Lyy0/e1;->f:Lyy0/j;

    .line 186
    .line 187
    iput v2, v6, Lyy0/e1;->e:I

    .line 188
    .line 189
    iget-object v2, v6, Lyy0/e1;->h:Lrx0/i;

    .line 190
    .line 191
    invoke-interface {v2, v3, v4, p1, v6}, Lay0/p;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object p1

    .line 195
    if-ne p1, p0, :cond_b

    .line 196
    .line 197
    goto :goto_7

    .line 198
    :cond_b
    :goto_5
    const/4 v2, 0x0

    .line 199
    iput-object v2, v6, Lyy0/e1;->f:Lyy0/j;

    .line 200
    .line 201
    iput v1, v6, Lyy0/e1;->e:I

    .line 202
    .line 203
    invoke-interface {v0, p1, v6}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object p1

    .line 207
    if-ne p1, p0, :cond_c

    .line 208
    .line 209
    goto :goto_7

    .line 210
    :cond_c
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 211
    .line 212
    :goto_7
    return-object p0

    .line 213
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
