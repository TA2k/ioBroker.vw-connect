.class public final Lok0/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lok0/d;


# direct methods
.method public synthetic constructor <init>(Lkotlin/coroutines/Continuation;Lok0/d;I)V
    .locals 0

    .line 1
    iput p3, p0, Lok0/b;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lok0/b;->h:Lok0/d;

    .line 4
    .line 5
    const/4 p2, 0x3

    .line 6
    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lok0/b;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    new-instance v0, Lok0/b;

    .line 11
    .line 12
    iget-object p0, p0, Lok0/b;->h:Lok0/d;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-direct {v0, p3, p0, v1}, Lok0/b;-><init>(Lkotlin/coroutines/Continuation;Lok0/d;I)V

    .line 16
    .line 17
    .line 18
    iput-object p1, v0, Lok0/b;->f:Lyy0/j;

    .line 19
    .line 20
    iput-object p2, v0, Lok0/b;->g:Ljava/lang/Object;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Lok0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_0
    new-instance v0, Lok0/b;

    .line 30
    .line 31
    iget-object p0, p0, Lok0/b;->h:Lok0/d;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-direct {v0, p3, p0, v1}, Lok0/b;-><init>(Lkotlin/coroutines/Continuation;Lok0/d;I)V

    .line 35
    .line 36
    .line 37
    iput-object p1, v0, Lok0/b;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object p2, v0, Lok0/b;->g:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lok0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lok0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lok0/b;->e:I

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
    goto :goto_3

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
    iget-object p1, p0, Lok0/b;->f:Lyy0/j;

    .line 31
    .line 32
    iget-object v1, p0, Lok0/b;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lgg0/b;

    .line 35
    .line 36
    const/4 v3, -0x1

    .line 37
    if-nez v1, :cond_2

    .line 38
    .line 39
    move v1, v3

    .line 40
    goto :goto_0

    .line 41
    :cond_2
    sget-object v4, Lok0/a;->a:[I

    .line 42
    .line 43
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    aget v1, v4, v1

    .line 48
    .line 49
    :goto_0
    if-eq v1, v3, :cond_5

    .line 50
    .line 51
    if-eq v1, v2, :cond_4

    .line 52
    .line 53
    const/4 v3, 0x2

    .line 54
    if-ne v1, v3, :cond_3

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    new-instance p0, La8/r0;

    .line 58
    .line 59
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 60
    .line 61
    .line 62
    throw p0

    .line 63
    :cond_4
    iget-object v1, p0, Lok0/b;->h:Lok0/d;

    .line 64
    .line 65
    iget-object v1, v1, Lok0/d;->a:Lfg0/d;

    .line 66
    .line 67
    invoke-virtual {v1}, Lfg0/d;->invoke()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    check-cast v1, Lyy0/i;

    .line 72
    .line 73
    new-instance v3, Lhg/q;

    .line 74
    .line 75
    const/16 v4, 0x14

    .line 76
    .line 77
    invoke-direct {v3, v1, v4}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 78
    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_5
    :goto_1
    sget-object v1, Lpk0/a;->g:Lpk0/a;

    .line 82
    .line 83
    new-instance v3, Lyy0/m;

    .line 84
    .line 85
    const/4 v4, 0x0

    .line 86
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 87
    .line 88
    .line 89
    :goto_2
    const/4 v1, 0x0

    .line 90
    iput-object v1, p0, Lok0/b;->f:Lyy0/j;

    .line 91
    .line 92
    iput-object v1, p0, Lok0/b;->g:Ljava/lang/Object;

    .line 93
    .line 94
    iput v2, p0, Lok0/b;->e:I

    .line 95
    .line 96
    invoke-static {p1, v3, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    if-ne p0, v0, :cond_6

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_6
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    :goto_4
    return-object v0

    .line 106
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 107
    .line 108
    iget v1, p0, Lok0/b;->e:I

    .line 109
    .line 110
    const/4 v2, 0x1

    .line 111
    if-eqz v1, :cond_8

    .line 112
    .line 113
    if-ne v1, v2, :cond_7

    .line 114
    .line 115
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    goto :goto_6

    .line 119
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 120
    .line 121
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 122
    .line 123
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    throw p0

    .line 127
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    iget-object p1, p0, Lok0/b;->f:Lyy0/j;

    .line 131
    .line 132
    iget-object v1, p0, Lok0/b;->g:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast v1, Lun0/b;

    .line 135
    .line 136
    iget-boolean v1, v1, Lun0/b;->b:Z

    .line 137
    .line 138
    const/4 v3, 0x0

    .line 139
    if-eqz v1, :cond_9

    .line 140
    .line 141
    iget-object v1, p0, Lok0/b;->h:Lok0/d;

    .line 142
    .line 143
    iget-object v4, v1, Lok0/d;->b:Lfg0/c;

    .line 144
    .line 145
    invoke-virtual {v4}, Lfg0/c;->invoke()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v4

    .line 149
    check-cast v4, Lyy0/i;

    .line 150
    .line 151
    new-instance v5, Lok0/b;

    .line 152
    .line 153
    const/4 v6, 0x1

    .line 154
    invoke-direct {v5, v3, v1, v6}, Lok0/b;-><init>(Lkotlin/coroutines/Continuation;Lok0/d;I)V

    .line 155
    .line 156
    .line 157
    invoke-static {v4, v5}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    goto :goto_5

    .line 162
    :cond_9
    sget-object v1, Lpk0/a;->h:Lpk0/a;

    .line 163
    .line 164
    new-instance v4, Lyy0/m;

    .line 165
    .line 166
    const/4 v5, 0x0

    .line 167
    invoke-direct {v4, v1, v5}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 168
    .line 169
    .line 170
    move-object v1, v4

    .line 171
    :goto_5
    iput-object v3, p0, Lok0/b;->f:Lyy0/j;

    .line 172
    .line 173
    iput-object v3, p0, Lok0/b;->g:Ljava/lang/Object;

    .line 174
    .line 175
    iput v2, p0, Lok0/b;->e:I

    .line 176
    .line 177
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    if-ne p0, v0, :cond_a

    .line 182
    .line 183
    goto :goto_7

    .line 184
    :cond_a
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 185
    .line 186
    :goto_7
    return-object v0

    .line 187
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
