.class public final Lga0/w;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lga0/h0;


# direct methods
.method public synthetic constructor <init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lga0/w;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lga0/w;->h:Lga0/h0;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lga0/w;->d:I

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
    new-instance v0, Lga0/w;

    .line 11
    .line 12
    iget-object p0, p0, Lga0/w;->h:Lga0/h0;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-direct {v0, v1, p0, p3}, Lga0/w;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, v0, Lga0/w;->f:Lyy0/j;

    .line 19
    .line 20
    iput-object p2, v0, Lga0/w;->g:Ljava/lang/Object;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Lga0/w;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_0
    new-instance v0, Lga0/w;

    .line 30
    .line 31
    iget-object p0, p0, Lga0/w;->h:Lga0/h0;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-direct {v0, v1, p0, p3}, Lga0/w;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 35
    .line 36
    .line 37
    iput-object p1, v0, Lga0/w;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object p2, v0, Lga0/w;->g:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lga0/w;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Lga0/w;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lga0/w;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    if-eqz v1, :cond_2

    .line 14
    .line 15
    if-ne v1, v2, :cond_1

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    move-object v0, v3

    .line 21
    goto :goto_3

    .line 22
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iget-object p1, p0, Lga0/w;->f:Lyy0/j;

    .line 34
    .line 35
    iget-object v1, p0, Lga0/w;->g:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v1, Lbg0/c;

    .line 38
    .line 39
    iget-object v4, p0, Lga0/w;->h:Lga0/h0;

    .line 40
    .line 41
    iget-object v4, v4, Lga0/h0;->j:Lrt0/u;

    .line 42
    .line 43
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    check-cast v4, Lyy0/i;

    .line 48
    .line 49
    const/4 v5, 0x0

    .line 50
    iput-object v5, p0, Lga0/w;->f:Lyy0/j;

    .line 51
    .line 52
    iput-object v5, p0, Lga0/w;->g:Ljava/lang/Object;

    .line 53
    .line 54
    iput v2, p0, Lga0/w;->e:I

    .line 55
    .line 56
    invoke-static {p1}, Lyy0/u;->s(Lyy0/j;)V

    .line 57
    .line 58
    .line 59
    new-instance v2, Lai/k;

    .line 60
    .line 61
    const/16 v5, 0x14

    .line 62
    .line 63
    invoke-direct {v2, v5, p1, v1}, Lai/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    new-instance p1, Lcs0/s;

    .line 67
    .line 68
    const/16 v1, 0x14

    .line 69
    .line 70
    invoke-direct {p1, v2, v1}, Lcs0/s;-><init>(Lyy0/j;I)V

    .line 71
    .line 72
    .line 73
    invoke-interface {v4, p1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    if-ne p0, v0, :cond_3

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_3
    move-object p0, v3

    .line 81
    :goto_0
    if-ne p0, v0, :cond_4

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_4
    move-object p0, v3

    .line 85
    :goto_1
    if-ne p0, v0, :cond_5

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_5
    move-object p0, v3

    .line 89
    :goto_2
    if-ne p0, v0, :cond_0

    .line 90
    .line 91
    :goto_3
    return-object v0

    .line 92
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 93
    .line 94
    iget v1, p0, Lga0/w;->e:I

    .line 95
    .line 96
    const/4 v2, 0x1

    .line 97
    if-eqz v1, :cond_7

    .line 98
    .line 99
    if-ne v1, v2, :cond_6

    .line 100
    .line 101
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    goto :goto_5

    .line 105
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 106
    .line 107
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 108
    .line 109
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    throw p0

    .line 113
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    iget-object p1, p0, Lga0/w;->f:Lyy0/j;

    .line 117
    .line 118
    iget-object v1, p0, Lga0/w;->g:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast v1, Lne0/t;

    .line 121
    .line 122
    instance-of v3, v1, Lne0/e;

    .line 123
    .line 124
    if-eqz v3, :cond_8

    .line 125
    .line 126
    check-cast v1, Lne0/e;

    .line 127
    .line 128
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast v1, Lzb0/a;

    .line 131
    .line 132
    iget-object v1, p0, Lga0/w;->h:Lga0/h0;

    .line 133
    .line 134
    iget-object v1, v1, Lga0/h0;->k:Lrt0/j;

    .line 135
    .line 136
    new-instance v3, Lrt0/h;

    .line 137
    .line 138
    const/4 v4, 0x0

    .line 139
    invoke-direct {v3, v4}, Lrt0/h;-><init>(Z)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v1, v3}, Lrt0/j;->a(Lrt0/h;)Lzy0/j;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    goto :goto_4

    .line 147
    :cond_8
    instance-of v3, v1, Lne0/c;

    .line 148
    .line 149
    if-eqz v3, :cond_a

    .line 150
    .line 151
    new-instance v3, Lyy0/m;

    .line 152
    .line 153
    const/4 v4, 0x0

    .line 154
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 155
    .line 156
    .line 157
    move-object v1, v3

    .line 158
    :goto_4
    const/4 v3, 0x0

    .line 159
    iput-object v3, p0, Lga0/w;->f:Lyy0/j;

    .line 160
    .line 161
    iput-object v3, p0, Lga0/w;->g:Ljava/lang/Object;

    .line 162
    .line 163
    iput v2, p0, Lga0/w;->e:I

    .line 164
    .line 165
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    if-ne p0, v0, :cond_9

    .line 170
    .line 171
    goto :goto_6

    .line 172
    :cond_9
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 173
    .line 174
    :goto_6
    return-object v0

    .line 175
    :cond_a
    new-instance p0, La8/r0;

    .line 176
    .line 177
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 178
    .line 179
    .line 180
    throw p0

    .line 181
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
