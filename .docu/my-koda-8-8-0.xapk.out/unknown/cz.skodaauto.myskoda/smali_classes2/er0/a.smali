.class public final Ler0/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Lne0/s;

.field public final synthetic h:Lss0/e;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lss0/e;Lay0/n;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Ler0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ler0/a;->h:Lss0/e;

    .line 4
    .line 5
    iput-object p2, p0, Ler0/a;->i:Ljava/lang/Object;

    .line 6
    .line 7
    const/4 p1, 0x3

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Ler0/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p2, Lne0/s;

    .line 6
    .line 7
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance v0, Ler0/a;

    .line 13
    .line 14
    iget-object v1, p0, Ler0/a;->i:Ljava/lang/Object;

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    iget-object p0, p0, Ler0/a;->h:Lss0/e;

    .line 18
    .line 19
    invoke-direct {v0, p0, v1, p3, v2}, Ler0/a;-><init>(Lss0/e;Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    iput-object p1, v0, Ler0/a;->f:Lyy0/j;

    .line 23
    .line 24
    iput-object p2, v0, Ler0/a;->g:Lne0/s;

    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    invoke-virtual {v0, p0}, Ler0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_0
    new-instance v0, Ler0/a;

    .line 34
    .line 35
    iget-object v1, p0, Ler0/a;->i:Ljava/lang/Object;

    .line 36
    .line 37
    const/4 v2, 0x0

    .line 38
    iget-object p0, p0, Ler0/a;->h:Lss0/e;

    .line 39
    .line 40
    invoke-direct {v0, p0, v1, p3, v2}, Ler0/a;-><init>(Lss0/e;Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 41
    .line 42
    .line 43
    iput-object p1, v0, Ler0/a;->f:Lyy0/j;

    .line 44
    .line 45
    iput-object p2, v0, Ler0/a;->g:Lne0/s;

    .line 46
    .line 47
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    invoke-virtual {v0, p0}, Ler0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Ler0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ler0/a;->f:Lyy0/j;

    .line 7
    .line 8
    iget-object v1, p0, Ler0/a;->g:Lne0/s;

    .line 9
    .line 10
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v3, p0, Ler0/a;->e:I

    .line 13
    .line 14
    const/4 v4, 0x2

    .line 15
    const/4 v5, 0x1

    .line 16
    if-eqz v3, :cond_2

    .line 17
    .line 18
    if-eq v3, v5, :cond_1

    .line 19
    .line 20
    if-ne v3, v4, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    :goto_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    instance-of p1, v1, Lne0/e;

    .line 39
    .line 40
    const/4 v3, 0x0

    .line 41
    if-eqz p1, :cond_3

    .line 42
    .line 43
    move-object p1, v1

    .line 44
    check-cast p1, Lne0/e;

    .line 45
    .line 46
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 47
    .line 48
    move-object v6, p1

    .line 49
    check-cast v6, Lss0/b;

    .line 50
    .line 51
    const-string v7, "<this>"

    .line 52
    .line 53
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    const-string v7, "id"

    .line 57
    .line 58
    iget-object v8, p0, Ler0/a;->h:Lss0/e;

    .line 59
    .line 60
    invoke-static {v8, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-static {v6, v8}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 64
    .line 65
    .line 66
    move-result-object v6

    .line 67
    invoke-static {v6}, Llp/tf;->d(Llf0/i;)Z

    .line 68
    .line 69
    .line 70
    move-result v6

    .line 71
    if-eqz v6, :cond_3

    .line 72
    .line 73
    iput-object v3, p0, Ler0/a;->f:Lyy0/j;

    .line 74
    .line 75
    iput-object v3, p0, Ler0/a;->g:Lne0/s;

    .line 76
    .line 77
    iput v5, p0, Ler0/a;->e:I

    .line 78
    .line 79
    iget-object v0, p0, Ler0/a;->i:Ljava/lang/Object;

    .line 80
    .line 81
    invoke-interface {v0, p1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    if-ne p0, v2, :cond_4

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_3
    iput-object v3, p0, Ler0/a;->f:Lyy0/j;

    .line 89
    .line 90
    iput-object v3, p0, Ler0/a;->g:Lne0/s;

    .line 91
    .line 92
    iput v4, p0, Ler0/a;->e:I

    .line 93
    .line 94
    invoke-interface {v0, v1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    if-ne p0, v2, :cond_4

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_4
    :goto_1
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    :goto_2
    return-object v2

    .line 104
    :pswitch_0
    iget-object v0, p0, Ler0/a;->f:Lyy0/j;

    .line 105
    .line 106
    iget-object v1, p0, Ler0/a;->g:Lne0/s;

    .line 107
    .line 108
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 109
    .line 110
    iget v3, p0, Ler0/a;->e:I

    .line 111
    .line 112
    const/4 v4, 0x2

    .line 113
    const/4 v5, 0x1

    .line 114
    if-eqz v3, :cond_7

    .line 115
    .line 116
    if-eq v3, v5, :cond_6

    .line 117
    .line 118
    if-ne v3, v4, :cond_5

    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 122
    .line 123
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 124
    .line 125
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    throw p0

    .line 129
    :cond_6
    :goto_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    instance-of p1, v1, Lne0/e;

    .line 137
    .line 138
    const/4 v3, 0x0

    .line 139
    if-eqz p1, :cond_8

    .line 140
    .line 141
    move-object p1, v1

    .line 142
    check-cast p1, Lne0/e;

    .line 143
    .line 144
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 145
    .line 146
    move-object v6, p1

    .line 147
    check-cast v6, Lss0/b;

    .line 148
    .line 149
    const-string v7, "<this>"

    .line 150
    .line 151
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    const-string v7, "id"

    .line 155
    .line 156
    iget-object v8, p0, Ler0/a;->h:Lss0/e;

    .line 157
    .line 158
    invoke-static {v8, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    invoke-static {v6, v8}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 162
    .line 163
    .line 164
    move-result-object v6

    .line 165
    sget-object v7, Llf0/i;->h:Llf0/i;

    .line 166
    .line 167
    if-ne v6, v7, :cond_8

    .line 168
    .line 169
    iput-object v3, p0, Ler0/a;->f:Lyy0/j;

    .line 170
    .line 171
    iput-object v3, p0, Ler0/a;->g:Lne0/s;

    .line 172
    .line 173
    iput v5, p0, Ler0/a;->e:I

    .line 174
    .line 175
    iget-object v0, p0, Ler0/a;->i:Ljava/lang/Object;

    .line 176
    .line 177
    invoke-interface {v0, p1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    if-ne p0, v2, :cond_9

    .line 182
    .line 183
    goto :goto_5

    .line 184
    :cond_8
    iput-object v3, p0, Ler0/a;->f:Lyy0/j;

    .line 185
    .line 186
    iput-object v3, p0, Ler0/a;->g:Lne0/s;

    .line 187
    .line 188
    iput v4, p0, Ler0/a;->e:I

    .line 189
    .line 190
    invoke-interface {v0, v1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    if-ne p0, v2, :cond_9

    .line 195
    .line 196
    goto :goto_5

    .line 197
    :cond_9
    :goto_4
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 198
    .line 199
    :goto_5
    return-object v2

    .line 200
    nop

    .line 201
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
