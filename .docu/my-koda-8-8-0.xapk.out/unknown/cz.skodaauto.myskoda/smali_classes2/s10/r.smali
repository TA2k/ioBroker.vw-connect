.class public final Ls10/r;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ls10/s;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;Ls10/s;)V
    .locals 0

    .line 1
    iput p1, p0, Ls10/r;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Ls10/r;->h:Ls10/s;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ls10/r;->d:I

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
    new-instance v0, Ls10/r;

    .line 11
    .line 12
    iget-object p0, p0, Ls10/r;->h:Ls10/s;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-direct {v0, v1, p3, p0}, Ls10/r;-><init>(ILkotlin/coroutines/Continuation;Ls10/s;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, v0, Ls10/r;->f:Lyy0/j;

    .line 19
    .line 20
    iput-object p2, v0, Ls10/r;->g:Ljava/lang/Object;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Ls10/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_0
    new-instance v0, Ls10/r;

    .line 30
    .line 31
    iget-object p0, p0, Ls10/r;->h:Ls10/s;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-direct {v0, v1, p3, p0}, Ls10/r;-><init>(ILkotlin/coroutines/Continuation;Ls10/s;)V

    .line 35
    .line 36
    .line 37
    iput-object p1, v0, Ls10/r;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object p2, v0, Ls10/r;->g:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Ls10/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 5

    .line 1
    iget v0, p0, Ls10/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ls10/r;->e:I

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
    goto :goto_1

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
    iget-object p1, p0, Ls10/r;->f:Lyy0/j;

    .line 31
    .line 32
    iget-object v1, p0, Ls10/r;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lne0/s;

    .line 35
    .line 36
    instance-of v3, v1, Lne0/e;

    .line 37
    .line 38
    if-eqz v3, :cond_2

    .line 39
    .line 40
    check-cast v1, Lne0/e;

    .line 41
    .line 42
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v1, Lss0/b;

    .line 45
    .line 46
    iget-object v1, p0, Ls10/r;->h:Ls10/s;

    .line 47
    .line 48
    iget-object v1, v1, Ls10/s;->h:Lq10/l;

    .line 49
    .line 50
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    check-cast v1, Lyy0/i;

    .line 55
    .line 56
    invoke-static {v1}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    goto :goto_0

    .line 61
    :cond_2
    instance-of v3, v1, Lne0/c;

    .line 62
    .line 63
    if-eqz v3, :cond_3

    .line 64
    .line 65
    new-instance v3, Lyy0/m;

    .line 66
    .line 67
    const/4 v4, 0x0

    .line 68
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 69
    .line 70
    .line 71
    move-object v1, v3

    .line 72
    goto :goto_0

    .line 73
    :cond_3
    instance-of v1, v1, Lne0/d;

    .line 74
    .line 75
    if-eqz v1, :cond_5

    .line 76
    .line 77
    new-instance v1, Lyy0/m;

    .line 78
    .line 79
    const/4 v3, 0x0

    .line 80
    sget-object v4, Lne0/d;->a:Lne0/d;

    .line 81
    .line 82
    invoke-direct {v1, v4, v3}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 83
    .line 84
    .line 85
    :goto_0
    const/4 v3, 0x0

    .line 86
    iput-object v3, p0, Ls10/r;->f:Lyy0/j;

    .line 87
    .line 88
    iput-object v3, p0, Ls10/r;->g:Ljava/lang/Object;

    .line 89
    .line 90
    iput v2, p0, Ls10/r;->e:I

    .line 91
    .line 92
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    if-ne p0, v0, :cond_4

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_4
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    :goto_2
    return-object v0

    .line 102
    :cond_5
    new-instance p0, La8/r0;

    .line 103
    .line 104
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 105
    .line 106
    .line 107
    throw p0

    .line 108
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 109
    .line 110
    iget v1, p0, Ls10/r;->e:I

    .line 111
    .line 112
    const/4 v2, 0x1

    .line 113
    if-eqz v1, :cond_7

    .line 114
    .line 115
    if-ne v1, v2, :cond_6

    .line 116
    .line 117
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_6
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
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    iget-object p1, p0, Ls10/r;->f:Lyy0/j;

    .line 133
    .line 134
    iget-object v1, p0, Ls10/r;->g:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v1, Lne0/t;

    .line 137
    .line 138
    iget-object v1, p0, Ls10/r;->h:Ls10/s;

    .line 139
    .line 140
    iget-object v1, v1, Ls10/s;->j:Lq10/c;

    .line 141
    .line 142
    new-instance v3, Lq10/b;

    .line 143
    .line 144
    const/4 v4, 0x0

    .line 145
    invoke-direct {v3, v4}, Lq10/b;-><init>(Z)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v1, v3}, Lq10/c;->a(Lq10/b;)Lzy0/j;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    const/4 v3, 0x0

    .line 153
    iput-object v3, p0, Ls10/r;->f:Lyy0/j;

    .line 154
    .line 155
    iput-object v3, p0, Ls10/r;->g:Ljava/lang/Object;

    .line 156
    .line 157
    iput v2, p0, Ls10/r;->e:I

    .line 158
    .line 159
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    if-ne p0, v0, :cond_8

    .line 164
    .line 165
    goto :goto_4

    .line 166
    :cond_8
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 167
    .line 168
    :goto_4
    return-object v0

    .line 169
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
