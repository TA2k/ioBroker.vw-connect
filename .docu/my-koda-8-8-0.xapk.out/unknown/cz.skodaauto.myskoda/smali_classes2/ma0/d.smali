.class public final Lma0/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lma0/g;


# direct methods
.method public synthetic constructor <init>(Lkotlin/coroutines/Continuation;Lma0/g;I)V
    .locals 0

    .line 1
    iput p3, p0, Lma0/d;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lma0/d;->h:Lma0/g;

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
    iget v0, p0, Lma0/d;->d:I

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
    new-instance v0, Lma0/d;

    .line 11
    .line 12
    iget-object p0, p0, Lma0/d;->h:Lma0/g;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-direct {v0, p3, p0, v1}, Lma0/d;-><init>(Lkotlin/coroutines/Continuation;Lma0/g;I)V

    .line 16
    .line 17
    .line 18
    iput-object p1, v0, Lma0/d;->f:Lyy0/j;

    .line 19
    .line 20
    iput-object p2, v0, Lma0/d;->g:Ljava/lang/Object;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Lma0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_0
    new-instance v0, Lma0/d;

    .line 30
    .line 31
    iget-object p0, p0, Lma0/d;->h:Lma0/g;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-direct {v0, p3, p0, v1}, Lma0/d;-><init>(Lkotlin/coroutines/Continuation;Lma0/g;I)V

    .line 35
    .line 36
    .line 37
    iput-object p1, v0, Lma0/d;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object p2, v0, Lma0/d;->g:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lma0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lma0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lma0/d;->e:I

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
    iget-object p1, p0, Lma0/d;->f:Lyy0/j;

    .line 31
    .line 32
    iget-object v1, p0, Lma0/d;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lne0/t;

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
    check-cast v1, Lss0/u;

    .line 45
    .line 46
    iget-object v3, p0, Lma0/d;->h:Lma0/g;

    .line 47
    .line 48
    iget-object v3, v3, Lma0/g;->j:Lka0/a;

    .line 49
    .line 50
    iget-object v1, v1, Lss0/u;->a:Ljava/lang/String;

    .line 51
    .line 52
    invoke-virtual {v3, v1}, Lka0/a;->a(Ljava/lang/String;)Lyy0/i;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    goto :goto_0

    .line 57
    :cond_2
    instance-of v3, v1, Lne0/c;

    .line 58
    .line 59
    if-eqz v3, :cond_4

    .line 60
    .line 61
    new-instance v3, Lyy0/m;

    .line 62
    .line 63
    const/4 v4, 0x0

    .line 64
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 65
    .line 66
    .line 67
    move-object v1, v3

    .line 68
    :goto_0
    const/4 v3, 0x0

    .line 69
    iput-object v3, p0, Lma0/d;->f:Lyy0/j;

    .line 70
    .line 71
    iput-object v3, p0, Lma0/d;->g:Ljava/lang/Object;

    .line 72
    .line 73
    iput v2, p0, Lma0/d;->e:I

    .line 74
    .line 75
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    if-ne p0, v0, :cond_3

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_3
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    :goto_2
    return-object v0

    .line 85
    :cond_4
    new-instance p0, La8/r0;

    .line 86
    .line 87
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 88
    .line 89
    .line 90
    throw p0

    .line 91
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 92
    .line 93
    iget v1, p0, Lma0/d;->e:I

    .line 94
    .line 95
    const/4 v2, 0x1

    .line 96
    if-eqz v1, :cond_6

    .line 97
    .line 98
    if-ne v1, v2, :cond_5

    .line 99
    .line 100
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    goto :goto_4

    .line 104
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 105
    .line 106
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 107
    .line 108
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    iget-object p1, p0, Lma0/d;->f:Lyy0/j;

    .line 116
    .line 117
    iget-object v1, p0, Lma0/d;->g:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast v1, Lne0/t;

    .line 120
    .line 121
    instance-of v3, v1, Lne0/e;

    .line 122
    .line 123
    if-eqz v3, :cond_7

    .line 124
    .line 125
    check-cast v1, Lne0/e;

    .line 126
    .line 127
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v1, Lss0/u;

    .line 130
    .line 131
    iget-object v3, p0, Lma0/d;->h:Lma0/g;

    .line 132
    .line 133
    iget-object v3, v3, Lma0/g;->k:Lka0/c;

    .line 134
    .line 135
    iget-object v1, v1, Lss0/u;->a:Ljava/lang/String;

    .line 136
    .line 137
    invoke-virtual {v3, v1}, Lka0/c;->a(Ljava/lang/String;)Lyy0/i;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    goto :goto_3

    .line 142
    :cond_7
    instance-of v3, v1, Lne0/c;

    .line 143
    .line 144
    if-eqz v3, :cond_9

    .line 145
    .line 146
    new-instance v3, Lyy0/m;

    .line 147
    .line 148
    const/4 v4, 0x0

    .line 149
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 150
    .line 151
    .line 152
    move-object v1, v3

    .line 153
    :goto_3
    const/4 v3, 0x0

    .line 154
    iput-object v3, p0, Lma0/d;->f:Lyy0/j;

    .line 155
    .line 156
    iput-object v3, p0, Lma0/d;->g:Ljava/lang/Object;

    .line 157
    .line 158
    iput v2, p0, Lma0/d;->e:I

    .line 159
    .line 160
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    if-ne p0, v0, :cond_8

    .line 165
    .line 166
    goto :goto_5

    .line 167
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 168
    .line 169
    :goto_5
    return-object v0

    .line 170
    :cond_9
    new-instance p0, La8/r0;

    .line 171
    .line 172
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 173
    .line 174
    .line 175
    throw p0

    .line 176
    nop

    .line 177
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
