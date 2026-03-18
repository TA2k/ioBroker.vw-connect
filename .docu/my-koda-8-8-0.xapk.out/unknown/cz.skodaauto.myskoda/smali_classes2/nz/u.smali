.class public final Lnz/u;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lnz/z;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;Lnz/z;)V
    .locals 0

    .line 1
    iput p1, p0, Lnz/u;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lnz/u;->h:Lnz/z;

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
    iget v0, p0, Lnz/u;->d:I

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
    new-instance v0, Lnz/u;

    .line 11
    .line 12
    iget-object p0, p0, Lnz/u;->h:Lnz/z;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-direct {v0, v1, p3, p0}, Lnz/u;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, v0, Lnz/u;->f:Lyy0/j;

    .line 19
    .line 20
    iput-object p2, v0, Lnz/u;->g:Ljava/lang/Object;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Lnz/u;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_0
    new-instance v0, Lnz/u;

    .line 30
    .line 31
    iget-object p0, p0, Lnz/u;->h:Lnz/z;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-direct {v0, v1, p3, p0}, Lnz/u;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 35
    .line 36
    .line 37
    iput-object p1, v0, Lnz/u;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object p2, v0, Lnz/u;->g:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lnz/u;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lnz/u;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lnz/u;->e:I

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
    iget-object p1, p0, Lnz/u;->f:Lyy0/j;

    .line 31
    .line 32
    iget-object v1, p0, Lnz/u;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lne0/t;

    .line 35
    .line 36
    instance-of v3, v1, Lne0/e;

    .line 37
    .line 38
    const/4 v4, 0x0

    .line 39
    if-eqz v3, :cond_2

    .line 40
    .line 41
    check-cast v1, Lne0/e;

    .line 42
    .line 43
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v1, Lmz/f;

    .line 46
    .line 47
    iget-object v3, p0, Lnz/u;->h:Lnz/z;

    .line 48
    .line 49
    iget-object v3, v3, Lnz/z;->q:Lyn0/h;

    .line 50
    .line 51
    iget-object v1, v1, Lmz/f;->g:Ljava/util/List;

    .line 52
    .line 53
    check-cast v1, Ljava/util/List;

    .line 54
    .line 55
    const-string v5, "<this>"

    .line 56
    .line 57
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    new-instance v5, Lh7/z;

    .line 61
    .line 62
    check-cast v1, Ljava/util/List;

    .line 63
    .line 64
    invoke-direct {v5, v3, v1, v4}, Lh7/z;-><init>(Ltr0/c;Ljava/util/List;Lkotlin/coroutines/Continuation;)V

    .line 65
    .line 66
    .line 67
    new-instance v1, Lyy0/m1;

    .line 68
    .line 69
    invoke-direct {v1, v5}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_2
    instance-of v3, v1, Lne0/c;

    .line 74
    .line 75
    if-eqz v3, :cond_4

    .line 76
    .line 77
    new-instance v3, Lyy0/m;

    .line 78
    .line 79
    const/4 v5, 0x0

    .line 80
    invoke-direct {v3, v1, v5}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 81
    .line 82
    .line 83
    move-object v1, v3

    .line 84
    :goto_0
    iput-object v4, p0, Lnz/u;->f:Lyy0/j;

    .line 85
    .line 86
    iput-object v4, p0, Lnz/u;->g:Ljava/lang/Object;

    .line 87
    .line 88
    iput v2, p0, Lnz/u;->e:I

    .line 89
    .line 90
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    if-ne p0, v0, :cond_3

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_3
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 98
    .line 99
    :goto_2
    return-object v0

    .line 100
    :cond_4
    new-instance p0, La8/r0;

    .line 101
    .line 102
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 103
    .line 104
    .line 105
    throw p0

    .line 106
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 107
    .line 108
    iget v1, p0, Lnz/u;->e:I

    .line 109
    .line 110
    const/4 v2, 0x1

    .line 111
    if-eqz v1, :cond_6

    .line 112
    .line 113
    if-ne v1, v2, :cond_5

    .line 114
    .line 115
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    goto :goto_3

    .line 119
    :cond_5
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
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    iget-object p1, p0, Lnz/u;->f:Lyy0/j;

    .line 131
    .line 132
    iget-object v1, p0, Lnz/u;->g:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast v1, Lne0/t;

    .line 135
    .line 136
    iget-object v1, p0, Lnz/u;->h:Lnz/z;

    .line 137
    .line 138
    iget-object v1, v1, Lnz/z;->l:Llz/e;

    .line 139
    .line 140
    new-instance v3, Llz/b;

    .line 141
    .line 142
    const/4 v4, 0x0

    .line 143
    invoke-direct {v3, v4}, Llz/b;-><init>(Z)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v1, v3}, Llz/e;->a(Llz/b;)Lzy0/j;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    const/4 v3, 0x0

    .line 151
    iput-object v3, p0, Lnz/u;->f:Lyy0/j;

    .line 152
    .line 153
    iput-object v3, p0, Lnz/u;->g:Ljava/lang/Object;

    .line 154
    .line 155
    iput v2, p0, Lnz/u;->e:I

    .line 156
    .line 157
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    if-ne p0, v0, :cond_7

    .line 162
    .line 163
    goto :goto_4

    .line 164
    :cond_7
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 165
    .line 166
    :goto_4
    return-object v0

    .line 167
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
