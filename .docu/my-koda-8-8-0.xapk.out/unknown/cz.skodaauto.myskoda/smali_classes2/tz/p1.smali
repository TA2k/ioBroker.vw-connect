.class public final Ltz/p1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ltz/q1;


# direct methods
.method public synthetic constructor <init>(Ltz/q1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltz/p1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/p1;->f:Ltz/q1;

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
    iget p1, p0, Ltz/p1;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ltz/p1;

    .line 7
    .line 8
    iget-object p0, p0, Ltz/p1;->f:Ltz/q1;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ltz/p1;-><init>(Ltz/q1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ltz/p1;

    .line 16
    .line 17
    iget-object p0, p0, Ltz/p1;->f:Ltz/q1;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ltz/p1;-><init>(Ltz/q1;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ltz/p1;->d:I

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
    invoke-virtual {p0, p1, p2}, Ltz/p1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltz/p1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ltz/p1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ltz/p1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ltz/p1;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ltz/p1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 5

    .line 1
    iget v0, p0, Ltz/p1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ltz/p1;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Ltz/p1;->f:Ltz/q1;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v3, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, v2, Ltz/q1;->k:Lml0/e;

    .line 33
    .line 34
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    check-cast p1, Lyy0/i;

    .line 39
    .line 40
    const-string v1, "<this>"

    .line 41
    .line 42
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    new-instance v1, Lhg/q;

    .line 46
    .line 47
    const/16 v4, 0xf

    .line 48
    .line 49
    invoke-direct {v1, p1, v4}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 50
    .line 51
    .line 52
    new-instance p1, Lam0/i;

    .line 53
    .line 54
    const/16 v4, 0x12

    .line 55
    .line 56
    invoke-direct {p1, v1, v4}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 57
    .line 58
    .line 59
    iput v3, p0, Ltz/p1;->e:I

    .line 60
    .line 61
    invoke-static {p1, p0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    if-ne p1, v0, :cond_2

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_2
    :goto_0
    check-cast p1, Lxj0/f;

    .line 69
    .line 70
    if-eqz p1, :cond_3

    .line 71
    .line 72
    iget-object p0, v2, Ltz/q1;->l:Lwj0/x;

    .line 73
    .line 74
    new-instance v0, Lxj0/x;

    .line 75
    .line 76
    const v1, 0x417b3333    # 15.7f

    .line 77
    .line 78
    .line 79
    invoke-direct {v0, p1, v1}, Lxj0/x;-><init>(Lxj0/f;F)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0, v0}, Lwj0/x;->a(Lxj0/x;)V

    .line 83
    .line 84
    .line 85
    :cond_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    :goto_1
    return-object v0

    .line 88
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 89
    .line 90
    iget v1, p0, Ltz/p1;->e:I

    .line 91
    .line 92
    iget-object v2, p0, Ltz/p1;->f:Ltz/q1;

    .line 93
    .line 94
    const/4 v3, 0x1

    .line 95
    if-eqz v1, :cond_5

    .line 96
    .line 97
    if-ne v1, v3, :cond_4

    .line 98
    .line 99
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 104
    .line 105
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 106
    .line 107
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    throw p0

    .line 111
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    iget-object p1, v2, Ltz/q1;->j:Lrz/v;

    .line 115
    .line 116
    iput v3, p0, Ltz/p1;->e:I

    .line 117
    .line 118
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 119
    .line 120
    .line 121
    iget-object v1, p1, Lrz/v;->b:Lrz/a;

    .line 122
    .line 123
    check-cast v1, Liy/b;

    .line 124
    .line 125
    sget-object v4, Lly/b;->r:Lly/b;

    .line 126
    .line 127
    invoke-interface {v1, v4}, Ltl0/a;->a(Lul0/f;)V

    .line 128
    .line 129
    .line 130
    iget-object p1, p1, Lrz/v;->a:Lrz/f;

    .line 131
    .line 132
    check-cast p1, Lpz/a;

    .line 133
    .line 134
    iget-object p1, p1, Lpz/a;->b:Lyy0/k1;

    .line 135
    .line 136
    invoke-static {p1, p0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    if-ne p1, v0, :cond_6

    .line 141
    .line 142
    goto :goto_4

    .line 143
    :cond_6
    :goto_2
    check-cast p1, Lsz/c;

    .line 144
    .line 145
    if-nez p1, :cond_7

    .line 146
    .line 147
    iget-object p0, v2, Ltz/q1;->m:Ltr0/b;

    .line 148
    .line 149
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_7
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    check-cast p0, Ltz/o1;

    .line 158
    .line 159
    iget-object v0, p1, Lsz/c;->a:Ljava/lang/String;

    .line 160
    .line 161
    iget-object p1, p1, Lsz/c;->b:Lxj0/f;

    .line 162
    .line 163
    iget-object v1, v2, Ltz/q1;->h:Lrz/c;

    .line 164
    .line 165
    invoke-virtual {v1, v0}, Lrz/c;->a(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 166
    .line 167
    .line 168
    move-result-object v1

    .line 169
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 170
    .line 171
    .line 172
    move-result v1

    .line 173
    xor-int/2addr v1, v3

    .line 174
    const/16 v3, 0x8

    .line 175
    .line 176
    invoke-static {p0, v0, p1, v1, v3}, Ltz/o1;->a(Ltz/o1;Ljava/lang/String;Lxj0/f;ZI)Ltz/o1;

    .line 177
    .line 178
    .line 179
    move-result-object p0

    .line 180
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 181
    .line 182
    .line 183
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 184
    .line 185
    :goto_4
    return-object v0

    .line 186
    nop

    .line 187
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
