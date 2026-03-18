.class public final Lm80/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lm80/h;


# direct methods
.method public synthetic constructor <init>(Lm80/h;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lm80/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm80/f;->f:Lm80/h;

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
    iget p1, p0, Lm80/f;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lm80/f;

    .line 7
    .line 8
    iget-object p0, p0, Lm80/f;->f:Lm80/h;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lm80/f;-><init>(Lm80/h;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lm80/f;

    .line 16
    .line 17
    iget-object p0, p0, Lm80/f;->f:Lm80/h;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lm80/f;-><init>(Lm80/h;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lm80/f;->d:I

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
    invoke-virtual {p0, p1, p2}, Lm80/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lm80/f;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lm80/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lm80/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lm80/f;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lm80/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 9

    .line 1
    iget v0, p0, Lm80/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lm80/f;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Lm80/f;->f:Lm80/h;

    .line 11
    .line 12
    const/4 v3, 0x2

    .line 13
    const/4 v4, 0x1

    .line 14
    if-eqz v1, :cond_2

    .line 15
    .line 16
    if-eq v1, v4, :cond_1

    .line 17
    .line 18
    if-ne v1, v3, :cond_0

    .line 19
    .line 20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iget-object p1, v2, Lm80/h;->i:Lk80/g;

    .line 40
    .line 41
    iput v4, p0, Lm80/f;->e:I

    .line 42
    .line 43
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    iget-object v1, p1, Lk80/g;->a:Lkf0/b0;

    .line 47
    .line 48
    invoke-virtual {v1}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    check-cast v1, Lyy0/i;

    .line 53
    .line 54
    new-instance v4, Lk31/t;

    .line 55
    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v6, 0x7

    .line 58
    invoke-direct {v4, p1, v5, v6}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 59
    .line 60
    .line 61
    invoke-static {v4, v1}, Lyy0/u;->x(Lay0/n;Lyy0/i;)Lyy0/m;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    new-instance v4, Lac/l;

    .line 66
    .line 67
    const/16 v5, 0x15

    .line 68
    .line 69
    invoke-direct {v4, v5, v1, p1}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    if-ne v4, v0, :cond_3

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_3
    move-object p1, v4

    .line 76
    :goto_0
    check-cast p1, Lyy0/i;

    .line 77
    .line 78
    new-instance v1, Lgt0/c;

    .line 79
    .line 80
    const/16 v4, 0x1d

    .line 81
    .line 82
    invoke-direct {v1, v2, v4}, Lgt0/c;-><init>(Ljava/lang/Object;I)V

    .line 83
    .line 84
    .line 85
    iput v3, p0, Lm80/f;->e:I

    .line 86
    .line 87
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    if-ne p0, v0, :cond_4

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_4
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    :goto_2
    return-object v0

    .line 97
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 98
    .line 99
    iget v1, p0, Lm80/f;->e:I

    .line 100
    .line 101
    iget-object v2, p0, Lm80/f;->f:Lm80/h;

    .line 102
    .line 103
    const/4 v3, 0x1

    .line 104
    if-eqz v1, :cond_6

    .line 105
    .line 106
    if-ne v1, v3, :cond_5

    .line 107
    .line 108
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 113
    .line 114
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 115
    .line 116
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    throw p0

    .line 120
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    iget-object p1, v2, Lm80/h;->h:Lkf0/k;

    .line 124
    .line 125
    iput v3, p0, Lm80/f;->e:I

    .line 126
    .line 127
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    invoke-virtual {p1, p0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    if-ne p1, v0, :cond_7

    .line 135
    .line 136
    goto :goto_4

    .line 137
    :cond_7
    :goto_3
    check-cast p1, Lss0/b;

    .line 138
    .line 139
    sget-object p0, Lss0/e;->y:Lss0/e;

    .line 140
    .line 141
    invoke-static {p1, p0}, Lkp/u6;->d(Lss0/b;Lss0/e;)Ler0/g;

    .line 142
    .line 143
    .line 144
    move-result-object v6

    .line 145
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    move-object v3, p0

    .line 150
    check-cast v3, Lm80/g;

    .line 151
    .line 152
    const/4 v7, 0x0

    .line 153
    const/16 v8, 0xa

    .line 154
    .line 155
    const/4 v4, 0x0

    .line 156
    const/4 v5, 0x0

    .line 157
    invoke-static/range {v3 .. v8}, Lm80/g;->a(Lm80/g;ZZLer0/g;Lql0/g;I)Lm80/g;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 162
    .line 163
    .line 164
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
