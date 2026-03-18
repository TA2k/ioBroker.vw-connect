.class public final Lig/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lig/i;


# direct methods
.method public synthetic constructor <init>(Lig/i;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lig/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lig/g;->f:Lig/i;

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
    iget p1, p0, Lig/g;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lig/g;

    .line 7
    .line 8
    iget-object p0, p0, Lig/g;->f:Lig/i;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lig/g;-><init>(Lig/i;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lig/g;

    .line 16
    .line 17
    iget-object p0, p0, Lig/g;->f:Lig/i;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lig/g;-><init>(Lig/i;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lig/g;->d:I

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
    invoke-virtual {p0, p1, p2}, Lig/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lig/g;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lig/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lig/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Lig/g;

    .line 29
    .line 30
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Lig/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lig/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lig/g;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Lig/g;->f:Lig/i;

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
    if-eq v1, v3, :cond_0

    .line 19
    .line 20
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 21
    .line 22
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 23
    .line 24
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    goto :goto_2

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
    iget-object p1, v2, Lig/i;->e:Lbq0/i;

    .line 40
    .line 41
    iput v4, p0, Lig/g;->e:I

    .line 42
    .line 43
    invoke-virtual {p1, p0}, Lbq0/i;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    if-ne p1, v0, :cond_3

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_3
    :goto_0
    check-cast p1, Lyy0/a2;

    .line 51
    .line 52
    new-instance v1, Lgt0/c;

    .line 53
    .line 54
    const/16 v4, 0x11

    .line 55
    .line 56
    invoke-direct {v1, v2, v4}, Lgt0/c;-><init>(Ljava/lang/Object;I)V

    .line 57
    .line 58
    .line 59
    iput v3, p0, Lig/g;->e:I

    .line 60
    .line 61
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    if-ne p0, v0, :cond_4

    .line 66
    .line 67
    :goto_1
    return-object v0

    .line 68
    :cond_4
    :goto_2
    new-instance p0, La8/r0;

    .line 69
    .line 70
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 71
    .line 72
    .line 73
    throw p0

    .line 74
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 75
    .line 76
    iget v1, p0, Lig/g;->e:I

    .line 77
    .line 78
    iget-object v2, p0, Lig/g;->f:Lig/i;

    .line 79
    .line 80
    const/4 v3, 0x1

    .line 81
    if-eqz v1, :cond_6

    .line 82
    .line 83
    if-ne v1, v3, :cond_5

    .line 84
    .line 85
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    goto :goto_3

    .line 89
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 90
    .line 91
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 92
    .line 93
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    iget-object p1, v2, Lig/i;->f:Lif0/d0;

    .line 101
    .line 102
    iget-object v1, v2, Lig/i;->d:Ljava/lang/String;

    .line 103
    .line 104
    iput v3, p0, Lig/g;->e:I

    .line 105
    .line 106
    invoke-virtual {p1, v1, p0}, Lif0/d0;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    if-ne p1, v0, :cond_7

    .line 111
    .line 112
    goto :goto_4

    .line 113
    :cond_7
    :goto_3
    check-cast p1, Llx0/o;

    .line 114
    .line 115
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 116
    .line 117
    instance-of p1, p0, Llx0/n;

    .line 118
    .line 119
    if-nez p1, :cond_8

    .line 120
    .line 121
    move-object p1, p0

    .line 122
    check-cast p1, Llx0/b0;

    .line 123
    .line 124
    :cond_8
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    if-eqz p0, :cond_a

    .line 129
    .line 130
    iget-object p1, v2, Lig/i;->i:Lyy0/c2;

    .line 131
    .line 132
    :cond_9
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    move-object v1, v0

    .line 137
    check-cast v1, Lig/f;

    .line 138
    .line 139
    invoke-static {p0}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    const/4 v3, 0x0

    .line 144
    const/16 v4, 0x3b

    .line 145
    .line 146
    const/4 v5, 0x0

    .line 147
    invoke-static {v1, v5, v2, v3, v4}, Lig/f;->a(Lig/f;Lig/a;Llc/l;ZI)Lig/f;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    invoke-virtual {p1, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    if-eqz v0, :cond_9

    .line 156
    .line 157
    :cond_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 158
    .line 159
    :goto_4
    return-object v0

    .line 160
    nop

    .line 161
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
