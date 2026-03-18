.class public final Le30/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Le30/j;


# direct methods
.method public synthetic constructor <init>(Le30/j;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Le30/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le30/e;->f:Le30/j;

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
    iget p1, p0, Le30/e;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Le30/e;

    .line 7
    .line 8
    iget-object p0, p0, Le30/e;->f:Le30/j;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Le30/e;-><init>(Le30/j;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Le30/e;

    .line 16
    .line 17
    iget-object p0, p0, Le30/e;->f:Le30/j;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Le30/e;-><init>(Le30/j;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Le30/e;->d:I

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
    invoke-virtual {p0, p1, p2}, Le30/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Le30/e;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Le30/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Le30/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Le30/e;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Le30/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Le30/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Le30/e;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_2

    .line 14
    .line 15
    if-ne v1, v3, :cond_1

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    move-object v0, v2

    .line 21
    goto :goto_1

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
    iget-object p1, p0, Le30/e;->f:Le30/j;

    .line 34
    .line 35
    iget-object v1, p1, Lql0/j;->g:Lyy0/l1;

    .line 36
    .line 37
    new-instance v4, Lac0/e;

    .line 38
    .line 39
    const/16 v5, 0x10

    .line 40
    .line 41
    invoke-direct {v4, p1, v5}, Lac0/e;-><init>(Ljava/lang/Object;I)V

    .line 42
    .line 43
    .line 44
    iput v3, p0, Le30/e;->e:I

    .line 45
    .line 46
    new-instance p1, Lcs0/s;

    .line 47
    .line 48
    const/4 v3, 0x7

    .line 49
    invoke-direct {p1, v4, v3}, Lcs0/s;-><init>(Lyy0/j;I)V

    .line 50
    .line 51
    .line 52
    iget-object v1, v1, Lyy0/l1;->d:Lyy0/a2;

    .line 53
    .line 54
    invoke-interface {v1, p1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    if-ne p0, v0, :cond_3

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_3
    move-object p0, v2

    .line 62
    :goto_0
    if-ne p0, v0, :cond_0

    .line 63
    .line 64
    :goto_1
    return-object v0

    .line 65
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 66
    .line 67
    iget v1, p0, Le30/e;->e:I

    .line 68
    .line 69
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    const/4 v3, 0x2

    .line 72
    const/4 v4, 0x1

    .line 73
    iget-object v5, p0, Le30/e;->f:Le30/j;

    .line 74
    .line 75
    if-eqz v1, :cond_7

    .line 76
    .line 77
    if-eq v1, v4, :cond_6

    .line 78
    .line 79
    if-ne v1, v3, :cond_5

    .line 80
    .line 81
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    :cond_4
    :goto_2
    move-object v0, v2

    .line 85
    goto :goto_4

    .line 86
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 87
    .line 88
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 89
    .line 90
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw p0

    .line 94
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    iget-object p1, v5, Le30/j;->h:Lkf0/m;

    .line 102
    .line 103
    iput v4, p0, Le30/e;->e:I

    .line 104
    .line 105
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 106
    .line 107
    .line 108
    invoke-virtual {p1, p0}, Lkf0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    if-ne p1, v0, :cond_8

    .line 113
    .line 114
    goto :goto_4

    .line 115
    :cond_8
    :goto_3
    check-cast p1, Lne0/t;

    .line 116
    .line 117
    instance-of v1, p1, Lne0/c;

    .line 118
    .line 119
    if-eqz v1, :cond_9

    .line 120
    .line 121
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    check-cast p0, Le30/h;

    .line 126
    .line 127
    const/4 p1, 0x0

    .line 128
    const/4 v0, 0x4

    .line 129
    const/4 v1, 0x0

    .line 130
    invoke-static {p0, p1, v1, v1, v0}, Le30/h;->a(Le30/h;ZLe30/g;Ljava/lang/String;I)Le30/h;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    invoke-virtual {v5, p0}, Lql0/j;->g(Lql0/h;)V

    .line 135
    .line 136
    .line 137
    goto :goto_2

    .line 138
    :cond_9
    instance-of v1, p1, Lne0/e;

    .line 139
    .line 140
    if-eqz v1, :cond_a

    .line 141
    .line 142
    check-cast p1, Lne0/e;

    .line 143
    .line 144
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast p1, Lss0/k;

    .line 147
    .line 148
    iput v3, p0, Le30/e;->e:I

    .line 149
    .line 150
    invoke-static {v5, p1, p0}, Le30/j;->h(Le30/j;Lss0/k;Lrx0/c;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    if-ne p0, v0, :cond_4

    .line 155
    .line 156
    :goto_4
    return-object v0

    .line 157
    :cond_a
    new-instance p0, La8/r0;

    .line 158
    .line 159
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 160
    .line 161
    .line 162
    throw p0

    .line 163
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
