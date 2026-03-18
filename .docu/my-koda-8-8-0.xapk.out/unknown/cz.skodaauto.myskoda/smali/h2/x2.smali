.class public final Lh2/x2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lm1/t;


# direct methods
.method public constructor <init>(Lm1/t;ILkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x5

    iput v0, p0, Lh2/x2;->d:I

    .line 1
    iput-object p1, p0, Lh2/x2;->f:Lm1/t;

    iput p2, p0, Lh2/x2;->e:I

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p3, p0, Lh2/x2;->d:I

    iput-object p1, p0, Lh2/x2;->f:Lm1/t;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lh2/x2;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh2/x2;

    .line 7
    .line 8
    iget-object p0, p0, Lh2/x2;->f:Lm1/t;

    .line 9
    .line 10
    const/16 v0, 0x8

    .line 11
    .line 12
    invoke-direct {p1, p0, p2, v0}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 13
    .line 14
    .line 15
    return-object p1

    .line 16
    :pswitch_0
    new-instance p1, Lh2/x2;

    .line 17
    .line 18
    iget-object p0, p0, Lh2/x2;->f:Lm1/t;

    .line 19
    .line 20
    const/4 v0, 0x7

    .line 21
    invoke-direct {p1, p0, p2, v0}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    return-object p1

    .line 25
    :pswitch_1
    new-instance p1, Lh2/x2;

    .line 26
    .line 27
    iget-object p0, p0, Lh2/x2;->f:Lm1/t;

    .line 28
    .line 29
    const/4 v0, 0x6

    .line 30
    invoke-direct {p1, p0, p2, v0}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    return-object p1

    .line 34
    :pswitch_2
    new-instance p1, Lh2/x2;

    .line 35
    .line 36
    iget-object v0, p0, Lh2/x2;->f:Lm1/t;

    .line 37
    .line 38
    iget p0, p0, Lh2/x2;->e:I

    .line 39
    .line 40
    invoke-direct {p1, v0, p0, p2}, Lh2/x2;-><init>(Lm1/t;ILkotlin/coroutines/Continuation;)V

    .line 41
    .line 42
    .line 43
    return-object p1

    .line 44
    :pswitch_3
    new-instance p1, Lh2/x2;

    .line 45
    .line 46
    iget-object p0, p0, Lh2/x2;->f:Lm1/t;

    .line 47
    .line 48
    const/4 v0, 0x4

    .line 49
    invoke-direct {p1, p0, p2, v0}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    return-object p1

    .line 53
    :pswitch_4
    new-instance p1, Lh2/x2;

    .line 54
    .line 55
    iget-object p0, p0, Lh2/x2;->f:Lm1/t;

    .line 56
    .line 57
    const/4 v0, 0x3

    .line 58
    invoke-direct {p1, p0, p2, v0}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 59
    .line 60
    .line 61
    return-object p1

    .line 62
    :pswitch_5
    new-instance p1, Lh2/x2;

    .line 63
    .line 64
    iget-object p0, p0, Lh2/x2;->f:Lm1/t;

    .line 65
    .line 66
    const/4 v0, 0x2

    .line 67
    invoke-direct {p1, p0, p2, v0}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 68
    .line 69
    .line 70
    return-object p1

    .line 71
    :pswitch_6
    new-instance p1, Lh2/x2;

    .line 72
    .line 73
    iget-object p0, p0, Lh2/x2;->f:Lm1/t;

    .line 74
    .line 75
    const/4 v0, 0x1

    .line 76
    invoke-direct {p1, p0, p2, v0}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 77
    .line 78
    .line 79
    return-object p1

    .line 80
    :pswitch_7
    new-instance p1, Lh2/x2;

    .line 81
    .line 82
    iget-object p0, p0, Lh2/x2;->f:Lm1/t;

    .line 83
    .line 84
    const/4 v0, 0x0

    .line 85
    invoke-direct {p1, p0, p2, v0}, Lh2/x2;-><init>(Lm1/t;Lkotlin/coroutines/Continuation;I)V

    .line 86
    .line 87
    .line 88
    return-object p1

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lh2/x2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lh2/x2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh2/x2;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh2/x2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lvy0/b0;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lh2/x2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lh2/x2;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lh2/x2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lvy0/b0;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lh2/x2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lh2/x2;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lh2/x2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p1, Lg1/e2;

    .line 58
    .line 59
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2}, Lh2/x2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lh2/x2;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lh2/x2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    return-object p1

    .line 73
    :pswitch_3
    check-cast p1, Lvy0/b0;

    .line 74
    .line 75
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    invoke-virtual {p0, p1, p2}, Lh2/x2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    check-cast p0, Lh2/x2;

    .line 82
    .line 83
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    invoke-virtual {p0, p1}, Lh2/x2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0

    .line 90
    :pswitch_4
    check-cast p1, Lvy0/b0;

    .line 91
    .line 92
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 93
    .line 94
    invoke-virtual {p0, p1, p2}, Lh2/x2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    check-cast p0, Lh2/x2;

    .line 99
    .line 100
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 101
    .line 102
    invoke-virtual {p0, p1}, Lh2/x2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0

    .line 107
    :pswitch_5
    check-cast p1, Lvy0/b0;

    .line 108
    .line 109
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 110
    .line 111
    invoke-virtual {p0, p1, p2}, Lh2/x2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    check-cast p0, Lh2/x2;

    .line 116
    .line 117
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 118
    .line 119
    invoke-virtual {p0, p1}, Lh2/x2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    return-object p0

    .line 124
    :pswitch_6
    check-cast p1, Lvy0/b0;

    .line 125
    .line 126
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 127
    .line 128
    invoke-virtual {p0, p1, p2}, Lh2/x2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    check-cast p0, Lh2/x2;

    .line 133
    .line 134
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 135
    .line 136
    invoke-virtual {p0, p1}, Lh2/x2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    return-object p0

    .line 141
    :pswitch_7
    check-cast p1, Lvy0/b0;

    .line 142
    .line 143
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 144
    .line 145
    invoke-virtual {p0, p1, p2}, Lh2/x2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    check-cast p0, Lh2/x2;

    .line 150
    .line 151
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 152
    .line 153
    invoke-virtual {p0, p1}, Lh2/x2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    return-object p0

    .line 158
    nop

    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lh2/x2;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    .line 5
    .line 6
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    iget-object v4, p0, Lh2/x2;->f:Lm1/t;

    .line 9
    .line 10
    const/4 v5, 0x1

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    iget v6, p0, Lh2/x2;->e:I

    .line 17
    .line 18
    if-eqz v6, :cond_1

    .line 19
    .line 20
    if-ne v6, v5, :cond_0

    .line 21
    .line 22
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    iput v5, p0, Lh2/x2;->e:I

    .line 36
    .line 37
    invoke-static {v4, v1, p0}, Lm1/t;->j(Lm1/t;ILrx0/i;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    if-ne p0, v0, :cond_2

    .line 42
    .line 43
    move-object v3, v0

    .line 44
    :cond_2
    :goto_0
    return-object v3

    .line 45
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 46
    .line 47
    iget v6, p0, Lh2/x2;->e:I

    .line 48
    .line 49
    if-eqz v6, :cond_4

    .line 50
    .line 51
    if-ne v6, v5, :cond_3

    .line 52
    .line 53
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0

    .line 63
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iput v5, p0, Lh2/x2;->e:I

    .line 67
    .line 68
    invoke-static {v4, v1, p0}, Lm1/t;->f(Lm1/t;ILrx0/i;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    if-ne p0, v0, :cond_5

    .line 73
    .line 74
    move-object v3, v0

    .line 75
    :cond_5
    :goto_1
    return-object v3

    .line 76
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 77
    .line 78
    iget v6, p0, Lh2/x2;->e:I

    .line 79
    .line 80
    if-eqz v6, :cond_7

    .line 81
    .line 82
    if-ne v6, v5, :cond_6

    .line 83
    .line 84
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 89
    .line 90
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw p0

    .line 94
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    iput v5, p0, Lh2/x2;->e:I

    .line 98
    .line 99
    invoke-static {v4, v1, p0}, Lm1/t;->f(Lm1/t;ILrx0/i;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    if-ne p0, v0, :cond_8

    .line 104
    .line 105
    move-object v3, v0

    .line 106
    :cond_8
    :goto_2
    return-object v3

    .line 107
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 108
    .line 109
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    iget p0, p0, Lh2/x2;->e:I

    .line 113
    .line 114
    invoke-virtual {v4, p0, v1, v5}, Lm1/t;->k(IIZ)V

    .line 115
    .line 116
    .line 117
    return-object v3

    .line 118
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 119
    .line 120
    iget v1, p0, Lh2/x2;->e:I

    .line 121
    .line 122
    if-eqz v1, :cond_a

    .line 123
    .line 124
    if-ne v1, v5, :cond_9

    .line 125
    .line 126
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    goto :goto_3

    .line 130
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 131
    .line 132
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    throw p0

    .line 136
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    new-instance p1, Lg1/d2;

    .line 140
    .line 141
    const/4 v1, 0x0

    .line 142
    const/4 v2, 0x2

    .line 143
    invoke-direct {p1, v2, v1, v5}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 144
    .line 145
    .line 146
    iput v5, p0, Lh2/x2;->e:I

    .line 147
    .line 148
    sget-object v1, Le1/w0;->d:Le1/w0;

    .line 149
    .line 150
    invoke-virtual {v4, v1, p1, p0}, Lm1/t;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    if-ne p0, v0, :cond_b

    .line 155
    .line 156
    move-object v3, v0

    .line 157
    :cond_b
    :goto_3
    return-object v3

    .line 158
    :pswitch_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 159
    .line 160
    iget v1, p0, Lh2/x2;->e:I

    .line 161
    .line 162
    if-eqz v1, :cond_d

    .line 163
    .line 164
    if-ne v1, v5, :cond_c

    .line 165
    .line 166
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    goto :goto_4

    .line 170
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 171
    .line 172
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    throw p0

    .line 176
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 177
    .line 178
    .line 179
    iget-object p1, v4, Lm1/t;->e:Lm1/o;

    .line 180
    .line 181
    iget-object p1, p1, Lm1/o;->b:Ll2/g1;

    .line 182
    .line 183
    invoke-virtual {p1}, Ll2/g1;->o()I

    .line 184
    .line 185
    .line 186
    move-result p1

    .line 187
    sub-int/2addr p1, v5

    .line 188
    iput v5, p0, Lh2/x2;->e:I

    .line 189
    .line 190
    invoke-static {v4, p1, p0}, Lm1/t;->j(Lm1/t;ILrx0/i;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    if-ne p0, v0, :cond_e

    .line 195
    .line 196
    move-object v3, v0

    .line 197
    :cond_e
    :goto_4
    return-object v3

    .line 198
    :pswitch_5
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 199
    .line 200
    iget v1, p0, Lh2/x2;->e:I

    .line 201
    .line 202
    if-eqz v1, :cond_10

    .line 203
    .line 204
    if-ne v1, v5, :cond_f

    .line 205
    .line 206
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 207
    .line 208
    .line 209
    goto :goto_5

    .line 210
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 211
    .line 212
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    throw p0

    .line 216
    :cond_10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    iget-object p1, v4, Lm1/t;->e:Lm1/o;

    .line 220
    .line 221
    iget-object p1, p1, Lm1/o;->b:Ll2/g1;

    .line 222
    .line 223
    invoke-virtual {p1}, Ll2/g1;->o()I

    .line 224
    .line 225
    .line 226
    move-result p1

    .line 227
    add-int/2addr p1, v5

    .line 228
    iput v5, p0, Lh2/x2;->e:I

    .line 229
    .line 230
    invoke-static {v4, p1, p0}, Lm1/t;->j(Lm1/t;ILrx0/i;)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object p0

    .line 234
    if-ne p0, v0, :cond_11

    .line 235
    .line 236
    move-object v3, v0

    .line 237
    :cond_11
    :goto_5
    return-object v3

    .line 238
    :pswitch_6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 239
    .line 240
    iget v1, p0, Lh2/x2;->e:I

    .line 241
    .line 242
    if-eqz v1, :cond_13

    .line 243
    .line 244
    if-ne v1, v5, :cond_12

    .line 245
    .line 246
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 247
    .line 248
    .line 249
    goto :goto_6

    .line 250
    :cond_12
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 251
    .line 252
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    throw p0

    .line 256
    :cond_13
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 257
    .line 258
    .line 259
    :try_start_1
    iget-object p1, v4, Lm1/t;->e:Lm1/o;

    .line 260
    .line 261
    iget-object p1, p1, Lm1/o;->b:Ll2/g1;

    .line 262
    .line 263
    invoke-virtual {p1}, Ll2/g1;->o()I

    .line 264
    .line 265
    .line 266
    move-result p1

    .line 267
    sub-int/2addr p1, v5

    .line 268
    iput v5, p0, Lh2/x2;->e:I

    .line 269
    .line 270
    invoke-static {v4, p1, p0}, Lm1/t;->f(Lm1/t;ILrx0/i;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object p0
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_0

    .line 274
    if-ne p0, v0, :cond_14

    .line 275
    .line 276
    move-object v3, v0

    .line 277
    :catch_0
    :cond_14
    :goto_6
    return-object v3

    .line 278
    :pswitch_7
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 279
    .line 280
    iget v1, p0, Lh2/x2;->e:I

    .line 281
    .line 282
    if-eqz v1, :cond_16

    .line 283
    .line 284
    if-ne v1, v5, :cond_15

    .line 285
    .line 286
    :try_start_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_1

    .line 287
    .line 288
    .line 289
    goto :goto_7

    .line 290
    :cond_15
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 291
    .line 292
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    throw p0

    .line 296
    :cond_16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 297
    .line 298
    .line 299
    :try_start_3
    iget-object p1, v4, Lm1/t;->e:Lm1/o;

    .line 300
    .line 301
    iget-object p1, p1, Lm1/o;->b:Ll2/g1;

    .line 302
    .line 303
    invoke-virtual {p1}, Ll2/g1;->o()I

    .line 304
    .line 305
    .line 306
    move-result p1

    .line 307
    add-int/2addr p1, v5

    .line 308
    iput v5, p0, Lh2/x2;->e:I

    .line 309
    .line 310
    invoke-static {v4, p1, p0}, Lm1/t;->f(Lm1/t;ILrx0/i;)Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object p0
    :try_end_3
    .catch Ljava/lang/IllegalArgumentException; {:try_start_3 .. :try_end_3} :catch_1

    .line 314
    if-ne p0, v0, :cond_17

    .line 315
    .line 316
    move-object v3, v0

    .line 317
    :catch_1
    :cond_17
    :goto_7
    return-object v3

    .line 318
    nop

    .line 319
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
