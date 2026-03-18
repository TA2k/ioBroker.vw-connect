.class public final Lga0/q;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lga0/h0;


# direct methods
.method public synthetic constructor <init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lga0/q;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lga0/q;->f:Lga0/h0;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lga0/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lga0/q;

    .line 7
    .line 8
    iget-object p0, p0, Lga0/q;->f:Lga0/h0;

    .line 9
    .line 10
    const/4 v1, 0x5

    .line 11
    invoke-direct {v0, v1, p0, p2}, Lga0/q;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lga0/q;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lga0/q;

    .line 18
    .line 19
    iget-object p0, p0, Lga0/q;->f:Lga0/h0;

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    invoke-direct {v0, v1, p0, p2}, Lga0/q;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lga0/q;->e:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lga0/q;

    .line 29
    .line 30
    iget-object p0, p0, Lga0/q;->f:Lga0/h0;

    .line 31
    .line 32
    const/4 v1, 0x3

    .line 33
    invoke-direct {v0, v1, p0, p2}, Lga0/q;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lga0/q;->e:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_2
    new-instance v0, Lga0/q;

    .line 40
    .line 41
    iget-object p0, p0, Lga0/q;->f:Lga0/h0;

    .line 42
    .line 43
    const/4 v1, 0x2

    .line 44
    invoke-direct {v0, v1, p0, p2}, Lga0/q;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 45
    .line 46
    .line 47
    iput-object p1, v0, Lga0/q;->e:Ljava/lang/Object;

    .line 48
    .line 49
    return-object v0

    .line 50
    :pswitch_3
    new-instance v0, Lga0/q;

    .line 51
    .line 52
    iget-object p0, p0, Lga0/q;->f:Lga0/h0;

    .line 53
    .line 54
    const/4 v1, 0x1

    .line 55
    invoke-direct {v0, v1, p0, p2}, Lga0/q;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 56
    .line 57
    .line 58
    iput-object p1, v0, Lga0/q;->e:Ljava/lang/Object;

    .line 59
    .line 60
    return-object v0

    .line 61
    :pswitch_4
    new-instance v0, Lga0/q;

    .line 62
    .line 63
    iget-object p0, p0, Lga0/q;->f:Lga0/h0;

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    invoke-direct {v0, v1, p0, p2}, Lga0/q;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 67
    .line 68
    .line 69
    iput-object p1, v0, Lga0/q;->e:Ljava/lang/Object;

    .line 70
    .line 71
    return-object v0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
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
    iget v0, p0, Lga0/q;->d:I

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
    invoke-virtual {p0, p1, p2}, Lga0/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lga0/q;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lga0/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lne0/c;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lga0/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lga0/q;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lga0/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    return-object p1

    .line 39
    :pswitch_1
    check-cast p1, Lne0/c;

    .line 40
    .line 41
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 42
    .line 43
    invoke-virtual {p0, p1, p2}, Lga0/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Lga0/q;

    .line 48
    .line 49
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    invoke-virtual {p0, p1}, Lga0/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    return-object p1

    .line 55
    :pswitch_2
    check-cast p1, Ljava/time/OffsetDateTime;

    .line 56
    .line 57
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 58
    .line 59
    invoke-virtual {p0, p1, p2}, Lga0/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, Lga0/q;

    .line 64
    .line 65
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    invoke-virtual {p0, p1}, Lga0/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    return-object p1

    .line 71
    :pswitch_3
    check-cast p1, Lss0/b;

    .line 72
    .line 73
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 74
    .line 75
    invoke-virtual {p0, p1, p2}, Lga0/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Lga0/q;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Lga0/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    return-object p1

    .line 87
    :pswitch_4
    check-cast p1, Lss0/b;

    .line 88
    .line 89
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 90
    .line 91
    invoke-virtual {p0, p1, p2}, Lga0/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    check-cast p0, Lga0/q;

    .line 96
    .line 97
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 98
    .line 99
    invoke-virtual {p0, p1}, Lga0/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    return-object p1

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lga0/q;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, v0, Lga0/q;->f:Lga0/h0;

    .line 8
    .line 9
    iget-object v0, v0, Lga0/q;->e:Ljava/lang/Object;

    .line 10
    .line 11
    packed-switch v1, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    check-cast v0, Lvy0/b0;

    .line 15
    .line 16
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    new-instance v1, Lga0/s;

    .line 22
    .line 23
    const/4 v2, 0x6

    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct {v1, v2, v3, v4}, Lga0/s;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    invoke-static {v0, v4, v4, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 30
    .line 31
    .line 32
    new-instance v1, Lga0/s;

    .line 33
    .line 34
    const/4 v5, 0x7

    .line 35
    invoke-direct {v1, v5, v3, v4}, Lga0/s;-><init>(ILga0/h0;Lkotlin/coroutines/Continuation;)V

    .line 36
    .line 37
    .line 38
    invoke-static {v0, v4, v4, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    return-object v0

    .line 43
    :pswitch_0
    check-cast v0, Lne0/c;

    .line 44
    .line 45
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 46
    .line 47
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v3, v0}, Lga0/h0;->k(Lne0/c;)Lga0/v;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 55
    .line 56
    .line 57
    return-object v2

    .line 58
    :pswitch_1
    check-cast v0, Lne0/c;

    .line 59
    .line 60
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 61
    .line 62
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v3, v0}, Lga0/h0;->k(Lne0/c;)Lga0/v;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 70
    .line 71
    .line 72
    return-object v2

    .line 73
    :pswitch_2
    move-object/from16 v18, v0

    .line 74
    .line 75
    check-cast v18, Ljava/time/OffsetDateTime;

    .line 76
    .line 77
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 78
    .line 79
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    move-object v4, v0

    .line 87
    check-cast v4, Lga0/v;

    .line 88
    .line 89
    const/16 v17, 0x0

    .line 90
    .line 91
    const/16 v19, 0x7fff

    .line 92
    .line 93
    const/4 v5, 0x0

    .line 94
    const/4 v6, 0x0

    .line 95
    const/4 v7, 0x0

    .line 96
    const/4 v8, 0x0

    .line 97
    const/4 v9, 0x0

    .line 98
    const/4 v10, 0x0

    .line 99
    const/4 v11, 0x0

    .line 100
    const/4 v12, 0x0

    .line 101
    const/4 v13, 0x0

    .line 102
    const/4 v14, 0x0

    .line 103
    const/4 v15, 0x0

    .line 104
    const/16 v16, 0x0

    .line 105
    .line 106
    invoke-static/range {v4 .. v19}, Lga0/v;->a(Lga0/v;Landroid/net/Uri;Lga0/t;ZZZZZLga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Ljava/time/OffsetDateTime;I)Lga0/v;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 111
    .line 112
    .line 113
    return-object v2

    .line 114
    :pswitch_3
    check-cast v0, Lss0/b;

    .line 115
    .line 116
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 117
    .line 118
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    const/4 v1, 0x0

    .line 122
    invoke-static {v0, v1}, Lkp/t8;->a(Lss0/b;Z)Lga0/v;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 127
    .line 128
    .line 129
    return-object v2

    .line 130
    :pswitch_4
    check-cast v0, Lss0/b;

    .line 131
    .line 132
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 133
    .line 134
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    invoke-static {v0}, Lst0/o;->a(Lss0/b;)Z

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    invoke-static {v0, v1}, Lkp/t8;->a(Lss0/b;Z)Lga0/v;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 146
    .line 147
    .line 148
    return-object v2

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
