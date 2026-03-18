.class public final Lw00/i;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy0/b0;

.field public final synthetic f:Lv00/i;

.field public final synthetic g:Ll2/b1;

.field public final synthetic h:Lh2/r8;


# direct methods
.method public synthetic constructor <init>(Lvy0/b0;Lv00/i;Ll2/b1;Lh2/r8;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p6, p0, Lw00/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw00/i;->e:Lvy0/b0;

    .line 4
    .line 5
    iput-object p2, p0, Lw00/i;->f:Lv00/i;

    .line 6
    .line 7
    iput-object p3, p0, Lw00/i;->g:Ll2/b1;

    .line 8
    .line 9
    iput-object p4, p0, Lw00/i;->h:Lh2/r8;

    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget p1, p0, Lw00/i;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lw00/i;

    .line 7
    .line 8
    iget-object v4, p0, Lw00/i;->h:Lh2/r8;

    .line 9
    .line 10
    const/4 v6, 0x1

    .line 11
    iget-object v1, p0, Lw00/i;->e:Lvy0/b0;

    .line 12
    .line 13
    iget-object v2, p0, Lw00/i;->f:Lv00/i;

    .line 14
    .line 15
    iget-object v3, p0, Lw00/i;->g:Ll2/b1;

    .line 16
    .line 17
    move-object v5, p2

    .line 18
    invoke-direct/range {v0 .. v6}, Lw00/i;-><init>(Lvy0/b0;Lv00/i;Ll2/b1;Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    return-object v0

    .line 22
    :pswitch_0
    move-object v5, p2

    .line 23
    new-instance v1, Lw00/i;

    .line 24
    .line 25
    move-object v6, v5

    .line 26
    iget-object v5, p0, Lw00/i;->h:Lh2/r8;

    .line 27
    .line 28
    const/4 v7, 0x0

    .line 29
    iget-object v2, p0, Lw00/i;->e:Lvy0/b0;

    .line 30
    .line 31
    iget-object v3, p0, Lw00/i;->f:Lv00/i;

    .line 32
    .line 33
    iget-object v4, p0, Lw00/i;->g:Ll2/b1;

    .line 34
    .line 35
    invoke-direct/range {v1 .. v7}, Lw00/i;-><init>(Lvy0/b0;Lv00/i;Ll2/b1;Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object v1

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lw00/i;->d:I

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
    invoke-virtual {p0, p1, p2}, Lw00/i;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lw00/i;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lw00/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lw00/i;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Lw00/i;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lw00/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    return-object p1

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lw00/i;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, v0, Lw00/i;->f:Lv00/i;

    .line 8
    .line 9
    const/4 v4, 0x3

    .line 10
    iget-object v5, v0, Lw00/i;->h:Lh2/r8;

    .line 11
    .line 12
    iget-object v6, v0, Lw00/i;->e:Lvy0/b0;

    .line 13
    .line 14
    iget-object v0, v0, Lw00/i;->g:Ll2/b1;

    .line 15
    .line 16
    const/4 v7, 0x0

    .line 17
    packed-switch v1, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Lv00/h;

    .line 30
    .line 31
    iget-boolean v0, v0, Lv00/h;->b:Z

    .line 32
    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    new-instance v0, Lh2/i0;

    .line 36
    .line 37
    const/16 v1, 0x1a

    .line 38
    .line 39
    invoke-direct {v0, v5, v7, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    invoke-static {v6, v7, v7, v0, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    move-object v4, v0

    .line 50
    check-cast v4, Lv00/h;

    .line 51
    .line 52
    const/4 v15, 0x0

    .line 53
    const/16 v16, 0xffd

    .line 54
    .line 55
    const/4 v5, 0x0

    .line 56
    const/4 v6, 0x0

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v8, 0x0

    .line 59
    const/4 v9, 0x0

    .line 60
    const/4 v10, 0x0

    .line 61
    const/4 v11, 0x0

    .line 62
    const/4 v12, 0x0

    .line 63
    const/4 v13, 0x0

    .line 64
    const/4 v14, 0x0

    .line 65
    invoke-static/range {v4 .. v16}, Lv00/h;->a(Lv00/h;Ljava/lang/String;ZZLjava/lang/String;ZLmh0/b;ILjava/util/List;ZZLv00/g;I)Lv00/h;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 70
    .line 71
    .line 72
    :cond_0
    return-object v2

    .line 73
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 74
    .line 75
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    check-cast v0, Lv00/h;

    .line 83
    .line 84
    iget-boolean v0, v0, Lv00/h;->i:Z

    .line 85
    .line 86
    if-eqz v0, :cond_1

    .line 87
    .line 88
    new-instance v0, Lh2/i0;

    .line 89
    .line 90
    const/16 v1, 0x19

    .line 91
    .line 92
    invoke-direct {v0, v5, v7, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 93
    .line 94
    .line 95
    invoke-static {v6, v7, v7, v0, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    move-object v4, v0

    .line 103
    check-cast v4, Lv00/h;

    .line 104
    .line 105
    const/4 v15, 0x0

    .line 106
    const/16 v16, 0xdff

    .line 107
    .line 108
    const/4 v5, 0x0

    .line 109
    const/4 v6, 0x0

    .line 110
    const/4 v7, 0x0

    .line 111
    const/4 v8, 0x0

    .line 112
    const/4 v9, 0x0

    .line 113
    const/4 v10, 0x0

    .line 114
    const/4 v11, 0x0

    .line 115
    const/4 v12, 0x0

    .line 116
    const/4 v13, 0x0

    .line 117
    const/4 v14, 0x0

    .line 118
    invoke-static/range {v4 .. v16}, Lv00/h;->a(Lv00/h;Ljava/lang/String;ZZLjava/lang/String;ZLmh0/b;ILjava/util/List;ZZLv00/g;I)Lv00/h;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 123
    .line 124
    .line 125
    :cond_1
    return-object v2

    .line 126
    nop

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
