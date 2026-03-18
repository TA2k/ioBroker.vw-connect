.class public final Lw30/r;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lw30/t;


# direct methods
.method public synthetic constructor <init>(Lw30/t;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lw30/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw30/r;->f:Lw30/t;

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
    .locals 2

    .line 1
    iget v0, p0, Lw30/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lw30/r;

    .line 7
    .line 8
    iget-object p0, p0, Lw30/r;->f:Lw30/t;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lw30/r;-><init>(Lw30/t;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lw30/r;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lw30/r;

    .line 18
    .line 19
    iget-object p0, p0, Lw30/r;->f:Lw30/t;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lw30/r;-><init>(Lw30/t;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lw30/r;->e:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lw30/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lss0/k;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lw30/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lw30/r;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lw30/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    check-cast p1, Lyr0/e;

    .line 23
    .line 24
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    invoke-virtual {p0, p1, p2}, Lw30/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lw30/r;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lw30/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    return-object p1

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lw30/r;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, v0, Lw30/r;->f:Lw30/t;

    .line 8
    .line 9
    iget-object v0, v0, Lw30/r;->e:Ljava/lang/Object;

    .line 10
    .line 11
    packed-switch v1, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    check-cast v0, Lss0/k;

    .line 15
    .line 16
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    move-object v4, v1

    .line 26
    check-cast v4, Lw30/s;

    .line 27
    .line 28
    iget-object v1, v0, Lss0/k;->a:Ljava/lang/String;

    .line 29
    .line 30
    iget-object v0, v0, Lss0/k;->b:Ljava/lang/String;

    .line 31
    .line 32
    if-nez v0, :cond_0

    .line 33
    .line 34
    const-string v0, ""

    .line 35
    .line 36
    :cond_0
    move-object v15, v0

    .line 37
    const/4 v14, 0x0

    .line 38
    const/16 v17, 0x3ff

    .line 39
    .line 40
    const/4 v5, 0x0

    .line 41
    const/4 v6, 0x0

    .line 42
    const/4 v7, 0x0

    .line 43
    const/4 v8, 0x0

    .line 44
    const/4 v9, 0x0

    .line 45
    const/4 v10, 0x0

    .line 46
    const/4 v11, 0x0

    .line 47
    const/4 v12, 0x0

    .line 48
    const/4 v13, 0x0

    .line 49
    move-object/from16 v16, v1

    .line 50
    .line 51
    invoke-static/range {v4 .. v17}, Lw30/s;->a(Lw30/s;Lql0/g;ZZZZZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/s;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 56
    .line 57
    .line 58
    return-object v2

    .line 59
    :pswitch_0
    check-cast v0, Lyr0/e;

    .line 60
    .line 61
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 62
    .line 63
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object v1, v0, Lyr0/e;->n:Ljava/util/List;

    .line 67
    .line 68
    sget-object v4, Lyr0/f;->e:Lyr0/f;

    .line 69
    .line 70
    invoke-interface {v1, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v9

    .line 74
    iget-object v1, v0, Lyr0/e;->n:Ljava/util/List;

    .line 75
    .line 76
    sget-object v4, Lyr0/f;->f:Lyr0/f;

    .line 77
    .line 78
    invoke-interface {v1, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v11

    .line 82
    sget-object v4, Lyr0/f;->g:Lyr0/f;

    .line 83
    .line 84
    invoke-interface {v1, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v12

    .line 88
    sget-object v4, Lyr0/f;->h:Lyr0/f;

    .line 89
    .line 90
    invoke-interface {v1, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v14

    .line 94
    sget-object v4, Lyr0/f;->i:Lyr0/f;

    .line 95
    .line 96
    invoke-interface {v1, v4}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v13

    .line 100
    iget-object v0, v0, Lyr0/e;->g:Ljava/lang/String;

    .line 101
    .line 102
    iget-object v1, v3, Lw30/t;->w:Lij0/a;

    .line 103
    .line 104
    invoke-static {v0, v1}, Llp/vc;->b(Ljava/lang/String;Lij0/a;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v15

    .line 108
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    move-object v5, v0

    .line 113
    check-cast v5, Lw30/s;

    .line 114
    .line 115
    const/16 v17, 0x0

    .line 116
    .line 117
    const/16 v18, 0xc17

    .line 118
    .line 119
    const/4 v6, 0x0

    .line 120
    const/4 v7, 0x0

    .line 121
    const/4 v8, 0x0

    .line 122
    const/4 v10, 0x0

    .line 123
    const/16 v16, 0x0

    .line 124
    .line 125
    invoke-static/range {v5 .. v18}, Lw30/s;->a(Lw30/s;Lql0/g;ZZZZZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/s;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 130
    .line 131
    .line 132
    return-object v2

    .line 133
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
