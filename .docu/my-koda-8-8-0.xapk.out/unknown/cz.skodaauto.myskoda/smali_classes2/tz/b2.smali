.class public final Ltz/b2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ltz/i2;


# direct methods
.method public synthetic constructor <init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltz/b2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/b2;->f:Ltz/i2;

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
    iget v0, p0, Ltz/b2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltz/b2;

    .line 7
    .line 8
    iget-object p0, p0, Ltz/b2;->f:Ltz/i2;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Ltz/b2;-><init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Ltz/b2;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Ltz/b2;

    .line 18
    .line 19
    iget-object p0, p0, Ltz/b2;->f:Ltz/i2;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Ltz/b2;-><init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Ltz/b2;->e:Ljava/lang/Object;

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
    iget v0, p0, Ltz/b2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/t;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Ltz/b2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltz/b2;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ltz/b2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    check-cast p1, Lxj0/b;

    .line 23
    .line 24
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    invoke-virtual {p0, p1, p2}, Ltz/b2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Ltz/b2;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Ltz/b2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 11

    .line 1
    iget v0, p0, Ltz/b2;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Ltz/b2;->f:Ltz/i2;

    .line 6
    .line 7
    iget-object p0, p0, Ltz/b2;->e:Ljava/lang/Object;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    check-cast p0, Lne0/t;

    .line 13
    .line 14
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    sget-object p1, Ltz/i2;->v:Lhl0/b;

    .line 20
    .line 21
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    move-object v3, p1

    .line 26
    check-cast v3, Ltz/f2;

    .line 27
    .line 28
    instance-of p1, p0, Lne0/c;

    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    :cond_0
    :goto_0
    move-object v6, v0

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    instance-of p1, p0, Lne0/e;

    .line 36
    .line 37
    if-eqz p1, :cond_3

    .line 38
    .line 39
    check-cast p0, Lne0/e;

    .line 40
    .line 41
    iget-object p0, p0, Lne0/e;->a:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Lbl0/n;

    .line 44
    .line 45
    iget-object p0, p0, Lbl0/n;->b:Ljava/lang/String;

    .line 46
    .line 47
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    const/16 v4, 0x32

    .line 52
    .line 53
    if-gt p1, v4, :cond_2

    .line 54
    .line 55
    move-object v0, p0

    .line 56
    :cond_2
    if-nez v0, :cond_0

    .line 57
    .line 58
    const/16 p1, 0x31

    .line 59
    .line 60
    invoke-static {p1, p0}, Lly0/p;->j0(ILjava/lang/String;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    const-string p1, "\u2026"

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    move-object v0, p0

    .line 71
    goto :goto_0

    .line 72
    :goto_1
    const/4 v9, 0x0

    .line 73
    const/16 v10, 0x2b

    .line 74
    .line 75
    const/4 v4, 0x0

    .line 76
    const/4 v5, 0x0

    .line 77
    const/4 v7, 0x0

    .line 78
    const/4 v8, 0x0

    .line 79
    invoke-static/range {v3 .. v10}, Ltz/f2;->a(Ltz/f2;Ljava/util/List;Lxj0/f;Ljava/lang/String;ZZZI)Ltz/f2;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 84
    .line 85
    .line 86
    return-object v1

    .line 87
    :cond_3
    new-instance p0, La8/r0;

    .line 88
    .line 89
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :pswitch_0
    check-cast p0, Lxj0/b;

    .line 94
    .line 95
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 96
    .line 97
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    sget-object p1, Ltz/i2;->v:Lhl0/b;

    .line 101
    .line 102
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    move-object v3, p1

    .line 107
    check-cast v3, Ltz/f2;

    .line 108
    .line 109
    iget-object v5, p0, Lxj0/b;->a:Lxj0/f;

    .line 110
    .line 111
    const/4 v9, 0x0

    .line 112
    const/16 v10, 0x3d

    .line 113
    .line 114
    const/4 v4, 0x0

    .line 115
    const/4 v6, 0x0

    .line 116
    const/4 v7, 0x0

    .line 117
    const/4 v8, 0x0

    .line 118
    invoke-static/range {v3 .. v10}, Ltz/f2;->a(Ltz/f2;Ljava/util/List;Lxj0/f;Ljava/lang/String;ZZZI)Ltz/f2;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 123
    .line 124
    .line 125
    return-object v1

    .line 126
    nop

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
