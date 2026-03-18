.class public final La71/d0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Landroid/content/Context;


# direct methods
.method public synthetic constructor <init>(Landroid/content/Context;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, La71/d0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La71/d0;->e:Landroid/content/Context;

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
    iget p1, p0, La71/d0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, La71/d0;

    .line 7
    .line 8
    iget-object p0, p0, La71/d0;->e:Landroid/content/Context;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, La71/d0;-><init>(Landroid/content/Context;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, La71/d0;

    .line 16
    .line 17
    iget-object p0, p0, La71/d0;->e:Landroid/content/Context;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, La71/d0;-><init>(Landroid/content/Context;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, La71/d0;->d:I

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
    invoke-virtual {p0, p1, p2}, La71/d0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, La71/d0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, La71/d0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p2}, La71/d0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, La71/d0;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, La71/d0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, La71/d0;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object p0, p0, La71/d0;->e:Landroid/content/Context;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    instance-of p1, p0, Lb/r;

    .line 16
    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    sget-wide v2, Le3/s;->h:J

    .line 20
    .line 21
    invoke-static {v2, v3}, Le3/j0;->z(J)I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    check-cast p0, Lb/r;

    .line 26
    .line 27
    new-instance v0, Lb/k0;

    .line 28
    .line 29
    new-instance v2, La00/a;

    .line 30
    .line 31
    const/16 v3, 0x1b

    .line 32
    .line 33
    invoke-direct {v2, v3}, La00/a;-><init>(I)V

    .line 34
    .line 35
    .line 36
    const/4 v4, 0x1

    .line 37
    invoke-direct {v0, p1, p1, v4, v2}, Lb/k0;-><init>(IIILay0/k;)V

    .line 38
    .line 39
    .line 40
    new-instance v2, Lb/k0;

    .line 41
    .line 42
    new-instance v5, La00/a;

    .line 43
    .line 44
    invoke-direct {v5, v3}, La00/a;-><init>(I)V

    .line 45
    .line 46
    .line 47
    invoke-direct {v2, p1, p1, v4, v5}, Lb/k0;-><init>(IIILay0/k;)V

    .line 48
    .line 49
    .line 50
    invoke-static {p0, v0, v2}, Lb/u;->a(Lb/r;Lb/k0;Lb/k0;)V

    .line 51
    .line 52
    .line 53
    :cond_0
    return-object v1

    .line 54
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 55
    .line 56
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    instance-of p1, p0, Lb/r;

    .line 60
    .line 61
    if-eqz p1, :cond_1

    .line 62
    .line 63
    sget-wide v2, Le3/s;->h:J

    .line 64
    .line 65
    invoke-static {v2, v3}, Le3/j0;->z(J)I

    .line 66
    .line 67
    .line 68
    move-result p1

    .line 69
    check-cast p0, Lb/r;

    .line 70
    .line 71
    new-instance v0, Lb/k0;

    .line 72
    .line 73
    new-instance v2, La00/a;

    .line 74
    .line 75
    const/16 v3, 0x1c

    .line 76
    .line 77
    invoke-direct {v2, v3}, La00/a;-><init>(I)V

    .line 78
    .line 79
    .line 80
    const/4 v4, 0x2

    .line 81
    invoke-direct {v0, p1, p1, v4, v2}, Lb/k0;-><init>(IIILay0/k;)V

    .line 82
    .line 83
    .line 84
    new-instance v2, Lb/k0;

    .line 85
    .line 86
    new-instance v5, La00/a;

    .line 87
    .line 88
    invoke-direct {v5, v3}, La00/a;-><init>(I)V

    .line 89
    .line 90
    .line 91
    invoke-direct {v2, p1, p1, v4, v5}, Lb/k0;-><init>(IIILay0/k;)V

    .line 92
    .line 93
    .line 94
    invoke-static {p0, v0, v2}, Lb/u;->a(Lb/r;Lb/k0;Lb/k0;)V

    .line 95
    .line 96
    .line 97
    :cond_1
    return-object v1

    .line 98
    nop

    .line 99
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
