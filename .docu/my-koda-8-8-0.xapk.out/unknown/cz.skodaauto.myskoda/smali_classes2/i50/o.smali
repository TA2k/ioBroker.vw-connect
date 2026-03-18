.class public final Li50/o;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Li91/r2;

.field public final synthetic f:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Li91/r2;Ll2/b1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Li50/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li50/o;->e:Li91/r2;

    .line 4
    .line 5
    iput-object p2, p0, Li50/o;->f:Ll2/b1;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public static final b(FLl2/b1;)V
    .locals 2

    .line 1
    sget v0, Lkv0/i;->c:F

    .line 2
    .line 3
    add-float/2addr p0, v0

    .line 4
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Lk1/z0;

    .line 9
    .line 10
    invoke-interface {v0}, Lk1/z0;->c()F

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    invoke-static {p0, v0}, Lt4/f;->a(FF)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-nez v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x7

    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-static {v1, v1, v1, p0, v0}, Landroidx/compose/foundation/layout/a;->c(FFFFI)Lk1/a1;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-interface {p1, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    :cond_0
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Li50/o;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Li50/o;

    .line 7
    .line 8
    iget-object v0, p0, Li50/o;->f:Ll2/b1;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    iget-object p0, p0, Li50/o;->e:Li91/r2;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Li50/o;-><init>(Li91/r2;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Li50/o;

    .line 18
    .line 19
    iget-object v0, p0, Li50/o;->f:Ll2/b1;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    iget-object p0, p0, Li50/o;->e:Li91/r2;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Li50/o;-><init>(Li91/r2;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    :pswitch_1
    new-instance p1, Li50/o;

    .line 29
    .line 30
    iget-object v0, p0, Li50/o;->f:Ll2/b1;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    iget-object p0, p0, Li50/o;->e:Li91/r2;

    .line 34
    .line 35
    invoke-direct {p1, p0, v0, p2, v1}, Li50/o;-><init>(Li91/r2;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object p1

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Li50/o;->d:I

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
    invoke-virtual {p0, p1, p2}, Li50/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Li50/o;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Li50/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Li50/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Li50/o;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Li50/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Li50/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    check-cast p0, Li50/o;

    .line 40
    .line 41
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {p0, p1}, Li50/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Li50/o;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Li50/o;->f:Ll2/b1;

    .line 6
    .line 7
    iget-object p0, p0, Li50/o;->e:Li91/r2;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Li91/r2;->c()Li91/s2;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    if-eq p0, p1, :cond_0

    .line 28
    .line 29
    invoke-interface {v2, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_0
    return-object v1

    .line 33
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0}, Li91/r2;->c()Li91/s2;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    const/4 v0, -0x1

    .line 43
    if-nez p1, :cond_1

    .line 44
    .line 45
    move p1, v0

    .line 46
    goto :goto_0

    .line 47
    :cond_1
    sget-object v3, Lkv0/f;->a:[I

    .line 48
    .line 49
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    aget p1, v3, p1

    .line 54
    .line 55
    :goto_0
    if-eq p1, v0, :cond_6

    .line 56
    .line 57
    const/4 v0, 0x1

    .line 58
    if-eq p1, v0, :cond_5

    .line 59
    .line 60
    const/4 v0, 0x2

    .line 61
    if-eq p1, v0, :cond_4

    .line 62
    .line 63
    const/4 v0, 0x3

    .line 64
    if-eq p1, v0, :cond_3

    .line 65
    .line 66
    const/4 v0, 0x4

    .line 67
    if-ne p1, v0, :cond_2

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
    new-instance p0, La8/r0;

    .line 71
    .line 72
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 73
    .line 74
    .line 75
    throw p0

    .line 76
    :cond_3
    :goto_1
    invoke-virtual {p0}, Li91/r2;->a()F

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    invoke-static {p0, v2}, Li50/o;->b(FLl2/b1;)V

    .line 81
    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_4
    invoke-virtual {p0}, Li91/r2;->b()F

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    invoke-static {p0, v2}, Li50/o;->b(FLl2/b1;)V

    .line 89
    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_5
    const/4 p0, 0x0

    .line 93
    int-to-float p0, p0

    .line 94
    invoke-static {p0, v2}, Li50/o;->b(FLl2/b1;)V

    .line 95
    .line 96
    .line 97
    :cond_6
    :goto_2
    return-object v1

    .line 98
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 99
    .line 100
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p0}, Li91/r2;->c()Li91/s2;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    if-eqz p0, :cond_7

    .line 108
    .line 109
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    if-eq p0, p1, :cond_7

    .line 114
    .line 115
    invoke-interface {v2, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    :cond_7
    return-object v1

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
