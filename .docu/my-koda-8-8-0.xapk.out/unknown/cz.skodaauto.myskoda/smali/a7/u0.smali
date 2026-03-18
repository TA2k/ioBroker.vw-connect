.class public final La7/u0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, La7/u0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La7/u0;->f:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, La7/u0;->g:Ljava/lang/String;

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


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, La7/u0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, La7/u0;

    .line 7
    .line 8
    iget-object v1, p0, La7/u0;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, La7/u0;->f:Ljava/lang/String;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p2, v2}, La7/u0;-><init>(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, La7/u0;->e:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, La7/u0;

    .line 20
    .line 21
    iget-object v1, p0, La7/u0;->g:Ljava/lang/String;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    iget-object p0, p0, La7/u0;->f:Ljava/lang/String;

    .line 25
    .line 26
    invoke-direct {v0, p0, v1, p2, v2}, La7/u0;-><init>(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, La7/u0;->e:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, La7/u0;->d:I

    .line 2
    .line 3
    check-cast p1, Lq6/b;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, La7/u0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, La7/u0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, La7/u0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p2}, La7/u0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, La7/u0;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, La7/u0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, La7/u0;->d:I

    .line 2
    .line 3
    iget-object v1, p0, La7/u0;->g:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, La7/u0;->f:Ljava/lang/String;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, La7/u0;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lq6/b;

    .line 13
    .line 14
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    invoke-static {v2}, Llp/m1;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-static {p1}, Ljp/ne;->b(Ljava/lang/String;)Lq6/e;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0, p1, v1}, Lq6/b;->f(Lq6/e;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, La7/u0;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Lq6/b;

    .line 44
    .line 45
    invoke-virtual {p0}, Lq6/b;->g()Lq6/b;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    sget-object v0, La7/v0;->g:Lq6/e;

    .line 50
    .line 51
    invoke-virtual {p0, v0}, Lq6/b;->c(Lq6/e;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    check-cast p0, Ljava/util/Set;

    .line 56
    .line 57
    if-nez p0, :cond_0

    .line 58
    .line 59
    sget-object p0, Lmx0/u;->d:Lmx0/u;

    .line 60
    .line 61
    :cond_0
    invoke-static {p0, v2}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-virtual {p1, v0, p0}, Lq6/b;->f(Lq6/e;Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    sget-object p0, La7/v0;->d:La7/p0;

    .line 69
    .line 70
    invoke-static {p0, v2}, La7/p0;->a(La7/p0;Ljava/lang/String;)Lq6/e;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-virtual {p1, p0, v1}, Lq6/b;->f(Lq6/e;Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1}, Lq6/b;->h()Lq6/b;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0

    .line 82
    nop

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
