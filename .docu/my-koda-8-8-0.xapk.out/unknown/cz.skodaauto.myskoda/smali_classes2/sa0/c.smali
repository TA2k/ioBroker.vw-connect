.class public final Lsa0/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lsa0/g;


# direct methods
.method public synthetic constructor <init>(Lsa0/g;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lsa0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lsa0/c;->f:Lsa0/g;

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
    iget v0, p0, Lsa0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lsa0/c;

    .line 7
    .line 8
    iget-object p0, p0, Lsa0/c;->f:Lsa0/g;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lsa0/c;-><init>(Lsa0/g;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lsa0/c;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lsa0/c;

    .line 18
    .line 19
    iget-object p0, p0, Lsa0/c;->f:Lsa0/g;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lsa0/c;-><init>(Lsa0/g;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lsa0/c;->e:Ljava/lang/Object;

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
    iget v0, p0, Lsa0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lra0/a;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lsa0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lsa0/c;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lsa0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    check-cast p1, Lcq0/n;

    .line 23
    .line 24
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    invoke-virtual {p0, p1, p2}, Lsa0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lsa0/c;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lsa0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Lsa0/c;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lsa0/c;->f:Lsa0/g;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    iget-object p0, p0, Lsa0/c;->e:Ljava/lang/Object;

    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    check-cast p0, Lra0/a;

    .line 14
    .line 15
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    iget-object p0, p0, Lra0/a;->e:Lra0/b;

    .line 23
    .line 24
    invoke-virtual {v1}, Lql0/j;->a()Lql0/h;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    check-cast p1, Lsa0/e;

    .line 29
    .line 30
    const/4 v0, 0x2

    .line 31
    invoke-static {p1, p0, v2, v0}, Lsa0/e;->a(Lsa0/e;Lra0/b;Lcq0/x;I)Lsa0/e;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {v1, p0}, Lql0/j;->g(Lql0/h;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    return-object v3

    .line 39
    :pswitch_0
    check-cast p0, Lcq0/n;

    .line 40
    .line 41
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 42
    .line 43
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v1}, Lql0/j;->a()Lql0/h;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    check-cast p1, Lsa0/e;

    .line 51
    .line 52
    if-eqz p0, :cond_1

    .line 53
    .line 54
    new-instance v0, Lcq0/x;

    .line 55
    .line 56
    iget-object v4, p0, Lcq0/n;->c:Ljava/lang/String;

    .line 57
    .line 58
    iget-object v5, p0, Lcq0/n;->k:Ljava/lang/String;

    .line 59
    .line 60
    iget-object p0, p0, Lcq0/n;->i:Ljava/lang/String;

    .line 61
    .line 62
    invoke-direct {v0, v4, v5, p0}, Lcq0/x;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_1
    move-object v0, v2

    .line 67
    :goto_0
    const/4 p0, 0x1

    .line 68
    invoke-static {p1, v2, v0, p0}, Lsa0/e;->a(Lsa0/e;Lra0/b;Lcq0/x;I)Lsa0/e;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-virtual {v1, p0}, Lql0/j;->g(Lql0/h;)V

    .line 73
    .line 74
    .line 75
    return-object v3

    .line 76
    nop

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
