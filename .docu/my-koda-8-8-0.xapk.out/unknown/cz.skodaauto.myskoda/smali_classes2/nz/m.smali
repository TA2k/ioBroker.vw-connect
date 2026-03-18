.class public final Lnz/m;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lnz/z;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;Lnz/z;)V
    .locals 0

    .line 1
    iput p1, p0, Lnz/m;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lnz/m;->f:Lnz/z;

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
    iget v0, p0, Lnz/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lnz/m;

    .line 7
    .line 8
    iget-object p0, p0, Lnz/m;->f:Lnz/z;

    .line 9
    .line 10
    const/4 v1, 0x3

    .line 11
    invoke-direct {v0, v1, p2, p0}, Lnz/m;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lnz/m;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lnz/m;

    .line 18
    .line 19
    iget-object p0, p0, Lnz/m;->f:Lnz/z;

    .line 20
    .line 21
    const/4 v1, 0x2

    .line 22
    invoke-direct {v0, v1, p2, p0}, Lnz/m;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lnz/m;->e:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lnz/m;

    .line 29
    .line 30
    iget-object p0, p0, Lnz/m;->f:Lnz/z;

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    invoke-direct {v0, v1, p2, p0}, Lnz/m;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lnz/m;->e:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_2
    new-instance v0, Lnz/m;

    .line 40
    .line 41
    iget-object p0, p0, Lnz/m;->f:Lnz/z;

    .line 42
    .line 43
    const/4 v1, 0x0

    .line 44
    invoke-direct {v0, v1, p2, p0}, Lnz/m;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 45
    .line 46
    .line 47
    iput-object p1, v0, Lnz/m;->e:Ljava/lang/Object;

    .line 48
    .line 49
    return-object v0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lnz/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/c;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lnz/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lnz/m;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lnz/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    check-cast p1, Lne0/c;

    .line 23
    .line 24
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    invoke-virtual {p0, p1, p2}, Lnz/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lnz/m;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lnz/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    return-object p1

    .line 38
    :pswitch_1
    check-cast p1, Lss0/b;

    .line 39
    .line 40
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 41
    .line 42
    invoke-virtual {p0, p1, p2}, Lnz/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    check-cast p0, Lnz/m;

    .line 47
    .line 48
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    invoke-virtual {p0, p1}, Lnz/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    return-object p1

    .line 54
    :pswitch_2
    check-cast p1, Lss0/b;

    .line 55
    .line 56
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 57
    .line 58
    invoke-virtual {p0, p1, p2}, Lnz/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    check-cast p0, Lnz/m;

    .line 63
    .line 64
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Lnz/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    return-object p1

    .line 70
    nop

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lnz/m;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Lnz/m;->f:Lnz/z;

    .line 6
    .line 7
    iget-object p0, p0, Lnz/m;->e:Ljava/lang/Object;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    check-cast p0, Lne0/c;

    .line 13
    .line 14
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    sget p1, Lnz/z;->B:I

    .line 20
    .line 21
    invoke-virtual {v2, p0}, Lnz/z;->h(Lne0/c;)V

    .line 22
    .line 23
    .line 24
    return-object v1

    .line 25
    :pswitch_0
    check-cast p0, Lne0/c;

    .line 26
    .line 27
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    sget p1, Lnz/z;->B:I

    .line 33
    .line 34
    invoke-virtual {v2, p0}, Lnz/z;->h(Lne0/c;)V

    .line 35
    .line 36
    .line 37
    return-object v1

    .line 38
    :pswitch_1
    check-cast p0, Lss0/b;

    .line 39
    .line 40
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 41
    .line 42
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    iget-object p1, v2, Lnz/z;->i:Lij0/a;

    .line 46
    .line 47
    invoke-static {p0, p1}, Ljp/bb;->i(Lss0/b;Lij0/a;)Lnz/s;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 52
    .line 53
    .line 54
    return-object v1

    .line 55
    :pswitch_2
    check-cast p0, Lss0/b;

    .line 56
    .line 57
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 58
    .line 59
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iget-object p1, v2, Lnz/z;->i:Lij0/a;

    .line 63
    .line 64
    invoke-static {p0, p1}, Ljp/bb;->i(Lss0/b;Lij0/a;)Lnz/s;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 69
    .line 70
    .line 71
    return-object v1

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
