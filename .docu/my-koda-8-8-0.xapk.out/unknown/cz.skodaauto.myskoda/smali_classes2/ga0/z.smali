.class public final Lga0/z;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Lne0/s;

.field public synthetic f:Lcn0/c;

.field public synthetic g:Lcn0/c;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lga0/z;->d:I

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lga0/z;->d:I

    .line 2
    .line 3
    check-cast p1, Lne0/s;

    .line 4
    .line 5
    check-cast p2, Lcn0/c;

    .line 6
    .line 7
    check-cast p3, Lcn0/c;

    .line 8
    .line 9
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 10
    .line 11
    packed-switch p0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    new-instance p0, Lga0/z;

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    const/4 v1, 0x2

    .line 18
    invoke-direct {p0, v0, p4, v1}, Lga0/z;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lga0/z;->e:Lne0/s;

    .line 22
    .line 23
    iput-object p2, p0, Lga0/z;->f:Lcn0/c;

    .line 24
    .line 25
    iput-object p3, p0, Lga0/z;->g:Lcn0/c;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lga0/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_0
    new-instance p0, Lga0/z;

    .line 35
    .line 36
    const/4 v0, 0x4

    .line 37
    const/4 v1, 0x1

    .line 38
    invoke-direct {p0, v0, p4, v1}, Lga0/z;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    iput-object p1, p0, Lga0/z;->e:Lne0/s;

    .line 42
    .line 43
    iput-object p2, p0, Lga0/z;->f:Lcn0/c;

    .line 44
    .line 45
    iput-object p3, p0, Lga0/z;->g:Lcn0/c;

    .line 46
    .line 47
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    invoke-virtual {p0, p1}, Lga0/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :pswitch_1
    new-instance p0, Lga0/z;

    .line 55
    .line 56
    const/4 v0, 0x4

    .line 57
    const/4 v1, 0x0

    .line 58
    invoke-direct {p0, v0, p4, v1}, Lga0/z;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 59
    .line 60
    .line 61
    iput-object p1, p0, Lga0/z;->e:Lne0/s;

    .line 62
    .line 63
    iput-object p2, p0, Lga0/z;->f:Lcn0/c;

    .line 64
    .line 65
    iput-object p3, p0, Lga0/z;->g:Lcn0/c;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lga0/z;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lga0/z;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lga0/z;->e:Lne0/s;

    .line 7
    .line 8
    iget-object v1, p0, Lga0/z;->f:Lcn0/c;

    .line 9
    .line 10
    iget-object p0, p0, Lga0/z;->g:Lcn0/c;

    .line 11
    .line 12
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    new-instance p1, Llx0/r;

    .line 18
    .line 19
    invoke-direct {p1, v0, v1, p0}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object p1

    .line 23
    :pswitch_0
    iget-object v0, p0, Lga0/z;->e:Lne0/s;

    .line 24
    .line 25
    iget-object v1, p0, Lga0/z;->f:Lcn0/c;

    .line 26
    .line 27
    iget-object p0, p0, Lga0/z;->g:Lcn0/c;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    filled-new-array {v1, p0}, [Lcn0/c;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-static {p0}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    new-instance p1, Llx0/l;

    .line 43
    .line 44
    invoke-direct {p1, v0, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object p1

    .line 48
    :pswitch_1
    iget-object v0, p0, Lga0/z;->e:Lne0/s;

    .line 49
    .line 50
    iget-object v1, p0, Lga0/z;->f:Lcn0/c;

    .line 51
    .line 52
    iget-object p0, p0, Lga0/z;->g:Lcn0/c;

    .line 53
    .line 54
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 55
    .line 56
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    filled-new-array {v1, p0}, [Lcn0/c;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-static {p0}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    new-instance p1, Llx0/l;

    .line 68
    .line 69
    invoke-direct {p1, v0, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    return-object p1

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
