.class public final Lnt0/h;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lnt0/i;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V
    .locals 0

    .line 1
    iput p1, p0, Lnt0/h;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lnt0/h;->e:Lnt0/i;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lnt0/h;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Throwable;

    .line 6
    .line 7
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance p1, Lnt0/h;

    .line 13
    .line 14
    iget-object p0, p0, Lnt0/h;->e:Lnt0/i;

    .line 15
    .line 16
    const/4 p2, 0x1

    .line 17
    invoke-direct {p1, p2, p3, p0}, Lnt0/h;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 18
    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    invoke-virtual {p1, p0}, Lnt0/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    new-instance p1, Lnt0/h;

    .line 27
    .line 28
    iget-object p0, p0, Lnt0/h;->e:Lnt0/i;

    .line 29
    .line 30
    const/4 p2, 0x0

    .line 31
    invoke-direct {p1, p2, p3, p0}, Lnt0/h;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    invoke-virtual {p1, p0}, Lnt0/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    return-object p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lnt0/h;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object p0, p0, Lnt0/h;->e:Lnt0/i;

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
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    move-object v2, p1

    .line 20
    check-cast v2, Lnt0/e;

    .line 21
    .line 22
    const/4 v9, 0x0

    .line 23
    const/16 v10, 0x7b

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    const/4 v4, 0x0

    .line 27
    const/4 v5, 0x0

    .line 28
    const/4 v6, 0x0

    .line 29
    const/4 v7, 0x0

    .line 30
    const/4 v8, 0x0

    .line 31
    invoke-static/range {v2 .. v10}, Lnt0/e;->a(Lnt0/e;Lql0/g;ZZZLjava/lang/String;Ljava/util/List;ZI)Lnt0/e;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 36
    .line 37
    .line 38
    return-object v1

    .line 39
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    move-object v2, p1

    .line 49
    check-cast v2, Lnt0/e;

    .line 50
    .line 51
    const/4 v9, 0x0

    .line 52
    const/16 v10, 0x7b

    .line 53
    .line 54
    const/4 v3, 0x0

    .line 55
    const/4 v4, 0x0

    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v6, 0x0

    .line 58
    const/4 v7, 0x0

    .line 59
    const/4 v8, 0x0

    .line 60
    invoke-static/range {v2 .. v10}, Lnt0/e;->a(Lnt0/e;Lql0/g;ZZZLjava/lang/String;Ljava/util/List;ZI)Lnt0/e;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 65
    .line 66
    .line 67
    return-object v1

    .line 68
    nop

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
