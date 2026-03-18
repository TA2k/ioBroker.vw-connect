.class public final Lr30/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Ljava/util/Iterator;

.field public e:I

.field public final synthetic f:Lv2/o;

.field public final synthetic g:Z

.field public final synthetic h:Ljava/util/List;

.field public final synthetic i:Lay0/a;


# direct methods
.method public constructor <init>(Lv2/o;ZLjava/util/List;Lay0/a;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lr30/e;->f:Lv2/o;

    .line 2
    .line 3
    iput-boolean p2, p0, Lr30/e;->g:Z

    .line 4
    .line 5
    iput-object p3, p0, Lr30/e;->h:Ljava/util/List;

    .line 6
    .line 7
    iput-object p4, p0, Lr30/e;->i:Lay0/a;

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6

    .line 1
    new-instance v0, Lr30/e;

    .line 2
    .line 3
    iget-object v3, p0, Lr30/e;->h:Ljava/util/List;

    .line 4
    .line 5
    iget-object v4, p0, Lr30/e;->i:Lay0/a;

    .line 6
    .line 7
    iget-object v1, p0, Lr30/e;->f:Lv2/o;

    .line 8
    .line 9
    iget-boolean v2, p0, Lr30/e;->g:Z

    .line 10
    .line 11
    move-object v5, p2

    .line 12
    invoke-direct/range {v0 .. v5}, Lr30/e;-><init>(Lv2/o;ZLjava/util/List;Lay0/a;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lr30/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lr30/e;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lr30/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lr30/e;->e:I

    .line 4
    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    const-wide/16 v4, 0x96

    .line 8
    .line 9
    iget-boolean v6, p0, Lr30/e;->g:Z

    .line 10
    .line 11
    iget-object v7, p0, Lr30/e;->f:Lv2/o;

    .line 12
    .line 13
    const/4 v8, 0x2

    .line 14
    const/4 v9, 0x1

    .line 15
    if-eqz v1, :cond_2

    .line 16
    .line 17
    if-eq v1, v9, :cond_1

    .line 18
    .line 19
    if-ne v1, v8, :cond_0

    .line 20
    .line 21
    iget-object v1, p0, Lr30/e;->d:Ljava/util/Iterator;

    .line 22
    .line 23
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    goto :goto_2

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v7}, Lv2/o;->clear()V

    .line 43
    .line 44
    .line 45
    sget-object p1, Lr30/h;->a:Lc1/s;

    .line 46
    .line 47
    if-eqz v6, :cond_3

    .line 48
    .line 49
    move-wide v10, v4

    .line 50
    goto :goto_0

    .line 51
    :cond_3
    move-wide v10, v2

    .line 52
    :goto_0
    iput v9, p0, Lr30/e;->e:I

    .line 53
    .line 54
    invoke-static {v10, v11, p0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    if-ne p1, v0, :cond_4

    .line 59
    .line 60
    goto :goto_4

    .line 61
    :cond_4
    :goto_1
    iget-object p1, p0, Lr30/e;->h:Ljava/util/List;

    .line 62
    .line 63
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    move-object v1, p1

    .line 68
    :cond_5
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    if-eqz p1, :cond_7

    .line 73
    .line 74
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    check-cast p1, Ljava/lang/String;

    .line 79
    .line 80
    invoke-virtual {v7, p1}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    sget-object p1, Lr30/h;->a:Lc1/s;

    .line 84
    .line 85
    if-eqz v6, :cond_6

    .line 86
    .line 87
    move-wide v9, v4

    .line 88
    goto :goto_3

    .line 89
    :cond_6
    move-wide v9, v2

    .line 90
    :goto_3
    iput-object v1, p0, Lr30/e;->d:Ljava/util/Iterator;

    .line 91
    .line 92
    iput v8, p0, Lr30/e;->e:I

    .line 93
    .line 94
    invoke-static {v9, v10, p0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    if-ne p1, v0, :cond_5

    .line 99
    .line 100
    :goto_4
    return-object v0

    .line 101
    :cond_7
    iget-object p0, p0, Lr30/e;->i:Lay0/a;

    .line 102
    .line 103
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 107
    .line 108
    return-object p0
.end method
