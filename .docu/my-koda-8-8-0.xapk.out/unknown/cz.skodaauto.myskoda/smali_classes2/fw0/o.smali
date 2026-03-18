.class public final Lfw0/o;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Throwable;

.field public f:I

.field public synthetic g:Lkw0/b;

.field public synthetic h:Ljava/lang/Throwable;

.field public final synthetic i:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lfw0/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lfw0/o;->i:Ljava/util/List;

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
    .locals 2

    .line 1
    iget v0, p0, Lfw0/o;->d:I

    .line 2
    .line 3
    check-cast p1, Lkw0/b;

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
    new-instance v0, Lfw0/o;

    .line 13
    .line 14
    iget-object p0, p0, Lfw0/o;->i:Ljava/util/List;

    .line 15
    .line 16
    const/4 v1, 0x1

    .line 17
    invoke-direct {v0, p0, p3, v1}, Lfw0/o;-><init>(Ljava/util/List;Lkotlin/coroutines/Continuation;I)V

    .line 18
    .line 19
    .line 20
    iput-object p1, v0, Lfw0/o;->g:Lkw0/b;

    .line 21
    .line 22
    iput-object p2, v0, Lfw0/o;->h:Ljava/lang/Throwable;

    .line 23
    .line 24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    invoke-virtual {v0, p0}, Lfw0/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_0
    new-instance v0, Lfw0/o;

    .line 32
    .line 33
    iget-object p0, p0, Lfw0/o;->i:Ljava/util/List;

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    invoke-direct {v0, p0, p3, v1}, Lfw0/o;-><init>(Ljava/util/List;Lkotlin/coroutines/Continuation;I)V

    .line 37
    .line 38
    .line 39
    iput-object p1, v0, Lfw0/o;->g:Lkw0/b;

    .line 40
    .line 41
    iput-object p2, v0, Lfw0/o;->h:Ljava/lang/Throwable;

    .line 42
    .line 43
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Lfw0/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lfw0/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lfw0/o;->g:Lkw0/b;

    .line 7
    .line 8
    iget-object v1, p0, Lfw0/o;->h:Ljava/lang/Throwable;

    .line 9
    .line 10
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v3, p0, Lfw0/o;->f:I

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    if-eqz v3, :cond_1

    .line 16
    .line 17
    if-ne v3, v4, :cond_0

    .line 18
    .line 19
    iget-object v2, p0, Lfw0/o;->e:Ljava/lang/Throwable;

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    invoke-static {v1}, Lmw0/a;->a(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    const/4 v1, 0x0

    .line 41
    iput-object v1, p0, Lfw0/o;->g:Lkw0/b;

    .line 42
    .line 43
    iput-object v1, p0, Lfw0/o;->h:Ljava/lang/Throwable;

    .line 44
    .line 45
    iput-object p1, p0, Lfw0/o;->e:Ljava/lang/Throwable;

    .line 46
    .line 47
    iput v4, p0, Lfw0/o;->f:I

    .line 48
    .line 49
    iget-object v1, p0, Lfw0/o;->i:Ljava/util/List;

    .line 50
    .line 51
    invoke-static {v1, p1, v0, p0}, Lfw0/s;->a(Ljava/util/List;Ljava/lang/Throwable;Lkw0/b;Lrx0/c;)V

    .line 52
    .line 53
    .line 54
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 55
    .line 56
    if-ne p0, v2, :cond_2

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_2
    move-object v2, p1

    .line 60
    :goto_0
    return-object v2

    .line 61
    :pswitch_0
    iget-object v0, p0, Lfw0/o;->g:Lkw0/b;

    .line 62
    .line 63
    iget-object v1, p0, Lfw0/o;->h:Ljava/lang/Throwable;

    .line 64
    .line 65
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 66
    .line 67
    iget v3, p0, Lfw0/o;->f:I

    .line 68
    .line 69
    const/4 v4, 0x1

    .line 70
    if-eqz v3, :cond_4

    .line 71
    .line 72
    if-ne v3, v4, :cond_3

    .line 73
    .line 74
    iget-object v2, p0, Lfw0/o;->e:Ljava/lang/Throwable;

    .line 75
    .line 76
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 81
    .line 82
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 83
    .line 84
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    invoke-static {v1}, Lmw0/a;->a(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    const/4 v1, 0x0

    .line 96
    iput-object v1, p0, Lfw0/o;->g:Lkw0/b;

    .line 97
    .line 98
    iput-object v1, p0, Lfw0/o;->h:Ljava/lang/Throwable;

    .line 99
    .line 100
    iput-object p1, p0, Lfw0/o;->e:Ljava/lang/Throwable;

    .line 101
    .line 102
    iput v4, p0, Lfw0/o;->f:I

    .line 103
    .line 104
    iget-object v1, p0, Lfw0/o;->i:Ljava/util/List;

    .line 105
    .line 106
    invoke-static {v1, p1, v0, p0}, Lfw0/s;->a(Ljava/util/List;Ljava/lang/Throwable;Lkw0/b;Lrx0/c;)V

    .line 107
    .line 108
    .line 109
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 110
    .line 111
    if-ne p0, v2, :cond_5

    .line 112
    .line 113
    goto :goto_1

    .line 114
    :cond_5
    move-object v2, p1

    .line 115
    :goto_1
    return-object v2

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
