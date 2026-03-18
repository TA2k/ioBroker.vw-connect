.class public final Lvy/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy/v;


# direct methods
.method public synthetic constructor <init>(Lvy/v;I)V
    .locals 0

    .line 1
    iput p2, p0, Lvy/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvy/r;->e:Lvy/v;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b(Lne0/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p2, Lvy/t;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lvy/t;

    .line 7
    .line 8
    iget v1, v0, Lvy/t;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lvy/t;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lvy/t;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lvy/t;-><init>(Lvy/r;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lvy/t;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lvy/t;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    iget-object p0, p0, Lvy/r;->e:Lvy/v;

    .line 33
    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v3, :cond_1

    .line 37
    .line 38
    iget-object p1, v0, Lvy/t;->d:Lvy/v;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    instance-of p2, p1, Lne0/c;

    .line 56
    .line 57
    if-eqz p2, :cond_4

    .line 58
    .line 59
    iget-object p2, p0, Lvy/v;->k:Ljn0/c;

    .line 60
    .line 61
    check-cast p1, Lne0/c;

    .line 62
    .line 63
    iput-object p0, v0, Lvy/t;->d:Lvy/v;

    .line 64
    .line 65
    iput v3, v0, Lvy/t;->g:I

    .line 66
    .line 67
    invoke-virtual {p2, p1, v0}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    if-ne p1, v1, :cond_3

    .line 72
    .line 73
    return-object v1

    .line 74
    :cond_3
    move-object p1, p0

    .line 75
    :goto_1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 76
    .line 77
    .line 78
    move-result-object p2

    .line 79
    move-object v0, p2

    .line 80
    check-cast v0, Lvy/p;

    .line 81
    .line 82
    iget-object v3, p0, Lvy/v;->w:Lvy/o;

    .line 83
    .line 84
    const/4 v6, 0x0

    .line 85
    const/16 v7, 0x1df

    .line 86
    .line 87
    const/4 v1, 0x0

    .line 88
    const/4 v2, 0x0

    .line 89
    const/4 v4, 0x0

    .line 90
    const/4 v5, 0x0

    .line 91
    invoke-static/range {v0 .. v7}, Lvy/p;->a(Lvy/p;ZZLvy/o;Lbo0/l;Lvy/n;ZI)Lvy/p;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    move-object v8, p1

    .line 96
    move-object p1, p0

    .line 97
    move-object p0, v8

    .line 98
    goto :goto_2

    .line 99
    :cond_4
    instance-of p1, p1, Lne0/e;

    .line 100
    .line 101
    if-eqz p1, :cond_5

    .line 102
    .line 103
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    check-cast p1, Lvy/p;

    .line 108
    .line 109
    sget-object p2, Lvy/o;->h:Lvy/o;

    .line 110
    .line 111
    invoke-static {p1, p2}, Llp/pc;->h(Lvy/p;Lvy/o;)Lvy/p;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    :goto_2
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 116
    .line 117
    .line 118
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    return-object p0

    .line 121
    :cond_5
    new-instance p0, La8/r0;

    .line 122
    .line 123
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 124
    .line 125
    .line 126
    throw p0
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lvy/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/t;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2}, Lvy/r;->b(Lne0/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 14
    .line 15
    iget-object p0, p0, Lvy/r;->e:Lvy/v;

    .line 16
    .line 17
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 18
    .line 19
    .line 20
    move-result-object p2

    .line 21
    move-object v0, p2

    .line 22
    check-cast v0, Lvy/p;

    .line 23
    .line 24
    sget-object p2, Lne0/d;->a:Lne0/d;

    .line 25
    .line 26
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    const/4 v6, 0x0

    .line 31
    const/16 v7, 0x1f7

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    const/4 v3, 0x0

    .line 35
    const/4 v4, 0x0

    .line 36
    const/4 v5, 0x0

    .line 37
    invoke-static/range {v0 .. v7}, Lvy/p;->a(Lvy/p;ZZLvy/o;Lbo0/l;Lvy/n;ZI)Lvy/p;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 42
    .line 43
    .line 44
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_1
    check-cast p1, Lne0/t;

    .line 48
    .line 49
    instance-of v0, p1, Lne0/c;

    .line 50
    .line 51
    if-eqz v0, :cond_0

    .line 52
    .line 53
    iget-object p0, p0, Lvy/r;->e:Lvy/v;

    .line 54
    .line 55
    iget-object p0, p0, Lvy/v;->k:Ljn0/c;

    .line 56
    .line 57
    check-cast p1, Lne0/c;

    .line 58
    .line 59
    invoke-virtual {p0, p1, p2}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 64
    .line 65
    if-ne p0, p1, :cond_0

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    :goto_0
    return-object p0

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
