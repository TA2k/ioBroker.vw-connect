.class public final Lyy0/m1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final e:Lrx0/i;


# direct methods
.method public constructor <init>(Lay0/n;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lyy0/m1;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    check-cast p1, Lrx0/i;

    iput-object p1, p0, Lyy0/m1;->e:Lrx0/i;

    return-void
.end method

.method public constructor <init>(Lay0/o;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lyy0/m1;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    check-cast p1, Lrx0/i;

    iput-object p1, p0, Lyy0/m1;->e:Lrx0/i;

    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lyy0/m1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lws/b;

    .line 7
    .line 8
    iget-object p0, p0, Lyy0/m1;->e:Lrx0/i;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, p0, p1, v1}, Lws/b;-><init>(Lay0/o;Lyy0/j;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    new-instance p0, Lvy0/y1;

    .line 15
    .line 16
    invoke-interface {p2}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    const/4 v1, 0x1

    .line 21
    invoke-direct {p0, p1, p2, v1}, Lvy0/y1;-><init>(Lpx0/g;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    const/4 p1, 0x1

    .line 25
    invoke-static {p0, p1, p0, v0}, Ljp/rb;->a(Laz0/p;ZLaz0/p;Lay0/n;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    if-ne p0, p1, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    :goto_0
    return-object p0

    .line 37
    :pswitch_0
    instance-of v0, p2, Lyy0/a;

    .line 38
    .line 39
    if-eqz v0, :cond_1

    .line 40
    .line 41
    move-object v0, p2

    .line 42
    check-cast v0, Lyy0/a;

    .line 43
    .line 44
    iget v1, v0, Lyy0/a;->g:I

    .line 45
    .line 46
    const/high16 v2, -0x80000000

    .line 47
    .line 48
    and-int v3, v1, v2

    .line 49
    .line 50
    if-eqz v3, :cond_1

    .line 51
    .line 52
    sub-int/2addr v1, v2

    .line 53
    iput v1, v0, Lyy0/a;->g:I

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_1
    new-instance v0, Lyy0/a;

    .line 57
    .line 58
    invoke-direct {v0, p0, p2}, Lyy0/a;-><init>(Lyy0/m1;Lkotlin/coroutines/Continuation;)V

    .line 59
    .line 60
    .line 61
    :goto_1
    iget-object p2, v0, Lyy0/a;->e:Ljava/lang/Object;

    .line 62
    .line 63
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 64
    .line 65
    iget v2, v0, Lyy0/a;->g:I

    .line 66
    .line 67
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    const/4 v4, 0x1

    .line 70
    if-eqz v2, :cond_3

    .line 71
    .line 72
    if-ne v2, v4, :cond_2

    .line 73
    .line 74
    iget-object p0, v0, Lyy0/a;->d:Lzy0/r;

    .line 75
    .line 76
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 77
    .line 78
    .line 79
    goto :goto_3

    .line 80
    :catchall_0
    move-exception p1

    .line 81
    goto :goto_6

    .line 82
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 83
    .line 84
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 85
    .line 86
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw p0

    .line 90
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    new-instance p2, Lzy0/r;

    .line 94
    .line 95
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    invoke-direct {p2, p1, v2}, Lzy0/r;-><init>(Lyy0/j;Lpx0/g;)V

    .line 100
    .line 101
    .line 102
    :try_start_1
    iput-object p2, v0, Lyy0/a;->d:Lzy0/r;

    .line 103
    .line 104
    iput v4, v0, Lyy0/a;->g:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 105
    .line 106
    :try_start_2
    iget-object p0, p0, Lyy0/m1;->e:Lrx0/i;

    .line 107
    .line 108
    invoke-interface {p0, p2, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 112
    if-ne p0, v1, :cond_4

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_4
    move-object p0, v3

    .line 116
    :goto_2
    if-ne p0, v1, :cond_5

    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_5
    move-object p0, p2

    .line 120
    :goto_3
    invoke-virtual {p0}, Lrx0/c;->releaseIntercepted()V

    .line 121
    .line 122
    .line 123
    move-object v1, v3

    .line 124
    :goto_4
    return-object v1

    .line 125
    :catchall_1
    move-exception p0

    .line 126
    move-object p1, p0

    .line 127
    :goto_5
    move-object p0, p2

    .line 128
    goto :goto_6

    .line 129
    :catchall_2
    move-exception p1

    .line 130
    goto :goto_5

    .line 131
    :goto_6
    invoke-virtual {p0}, Lrx0/c;->releaseIntercepted()V

    .line 132
    .line 133
    .line 134
    throw p1

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
