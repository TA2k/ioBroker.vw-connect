.class public final Lyy0/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:Lyy0/i;

.field public final synthetic e:Lrx0/i;


# direct methods
.method public constructor <init>(Lyy0/i;Lay0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyy0/x;->d:Lyy0/i;

    .line 5
    .line 6
    check-cast p2, Lrx0/i;

    .line 7
    .line 8
    iput-object p2, p0, Lyy0/x;->e:Lrx0/i;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lyy0/w;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lyy0/w;

    .line 7
    .line 8
    iget v1, v0, Lyy0/w;->e:I

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
    iput v1, v0, Lyy0/w;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyy0/w;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lyy0/w;-><init>(Lyy0/x;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lyy0/w;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyy0/w;->e:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    const/4 v6, 0x0

    .line 35
    if-eqz v2, :cond_4

    .line 36
    .line 37
    if-eq v2, v5, :cond_3

    .line 38
    .line 39
    if-eq v2, v4, :cond_2

    .line 40
    .line 41
    if-ne v2, v3, :cond_1

    .line 42
    .line 43
    iget-object p0, v0, Lyy0/w;->g:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Lzy0/r;

    .line 46
    .line 47
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    .line 50
    goto :goto_2

    .line 51
    :catchall_0
    move-exception p1

    .line 52
    goto :goto_3

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_2
    iget-object p0, v0, Lyy0/w;->g:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p0, Ljava/lang/Throwable;

    .line 64
    .line 65
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_6

    .line 69
    :cond_3
    iget-object p1, v0, Lyy0/w;->h:Lyy0/j;

    .line 70
    .line 71
    iget-object p0, v0, Lyy0/w;->g:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p0, Lyy0/x;

    .line 74
    .line 75
    :try_start_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 76
    .line 77
    .line 78
    goto :goto_1

    .line 79
    :catchall_1
    move-exception p1

    .line 80
    move-object v7, p1

    .line 81
    move-object p1, p0

    .line 82
    move-object p0, v7

    .line 83
    goto :goto_4

    .line 84
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    :try_start_2
    iget-object p2, p0, Lyy0/x;->d:Lyy0/i;

    .line 88
    .line 89
    iput-object p0, v0, Lyy0/w;->g:Ljava/lang/Object;

    .line 90
    .line 91
    iput-object p1, v0, Lyy0/w;->h:Lyy0/j;

    .line 92
    .line 93
    iput v5, v0, Lyy0/w;->e:I

    .line 94
    .line 95
    invoke-interface {p2, p1, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 99
    if-ne p2, v1, :cond_5

    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_5
    :goto_1
    new-instance p2, Lzy0/r;

    .line 103
    .line 104
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    invoke-direct {p2, p1, v2}, Lzy0/r;-><init>(Lyy0/j;Lpx0/g;)V

    .line 109
    .line 110
    .line 111
    :try_start_3
    iget-object p0, p0, Lyy0/x;->e:Lrx0/i;

    .line 112
    .line 113
    iput-object p2, v0, Lyy0/w;->g:Ljava/lang/Object;

    .line 114
    .line 115
    iput-object v6, v0, Lyy0/w;->h:Lyy0/j;

    .line 116
    .line 117
    iput v3, v0, Lyy0/w;->e:I

    .line 118
    .line 119
    invoke-interface {p0, p2, v6, v0}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 123
    if-ne p0, v1, :cond_6

    .line 124
    .line 125
    goto :goto_5

    .line 126
    :cond_6
    move-object p0, p2

    .line 127
    :goto_2
    invoke-virtual {p0}, Lrx0/c;->releaseIntercepted()V

    .line 128
    .line 129
    .line 130
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 131
    .line 132
    return-object p0

    .line 133
    :catchall_2
    move-exception p1

    .line 134
    move-object p0, p2

    .line 135
    :goto_3
    invoke-virtual {p0}, Lrx0/c;->releaseIntercepted()V

    .line 136
    .line 137
    .line 138
    throw p1

    .line 139
    :goto_4
    new-instance p2, Lyy0/i2;

    .line 140
    .line 141
    invoke-direct {p2, p0}, Lyy0/i2;-><init>(Ljava/lang/Throwable;)V

    .line 142
    .line 143
    .line 144
    iget-object p1, p1, Lyy0/x;->e:Lrx0/i;

    .line 145
    .line 146
    iput-object p0, v0, Lyy0/w;->g:Ljava/lang/Object;

    .line 147
    .line 148
    iput-object v6, v0, Lyy0/w;->h:Lyy0/j;

    .line 149
    .line 150
    iput v4, v0, Lyy0/w;->e:I

    .line 151
    .line 152
    invoke-static {p2, p1, p0, v0}, Lyy0/u;->e(Lyy0/i2;Lay0/o;Ljava/lang/Throwable;Lrx0/c;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object p1

    .line 156
    if-ne p1, v1, :cond_7

    .line 157
    .line 158
    :goto_5
    return-object v1

    .line 159
    :cond_7
    :goto_6
    throw p0
.end method
