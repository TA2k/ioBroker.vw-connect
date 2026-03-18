.class public final Lzc0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lbd0/a;


# instance fields
.field public final a:Lyy0/q1;

.field public final b:Lyy0/k1;

.field public final c:Lyy0/q1;

.field public final d:Lyy0/q1;


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x5

    .line 5
    const/4 v1, 0x1

    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-static {v1, v0, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lzc0/b;->a:Lyy0/q1;

    .line 12
    .line 13
    new-instance v1, Lyy0/k1;

    .line 14
    .line 15
    invoke-direct {v1, v0}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 16
    .line 17
    .line 18
    iput-object v1, p0, Lzc0/b;->b:Lyy0/k1;

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    const/4 v1, 0x6

    .line 22
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    iput-object v3, p0, Lzc0/b;->c:Lyy0/q1;

    .line 27
    .line 28
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iput-object v0, p0, Lzc0/b;->d:Lyy0/q1;

    .line 33
    .line 34
    return-void
.end method

.method public static final a(Lzc0/b;Lne0/t;ZLrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lzc0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lzc0/a;

    .line 7
    .line 8
    iget v1, v0, Lzc0/a;->g:I

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
    iput v1, v0, Lzc0/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzc0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lzc0/a;-><init>(Lzc0/b;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lzc0/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lzc0/a;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    iget-object p1, v0, Lzc0/a;->d:Lne0/e;

    .line 38
    .line 39
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    .line 41
    .line 42
    goto :goto_1

    .line 43
    :catchall_0
    move-exception v0

    .line 44
    move-object p0, v0

    .line 45
    goto :goto_2

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    instance-of p3, p1, Lne0/e;

    .line 58
    .line 59
    if-eqz p3, :cond_6

    .line 60
    .line 61
    if-eqz p2, :cond_5

    .line 62
    .line 63
    :try_start_1
    new-instance p2, Lyj0/c;

    .line 64
    .line 65
    const/4 p3, 0x7

    .line 66
    invoke-direct {p2, p0, v4, p3}, Lyj0/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 67
    .line 68
    .line 69
    move-object p0, p1

    .line 70
    check-cast p0, Lne0/e;

    .line 71
    .line 72
    iput-object p0, v0, Lzc0/a;->d:Lne0/e;

    .line 73
    .line 74
    iput v3, v0, Lzc0/a;->g:I

    .line 75
    .line 76
    const-wide/16 v2, 0x3e8

    .line 77
    .line 78
    invoke-static {v2, v3, p2, v0}, Lvy0/e0;->S(JLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    if-ne p0, v1, :cond_3

    .line 83
    .line 84
    return-object v1

    .line 85
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :goto_2
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    :goto_3
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 93
    .line 94
    .line 95
    move-result-object p2

    .line 96
    if-nez p2, :cond_4

    .line 97
    .line 98
    check-cast p0, Llx0/b0;

    .line 99
    .line 100
    goto :goto_4

    .line 101
    :cond_4
    new-instance v0, Lne0/c;

    .line 102
    .line 103
    new-instance v1, Lcd0/a;

    .line 104
    .line 105
    const-string p0, "Deeplink has been expected but not handled"

    .line 106
    .line 107
    invoke-direct {v1, p0, v4}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 108
    .line 109
    .line 110
    const/4 v4, 0x0

    .line 111
    const/16 v5, 0x1e

    .line 112
    .line 113
    const/4 v2, 0x0

    .line 114
    const/4 v3, 0x0

    .line 115
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 116
    .line 117
    .line 118
    move-object p1, v0

    .line 119
    :cond_5
    :goto_4
    return-object p1

    .line 120
    :cond_6
    instance-of p0, p1, Lne0/c;

    .line 121
    .line 122
    if-eqz p0, :cond_7

    .line 123
    .line 124
    return-object p1

    .line 125
    :cond_7
    new-instance p0, La8/r0;

    .line 126
    .line 127
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 128
    .line 129
    .line 130
    throw p0
.end method


# virtual methods
.method public final b(Ljava/net/URL;ZZZZ)Lyy0/m1;
    .locals 6

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    new-instance v0, Lzc0/d;

    .line 3
    .line 4
    move-object v1, p1

    .line 5
    move v2, p2

    .line 6
    move v3, p3

    .line 7
    move v4, p4

    .line 8
    move v5, p5

    .line 9
    invoke-direct/range {v0 .. v5}, Lzc0/d;-><init>(Ljava/net/URL;ZZZZ)V

    .line 10
    .line 11
    .line 12
    iget-object p1, p0, Lzc0/b;->a:Lyy0/q1;

    .line 13
    .line 14
    invoke-virtual {p1, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    new-instance p1, Lau0/b;

    .line 18
    .line 19
    const/4 p2, 0x0

    .line 20
    const/16 p3, 0xb

    .line 21
    .line 22
    invoke-direct {p1, p0, v4, p2, p3}, Lau0/b;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    new-instance p2, Lyy0/m1;

    .line 26
    .line 27
    invoke-direct {p2, p1}, Lyy0/m1;-><init>(Lay0/n;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    .line 29
    .line 30
    monitor-exit p0

    .line 31
    return-object p2

    .line 32
    :catchall_0
    move-exception v0

    .line 33
    move-object p1, v0

    .line 34
    monitor-exit p0

    .line 35
    throw p1
.end method
