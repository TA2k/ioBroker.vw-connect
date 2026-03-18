.class public abstract Lzy0/f;
.super Lzy0/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:Lyy0/i;


# direct methods
.method public constructor <init>(Lyy0/i;Lpx0/g;ILxy0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0, p2, p3, p4}, Lzy0/e;-><init>(Lpx0/g;ILxy0/a;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzy0/f;->g:Lyy0/i;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lzy0/e;->e:I

    .line 2
    .line 3
    const/4 v1, -0x3

    .line 4
    if-ne v0, v1, :cond_4

    .line 5
    .line 6
    invoke-interface {p2}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 11
    .line 12
    new-instance v2, Lvj0/b;

    .line 13
    .line 14
    const/16 v3, 0x16

    .line 15
    .line 16
    invoke-direct {v2, v3}, Lvj0/b;-><init>(I)V

    .line 17
    .line 18
    .line 19
    iget-object v3, p0, Lzy0/e;->d:Lpx0/g;

    .line 20
    .line 21
    invoke-interface {v3, v1, v2}, Lpx0/g;->fold(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    check-cast v1, Ljava/lang/Boolean;

    .line 26
    .line 27
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-nez v1, :cond_0

    .line 32
    .line 33
    invoke-interface {v0, v3}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 v1, 0x0

    .line 39
    invoke-static {v0, v3, v1}, Lvy0/e0;->s(Lpx0/g;Lpx0/g;Z)Lpx0/g;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    :goto_0
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-eqz v2, :cond_1

    .line 48
    .line 49
    invoke-virtual {p0, p1, p2}, Lzy0/f;->i(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 54
    .line 55
    if-ne p0, p1, :cond_5

    .line 56
    .line 57
    return-object p0

    .line 58
    :cond_1
    sget-object v2, Lpx0/c;->d:Lpx0/c;

    .line 59
    .line 60
    invoke-interface {v1, v2}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    invoke-interface {v0, v2}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    if-eqz v0, :cond_4

    .line 73
    .line 74
    invoke-interface {p2}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    instance-of v2, p1, Lzy0/u;

    .line 79
    .line 80
    if-nez v2, :cond_3

    .line 81
    .line 82
    instance-of v2, p1, Lzy0/q;

    .line 83
    .line 84
    if-eqz v2, :cond_2

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_2
    new-instance v2, Laa/h0;

    .line 88
    .line 89
    invoke-direct {v2, p1, v0}, Laa/h0;-><init>(Lyy0/j;Lpx0/g;)V

    .line 90
    .line 91
    .line 92
    move-object p1, v2

    .line 93
    :cond_3
    :goto_1
    new-instance v0, Lyz/b;

    .line 94
    .line 95
    const/4 v2, 0x0

    .line 96
    const/16 v3, 0xa

    .line 97
    .line 98
    invoke-direct {v0, p0, v2, v3}, Lyz/b;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 99
    .line 100
    .line 101
    invoke-static {v1}, Laz0/b;->m(Lpx0/g;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    invoke-static {v1, p1, p0, v0, p2}, Lzy0/c;->c(Lpx0/g;Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 110
    .line 111
    if-ne p0, p1, :cond_5

    .line 112
    .line 113
    return-object p0

    .line 114
    :cond_4
    invoke-super {p0, p1, p2}, Lzy0/e;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 119
    .line 120
    if-ne p0, p1, :cond_5

    .line 121
    .line 122
    return-object p0

    .line 123
    :cond_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 124
    .line 125
    return-object p0
.end method

.method public final e(Lxy0/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance v0, Lzy0/u;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lzy0/u;-><init>(Lxy0/x;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0, p2}, Lzy0/f;->i(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    if-ne p0, p1, :cond_0

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0
.end method

.method public abstract i(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lzy0/f;->g:Lyy0/i;

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string v1, " -> "

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-super {p0}, Lzy0/e;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method
