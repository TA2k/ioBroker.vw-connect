.class public final Lc00/q1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:Lc00/t1;

.field public final synthetic e:J

.field public final synthetic f:Z


# direct methods
.method public constructor <init>(Lc00/t1;JZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc00/q1;->d:Lc00/t1;

    .line 5
    .line 6
    iput-wide p2, p0, Lc00/q1;->e:J

    .line 7
    .line 8
    iput-boolean p4, p0, Lc00/q1;->f:Z

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    check-cast p1, Lne0/t;

    .line 2
    .line 3
    instance-of v0, p1, Lne0/c;

    .line 4
    .line 5
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v2, p0, Lc00/q1;->d:Lc00/t1;

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    iget-object p0, v2, Lc00/t1;->m:Ljn0/c;

    .line 12
    .line 13
    check-cast p1, Lne0/c;

    .line 14
    .line 15
    invoke-virtual {p0, p1, p2}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    if-ne p0, p1, :cond_0

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_0
    return-object v1

    .line 25
    :cond_1
    instance-of p1, p1, Lne0/e;

    .line 26
    .line 27
    if-eqz p1, :cond_4

    .line 28
    .line 29
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    iget-object p2, v2, Lc00/t1;->i:Lij0/a;

    .line 34
    .line 35
    check-cast p1, Lc00/n1;

    .line 36
    .line 37
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    check-cast v0, Lc00/n1;

    .line 42
    .line 43
    iget-object v0, v0, Lc00/n1;->c:Ljava/util/List;

    .line 44
    .line 45
    check-cast v0, Ljava/lang/Iterable;

    .line 46
    .line 47
    new-instance v3, Ljava/util/ArrayList;

    .line 48
    .line 49
    const/16 v4, 0xa

    .line 50
    .line 51
    invoke-static {v0, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 56
    .line 57
    .line 58
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    if-eqz v4, :cond_3

    .line 67
    .line 68
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    check-cast v4, Lc00/m1;

    .line 73
    .line 74
    iget-wide v5, v4, Lc00/m1;->a:J

    .line 75
    .line 76
    iget-wide v7, p0, Lc00/q1;->e:J

    .line 77
    .line 78
    cmp-long v5, v5, v7

    .line 79
    .line 80
    invoke-static {v4, p2}, Ljp/fc;->h(Lc00/m1;Lij0/a;)Lc00/m1;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    if-nez v5, :cond_2

    .line 85
    .line 86
    const/4 v5, 0x0

    .line 87
    const/16 v6, 0x17f

    .line 88
    .line 89
    iget-boolean v7, p0, Lc00/q1;->f:Z

    .line 90
    .line 91
    invoke-static {v4, v5, v7, v6}, Lc00/m1;->a(Lc00/m1;Ljava/lang/String;ZI)Lc00/m1;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    :cond_2
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_3
    const/16 p0, 0xb

    .line 100
    .line 101
    const/4 p2, 0x0

    .line 102
    invoke-static {p1, p2, v3, p0}, Lc00/n1;->a(Lc00/n1;ZLjava/util/List;I)Lc00/n1;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 107
    .line 108
    .line 109
    return-object v1

    .line 110
    :cond_4
    new-instance p0, La8/r0;

    .line 111
    .line 112
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 113
    .line 114
    .line 115
    throw p0
.end method
