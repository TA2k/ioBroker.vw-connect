.class public final Ldf/d;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lay0/k;

.field public final e:Li91/i4;

.field public final f:Lyy0/c2;

.field public final g:Lyy0/l1;


# direct methods
.method public constructor <init>(Ljava/util/List;Lay0/k;Li91/i4;)V
    .locals 6

    .line 1
    const-string v0, "goToNext"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Ldf/d;->d:Lay0/k;

    .line 10
    .line 11
    iput-object p3, p0, Ldf/d;->e:Li91/i4;

    .line 12
    .line 13
    sget p2, Ldf/c;->c:I

    .line 14
    .line 15
    sget-object p2, Lje/y;->f:Lsx0/b;

    .line 16
    .line 17
    new-instance p3, Ljava/util/ArrayList;

    .line 18
    .line 19
    const/16 v0, 0xa

    .line 20
    .line 21
    invoke-static {p2, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    invoke-direct {p3, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p2}, Lmx0/e;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p2

    .line 32
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    const/4 v1, 0x0

    .line 37
    const/4 v2, 0x0

    .line 38
    if-eqz v0, :cond_3

    .line 39
    .line 40
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    check-cast v0, Lje/y;

    .line 45
    .line 46
    move-object v3, p1

    .line 47
    check-cast v3, Ljava/lang/Iterable;

    .line 48
    .line 49
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    :cond_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    if-eqz v4, :cond_1

    .line 58
    .line 59
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    move-object v5, v4

    .line 64
    check-cast v5, Lje/z;

    .line 65
    .line 66
    iget-object v5, v5, Lje/z;->d:Lje/y;

    .line 67
    .line 68
    if-ne v5, v0, :cond_0

    .line 69
    .line 70
    move-object v1, v4

    .line 71
    :cond_1
    if-eqz v1, :cond_2

    .line 72
    .line 73
    const/4 v2, 0x1

    .line 74
    :cond_2
    new-instance v1, Ldf/a;

    .line 75
    .line 76
    new-instance v3, Lje/z;

    .line 77
    .line 78
    invoke-direct {v3, v0}, Lje/z;-><init>(Lje/y;)V

    .line 79
    .line 80
    .line 81
    xor-int/lit8 v0, v2, 0x1

    .line 82
    .line 83
    invoke-direct {v1, v3, v2, v0}, Ldf/a;-><init>(Lje/z;ZZ)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p3, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_3
    new-instance p1, Ldf/c;

    .line 91
    .line 92
    invoke-direct {p1, p3, v2}, Ldf/c;-><init>(Ljava/util/ArrayList;Z)V

    .line 93
    .line 94
    .line 95
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    iput-object p1, p0, Ldf/d;->f:Lyy0/c2;

    .line 100
    .line 101
    new-instance p2, Lyy0/l1;

    .line 102
    .line 103
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 104
    .line 105
    .line 106
    iput-object p2, p0, Ldf/d;->g:Lyy0/l1;

    .line 107
    .line 108
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    new-instance p2, La50/a;

    .line 113
    .line 114
    const/16 p3, 0x1b

    .line 115
    .line 116
    invoke-direct {p2, p0, v1, p3}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 117
    .line 118
    .line 119
    const/4 p0, 0x3

    .line 120
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 121
    .line 122
    .line 123
    return-void
.end method

.method public static a(Lyy0/a2;)Ljava/util/ArrayList;
    .locals 4

    .line 1
    invoke-interface {p0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Ldf/c;

    .line 6
    .line 7
    iget-object p0, p0, Ldf/c;->b:Ljava/util/ArrayList;

    .line 8
    .line 9
    new-instance v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    move-object v2, v1

    .line 29
    check-cast v2, Ldf/a;

    .line 30
    .line 31
    iget-boolean v3, v2, Ldf/a;->b:Z

    .line 32
    .line 33
    if-eqz v3, :cond_0

    .line 34
    .line 35
    iget-boolean v2, v2, Ldf/a;->c:Z

    .line 36
    .line 37
    if-eqz v2, :cond_0

    .line 38
    .line 39
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    new-instance p0, Ljava/util/ArrayList;

    .line 44
    .line 45
    const/16 v1, 0xa

    .line 46
    .line 47
    invoke-static {v0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    invoke-direct {p0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-eqz v1, :cond_2

    .line 63
    .line 64
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    check-cast v1, Ldf/a;

    .line 69
    .line 70
    iget-object v1, v1, Ldf/a;->a:Lje/z;

    .line 71
    .line 72
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_2
    return-object p0
.end method
