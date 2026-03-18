.class public final Lw31/g;
.super Lq41/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lz9/y;

.field public final g:Ljava/util/Calendar;

.field public final h:Ljava/util/Locale;

.field public final i:Lk31/m;

.field public final j:Lk31/o;

.field public final k:Lk31/l0;

.field public final l:Lk31/n;

.field public m:Li31/h;


# direct methods
.method public constructor <init>(Lz9/y;Ljava/util/Calendar;Ljava/util/Locale;Lk31/m;Lk31/o;Lk31/l0;Lk31/n;)V
    .locals 4

    .line 1
    new-instance v0, Lw31/h;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v2, v2, v3}, Lw31/h;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Z)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lq41/b;-><init>(Lq41/a;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lw31/g;->f:Lz9/y;

    .line 14
    .line 15
    iput-object p2, p0, Lw31/g;->g:Ljava/util/Calendar;

    .line 16
    .line 17
    iput-object p3, p0, Lw31/g;->h:Ljava/util/Locale;

    .line 18
    .line 19
    iput-object p4, p0, Lw31/g;->i:Lk31/m;

    .line 20
    .line 21
    iput-object p5, p0, Lw31/g;->j:Lk31/o;

    .line 22
    .line 23
    iput-object p6, p0, Lw31/g;->k:Lk31/l0;

    .line 24
    .line 25
    iput-object p7, p0, Lw31/g;->l:Lk31/n;

    .line 26
    .line 27
    invoke-virtual {p7}, Lk31/n;->invoke()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    check-cast p1, Li31/j;

    .line 32
    .line 33
    if-eqz p1, :cond_0

    .line 34
    .line 35
    iget-boolean v3, p1, Li31/j;->c:Z

    .line 36
    .line 37
    :cond_0
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    new-instance p2, Lac0/m;

    .line 42
    .line 43
    const/16 p3, 0xd

    .line 44
    .line 45
    invoke-direct {p2, p0, v3, v1, p3}, Lac0/m;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 46
    .line 47
    .line 48
    const/4 p0, 0x3

    .line 49
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public static b(Ljava/util/List;)Ljava/util/ArrayList;
    .locals 5

    .line 1
    check-cast p0, Ljava/lang/Iterable;

    .line 2
    .line 3
    new-instance v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    const/16 v1, 0xa

    .line 6
    .line 7
    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Li31/e0;

    .line 29
    .line 30
    new-instance v2, Lp31/g;

    .line 31
    .line 32
    iget-object v3, v1, Li31/e0;->d:Ljava/lang/String;

    .line 33
    .line 34
    const/4 v4, 0x0

    .line 35
    invoke-direct {v2, v1, v3, v4}, Lp31/g;-><init>(Ljava/lang/Object;Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    new-instance p0, Ljava/util/ArrayList;

    .line 43
    .line 44
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    :cond_1
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_2

    .line 56
    .line 57
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    move-object v2, v1

    .line 62
    check-cast v2, Lp31/g;

    .line 63
    .line 64
    iget-object v2, v2, Lp31/g;->b:Ljava/lang/String;

    .line 65
    .line 66
    invoke-static {v2}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    if-nez v2, :cond_1

    .line 71
    .line 72
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_2
    new-instance v0, Ljava/util/HashSet;

    .line 77
    .line 78
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 79
    .line 80
    .line 81
    new-instance v1, Ljava/util/ArrayList;

    .line 82
    .line 83
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    :cond_3
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    if-eqz v2, :cond_4

    .line 95
    .line 96
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    move-object v3, v2

    .line 101
    check-cast v3, Lp31/g;

    .line 102
    .line 103
    iget-object v3, v3, Lp31/g;->b:Ljava/lang/String;

    .line 104
    .line 105
    invoke-virtual {v0, v3}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v3

    .line 109
    if-eqz v3, :cond_3

    .line 110
    .line 111
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_4
    return-object v1
.end method
