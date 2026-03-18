.class public final Lp6/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ldy0/b;


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Lb3/g;

.field public final f:Lay0/k;

.field public final g:Lvy0/b0;

.field public final h:Ljava/lang/Object;

.field public volatile i:Lq6/c;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lb3/g;Lay0/k;Lvy0/b0;)V
    .locals 1

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lp6/b;->d:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p2, p0, Lp6/b;->e:Lb3/g;

    .line 12
    .line 13
    iput-object p3, p0, Lp6/b;->f:Lay0/k;

    .line 14
    .line 15
    iput-object p4, p0, Lp6/b;->g:Lvy0/b0;

    .line 16
    .line 17
    new-instance p1, Ljava/lang/Object;

    .line 18
    .line 19
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object p1, p0, Lp6/b;->h:Ljava/lang/Object;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Landroid/content/Context;

    .line 2
    .line 3
    const-string v0, "thisRef"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "property"

    .line 9
    .line 10
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p2, p0, Lp6/b;->i:Lq6/c;

    .line 14
    .line 15
    if-nez p2, :cond_2

    .line 16
    .line 17
    iget-object p2, p0, Lp6/b;->h:Ljava/lang/Object;

    .line 18
    .line 19
    monitor-enter p2

    .line 20
    :try_start_0
    iget-object v0, p0, Lp6/b;->i:Lq6/c;

    .line 21
    .line 22
    if-nez v0, :cond_1

    .line 23
    .line 24
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    iget-object v0, p0, Lp6/b;->e:Lb3/g;

    .line 29
    .line 30
    iget-object v1, p0, Lp6/b;->f:Lay0/k;

    .line 31
    .line 32
    const-string v2, "applicationContext"

    .line 33
    .line 34
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-interface {v1, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Ljava/util/List;

    .line 42
    .line 43
    iget-object v2, p0, Lp6/b;->g:Lvy0/b0;

    .line 44
    .line 45
    new-instance v3, La4/b;

    .line 46
    .line 47
    const/4 v4, 0x6

    .line 48
    invoke-direct {v3, v4, p1, p0}, La4/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    const-string p1, "migrations"

    .line 52
    .line 53
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    new-instance p1, Lm6/b0;

    .line 57
    .line 58
    sget-object v4, Lq6/d;->a:Lq6/d;

    .line 59
    .line 60
    new-instance v5, La7/j;

    .line 61
    .line 62
    const/16 v6, 0x12

    .line 63
    .line 64
    invoke-direct {v5, v3, v6}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 65
    .line 66
    .line 67
    sget-object v3, Lm6/a0;->f:Lm6/a0;

    .line 68
    .line 69
    invoke-direct {p1, v4, v3, v5}, Lm6/b0;-><init>(Lm6/u0;Lay0/k;Lay0/a;)V

    .line 70
    .line 71
    .line 72
    new-instance v3, Lq6/c;

    .line 73
    .line 74
    if-eqz v0, :cond_0

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_0
    new-instance v0, La61/a;

    .line 78
    .line 79
    const/16 v4, 0xa

    .line 80
    .line 81
    invoke-direct {v0, v4}, La61/a;-><init>(I)V

    .line 82
    .line 83
    .line 84
    :goto_0
    new-instance v4, Lk31/t;

    .line 85
    .line 86
    const/4 v5, 0x0

    .line 87
    const/16 v6, 0x13

    .line 88
    .line 89
    invoke-direct {v4, v1, v5, v6}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 90
    .line 91
    .line 92
    invoke-static {v4}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    new-instance v4, Lm6/w;

    .line 97
    .line 98
    invoke-direct {v4, p1, v1, v0, v2}, Lm6/w;-><init>(Lm6/b0;Ljava/util/List;Lm6/c;Lvy0/b0;)V

    .line 99
    .line 100
    .line 101
    invoke-direct {v3, v4}, Lq6/c;-><init>(Lm6/g;)V

    .line 102
    .line 103
    .line 104
    new-instance p1, Lq6/c;

    .line 105
    .line 106
    invoke-direct {p1, v3}, Lq6/c;-><init>(Lm6/g;)V

    .line 107
    .line 108
    .line 109
    iput-object p1, p0, Lp6/b;->i:Lq6/c;

    .line 110
    .line 111
    goto :goto_1

    .line 112
    :catchall_0
    move-exception p0

    .line 113
    goto :goto_2

    .line 114
    :cond_1
    :goto_1
    iget-object p0, p0, Lp6/b;->i:Lq6/c;

    .line 115
    .line 116
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 117
    .line 118
    .line 119
    monitor-exit p2

    .line 120
    return-object p0

    .line 121
    :goto_2
    monitor-exit p2

    .line 122
    throw p0

    .line 123
    :cond_2
    return-object p2
.end method
