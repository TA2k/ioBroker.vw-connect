.class public abstract Llp/rc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lay0/k;)Lvz0/t;
    .locals 15

    .line 1
    sget-object v0, Lvz0/d;->d:Lvz0/c;

    .line 2
    .line 3
    const-string v1, "from"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lvz0/i;

    .line 9
    .line 10
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    iget-object v2, v0, Lvz0/d;->a:Lvz0/k;

    .line 14
    .line 15
    iget-boolean v3, v2, Lvz0/k;->a:Z

    .line 16
    .line 17
    iput-boolean v3, v1, Lvz0/i;->a:Z

    .line 18
    .line 19
    iget-boolean v3, v2, Lvz0/k;->e:Z

    .line 20
    .line 21
    iput-boolean v3, v1, Lvz0/i;->b:Z

    .line 22
    .line 23
    iget-boolean v3, v2, Lvz0/k;->b:Z

    .line 24
    .line 25
    iput-boolean v3, v1, Lvz0/i;->c:Z

    .line 26
    .line 27
    iget-boolean v3, v2, Lvz0/k;->c:Z

    .line 28
    .line 29
    iput-boolean v3, v1, Lvz0/i;->d:Z

    .line 30
    .line 31
    iget-object v10, v2, Lvz0/k;->f:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v11, v2, Lvz0/k;->g:Ljava/lang/String;

    .line 34
    .line 35
    iget-object v14, v2, Lvz0/k;->j:Lvz0/a;

    .line 36
    .line 37
    iget-boolean v13, v2, Lvz0/k;->i:Z

    .line 38
    .line 39
    iget-boolean v3, v2, Lvz0/k;->h:Z

    .line 40
    .line 41
    iput-boolean v3, v1, Lvz0/i;->e:Z

    .line 42
    .line 43
    iget-boolean v2, v2, Lvz0/k;->d:Z

    .line 44
    .line 45
    iput-boolean v2, v1, Lvz0/i;->f:Z

    .line 46
    .line 47
    iget-object v0, v0, Lvz0/d;->b:Lwq/f;

    .line 48
    .line 49
    invoke-interface {p0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    const-string p0, "    "

    .line 53
    .line 54
    invoke-static {v10, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    if-eqz p0, :cond_1

    .line 59
    .line 60
    new-instance v4, Lvz0/k;

    .line 61
    .line 62
    iget-boolean v5, v1, Lvz0/i;->a:Z

    .line 63
    .line 64
    iget-boolean v6, v1, Lvz0/i;->c:Z

    .line 65
    .line 66
    iget-boolean v7, v1, Lvz0/i;->d:Z

    .line 67
    .line 68
    iget-boolean v8, v1, Lvz0/i;->f:Z

    .line 69
    .line 70
    iget-boolean v9, v1, Lvz0/i;->b:Z

    .line 71
    .line 72
    iget-boolean v12, v1, Lvz0/i;->e:Z

    .line 73
    .line 74
    invoke-direct/range {v4 .. v14}, Lvz0/k;-><init>(ZZZZZLjava/lang/String;Ljava/lang/String;ZZLvz0/a;)V

    .line 75
    .line 76
    .line 77
    new-instance p0, Lvz0/t;

    .line 78
    .line 79
    const-string v1, "module"

    .line 80
    .line 81
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-direct {p0, v4, v0}, Lvz0/d;-><init>(Lvz0/k;Lwq/f;)V

    .line 85
    .line 86
    .line 87
    sget-object v1, Lxz0/a;->a:Lwq/f;

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    if-eqz v0, :cond_0

    .line 94
    .line 95
    return-object p0

    .line 96
    :cond_0
    sget-object v0, Lvz0/a;->d:Lvz0/a;

    .line 97
    .line 98
    return-object p0

    .line 99
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 100
    .line 101
    const-string v0, "Indent should not be specified when default printing mode is used"

    .line 102
    .line 103
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    throw p0
.end method

.method public static final b(F)Ltw/f;
    .locals 5

    .line 1
    sget v0, Ltw/f;->h:I

    .line 2
    .line 3
    new-instance v0, Ltw/f;

    .line 4
    .line 5
    new-instance v1, Ltw/a;

    .line 6
    .line 7
    sget-object v2, Ltw/j;->a:Ltw/j;

    .line 8
    .line 9
    invoke-direct {v1, p0}, Ltw/a;-><init>(F)V

    .line 10
    .line 11
    .line 12
    new-instance v2, Ltw/a;

    .line 13
    .line 14
    invoke-direct {v2, p0}, Ltw/a;-><init>(F)V

    .line 15
    .line 16
    .line 17
    new-instance v3, Ltw/a;

    .line 18
    .line 19
    invoke-direct {v3, p0}, Ltw/a;-><init>(F)V

    .line 20
    .line 21
    .line 22
    new-instance v4, Ltw/a;

    .line 23
    .line 24
    invoke-direct {v4, p0}, Ltw/a;-><init>(F)V

    .line 25
    .line 26
    .line 27
    invoke-direct {v0, v1, v2, v3, v4}, Ltw/f;-><init>(Ltw/c;Ltw/c;Ltw/c;Ltw/c;)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method
