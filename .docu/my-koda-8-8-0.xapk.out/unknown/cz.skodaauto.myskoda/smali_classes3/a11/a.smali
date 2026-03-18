.class public final La11/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk11/a;


# virtual methods
.method public final a(Lca/m;)V
    .locals 6

    .line 1
    new-instance p0, Lb11/b;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const-class v0, Lr21/c;

    .line 7
    .line 8
    invoke-static {v0}, Ljava/util/EnumSet;->allOf(Ljava/lang/Class;)Ljava/util/EnumSet;

    .line 9
    .line 10
    .line 11
    sget-object v0, Lr21/c;->d:Lr21/c;

    .line 12
    .line 13
    sget-object v1, Lr21/c;->e:Lr21/c;

    .line 14
    .line 15
    invoke-static {v0, v1}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    if-eqz v2, :cond_3

    .line 20
    .line 21
    new-instance v3, Ljava/util/HashSet;

    .line 22
    .line 23
    invoke-direct {v3, v2}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v3, v0}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v2, 0x0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    new-instance v0, Lmb/e;

    .line 34
    .line 35
    const/16 v4, 0xd

    .line 36
    .line 37
    invoke-direct {v0, v4}, Lmb/e;-><init>(I)V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    move-object v0, v2

    .line 42
    :goto_0
    sget-object v4, Lr21/c;->f:Lr21/c;

    .line 43
    .line 44
    invoke-virtual {v3, v4}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-eqz v4, :cond_1

    .line 49
    .line 50
    new-instance v4, Lnm0/b;

    .line 51
    .line 52
    const/16 v5, 0xd

    .line 53
    .line 54
    invoke-direct {v4, v5}, Lnm0/b;-><init>(I)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_1
    move-object v4, v2

    .line 59
    :goto_1
    invoke-virtual {v3, v1}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-eqz v1, :cond_2

    .line 64
    .line 65
    new-instance v2, Lip/v;

    .line 66
    .line 67
    const/16 v1, 0xd

    .line 68
    .line 69
    invoke-direct {v2, v1}, Lip/v;-><init>(I)V

    .line 70
    .line 71
    .line 72
    :cond_2
    new-instance v1, Lil/g;

    .line 73
    .line 74
    const/16 v3, 0x1d

    .line 75
    .line 76
    invoke-direct {v1, v0, v4, v2, v3}, Lil/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 77
    .line 78
    .line 79
    iput-object v1, p0, Lb11/b;->a:Lil/g;

    .line 80
    .line 81
    iget-object p1, p1, Lca/m;->g:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p1, Ljava/util/ArrayList;

    .line 84
    .line 85
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    return-void

    .line 89
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    .line 90
    .line 91
    const-string p1, "linkTypes must not be null"

    .line 92
    .line 93
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0
.end method
