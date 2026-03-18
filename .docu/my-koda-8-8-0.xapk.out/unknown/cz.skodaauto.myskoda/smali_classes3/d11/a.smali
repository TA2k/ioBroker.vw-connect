.class public final Ld11/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm11/a;


# virtual methods
.method public final a()C
    .locals 0

    .line 1
    const/16 p0, 0x7e

    .line 2
    .line 3
    return p0
.end method

.method public final b()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final c(Lg11/d;Lg11/d;)I
    .locals 6

    .line 1
    iget-object p0, p1, Lg11/d;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p2, Lg11/d;->a:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const/4 v3, 0x0

    .line 14
    if-ne v0, v2, :cond_2

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    const/4 v2, 0x2

    .line 21
    if-gt v0, v2, :cond_2

    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    invoke-static {p0, v0}, Lkx/a;->f(Ljava/util/ArrayList;I)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Lj11/y;

    .line 29
    .line 30
    new-instance v2, Lc11/a;

    .line 31
    .line 32
    invoke-direct {v2}, Lj11/s;-><init>()V

    .line 33
    .line 34
    .line 35
    new-instance v4, Lbn/c;

    .line 36
    .line 37
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    invoke-virtual {p1, v5}, Lg11/d;->b(I)Ljava/util/List;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    check-cast p1, Ljava/util/List;

    .line 49
    .line 50
    invoke-virtual {v4, p1}, Lbn/c;->h(Ljava/util/List;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    check-cast p1, Lj11/y;

    .line 58
    .line 59
    iget-object v3, v0, Lj11/s;->e:Lj11/s;

    .line 60
    .line 61
    new-instance v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;

    .line 62
    .line 63
    invoke-direct {v5, v3, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;-><init>(Lj11/s;Lj11/s;)V

    .line 64
    .line 65
    .line 66
    :goto_0
    invoke-virtual {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->hasNext()Z

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    if-eqz p1, :cond_0

    .line 71
    .line 72
    invoke-virtual {v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->next()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    check-cast p1, Lj11/s;

    .line 77
    .line 78
    invoke-virtual {v2, p1}, Lj11/s;->c(Lj11/s;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p1}, Lj11/s;->d()Ljava/util/List;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    invoke-virtual {v4, p1}, Lbn/c;->g(Ljava/util/List;)V

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 90
    .line 91
    .line 92
    move-result p1

    .line 93
    invoke-virtual {p2, p1}, Lg11/d;->a(I)Ljava/util/List;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    check-cast p1, Ljava/util/List;

    .line 98
    .line 99
    invoke-virtual {v4, p1}, Lbn/c;->h(Ljava/util/List;)V

    .line 100
    .line 101
    .line 102
    iget-object p1, v4, Lbn/c;->d:Ljava/util/ArrayList;

    .line 103
    .line 104
    if-eqz p1, :cond_1

    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_1
    sget-object p1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 108
    .line 109
    :goto_1
    invoke-virtual {v2, p1}, Lj11/s;->g(Ljava/util/List;)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v0, v2}, Lj11/s;->e(Lj11/s;)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    return p0

    .line 120
    :cond_2
    return v3
.end method

.method public final d()C
    .locals 0

    .line 1
    const/16 p0, 0x7e

    .line 2
    .line 3
    return p0
.end method
