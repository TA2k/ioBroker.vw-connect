.class public final Lin/z1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgs/c;


# static fields
.field public static g:Ljava/util/HashSet;


# instance fields
.field public a:Ljava/lang/Object;

.field public b:Ljava/lang/Object;

.field public c:Ljava/lang/Object;

.field public d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-nez p3, :cond_0

    .line 5
    .line 6
    sget-object p3, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    invoke-static {p3}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 10
    .line 11
    .line 12
    move-result-object p3

    .line 13
    :goto_0
    iput-object p3, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 14
    .line 15
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 16
    .line 17
    iput-object p1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 18
    .line 19
    iput-object p2, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 20
    .line 21
    sget-object p1, Lxp/a;->b:Lxp/a;

    .line 22
    .line 23
    iput-object p1, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 24
    .line 25
    new-instance p1, Ljava/util/HashSet;

    .line 26
    .line 27
    invoke-direct {p1, p3}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 28
    .line 29
    .line 30
    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 31
    .line 32
    .line 33
    move-result-object p2

    .line 34
    invoke-interface {p2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result p3

    .line 42
    if-nez p3, :cond_1

    .line 43
    .line 44
    invoke-static {p1}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    iput-object p1, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 49
    .line 50
    return-void

    .line 51
    :cond_1
    invoke-static {p2}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    throw p0
.end method

.method public static A(Lin/d1;Lin/d1;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lin/d1;->m:Lin/e0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p1, Lin/d1;->m:Lin/e0;

    .line 6
    .line 7
    iput-object v0, p0, Lin/d1;->m:Lin/e0;

    .line 8
    .line 9
    :cond_0
    iget-object v0, p0, Lin/d1;->n:Lin/e0;

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    iget-object v0, p1, Lin/d1;->n:Lin/e0;

    .line 14
    .line 15
    iput-object v0, p0, Lin/d1;->n:Lin/e0;

    .line 16
    .line 17
    :cond_1
    iget-object v0, p0, Lin/d1;->o:Lin/e0;

    .line 18
    .line 19
    if-nez v0, :cond_2

    .line 20
    .line 21
    iget-object v0, p1, Lin/d1;->o:Lin/e0;

    .line 22
    .line 23
    iput-object v0, p0, Lin/d1;->o:Lin/e0;

    .line 24
    .line 25
    :cond_2
    iget-object v0, p0, Lin/d1;->p:Lin/e0;

    .line 26
    .line 27
    if-nez v0, :cond_3

    .line 28
    .line 29
    iget-object v0, p1, Lin/d1;->p:Lin/e0;

    .line 30
    .line 31
    iput-object v0, p0, Lin/d1;->p:Lin/e0;

    .line 32
    .line 33
    :cond_3
    iget-object v0, p0, Lin/d1;->q:Lin/e0;

    .line 34
    .line 35
    if-nez v0, :cond_4

    .line 36
    .line 37
    iget-object p1, p1, Lin/d1;->q:Lin/e0;

    .line 38
    .line 39
    iput-object p1, p0, Lin/d1;->q:Lin/e0;

    .line 40
    .line 41
    :cond_4
    return-void
.end method

.method public static B(Lin/m0;Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lin/a1;->a:Lil/g;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    new-instance p0, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v0, "Pattern reference \'"

    .line 12
    .line 13
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string p1, "\' not found"

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    const-string p1, "SVGAndroidRenderer"

    .line 29
    .line 30
    invoke-static {p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_0
    instance-of v1, v0, Lin/m0;

    .line 35
    .line 36
    if-nez v1, :cond_1

    .line 37
    .line 38
    const/4 p0, 0x0

    .line 39
    new-array p0, p0, [Ljava/lang/Object;

    .line 40
    .line 41
    const-string p1, "Pattern href attributes must point to other pattern elements"

    .line 42
    .line 43
    invoke-static {p1, p0}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    if-ne v0, p0, :cond_2

    .line 48
    .line 49
    const-string p0, "Circular reference in pattern href attribute \'%s\'"

    .line 50
    .line 51
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-static {p0, p1}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_2
    check-cast v0, Lin/m0;

    .line 60
    .line 61
    iget-object p1, p0, Lin/m0;->p:Ljava/lang/Boolean;

    .line 62
    .line 63
    if-nez p1, :cond_3

    .line 64
    .line 65
    iget-object p1, v0, Lin/m0;->p:Ljava/lang/Boolean;

    .line 66
    .line 67
    iput-object p1, p0, Lin/m0;->p:Ljava/lang/Boolean;

    .line 68
    .line 69
    :cond_3
    iget-object p1, p0, Lin/m0;->q:Ljava/lang/Boolean;

    .line 70
    .line 71
    if-nez p1, :cond_4

    .line 72
    .line 73
    iget-object p1, v0, Lin/m0;->q:Ljava/lang/Boolean;

    .line 74
    .line 75
    iput-object p1, p0, Lin/m0;->q:Ljava/lang/Boolean;

    .line 76
    .line 77
    :cond_4
    iget-object p1, p0, Lin/m0;->r:Landroid/graphics/Matrix;

    .line 78
    .line 79
    if-nez p1, :cond_5

    .line 80
    .line 81
    iget-object p1, v0, Lin/m0;->r:Landroid/graphics/Matrix;

    .line 82
    .line 83
    iput-object p1, p0, Lin/m0;->r:Landroid/graphics/Matrix;

    .line 84
    .line 85
    :cond_5
    iget-object p1, p0, Lin/m0;->s:Lin/e0;

    .line 86
    .line 87
    if-nez p1, :cond_6

    .line 88
    .line 89
    iget-object p1, v0, Lin/m0;->s:Lin/e0;

    .line 90
    .line 91
    iput-object p1, p0, Lin/m0;->s:Lin/e0;

    .line 92
    .line 93
    :cond_6
    iget-object p1, p0, Lin/m0;->t:Lin/e0;

    .line 94
    .line 95
    if-nez p1, :cond_7

    .line 96
    .line 97
    iget-object p1, v0, Lin/m0;->t:Lin/e0;

    .line 98
    .line 99
    iput-object p1, p0, Lin/m0;->t:Lin/e0;

    .line 100
    .line 101
    :cond_7
    iget-object p1, p0, Lin/m0;->u:Lin/e0;

    .line 102
    .line 103
    if-nez p1, :cond_8

    .line 104
    .line 105
    iget-object p1, v0, Lin/m0;->u:Lin/e0;

    .line 106
    .line 107
    iput-object p1, p0, Lin/m0;->u:Lin/e0;

    .line 108
    .line 109
    :cond_8
    iget-object p1, p0, Lin/m0;->v:Lin/e0;

    .line 110
    .line 111
    if-nez p1, :cond_9

    .line 112
    .line 113
    iget-object p1, v0, Lin/m0;->v:Lin/e0;

    .line 114
    .line 115
    iput-object p1, p0, Lin/m0;->v:Lin/e0;

    .line 116
    .line 117
    :cond_9
    iget-object p1, p0, Lin/v0;->i:Ljava/util/List;

    .line 118
    .line 119
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 120
    .line 121
    .line 122
    move-result p1

    .line 123
    if-eqz p1, :cond_a

    .line 124
    .line 125
    iget-object p1, v0, Lin/v0;->i:Ljava/util/List;

    .line 126
    .line 127
    iput-object p1, p0, Lin/v0;->i:Ljava/util/List;

    .line 128
    .line 129
    :cond_a
    iget-object p1, p0, Lin/e1;->o:Ld3/a;

    .line 130
    .line 131
    if-nez p1, :cond_b

    .line 132
    .line 133
    iget-object p1, v0, Lin/e1;->o:Ld3/a;

    .line 134
    .line 135
    iput-object p1, p0, Lin/e1;->o:Ld3/a;

    .line 136
    .line 137
    :cond_b
    iget-object p1, p0, Lin/c1;->n:Lin/s;

    .line 138
    .line 139
    if-nez p1, :cond_c

    .line 140
    .line 141
    iget-object p1, v0, Lin/c1;->n:Lin/s;

    .line 142
    .line 143
    iput-object p1, p0, Lin/c1;->n:Lin/s;

    .line 144
    .line 145
    :cond_c
    iget-object p1, v0, Lin/m0;->w:Ljava/lang/String;

    .line 146
    .line 147
    if-eqz p1, :cond_d

    .line 148
    .line 149
    invoke-static {p0, p1}, Lin/z1;->B(Lin/m0;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    :cond_d
    return-void
.end method

.method public static C(Lt7/l0;Lhr/h0;Lh8/b0;Lt7/n0;)Lh8/b0;
    .locals 11

    .line 1
    check-cast p0, La8/i0;

    .line 2
    .line 3
    invoke-virtual {p0}, La8/i0;->k0()Lt7/p0;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, La8/i0;->y1:La8/i1;

    .line 11
    .line 12
    iget-object v1, v1, La8/i1;->a:Lt7/p0;

    .line 13
    .line 14
    invoke-virtual {v1}, Lt7/p0;->p()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    const/4 v2, 0x0

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    move v1, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    iget-object v1, p0, La8/i0;->y1:La8/i1;

    .line 24
    .line 25
    iget-object v3, v1, La8/i1;->a:Lt7/p0;

    .line 26
    .line 27
    iget-object v1, v1, La8/i1;->b:Lh8/b0;

    .line 28
    .line 29
    iget-object v1, v1, Lh8/b0;->a:Ljava/lang/Object;

    .line 30
    .line 31
    invoke-virtual {v3, v1}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    :goto_0
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    const/4 v4, 0x0

    .line 40
    if-eqz v3, :cond_1

    .line 41
    .line 42
    move-object v6, v4

    .line 43
    goto :goto_1

    .line 44
    :cond_1
    invoke-virtual {v0, v1}, Lt7/p0;->l(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    move-object v6, v3

    .line 49
    :goto_1
    invoke-virtual {p0}, La8/i0;->r0()Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-nez v3, :cond_3

    .line 54
    .line 55
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-eqz v3, :cond_2

    .line 60
    .line 61
    goto :goto_3

    .line 62
    :cond_2
    invoke-virtual {v0, v1, p3, v2}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-virtual {p0}, La8/i0;->i0()J

    .line 67
    .line 68
    .line 69
    move-result-wide v7

    .line 70
    invoke-static {v7, v8}, Lw7/w;->D(J)J

    .line 71
    .line 72
    .line 73
    move-result-wide v7

    .line 74
    iget-wide v9, p3, Lt7/n0;->e:J

    .line 75
    .line 76
    sub-long/2addr v7, v9

    .line 77
    invoke-virtual {v0, v7, v8}, Lt7/n0;->b(J)I

    .line 78
    .line 79
    .line 80
    move-result p3

    .line 81
    :goto_2
    move v10, p3

    .line 82
    goto :goto_4

    .line 83
    :cond_3
    :goto_3
    const/4 p3, -0x1

    .line 84
    goto :goto_2

    .line 85
    :goto_4
    invoke-virtual {p1}, Ljava/util/AbstractCollection;->size()I

    .line 86
    .line 87
    .line 88
    move-result p3

    .line 89
    if-ge v2, p3, :cond_5

    .line 90
    .line 91
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p3

    .line 95
    move-object v5, p3

    .line 96
    check-cast v5, Lh8/b0;

    .line 97
    .line 98
    invoke-virtual {p0}, La8/i0;->r0()Z

    .line 99
    .line 100
    .line 101
    move-result v7

    .line 102
    invoke-virtual {p0}, La8/i0;->f0()I

    .line 103
    .line 104
    .line 105
    move-result v8

    .line 106
    invoke-virtual {p0}, La8/i0;->g0()I

    .line 107
    .line 108
    .line 109
    move-result v9

    .line 110
    invoke-static/range {v5 .. v10}, Lin/z1;->I(Lh8/b0;Ljava/lang/Object;ZIII)Z

    .line 111
    .line 112
    .line 113
    move-result p3

    .line 114
    if-eqz p3, :cond_4

    .line 115
    .line 116
    return-object v5

    .line 117
    :cond_4
    add-int/lit8 v2, v2, 0x1

    .line 118
    .line 119
    goto :goto_4

    .line 120
    :cond_5
    invoke-virtual {p1}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 121
    .line 122
    .line 123
    move-result p1

    .line 124
    if-eqz p1, :cond_6

    .line 125
    .line 126
    if-eqz p2, :cond_6

    .line 127
    .line 128
    invoke-virtual {p0}, La8/i0;->r0()Z

    .line 129
    .line 130
    .line 131
    move-result v7

    .line 132
    invoke-virtual {p0}, La8/i0;->f0()I

    .line 133
    .line 134
    .line 135
    move-result v8

    .line 136
    invoke-virtual {p0}, La8/i0;->g0()I

    .line 137
    .line 138
    .line 139
    move-result v9

    .line 140
    move-object v5, p2

    .line 141
    invoke-static/range {v5 .. v10}, Lin/z1;->I(Lh8/b0;Ljava/lang/Object;ZIII)Z

    .line 142
    .line 143
    .line 144
    move-result p0

    .line 145
    if-eqz p0, :cond_6

    .line 146
    .line 147
    return-object v5

    .line 148
    :cond_6
    return-object v4
.end method

.method public static I(Lh8/b0;Ljava/lang/Object;ZIII)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lh8/b0;->a:Ljava/lang/Object;

    .line 2
    .line 3
    iget v1, p0, Lh8/b0;->b:I

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    const/4 v0, 0x0

    .line 10
    if-nez p1, :cond_0

    .line 11
    .line 12
    return v0

    .line 13
    :cond_0
    if-eqz p2, :cond_1

    .line 14
    .line 15
    if-ne v1, p3, :cond_1

    .line 16
    .line 17
    iget p1, p0, Lh8/b0;->c:I

    .line 18
    .line 19
    if-eq p1, p4, :cond_2

    .line 20
    .line 21
    :cond_1
    if-nez p2, :cond_3

    .line 22
    .line 23
    const/4 p1, -0x1

    .line 24
    if-ne v1, p1, :cond_3

    .line 25
    .line 26
    iget p0, p0, Lh8/b0;->e:I

    .line 27
    .line 28
    if-ne p0, p5, :cond_3

    .line 29
    .line 30
    :cond_2
    const/4 p0, 0x1

    .line 31
    return p0

    .line 32
    :cond_3
    return v0
.end method

.method public static J(Lin/s0;J)Z
    .locals 2

    .line 1
    iget-wide v0, p0, Lin/s0;->d:J

    .line 2
    .line 3
    and-long p0, v0, p1

    .line 4
    .line 5
    const-wide/16 v0, 0x0

    .line 6
    .line 7
    cmp-long p0, p0, v0

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public static N(Lin/n0;)Landroid/graphics/Path;
    .locals 5

    .line 1
    new-instance v0, Landroid/graphics/Path;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lin/n0;->o:[F

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    aget v2, v1, v2

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    aget v1, v1, v3

    .line 13
    .line 14
    invoke-virtual {v0, v2, v1}, Landroid/graphics/Path;->moveTo(FF)V

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    :goto_0
    iget-object v2, p0, Lin/n0;->o:[F

    .line 19
    .line 20
    array-length v3, v2

    .line 21
    if-ge v1, v3, :cond_0

    .line 22
    .line 23
    aget v3, v2, v1

    .line 24
    .line 25
    add-int/lit8 v4, v1, 0x1

    .line 26
    .line 27
    aget v2, v2, v4

    .line 28
    .line 29
    invoke-virtual {v0, v3, v2}, Landroid/graphics/Path;->lineTo(FF)V

    .line 30
    .line 31
    .line 32
    add-int/lit8 v1, v1, 0x2

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    instance-of v1, p0, Lin/o0;

    .line 36
    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    invoke-virtual {v0}, Landroid/graphics/Path;->close()V

    .line 40
    .line 41
    .line 42
    :cond_1
    iget-object v1, p0, Lin/x0;->h:Ld3/a;

    .line 43
    .line 44
    if-nez v1, :cond_2

    .line 45
    .line 46
    invoke-static {v0}, Lin/z1;->k(Landroid/graphics/Path;)Ld3/a;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    iput-object v1, p0, Lin/x0;->h:Ld3/a;

    .line 51
    .line 52
    :cond_2
    return-object v0
.end method

.method public static c0(Lin/x1;ZLin/b1;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lin/x1;->a:Lin/s0;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    iget-object v0, v0, Lin/s0;->f:Ljava/lang/Float;

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    iget-object v0, v0, Lin/s0;->h:Ljava/lang/Float;

    .line 9
    .line 10
    :goto_0
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    instance-of v1, p2, Lin/v;

    .line 15
    .line 16
    if-eqz v1, :cond_1

    .line 17
    .line 18
    check-cast p2, Lin/v;

    .line 19
    .line 20
    iget p2, p2, Lin/v;->d:I

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_1
    instance-of p2, p2, Lin/w;

    .line 24
    .line 25
    if-eqz p2, :cond_3

    .line 26
    .line 27
    iget-object p2, p0, Lin/x1;->a:Lin/s0;

    .line 28
    .line 29
    iget-object p2, p2, Lin/s0;->n:Lin/v;

    .line 30
    .line 31
    iget p2, p2, Lin/v;->d:I

    .line 32
    .line 33
    :goto_1
    invoke-static {p2, v0}, Lin/z1;->q(IF)I

    .line 34
    .line 35
    .line 36
    move-result p2

    .line 37
    if-eqz p1, :cond_2

    .line 38
    .line 39
    iget-object p0, p0, Lin/x1;->d:Landroid/graphics/Paint;

    .line 40
    .line 41
    invoke-virtual {p0, p2}, Landroid/graphics/Paint;->setColor(I)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_2
    iget-object p0, p0, Lin/x1;->e:Landroid/graphics/Paint;

    .line 46
    .line 47
    invoke-virtual {p0, p2}, Landroid/graphics/Paint;->setColor(I)V

    .line 48
    .line 49
    .line 50
    :cond_3
    return-void
.end method

.method public static h(FFFFFZZFFLin/l0;)V
    .locals 36

    .line 1
    move/from16 v0, p4

    .line 2
    .line 3
    move/from16 v1, p6

    .line 4
    .line 5
    move/from16 v3, p8

    .line 6
    .line 7
    cmpl-float v4, p0, p7

    .line 8
    .line 9
    if-nez v4, :cond_0

    .line 10
    .line 11
    cmpl-float v4, p1, v3

    .line 12
    .line 13
    if-nez v4, :cond_0

    .line 14
    .line 15
    goto/16 :goto_7

    .line 16
    .line 17
    :cond_0
    const/4 v4, 0x0

    .line 18
    cmpl-float v5, p2, v4

    .line 19
    .line 20
    if-eqz v5, :cond_1

    .line 21
    .line 22
    cmpl-float v4, p3, v4

    .line 23
    .line 24
    if-nez v4, :cond_2

    .line 25
    .line 26
    :cond_1
    move/from16 v2, p7

    .line 27
    .line 28
    move-object/from16 v0, p9

    .line 29
    .line 30
    goto/16 :goto_8

    .line 31
    .line 32
    :cond_2
    invoke-static/range {p2 .. p2}, Ljava/lang/Math;->abs(F)F

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    invoke-static/range {p3 .. p3}, Ljava/lang/Math;->abs(F)F

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    float-to-double v6, v0

    .line 41
    const-wide v8, 0x4076800000000000L    # 360.0

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    rem-double/2addr v6, v8

    .line 47
    invoke-static {v6, v7}, Ljava/lang/Math;->toRadians(D)D

    .line 48
    .line 49
    .line 50
    move-result-wide v6

    .line 51
    invoke-static {v6, v7}, Ljava/lang/Math;->cos(D)D

    .line 52
    .line 53
    .line 54
    move-result-wide v8

    .line 55
    invoke-static {v6, v7}, Ljava/lang/Math;->sin(D)D

    .line 56
    .line 57
    .line 58
    move-result-wide v6

    .line 59
    sub-float v10, p0, p7

    .line 60
    .line 61
    float-to-double v10, v10

    .line 62
    const-wide/high16 v12, 0x4000000000000000L    # 2.0

    .line 63
    .line 64
    div-double/2addr v10, v12

    .line 65
    sub-float v14, p1, v3

    .line 66
    .line 67
    float-to-double v14, v14

    .line 68
    div-double/2addr v14, v12

    .line 69
    mul-double v16, v8, v10

    .line 70
    .line 71
    mul-double v18, v6, v14

    .line 72
    .line 73
    move-wide/from16 p2, v12

    .line 74
    .line 75
    add-double v12, v18, v16

    .line 76
    .line 77
    move-wide/from16 v16, v8

    .line 78
    .line 79
    neg-double v8, v6

    .line 80
    mul-double/2addr v8, v10

    .line 81
    mul-double v10, v16, v14

    .line 82
    .line 83
    add-double/2addr v10, v8

    .line 84
    mul-float v8, v4, v4

    .line 85
    .line 86
    float-to-double v8, v8

    .line 87
    mul-float v14, v5, v5

    .line 88
    .line 89
    float-to-double v14, v14

    .line 90
    mul-double v18, v12, v12

    .line 91
    .line 92
    mul-double v20, v10, v10

    .line 93
    .line 94
    div-double v22, v18, v8

    .line 95
    .line 96
    div-double v24, v20, v14

    .line 97
    .line 98
    add-double v24, v24, v22

    .line 99
    .line 100
    const-wide v22, 0x3fefffeb074a771dL    # 0.99999

    .line 101
    .line 102
    .line 103
    .line 104
    .line 105
    cmpl-double v22, v24, v22

    .line 106
    .line 107
    if-lez v22, :cond_3

    .line 108
    .line 109
    invoke-static/range {v24 .. v25}, Ljava/lang/Math;->sqrt(D)D

    .line 110
    .line 111
    .line 112
    move-result-wide v8

    .line 113
    const-wide v14, 0x3ff0000a7c5ac472L    # 1.00001

    .line 114
    .line 115
    .line 116
    .line 117
    .line 118
    mul-double/2addr v8, v14

    .line 119
    float-to-double v14, v4

    .line 120
    mul-double/2addr v14, v8

    .line 121
    double-to-float v4, v14

    .line 122
    float-to-double v14, v5

    .line 123
    mul-double/2addr v8, v14

    .line 124
    double-to-float v5, v8

    .line 125
    mul-float v8, v4, v4

    .line 126
    .line 127
    float-to-double v8, v8

    .line 128
    mul-float v14, v5, v5

    .line 129
    .line 130
    float-to-double v14, v14

    .line 131
    :cond_3
    const-wide/high16 v22, -0x4010000000000000L    # -1.0

    .line 132
    .line 133
    const-wide/high16 v24, 0x3ff0000000000000L    # 1.0

    .line 134
    .line 135
    move-wide/from16 v26, v6

    .line 136
    .line 137
    move/from16 v6, p5

    .line 138
    .line 139
    if-ne v6, v1, :cond_4

    .line 140
    .line 141
    move-wide/from16 v6, v22

    .line 142
    .line 143
    goto :goto_0

    .line 144
    :cond_4
    move-wide/from16 v6, v24

    .line 145
    .line 146
    :goto_0
    mul-double v28, v8, v14

    .line 147
    .line 148
    mul-double v8, v8, v20

    .line 149
    .line 150
    sub-double v28, v28, v8

    .line 151
    .line 152
    mul-double v14, v14, v18

    .line 153
    .line 154
    sub-double v28, v28, v14

    .line 155
    .line 156
    add-double/2addr v8, v14

    .line 157
    div-double v28, v28, v8

    .line 158
    .line 159
    const-wide/16 v8, 0x0

    .line 160
    .line 161
    cmpg-double v14, v28, v8

    .line 162
    .line 163
    if-gez v14, :cond_5

    .line 164
    .line 165
    move-wide/from16 v28, v8

    .line 166
    .line 167
    :cond_5
    invoke-static/range {v28 .. v29}, Ljava/lang/Math;->sqrt(D)D

    .line 168
    .line 169
    .line 170
    move-result-wide v14

    .line 171
    mul-double/2addr v14, v6

    .line 172
    float-to-double v6, v4

    .line 173
    mul-double v18, v6, v10

    .line 174
    .line 175
    move-wide/from16 v20, v8

    .line 176
    .line 177
    float-to-double v8, v5

    .line 178
    div-double v18, v18, v8

    .line 179
    .line 180
    mul-double v18, v18, v14

    .line 181
    .line 182
    mul-double v28, v8, v12

    .line 183
    .line 184
    move-wide/from16 v30, v6

    .line 185
    .line 186
    div-double v6, v28, v30

    .line 187
    .line 188
    neg-double v6, v6

    .line 189
    mul-double/2addr v14, v6

    .line 190
    add-float v6, p0, p7

    .line 191
    .line 192
    float-to-double v6, v6

    .line 193
    div-double v6, v6, p2

    .line 194
    .line 195
    add-float v1, p1, v3

    .line 196
    .line 197
    move-wide/from16 v28, v6

    .line 198
    .line 199
    float-to-double v6, v1

    .line 200
    div-double v6, v6, p2

    .line 201
    .line 202
    mul-double v32, v16, v18

    .line 203
    .line 204
    mul-double v34, v26, v14

    .line 205
    .line 206
    sub-double v32, v32, v34

    .line 207
    .line 208
    move-wide/from16 p0, v6

    .line 209
    .line 210
    add-double v6, v32, v28

    .line 211
    .line 212
    mul-double v26, v26, v18

    .line 213
    .line 214
    mul-double v16, v16, v14

    .line 215
    .line 216
    add-double v16, v16, v26

    .line 217
    .line 218
    move-wide/from16 v26, v8

    .line 219
    .line 220
    add-double v8, v16, p0

    .line 221
    .line 222
    sub-double v16, v12, v18

    .line 223
    .line 224
    div-double v16, v16, v30

    .line 225
    .line 226
    sub-double v28, v10, v14

    .line 227
    .line 228
    div-double v28, v28, v26

    .line 229
    .line 230
    neg-double v12, v12

    .line 231
    sub-double v12, v12, v18

    .line 232
    .line 233
    div-double v12, v12, v30

    .line 234
    .line 235
    neg-double v10, v10

    .line 236
    sub-double/2addr v10, v14

    .line 237
    div-double v10, v10, v26

    .line 238
    .line 239
    mul-double v14, v16, v16

    .line 240
    .line 241
    mul-double v18, v28, v28

    .line 242
    .line 243
    add-double v18, v18, v14

    .line 244
    .line 245
    invoke-static/range {v18 .. v19}, Ljava/lang/Math;->sqrt(D)D

    .line 246
    .line 247
    .line 248
    move-result-wide v14

    .line 249
    cmpg-double v1, v28, v20

    .line 250
    .line 251
    if-gez v1, :cond_6

    .line 252
    .line 253
    move-wide/from16 v26, v22

    .line 254
    .line 255
    goto :goto_1

    .line 256
    :cond_6
    move-wide/from16 v26, v24

    .line 257
    .line 258
    :goto_1
    div-double v14, v16, v14

    .line 259
    .line 260
    invoke-static {v14, v15}, Ljava/lang/Math;->acos(D)D

    .line 261
    .line 262
    .line 263
    move-result-wide v14

    .line 264
    mul-double v14, v14, v26

    .line 265
    .line 266
    mul-double v26, v12, v12

    .line 267
    .line 268
    mul-double v30, v10, v10

    .line 269
    .line 270
    add-double v30, v30, v26

    .line 271
    .line 272
    mul-double v30, v30, v18

    .line 273
    .line 274
    invoke-static/range {v30 .. v31}, Ljava/lang/Math;->sqrt(D)D

    .line 275
    .line 276
    .line 277
    move-result-wide v18

    .line 278
    mul-double v26, v16, v12

    .line 279
    .line 280
    mul-double v30, v28, v10

    .line 281
    .line 282
    add-double v30, v30, v26

    .line 283
    .line 284
    mul-double v16, v16, v10

    .line 285
    .line 286
    mul-double v28, v28, v12

    .line 287
    .line 288
    sub-double v16, v16, v28

    .line 289
    .line 290
    cmpg-double v1, v16, v20

    .line 291
    .line 292
    if-gez v1, :cond_7

    .line 293
    .line 294
    move-wide/from16 v10, v22

    .line 295
    .line 296
    goto :goto_2

    .line 297
    :cond_7
    move-wide/from16 v10, v24

    .line 298
    .line 299
    :goto_2
    div-double v30, v30, v18

    .line 300
    .line 301
    cmpg-double v1, v30, v22

    .line 302
    .line 303
    const-wide v12, 0x400921fb54442d18L    # Math.PI

    .line 304
    .line 305
    .line 306
    .line 307
    .line 308
    if-gez v1, :cond_8

    .line 309
    .line 310
    move-wide/from16 v16, v12

    .line 311
    .line 312
    goto :goto_3

    .line 313
    :cond_8
    cmpl-double v1, v30, v24

    .line 314
    .line 315
    if-lez v1, :cond_9

    .line 316
    .line 317
    move-wide/from16 v16, v20

    .line 318
    .line 319
    goto :goto_3

    .line 320
    :cond_9
    invoke-static/range {v30 .. v31}, Ljava/lang/Math;->acos(D)D

    .line 321
    .line 322
    .line 323
    move-result-wide v16

    .line 324
    :goto_3
    mul-double v10, v10, v16

    .line 325
    .line 326
    const-wide v16, 0x401921fb54442d18L    # 6.283185307179586

    .line 327
    .line 328
    .line 329
    .line 330
    .line 331
    if-nez p6, :cond_a

    .line 332
    .line 333
    cmpl-double v1, v10, v20

    .line 334
    .line 335
    if-lez v1, :cond_a

    .line 336
    .line 337
    sub-double v10, v10, v16

    .line 338
    .line 339
    goto :goto_4

    .line 340
    :cond_a
    if-eqz p6, :cond_b

    .line 341
    .line 342
    cmpg-double v1, v10, v20

    .line 343
    .line 344
    if-gez v1, :cond_b

    .line 345
    .line 346
    add-double v10, v10, v16

    .line 347
    .line 348
    :cond_b
    :goto_4
    rem-double v10, v10, v16

    .line 349
    .line 350
    rem-double v14, v14, v16

    .line 351
    .line 352
    invoke-static {v10, v11}, Ljava/lang/Math;->abs(D)D

    .line 353
    .line 354
    .line 355
    move-result-wide v16

    .line 356
    mul-double v16, v16, p2

    .line 357
    .line 358
    div-double v16, v16, v12

    .line 359
    .line 360
    invoke-static/range {v16 .. v17}, Ljava/lang/Math;->ceil(D)D

    .line 361
    .line 362
    .line 363
    move-result-wide v12

    .line 364
    double-to-int v1, v12

    .line 365
    int-to-double v12, v1

    .line 366
    div-double/2addr v10, v12

    .line 367
    div-double v12, v10, p2

    .line 368
    .line 369
    invoke-static {v12, v13}, Ljava/lang/Math;->sin(D)D

    .line 370
    .line 371
    .line 372
    move-result-wide v16

    .line 373
    const-wide v18, 0x3ff5555555555555L    # 1.3333333333333333

    .line 374
    .line 375
    .line 376
    .line 377
    .line 378
    mul-double v16, v16, v18

    .line 379
    .line 380
    invoke-static {v12, v13}, Ljava/lang/Math;->cos(D)D

    .line 381
    .line 382
    .line 383
    move-result-wide v12

    .line 384
    add-double v12, v12, v24

    .line 385
    .line 386
    div-double v16, v16, v12

    .line 387
    .line 388
    mul-int/lit8 v12, v1, 0x6

    .line 389
    .line 390
    new-array v13, v12, [F

    .line 391
    .line 392
    const/16 v18, 0x0

    .line 393
    .line 394
    move-wide/from16 p0, v10

    .line 395
    .line 396
    move/from16 v10, v18

    .line 397
    .line 398
    move v11, v10

    .line 399
    :goto_5
    if-ge v10, v1, :cond_c

    .line 400
    .line 401
    move-wide/from16 p2, v14

    .line 402
    .line 403
    int-to-double v14, v10

    .line 404
    mul-double v14, v14, p0

    .line 405
    .line 406
    add-double v14, v14, p2

    .line 407
    .line 408
    invoke-static {v14, v15}, Ljava/lang/Math;->cos(D)D

    .line 409
    .line 410
    .line 411
    move-result-wide v19

    .line 412
    invoke-static {v14, v15}, Ljava/lang/Math;->sin(D)D

    .line 413
    .line 414
    .line 415
    move-result-wide v21

    .line 416
    add-int/lit8 v23, v11, 0x1

    .line 417
    .line 418
    mul-double v24, v16, v21

    .line 419
    .line 420
    move/from16 v26, v10

    .line 421
    .line 422
    move/from16 p5, v11

    .line 423
    .line 424
    sub-double v10, v19, v24

    .line 425
    .line 426
    double-to-float v10, v10

    .line 427
    aput v10, v13, p5

    .line 428
    .line 429
    add-int/lit8 v11, p5, 0x2

    .line 430
    .line 431
    mul-double v19, v19, v16

    .line 432
    .line 433
    move/from16 p6, v11

    .line 434
    .line 435
    add-double v10, v19, v21

    .line 436
    .line 437
    double-to-float v10, v10

    .line 438
    aput v10, v13, v23

    .line 439
    .line 440
    add-double v14, v14, p0

    .line 441
    .line 442
    invoke-static {v14, v15}, Ljava/lang/Math;->cos(D)D

    .line 443
    .line 444
    .line 445
    move-result-wide v10

    .line 446
    invoke-static {v14, v15}, Ljava/lang/Math;->sin(D)D

    .line 447
    .line 448
    .line 449
    move-result-wide v14

    .line 450
    add-int/lit8 v19, p5, 0x3

    .line 451
    .line 452
    mul-double v20, v16, v14

    .line 453
    .line 454
    move/from16 v22, v1

    .line 455
    .line 456
    add-double v1, v20, v10

    .line 457
    .line 458
    double-to-float v1, v1

    .line 459
    aput v1, v13, p6

    .line 460
    .line 461
    add-int/lit8 v1, p5, 0x4

    .line 462
    .line 463
    mul-double v20, v16, v10

    .line 464
    .line 465
    move/from16 p6, v1

    .line 466
    .line 467
    sub-double v1, v14, v20

    .line 468
    .line 469
    double-to-float v1, v1

    .line 470
    aput v1, v13, v19

    .line 471
    .line 472
    add-int/lit8 v1, p5, 0x5

    .line 473
    .line 474
    double-to-float v2, v10

    .line 475
    aput v2, v13, p6

    .line 476
    .line 477
    add-int/lit8 v11, p5, 0x6

    .line 478
    .line 479
    double-to-float v2, v14

    .line 480
    aput v2, v13, v1

    .line 481
    .line 482
    add-int/lit8 v10, v26, 0x1

    .line 483
    .line 484
    move-wide/from16 v14, p2

    .line 485
    .line 486
    move/from16 v1, v22

    .line 487
    .line 488
    goto :goto_5

    .line 489
    :cond_c
    new-instance v1, Landroid/graphics/Matrix;

    .line 490
    .line 491
    invoke-direct {v1}, Landroid/graphics/Matrix;-><init>()V

    .line 492
    .line 493
    .line 494
    invoke-virtual {v1, v4, v5}, Landroid/graphics/Matrix;->postScale(FF)Z

    .line 495
    .line 496
    .line 497
    invoke-virtual {v1, v0}, Landroid/graphics/Matrix;->postRotate(F)Z

    .line 498
    .line 499
    .line 500
    double-to-float v0, v6

    .line 501
    double-to-float v2, v8

    .line 502
    invoke-virtual {v1, v0, v2}, Landroid/graphics/Matrix;->postTranslate(FF)Z

    .line 503
    .line 504
    .line 505
    invoke-virtual {v1, v13}, Landroid/graphics/Matrix;->mapPoints([F)V

    .line 506
    .line 507
    .line 508
    add-int/lit8 v0, v12, -0x2

    .line 509
    .line 510
    aput p7, v13, v0

    .line 511
    .line 512
    add-int/lit8 v0, v12, -0x1

    .line 513
    .line 514
    aput v3, v13, v0

    .line 515
    .line 516
    move/from16 v0, v18

    .line 517
    .line 518
    :goto_6
    if-ge v0, v12, :cond_d

    .line 519
    .line 520
    aget v1, v13, v0

    .line 521
    .line 522
    add-int/lit8 v2, v0, 0x1

    .line 523
    .line 524
    aget v2, v13, v2

    .line 525
    .line 526
    add-int/lit8 v3, v0, 0x2

    .line 527
    .line 528
    aget v3, v13, v3

    .line 529
    .line 530
    add-int/lit8 v4, v0, 0x3

    .line 531
    .line 532
    aget v4, v13, v4

    .line 533
    .line 534
    add-int/lit8 v5, v0, 0x4

    .line 535
    .line 536
    aget v5, v13, v5

    .line 537
    .line 538
    add-int/lit8 v6, v0, 0x5

    .line 539
    .line 540
    aget v6, v13, v6

    .line 541
    .line 542
    move-object/from16 p0, p9

    .line 543
    .line 544
    move/from16 p1, v1

    .line 545
    .line 546
    move/from16 p2, v2

    .line 547
    .line 548
    move/from16 p3, v3

    .line 549
    .line 550
    move/from16 p4, v4

    .line 551
    .line 552
    move/from16 p5, v5

    .line 553
    .line 554
    move/from16 p6, v6

    .line 555
    .line 556
    invoke-interface/range {p0 .. p6}, Lin/l0;->c(FFFFFF)V

    .line 557
    .line 558
    .line 559
    add-int/lit8 v0, v0, 0x6

    .line 560
    .line 561
    goto :goto_6

    .line 562
    :cond_d
    :goto_7
    return-void

    .line 563
    :goto_8
    invoke-interface {v0, v2, v3}, Lin/l0;->e(FF)V

    .line 564
    .line 565
    .line 566
    return-void
.end method

.method public static k(Landroid/graphics/Path;)Ld3/a;
    .locals 4

    .line 1
    new-instance v0, Landroid/graphics/RectF;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    invoke-virtual {p0, v0, v1}, Landroid/graphics/Path;->computeBounds(Landroid/graphics/RectF;Z)V

    .line 8
    .line 9
    .line 10
    new-instance p0, Ld3/a;

    .line 11
    .line 12
    iget v1, v0, Landroid/graphics/RectF;->left:F

    .line 13
    .line 14
    iget v2, v0, Landroid/graphics/RectF;->top:F

    .line 15
    .line 16
    invoke-virtual {v0}, Landroid/graphics/RectF;->width()F

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    invoke-virtual {v0}, Landroid/graphics/RectF;->height()F

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-direct {p0, v1, v2, v3, v0}, Ld3/a;-><init>(FFFF)V

    .line 25
    .line 26
    .line 27
    return-object p0
.end method

.method public static m(Ld3/a;Ld3/a;Lin/s;)Landroid/graphics/Matrix;
    .locals 9

    .line 1
    new-instance v0, Landroid/graphics/Matrix;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 4
    .line 5
    .line 6
    if-eqz p2, :cond_5

    .line 7
    .line 8
    iget-object v1, p2, Lin/s;->a:Lin/r;

    .line 9
    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    goto/16 :goto_5

    .line 13
    .line 14
    :cond_0
    iget v2, p0, Ld3/a;->d:F

    .line 15
    .line 16
    iget v3, p1, Ld3/a;->d:F

    .line 17
    .line 18
    div-float/2addr v2, v3

    .line 19
    iget v3, p0, Ld3/a;->e:F

    .line 20
    .line 21
    iget v4, p1, Ld3/a;->e:F

    .line 22
    .line 23
    div-float/2addr v3, v4

    .line 24
    iget v4, p1, Ld3/a;->b:F

    .line 25
    .line 26
    neg-float v4, v4

    .line 27
    iget v5, p1, Ld3/a;->c:F

    .line 28
    .line 29
    neg-float v5, v5

    .line 30
    sget-object v6, Lin/s;->c:Lin/s;

    .line 31
    .line 32
    invoke-virtual {p2, v6}, Lin/s;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v6

    .line 36
    if-eqz v6, :cond_1

    .line 37
    .line 38
    iget p1, p0, Ld3/a;->b:F

    .line 39
    .line 40
    iget p0, p0, Ld3/a;->c:F

    .line 41
    .line 42
    invoke-virtual {v0, p1, p0}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 43
    .line 44
    .line 45
    invoke-virtual {v0, v2, v3}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0, v4, v5}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 49
    .line 50
    .line 51
    return-object v0

    .line 52
    :cond_1
    iget p2, p2, Lin/s;->b:I

    .line 53
    .line 54
    const/4 v6, 0x2

    .line 55
    if-ne p2, v6, :cond_2

    .line 56
    .line 57
    invoke-static {v2, v3}, Ljava/lang/Math;->max(FF)F

    .line 58
    .line 59
    .line 60
    move-result p2

    .line 61
    goto :goto_0

    .line 62
    :cond_2
    invoke-static {v2, v3}, Ljava/lang/Math;->min(FF)F

    .line 63
    .line 64
    .line 65
    move-result p2

    .line 66
    :goto_0
    iget v2, p0, Ld3/a;->d:F

    .line 67
    .line 68
    div-float/2addr v2, p2

    .line 69
    iget v3, p0, Ld3/a;->e:F

    .line 70
    .line 71
    div-float/2addr v3, p2

    .line 72
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 73
    .line 74
    .line 75
    move-result v7

    .line 76
    const/high16 v8, 0x40000000    # 2.0f

    .line 77
    .line 78
    if-eq v7, v6, :cond_4

    .line 79
    .line 80
    const/4 v6, 0x3

    .line 81
    if-eq v7, v6, :cond_3

    .line 82
    .line 83
    const/4 v6, 0x5

    .line 84
    if-eq v7, v6, :cond_4

    .line 85
    .line 86
    const/4 v6, 0x6

    .line 87
    if-eq v7, v6, :cond_3

    .line 88
    .line 89
    const/16 v6, 0x8

    .line 90
    .line 91
    if-eq v7, v6, :cond_4

    .line 92
    .line 93
    const/16 v6, 0x9

    .line 94
    .line 95
    if-eq v7, v6, :cond_3

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_3
    iget v6, p1, Ld3/a;->d:F

    .line 99
    .line 100
    sub-float/2addr v6, v2

    .line 101
    :goto_1
    sub-float/2addr v4, v6

    .line 102
    goto :goto_2

    .line 103
    :cond_4
    iget v6, p1, Ld3/a;->d:F

    .line 104
    .line 105
    sub-float/2addr v6, v2

    .line 106
    div-float/2addr v6, v8

    .line 107
    goto :goto_1

    .line 108
    :goto_2
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    packed-switch v1, :pswitch_data_0

    .line 113
    .line 114
    .line 115
    goto :goto_4

    .line 116
    :pswitch_0
    iget p1, p1, Ld3/a;->e:F

    .line 117
    .line 118
    sub-float/2addr p1, v3

    .line 119
    :goto_3
    sub-float/2addr v5, p1

    .line 120
    goto :goto_4

    .line 121
    :pswitch_1
    iget p1, p1, Ld3/a;->e:F

    .line 122
    .line 123
    sub-float/2addr p1, v3

    .line 124
    div-float/2addr p1, v8

    .line 125
    goto :goto_3

    .line 126
    :goto_4
    iget p1, p0, Ld3/a;->b:F

    .line 127
    .line 128
    iget p0, p0, Ld3/a;->c:F

    .line 129
    .line 130
    invoke-virtual {v0, p1, p0}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 131
    .line 132
    .line 133
    invoke-virtual {v0, p2, p2}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 134
    .line 135
    .line 136
    invoke-virtual {v0, v4, v5}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 137
    .line 138
    .line 139
    :cond_5
    :goto_5
    return-object v0

    .line 140
    nop

    .line 141
    :pswitch_data_0
    .packed-switch 0x4
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public static p(Ljava/lang/String;Ljava/lang/Integer;I)Landroid/graphics/Typeface;
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    const/4 v2, 0x2

    .line 4
    if-ne p2, v2, :cond_0

    .line 5
    .line 6
    move p2, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move p2, v0

    .line 9
    :goto_0
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    const/16 v3, 0x1f4

    .line 14
    .line 15
    const/4 v4, 0x3

    .line 16
    if-le p1, v3, :cond_2

    .line 17
    .line 18
    if-eqz p2, :cond_1

    .line 19
    .line 20
    move p1, v4

    .line 21
    goto :goto_1

    .line 22
    :cond_1
    move p1, v1

    .line 23
    goto :goto_1

    .line 24
    :cond_2
    if-eqz p2, :cond_3

    .line 25
    .line 26
    move p1, v2

    .line 27
    goto :goto_1

    .line 28
    :cond_3
    move p1, v0

    .line 29
    :goto_1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 33
    .line 34
    .line 35
    move-result p2

    .line 36
    const/4 v3, -0x1

    .line 37
    sparse-switch p2, :sswitch_data_0

    .line 38
    .line 39
    .line 40
    :goto_2
    move v0, v3

    .line 41
    goto :goto_3

    .line 42
    :sswitch_0
    const-string p2, "cursive"

    .line 43
    .line 44
    invoke-virtual {p0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    if-nez p0, :cond_4

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_4
    const/4 v0, 0x4

    .line 52
    goto :goto_3

    .line 53
    :sswitch_1
    const-string p2, "serif"

    .line 54
    .line 55
    invoke-virtual {p0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    if-nez p0, :cond_5

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_5
    move v0, v4

    .line 63
    goto :goto_3

    .line 64
    :sswitch_2
    const-string p2, "fantasy"

    .line 65
    .line 66
    invoke-virtual {p0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    if-nez p0, :cond_6

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_6
    move v0, v2

    .line 74
    goto :goto_3

    .line 75
    :sswitch_3
    const-string p2, "monospace"

    .line 76
    .line 77
    invoke-virtual {p0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    if-nez p0, :cond_7

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_7
    move v0, v1

    .line 85
    goto :goto_3

    .line 86
    :sswitch_4
    const-string p2, "sans-serif"

    .line 87
    .line 88
    invoke-virtual {p0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    if-nez p0, :cond_8

    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_8
    :goto_3
    packed-switch v0, :pswitch_data_0

    .line 96
    .line 97
    .line 98
    const/4 p0, 0x0

    .line 99
    return-object p0

    .line 100
    :pswitch_0
    sget-object p0, Landroid/graphics/Typeface;->SANS_SERIF:Landroid/graphics/Typeface;

    .line 101
    .line 102
    invoke-static {p0, p1}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0

    .line 107
    :pswitch_1
    sget-object p0, Landroid/graphics/Typeface;->SERIF:Landroid/graphics/Typeface;

    .line 108
    .line 109
    invoke-static {p0, p1}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    return-object p0

    .line 114
    :pswitch_2
    sget-object p0, Landroid/graphics/Typeface;->SANS_SERIF:Landroid/graphics/Typeface;

    .line 115
    .line 116
    invoke-static {p0, p1}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    return-object p0

    .line 121
    :pswitch_3
    sget-object p0, Landroid/graphics/Typeface;->MONOSPACE:Landroid/graphics/Typeface;

    .line 122
    .line 123
    invoke-static {p0, p1}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    return-object p0

    .line 128
    :pswitch_4
    sget-object p0, Landroid/graphics/Typeface;->SANS_SERIF:Landroid/graphics/Typeface;

    .line 129
    .line 130
    invoke-static {p0, p1}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    return-object p0

    .line 135
    :sswitch_data_0
    .sparse-switch
        -0x5b97f43d -> :sswitch_4
        -0x5559f3fd -> :sswitch_3
        -0x407a00da -> :sswitch_2
        0x684317d -> :sswitch_1
        0x432c41c5 -> :sswitch_0
    .end sparse-switch

    .line 136
    .line 137
    .line 138
    .line 139
    .line 140
    .line 141
    .line 142
    .line 143
    .line 144
    .line 145
    .line 146
    .line 147
    .line 148
    .line 149
    .line 150
    .line 151
    .line 152
    .line 153
    .line 154
    .line 155
    .line 156
    .line 157
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static q(IF)I
    .locals 2

    .line 1
    shr-int/lit8 v0, p0, 0x18

    .line 2
    .line 3
    const/16 v1, 0xff

    .line 4
    .line 5
    and-int/2addr v0, v1

    .line 6
    int-to-float v0, v0

    .line 7
    mul-float/2addr v0, p1

    .line 8
    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    if-gez p1, :cond_0

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    if-le p1, v1, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    move v1, p1

    .line 20
    :goto_0
    shl-int/lit8 p1, v1, 0x18

    .line 21
    .line 22
    const v0, 0xffffff

    .line 23
    .line 24
    .line 25
    and-int/2addr p0, v0

    .line 26
    or-int/2addr p0, p1

    .line 27
    return p0
.end method

.method public static varargs w(Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "SVGAndroidRenderer"

    .line 2
    .line 3
    invoke-static {p0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public static z(Lin/z;Ljava/lang/String;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lin/a1;->a:Lil/g;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    new-instance p0, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v0, "Gradient reference \'"

    .line 12
    .line 13
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string p1, "\' not found"

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    const-string p1, "SVGAndroidRenderer"

    .line 29
    .line 30
    invoke-static {p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_0
    instance-of v1, v0, Lin/z;

    .line 35
    .line 36
    if-nez v1, :cond_1

    .line 37
    .line 38
    const/4 p0, 0x0

    .line 39
    new-array p0, p0, [Ljava/lang/Object;

    .line 40
    .line 41
    const-string p1, "Gradient href attributes must point to other gradient elements"

    .line 42
    .line 43
    invoke-static {p1, p0}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    if-ne v0, p0, :cond_2

    .line 48
    .line 49
    const-string p0, "Circular reference in gradient href attribute \'%s\'"

    .line 50
    .line 51
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-static {p0, p1}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_2
    move-object p1, v0

    .line 60
    check-cast p1, Lin/z;

    .line 61
    .line 62
    iget-object v1, p0, Lin/z;->i:Ljava/lang/Boolean;

    .line 63
    .line 64
    if-nez v1, :cond_3

    .line 65
    .line 66
    iget-object v1, p1, Lin/z;->i:Ljava/lang/Boolean;

    .line 67
    .line 68
    iput-object v1, p0, Lin/z;->i:Ljava/lang/Boolean;

    .line 69
    .line 70
    :cond_3
    iget-object v1, p0, Lin/z;->j:Landroid/graphics/Matrix;

    .line 71
    .line 72
    if-nez v1, :cond_4

    .line 73
    .line 74
    iget-object v1, p1, Lin/z;->j:Landroid/graphics/Matrix;

    .line 75
    .line 76
    iput-object v1, p0, Lin/z;->j:Landroid/graphics/Matrix;

    .line 77
    .line 78
    :cond_4
    iget v1, p0, Lin/z;->k:I

    .line 79
    .line 80
    if-nez v1, :cond_5

    .line 81
    .line 82
    iget v1, p1, Lin/z;->k:I

    .line 83
    .line 84
    iput v1, p0, Lin/z;->k:I

    .line 85
    .line 86
    :cond_5
    iget-object v1, p0, Lin/z;->h:Ljava/util/List;

    .line 87
    .line 88
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-eqz v1, :cond_6

    .line 93
    .line 94
    iget-object v1, p1, Lin/z;->h:Ljava/util/List;

    .line 95
    .line 96
    iput-object v1, p0, Lin/z;->h:Ljava/util/List;

    .line 97
    .line 98
    :cond_6
    :try_start_0
    instance-of v1, p0, Lin/z0;

    .line 99
    .line 100
    if-eqz v1, :cond_a

    .line 101
    .line 102
    move-object v1, p0

    .line 103
    check-cast v1, Lin/z0;

    .line 104
    .line 105
    check-cast v0, Lin/z0;

    .line 106
    .line 107
    iget-object v2, v1, Lin/z0;->m:Lin/e0;

    .line 108
    .line 109
    if-nez v2, :cond_7

    .line 110
    .line 111
    iget-object v2, v0, Lin/z0;->m:Lin/e0;

    .line 112
    .line 113
    iput-object v2, v1, Lin/z0;->m:Lin/e0;

    .line 114
    .line 115
    :cond_7
    iget-object v2, v1, Lin/z0;->n:Lin/e0;

    .line 116
    .line 117
    if-nez v2, :cond_8

    .line 118
    .line 119
    iget-object v2, v0, Lin/z0;->n:Lin/e0;

    .line 120
    .line 121
    iput-object v2, v1, Lin/z0;->n:Lin/e0;

    .line 122
    .line 123
    :cond_8
    iget-object v2, v1, Lin/z0;->o:Lin/e0;

    .line 124
    .line 125
    if-nez v2, :cond_9

    .line 126
    .line 127
    iget-object v2, v0, Lin/z0;->o:Lin/e0;

    .line 128
    .line 129
    iput-object v2, v1, Lin/z0;->o:Lin/e0;

    .line 130
    .line 131
    :cond_9
    iget-object v2, v1, Lin/z0;->p:Lin/e0;

    .line 132
    .line 133
    if-nez v2, :cond_b

    .line 134
    .line 135
    iget-object v0, v0, Lin/z0;->p:Lin/e0;

    .line 136
    .line 137
    iput-object v0, v1, Lin/z0;->p:Lin/e0;

    .line 138
    .line 139
    goto :goto_0

    .line 140
    :cond_a
    move-object v1, p0

    .line 141
    check-cast v1, Lin/d1;

    .line 142
    .line 143
    check-cast v0, Lin/d1;

    .line 144
    .line 145
    invoke-static {v1, v0}, Lin/z1;->A(Lin/d1;Lin/d1;)V
    :try_end_0
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_0

    .line 146
    .line 147
    .line 148
    :catch_0
    :cond_b
    :goto_0
    iget-object p1, p1, Lin/z;->l:Ljava/lang/String;

    .line 149
    .line 150
    if-eqz p1, :cond_c

    .line 151
    .line 152
    invoke-static {p0, p1}, Lin/z1;->z(Lin/z;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    :cond_c
    return-void
.end method


# virtual methods
.method public D(Lin/y0;)Lin/x1;
    .locals 2

    .line 1
    new-instance v0, Lin/x1;

    .line 2
    .line 3
    invoke-direct {v0}, Lin/x1;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lin/s0;->a()Lin/s0;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {p0, v0, v1}, Lin/z1;->j0(Lin/x1;Lin/s0;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, p1, v0}, Lin/z1;->E(Lin/a1;Lin/x1;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public E(Lin/a1;Lin/x1;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    :goto_0
    instance-of v1, p1, Lin/y0;

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    move-object v2, p1

    .line 12
    check-cast v2, Lin/y0;

    .line 13
    .line 14
    invoke-virtual {v0, v1, v2}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    iget-object p1, p1, Lin/a1;->b:Lin/w0;

    .line 18
    .line 19
    if-nez p1, :cond_2

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Lin/y0;

    .line 36
    .line 37
    invoke-virtual {p0, p2, v0}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 38
    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    iget-object p0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Lin/x1;

    .line 44
    .line 45
    iget-object p1, p0, Lin/x1;->g:Ld3/a;

    .line 46
    .line 47
    iput-object p1, p2, Lin/x1;->g:Ld3/a;

    .line 48
    .line 49
    iget-object p0, p0, Lin/x1;->f:Ld3/a;

    .line 50
    .line 51
    iput-object p0, p2, Lin/x1;->f:Ld3/a;

    .line 52
    .line 53
    return-void

    .line 54
    :cond_2
    check-cast p1, Lin/a1;

    .line 55
    .line 56
    goto :goto_0
.end method

.method public F()I
    .locals 3

    .line 1
    iget-object p0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lin/x1;

    .line 4
    .line 5
    iget-object p0, p0, Lin/x1;->a:Lin/s0;

    .line 6
    .line 7
    iget v0, p0, Lin/s0;->L:I

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-eq v0, v1, :cond_2

    .line 11
    .line 12
    iget v0, p0, Lin/s0;->M:I

    .line 13
    .line 14
    const/4 v2, 0x2

    .line 15
    if-ne v0, v2, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    if-ne v0, v1, :cond_1

    .line 19
    .line 20
    const/4 p0, 0x3

    .line 21
    return p0

    .line 22
    :cond_1
    return v1

    .line 23
    :cond_2
    :goto_0
    iget p0, p0, Lin/s0;->M:I

    .line 24
    .line 25
    return p0
.end method

.method public G()Landroid/graphics/Path$FillType;
    .locals 1

    .line 1
    iget-object p0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lin/x1;

    .line 4
    .line 5
    iget-object p0, p0, Lin/x1;->a:Lin/s0;

    .line 6
    .line 7
    iget p0, p0, Lin/s0;->N:I

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x2

    .line 12
    if-ne p0, v0, :cond_0

    .line 13
    .line 14
    sget-object p0, Landroid/graphics/Path$FillType;->EVEN_ODD:Landroid/graphics/Path$FillType;

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    sget-object p0, Landroid/graphics/Path$FillType;->WINDING:Landroid/graphics/Path$FillType;

    .line 18
    .line 19
    return-object p0
.end method

.method public H(Ljava/lang/Class;)Lgs/q;
    .locals 0

    .line 1
    invoke-static {p1}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p0, p1}, Lin/z1;->g(Lgs/s;)Lgs/q;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public K()Lu01/s;
    .locals 2

    .line 1
    sget-object v0, Ln01/d;->a:Ln01/b;

    .line 2
    .line 3
    sget-object v0, Ln01/d;->a:Ln01/b;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move-object v0, v1

    .line 10
    :goto_0
    if-eqz v0, :cond_1

    .line 11
    .line 12
    iget-object v0, v0, Ln01/b;->c:Landroid/content/Context;

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_1
    move-object v0, v1

    .line 16
    :goto_1
    if-eqz v0, :cond_2

    .line 17
    .line 18
    invoke-virtual {v0}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    :cond_2
    if-nez v1, :cond_4

    .line 23
    .line 24
    sget-object p0, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;

    .line 25
    .line 26
    if-nez p0, :cond_3

    .line 27
    .line 28
    new-instance p0, Ljava/io/IOException;

    .line 29
    .line 30
    const-string v0, "Platform applicationContext not initialized. Possibly running Android unit test without Robolectric. Android tests should run with Robolectric and call OkHttp.initialize before test"

    .line 31
    .line 32
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw p0

    .line 36
    :cond_3
    new-instance p0, Ljava/io/IOException;

    .line 37
    .line 38
    const-string v0, "Platform applicationContext not initialized. Startup Initializer possibly disabled, call OkHttp.initialize before test."

    .line 39
    .line 40
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_4
    iget-object p0, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Ljava/lang/String;

    .line 47
    .line 48
    invoke-virtual {v1, p0}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    const-string v0, "open(...)"

    .line 53
    .line 54
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-static {p0}, Lu01/b;->g(Ljava/io/InputStream;)Lu01/s;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0
.end method

.method public L(Lin/t;)Landroid/graphics/Path;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Lin/t;->o:Lin/e0;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    invoke-virtual {v2, v0}, Lin/e0;->d(Lin/z1;)F

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    move v9, v2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v9, v3

    .line 17
    :goto_0
    iget-object v2, v1, Lin/t;->p:Lin/e0;

    .line 18
    .line 19
    if-eqz v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v2, v0}, Lin/e0;->e(Lin/z1;)F

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    :cond_1
    move/from16 v16, v3

    .line 26
    .line 27
    iget-object v2, v1, Lin/t;->q:Lin/e0;

    .line 28
    .line 29
    invoke-virtual {v2, v0}, Lin/e0;->a(Lin/z1;)F

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    sub-float v2, v9, v0

    .line 34
    .line 35
    sub-float v8, v16, v0

    .line 36
    .line 37
    add-float v5, v9, v0

    .line 38
    .line 39
    add-float v3, v16, v0

    .line 40
    .line 41
    iget-object v4, v1, Lin/x0;->h:Ld3/a;

    .line 42
    .line 43
    if-nez v4, :cond_2

    .line 44
    .line 45
    new-instance v4, Ld3/a;

    .line 46
    .line 47
    const/high16 v6, 0x40000000    # 2.0f

    .line 48
    .line 49
    mul-float/2addr v6, v0

    .line 50
    invoke-direct {v4, v2, v8, v6, v6}, Ld3/a;-><init>(FFFF)V

    .line 51
    .line 52
    .line 53
    iput-object v4, v1, Lin/x0;->h:Ld3/a;

    .line 54
    .line 55
    :cond_2
    const v1, 0x3f0d6289

    .line 56
    .line 57
    .line 58
    mul-float/2addr v0, v1

    .line 59
    new-instance v4, Landroid/graphics/Path;

    .line 60
    .line 61
    invoke-direct {v4}, Landroid/graphics/Path;-><init>()V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v4, v9, v8}, Landroid/graphics/Path;->moveTo(FF)V

    .line 65
    .line 66
    .line 67
    add-float v7, v9, v0

    .line 68
    .line 69
    sub-float v14, v16, v0

    .line 70
    .line 71
    move v15, v5

    .line 72
    move-object v10, v4

    .line 73
    move v13, v5

    .line 74
    move v11, v7

    .line 75
    move v12, v8

    .line 76
    invoke-virtual/range {v10 .. v16}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 77
    .line 78
    .line 79
    move v1, v12

    .line 80
    move/from16 v17, v14

    .line 81
    .line 82
    add-float v14, v16, v0

    .line 83
    .line 84
    move v10, v3

    .line 85
    move v8, v3

    .line 86
    move v6, v14

    .line 87
    invoke-virtual/range {v4 .. v10}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 88
    .line 89
    .line 90
    sub-float v7, v9, v0

    .line 91
    .line 92
    move v15, v2

    .line 93
    move v13, v2

    .line 94
    move-object v10, v4

    .line 95
    move v11, v7

    .line 96
    move v12, v8

    .line 97
    invoke-virtual/range {v10 .. v16}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 98
    .line 99
    .line 100
    move v5, v13

    .line 101
    move v10, v1

    .line 102
    move v8, v1

    .line 103
    move/from16 v6, v17

    .line 104
    .line 105
    invoke-virtual/range {v4 .. v10}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v4}, Landroid/graphics/Path;->close()V

    .line 109
    .line 110
    .line 111
    return-object v4
.end method

.method public M(Lin/y;)Landroid/graphics/Path;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Lin/y;->o:Lin/e0;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    invoke-virtual {v2, v0}, Lin/e0;->d(Lin/z1;)F

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    move v9, v2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v9, v3

    .line 17
    :goto_0
    iget-object v2, v1, Lin/y;->p:Lin/e0;

    .line 18
    .line 19
    if-eqz v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v2, v0}, Lin/e0;->e(Lin/z1;)F

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    :cond_1
    move/from16 v16, v3

    .line 26
    .line 27
    iget-object v2, v1, Lin/y;->q:Lin/e0;

    .line 28
    .line 29
    invoke-virtual {v2, v0}, Lin/e0;->d(Lin/z1;)F

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    iget-object v3, v1, Lin/y;->r:Lin/e0;

    .line 34
    .line 35
    invoke-virtual {v3, v0}, Lin/e0;->e(Lin/z1;)F

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    sub-float v3, v9, v2

    .line 40
    .line 41
    sub-float v8, v16, v0

    .line 42
    .line 43
    add-float v5, v9, v2

    .line 44
    .line 45
    add-float v4, v16, v0

    .line 46
    .line 47
    iget-object v6, v1, Lin/x0;->h:Ld3/a;

    .line 48
    .line 49
    if-nez v6, :cond_2

    .line 50
    .line 51
    new-instance v6, Ld3/a;

    .line 52
    .line 53
    const/high16 v7, 0x40000000    # 2.0f

    .line 54
    .line 55
    mul-float v10, v2, v7

    .line 56
    .line 57
    mul-float/2addr v7, v0

    .line 58
    invoke-direct {v6, v3, v8, v10, v7}, Ld3/a;-><init>(FFFF)V

    .line 59
    .line 60
    .line 61
    iput-object v6, v1, Lin/x0;->h:Ld3/a;

    .line 62
    .line 63
    :cond_2
    const v1, 0x3f0d6289

    .line 64
    .line 65
    .line 66
    mul-float/2addr v2, v1

    .line 67
    mul-float/2addr v0, v1

    .line 68
    new-instance v10, Landroid/graphics/Path;

    .line 69
    .line 70
    invoke-direct {v10}, Landroid/graphics/Path;-><init>()V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v10, v9, v8}, Landroid/graphics/Path;->moveTo(FF)V

    .line 74
    .line 75
    .line 76
    add-float v7, v9, v2

    .line 77
    .line 78
    sub-float v14, v16, v0

    .line 79
    .line 80
    move v15, v5

    .line 81
    move v13, v5

    .line 82
    move v11, v7

    .line 83
    move v12, v8

    .line 84
    invoke-virtual/range {v10 .. v16}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 85
    .line 86
    .line 87
    move v1, v12

    .line 88
    move/from16 v17, v14

    .line 89
    .line 90
    add-float v14, v16, v0

    .line 91
    .line 92
    move v8, v4

    .line 93
    move-object v4, v10

    .line 94
    move v10, v8

    .line 95
    move v6, v14

    .line 96
    invoke-virtual/range {v4 .. v10}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 97
    .line 98
    .line 99
    sub-float v7, v9, v2

    .line 100
    .line 101
    move v15, v3

    .line 102
    move v13, v3

    .line 103
    move-object v10, v4

    .line 104
    move v11, v7

    .line 105
    move v12, v8

    .line 106
    invoke-virtual/range {v10 .. v16}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 107
    .line 108
    .line 109
    move v5, v13

    .line 110
    move v10, v1

    .line 111
    move v8, v1

    .line 112
    move/from16 v6, v17

    .line 113
    .line 114
    invoke-virtual/range {v4 .. v10}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v4}, Landroid/graphics/Path;->close()V

    .line 118
    .line 119
    .line 120
    return-object v4
.end method

.method public O(Lin/p0;)Landroid/graphics/Path;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Lin/p0;->s:Lin/e0;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    if-nez v2, :cond_0

    .line 9
    .line 10
    iget-object v4, v1, Lin/p0;->t:Lin/e0;

    .line 11
    .line 12
    if-nez v4, :cond_0

    .line 13
    .line 14
    move v2, v3

    .line 15
    :goto_0
    move v4, v2

    .line 16
    goto :goto_1

    .line 17
    :cond_0
    if-nez v2, :cond_1

    .line 18
    .line 19
    iget-object v2, v1, Lin/p0;->t:Lin/e0;

    .line 20
    .line 21
    invoke-virtual {v2, v0}, Lin/e0;->e(Lin/z1;)F

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    goto :goto_0

    .line 26
    :cond_1
    iget-object v4, v1, Lin/p0;->t:Lin/e0;

    .line 27
    .line 28
    if-nez v4, :cond_2

    .line 29
    .line 30
    invoke-virtual {v2, v0}, Lin/e0;->d(Lin/z1;)F

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    goto :goto_0

    .line 35
    :cond_2
    invoke-virtual {v2, v0}, Lin/e0;->d(Lin/z1;)F

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    iget-object v4, v1, Lin/p0;->t:Lin/e0;

    .line 40
    .line 41
    invoke-virtual {v4, v0}, Lin/e0;->e(Lin/z1;)F

    .line 42
    .line 43
    .line 44
    move-result v4

    .line 45
    :goto_1
    iget-object v5, v1, Lin/p0;->q:Lin/e0;

    .line 46
    .line 47
    invoke-virtual {v5, v0}, Lin/e0;->d(Lin/z1;)F

    .line 48
    .line 49
    .line 50
    move-result v5

    .line 51
    const/high16 v6, 0x40000000    # 2.0f

    .line 52
    .line 53
    div-float/2addr v5, v6

    .line 54
    invoke-static {v2, v5}, Ljava/lang/Math;->min(FF)F

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    iget-object v5, v1, Lin/p0;->r:Lin/e0;

    .line 59
    .line 60
    invoke-virtual {v5, v0}, Lin/e0;->e(Lin/z1;)F

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    div-float/2addr v5, v6

    .line 65
    invoke-static {v4, v5}, Ljava/lang/Math;->min(FF)F

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    iget-object v5, v1, Lin/p0;->o:Lin/e0;

    .line 70
    .line 71
    if-eqz v5, :cond_3

    .line 72
    .line 73
    invoke-virtual {v5, v0}, Lin/e0;->d(Lin/z1;)F

    .line 74
    .line 75
    .line 76
    move-result v5

    .line 77
    move v7, v5

    .line 78
    goto :goto_2

    .line 79
    :cond_3
    move v7, v3

    .line 80
    :goto_2
    iget-object v5, v1, Lin/p0;->p:Lin/e0;

    .line 81
    .line 82
    if-eqz v5, :cond_4

    .line 83
    .line 84
    invoke-virtual {v5, v0}, Lin/e0;->e(Lin/z1;)F

    .line 85
    .line 86
    .line 87
    move-result v5

    .line 88
    move v10, v5

    .line 89
    goto :goto_3

    .line 90
    :cond_4
    move v10, v3

    .line 91
    :goto_3
    iget-object v5, v1, Lin/p0;->q:Lin/e0;

    .line 92
    .line 93
    invoke-virtual {v5, v0}, Lin/e0;->d(Lin/z1;)F

    .line 94
    .line 95
    .line 96
    move-result v5

    .line 97
    iget-object v6, v1, Lin/p0;->r:Lin/e0;

    .line 98
    .line 99
    invoke-virtual {v6, v0}, Lin/e0;->e(Lin/z1;)F

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    iget-object v6, v1, Lin/x0;->h:Ld3/a;

    .line 104
    .line 105
    if-nez v6, :cond_5

    .line 106
    .line 107
    new-instance v6, Ld3/a;

    .line 108
    .line 109
    invoke-direct {v6, v7, v10, v5, v0}, Ld3/a;-><init>(FFFF)V

    .line 110
    .line 111
    .line 112
    iput-object v6, v1, Lin/x0;->h:Ld3/a;

    .line 113
    .line 114
    :cond_5
    add-float/2addr v5, v7

    .line 115
    add-float v15, v10, v0

    .line 116
    .line 117
    new-instance v6, Landroid/graphics/Path;

    .line 118
    .line 119
    invoke-direct {v6}, Landroid/graphics/Path;-><init>()V

    .line 120
    .line 121
    .line 122
    cmpl-float v0, v2, v3

    .line 123
    .line 124
    if-eqz v0, :cond_6

    .line 125
    .line 126
    cmpl-float v0, v4, v3

    .line 127
    .line 128
    if-nez v0, :cond_7

    .line 129
    .line 130
    :cond_6
    move v11, v5

    .line 131
    goto :goto_4

    .line 132
    :cond_7
    const v0, 0x3f0d6289

    .line 133
    .line 134
    .line 135
    mul-float v1, v2, v0

    .line 136
    .line 137
    mul-float/2addr v0, v4

    .line 138
    add-float v14, v10, v4

    .line 139
    .line 140
    invoke-virtual {v6, v7, v14}, Landroid/graphics/Path;->moveTo(FF)V

    .line 141
    .line 142
    .line 143
    sub-float v8, v14, v0

    .line 144
    .line 145
    add-float v11, v7, v2

    .line 146
    .line 147
    sub-float v9, v11, v1

    .line 148
    .line 149
    move v12, v10

    .line 150
    invoke-virtual/range {v6 .. v12}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 151
    .line 152
    .line 153
    move/from16 v18, v9

    .line 154
    .line 155
    move v3, v11

    .line 156
    sub-float v2, v5, v2

    .line 157
    .line 158
    invoke-virtual {v6, v2, v10}, Landroid/graphics/Path;->lineTo(FF)V

    .line 159
    .line 160
    .line 161
    add-float v9, v2, v1

    .line 162
    .line 163
    move v13, v5

    .line 164
    move v11, v5

    .line 165
    move v12, v8

    .line 166
    move-object v8, v6

    .line 167
    invoke-virtual/range {v8 .. v14}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 168
    .line 169
    .line 170
    move v1, v14

    .line 171
    move v14, v9

    .line 172
    sub-float v4, v15, v4

    .line 173
    .line 174
    invoke-virtual {v6, v11, v4}, Landroid/graphics/Path;->lineTo(FF)V

    .line 175
    .line 176
    .line 177
    add-float v10, v4, v0

    .line 178
    .line 179
    move/from16 v17, v15

    .line 180
    .line 181
    move/from16 v16, v2

    .line 182
    .line 183
    move v13, v10

    .line 184
    move v12, v11

    .line 185
    move-object v11, v6

    .line 186
    invoke-virtual/range {v11 .. v17}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v6, v3, v15}, Landroid/graphics/Path;->lineTo(FF)V

    .line 190
    .line 191
    .line 192
    move v11, v7

    .line 193
    move v12, v4

    .line 194
    move v9, v7

    .line 195
    move v8, v15

    .line 196
    move/from16 v7, v18

    .line 197
    .line 198
    invoke-virtual/range {v6 .. v12}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 199
    .line 200
    .line 201
    move v7, v9

    .line 202
    invoke-virtual {v6, v7, v1}, Landroid/graphics/Path;->lineTo(FF)V

    .line 203
    .line 204
    .line 205
    goto :goto_5

    .line 206
    :goto_4
    invoke-virtual {v6, v7, v10}, Landroid/graphics/Path;->moveTo(FF)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v6, v11, v10}, Landroid/graphics/Path;->lineTo(FF)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v6, v11, v15}, Landroid/graphics/Path;->lineTo(FF)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v6, v7, v15}, Landroid/graphics/Path;->lineTo(FF)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v6, v7, v10}, Landroid/graphics/Path;->lineTo(FF)V

    .line 219
    .line 220
    .line 221
    :goto_5
    invoke-virtual {v6}, Landroid/graphics/Path;->close()V

    .line 222
    .line 223
    .line 224
    return-object v6
.end method

.method public P(Lin/e0;Lin/e0;Lin/e0;Lin/e0;)Ld3/a;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p1, p0}, Lin/e0;->d(Lin/z1;)F

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move p1, v0

    .line 10
    :goto_0
    if-eqz p2, :cond_1

    .line 11
    .line 12
    invoke-virtual {p2, p0}, Lin/e0;->e(Lin/z1;)F

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    :cond_1
    iget-object p2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p2, Lin/x1;

    .line 19
    .line 20
    iget-object v1, p2, Lin/x1;->g:Ld3/a;

    .line 21
    .line 22
    if-eqz v1, :cond_2

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_2
    iget-object v1, p2, Lin/x1;->f:Ld3/a;

    .line 26
    .line 27
    :goto_1
    if-eqz p3, :cond_3

    .line 28
    .line 29
    invoke-virtual {p3, p0}, Lin/e0;->d(Lin/z1;)F

    .line 30
    .line 31
    .line 32
    move-result p2

    .line 33
    goto :goto_2

    .line 34
    :cond_3
    iget p2, v1, Ld3/a;->d:F

    .line 35
    .line 36
    :goto_2
    if-eqz p4, :cond_4

    .line 37
    .line 38
    invoke-virtual {p4, p0}, Lin/e0;->e(Lin/z1;)F

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    goto :goto_3

    .line 43
    :cond_4
    iget p0, v1, Ld3/a;->e:F

    .line 44
    .line 45
    :goto_3
    new-instance p3, Ld3/a;

    .line 46
    .line 47
    invoke-direct {p3, p1, v0, p2, p0}, Ld3/a;-><init>(FFFF)V

    .line 48
    .line 49
    .line 50
    return-object p3
.end method

.method public Q(Lin/x0;Z)Landroid/graphics/Path;
    .locals 9

    .line 1
    iget-object v0, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/Stack;

    .line 4
    .line 5
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lin/x1;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    new-instance v0, Lin/x1;

    .line 13
    .line 14
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lin/x1;

    .line 17
    .line 18
    invoke-direct {v0, v1}, Lin/x1;-><init>(Lin/x1;)V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 22
    .line 23
    invoke-virtual {p0, v0, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v1, 0x0

    .line 31
    if-eqz v0, :cond_20

    .line 32
    .line 33
    invoke-virtual {p0}, Lin/z1;->m0()Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-nez v0, :cond_0

    .line 38
    .line 39
    goto/16 :goto_a

    .line 40
    .line 41
    :cond_0
    instance-of v0, p1, Lin/p1;

    .line 42
    .line 43
    const/4 v2, 0x0

    .line 44
    if-eqz v0, :cond_6

    .line 45
    .line 46
    if-nez p2, :cond_1

    .line 47
    .line 48
    const-string p2, "<use> elements inside a <clipPath> cannot reference another <use>"

    .line 49
    .line 50
    new-array v0, v2, [Ljava/lang/Object;

    .line 51
    .line 52
    invoke-static {p2, v0}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    :cond_1
    move-object p2, p1

    .line 56
    check-cast p2, Lin/p1;

    .line 57
    .line 58
    iget-object v0, p1, Lin/a1;->a:Lil/g;

    .line 59
    .line 60
    iget-object v3, p2, Lin/p1;->o:Ljava/lang/String;

    .line 61
    .line 62
    invoke-virtual {v0, v3}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    if-nez v0, :cond_2

    .line 67
    .line 68
    iget-object p1, p2, Lin/p1;->o:Ljava/lang/String;

    .line 69
    .line 70
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    const-string p2, "Use reference \'%s\' not found"

    .line 75
    .line 76
    invoke-static {p2, p1}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    iget-object p1, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast p1, Ljava/util/Stack;

    .line 82
    .line 83
    invoke-virtual {p1}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    check-cast p1, Lin/x1;

    .line 88
    .line 89
    iput-object p1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 90
    .line 91
    return-object v1

    .line 92
    :cond_2
    instance-of v3, v0, Lin/x0;

    .line 93
    .line 94
    if-nez v3, :cond_3

    .line 95
    .line 96
    iget-object p1, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast p1, Ljava/util/Stack;

    .line 99
    .line 100
    invoke-virtual {p1}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    check-cast p1, Lin/x1;

    .line 105
    .line 106
    iput-object p1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 107
    .line 108
    return-object v1

    .line 109
    :cond_3
    check-cast v0, Lin/x0;

    .line 110
    .line 111
    invoke-virtual {p0, v0, v2}, Lin/z1;->Q(Lin/x0;Z)Landroid/graphics/Path;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    if-nez v0, :cond_4

    .line 116
    .line 117
    goto/16 :goto_1

    .line 118
    .line 119
    :cond_4
    iget-object v1, p2, Lin/x0;->h:Ld3/a;

    .line 120
    .line 121
    if-nez v1, :cond_5

    .line 122
    .line 123
    invoke-static {v0}, Lin/z1;->k(Landroid/graphics/Path;)Ld3/a;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    iput-object v1, p2, Lin/x0;->h:Ld3/a;

    .line 128
    .line 129
    :cond_5
    iget-object p2, p2, Lin/b0;->n:Landroid/graphics/Matrix;

    .line 130
    .line 131
    if-eqz p2, :cond_1d

    .line 132
    .line 133
    invoke-virtual {v0, p2}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 134
    .line 135
    .line 136
    goto/16 :goto_9

    .line 137
    .line 138
    :cond_6
    instance-of p2, p1, Lin/a0;

    .line 139
    .line 140
    if-eqz p2, :cond_10

    .line 141
    .line 142
    move-object p2, p1

    .line 143
    check-cast p2, Lin/a0;

    .line 144
    .line 145
    instance-of v0, p1, Lin/k0;

    .line 146
    .line 147
    if-eqz v0, :cond_7

    .line 148
    .line 149
    move-object v0, p1

    .line 150
    check-cast v0, Lin/k0;

    .line 151
    .line 152
    new-instance v2, Lin/t1;

    .line 153
    .line 154
    iget-object v0, v0, Lin/k0;->o:Li4/c;

    .line 155
    .line 156
    invoke-direct {v2, v0}, Lin/t1;-><init>(Li4/c;)V

    .line 157
    .line 158
    .line 159
    iget-object v0, v2, Lin/t1;->c:Ljava/lang/Object;

    .line 160
    .line 161
    check-cast v0, Landroid/graphics/Path;

    .line 162
    .line 163
    iget-object v2, p1, Lin/x0;->h:Ld3/a;

    .line 164
    .line 165
    if-nez v2, :cond_c

    .line 166
    .line 167
    invoke-static {v0}, Lin/z1;->k(Landroid/graphics/Path;)Ld3/a;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    iput-object v2, p1, Lin/x0;->h:Ld3/a;

    .line 172
    .line 173
    goto :goto_0

    .line 174
    :cond_7
    instance-of v0, p1, Lin/p0;

    .line 175
    .line 176
    if-eqz v0, :cond_8

    .line 177
    .line 178
    move-object v0, p1

    .line 179
    check-cast v0, Lin/p0;

    .line 180
    .line 181
    invoke-virtual {p0, v0}, Lin/z1;->O(Lin/p0;)Landroid/graphics/Path;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    goto :goto_0

    .line 186
    :cond_8
    instance-of v0, p1, Lin/t;

    .line 187
    .line 188
    if-eqz v0, :cond_9

    .line 189
    .line 190
    move-object v0, p1

    .line 191
    check-cast v0, Lin/t;

    .line 192
    .line 193
    invoke-virtual {p0, v0}, Lin/z1;->L(Lin/t;)Landroid/graphics/Path;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    goto :goto_0

    .line 198
    :cond_9
    instance-of v0, p1, Lin/y;

    .line 199
    .line 200
    if-eqz v0, :cond_a

    .line 201
    .line 202
    move-object v0, p1

    .line 203
    check-cast v0, Lin/y;

    .line 204
    .line 205
    invoke-virtual {p0, v0}, Lin/z1;->M(Lin/y;)Landroid/graphics/Path;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    goto :goto_0

    .line 210
    :cond_a
    instance-of v0, p1, Lin/n0;

    .line 211
    .line 212
    if-eqz v0, :cond_b

    .line 213
    .line 214
    move-object v0, p1

    .line 215
    check-cast v0, Lin/n0;

    .line 216
    .line 217
    invoke-static {v0}, Lin/z1;->N(Lin/n0;)Landroid/graphics/Path;

    .line 218
    .line 219
    .line 220
    move-result-object v0

    .line 221
    goto :goto_0

    .line 222
    :cond_b
    move-object v0, v1

    .line 223
    :cond_c
    :goto_0
    if-nez v0, :cond_d

    .line 224
    .line 225
    :goto_1
    return-object v1

    .line 226
    :cond_d
    iget-object v1, p2, Lin/x0;->h:Ld3/a;

    .line 227
    .line 228
    if-nez v1, :cond_e

    .line 229
    .line 230
    invoke-static {v0}, Lin/z1;->k(Landroid/graphics/Path;)Ld3/a;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    iput-object v1, p2, Lin/x0;->h:Ld3/a;

    .line 235
    .line 236
    :cond_e
    iget-object p2, p2, Lin/a0;->n:Landroid/graphics/Matrix;

    .line 237
    .line 238
    if-eqz p2, :cond_f

    .line 239
    .line 240
    invoke-virtual {v0, p2}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 241
    .line 242
    .line 243
    :cond_f
    invoke-virtual {p0}, Lin/z1;->G()Landroid/graphics/Path$FillType;

    .line 244
    .line 245
    .line 246
    move-result-object p2

    .line 247
    invoke-virtual {v0, p2}, Landroid/graphics/Path;->setFillType(Landroid/graphics/Path$FillType;)V

    .line 248
    .line 249
    .line 250
    goto/16 :goto_9

    .line 251
    .line 252
    :cond_10
    instance-of p2, p1, Lin/j1;

    .line 253
    .line 254
    if-eqz p2, :cond_1f

    .line 255
    .line 256
    move-object p2, p1

    .line 257
    check-cast p2, Lin/j1;

    .line 258
    .line 259
    iget-object v0, p2, Lin/n1;->n:Ljava/util/ArrayList;

    .line 260
    .line 261
    const/4 v1, 0x0

    .line 262
    if-eqz v0, :cond_12

    .line 263
    .line 264
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 265
    .line 266
    .line 267
    move-result v0

    .line 268
    if-nez v0, :cond_11

    .line 269
    .line 270
    goto :goto_2

    .line 271
    :cond_11
    iget-object v0, p2, Lin/n1;->n:Ljava/util/ArrayList;

    .line 272
    .line 273
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v0

    .line 277
    check-cast v0, Lin/e0;

    .line 278
    .line 279
    invoke-virtual {v0, p0}, Lin/e0;->d(Lin/z1;)F

    .line 280
    .line 281
    .line 282
    move-result v0

    .line 283
    goto :goto_3

    .line 284
    :cond_12
    :goto_2
    move v0, v1

    .line 285
    :goto_3
    iget-object v3, p2, Lin/n1;->o:Ljava/util/ArrayList;

    .line 286
    .line 287
    if-eqz v3, :cond_14

    .line 288
    .line 289
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 290
    .line 291
    .line 292
    move-result v3

    .line 293
    if-nez v3, :cond_13

    .line 294
    .line 295
    goto :goto_4

    .line 296
    :cond_13
    iget-object v3, p2, Lin/n1;->o:Ljava/util/ArrayList;

    .line 297
    .line 298
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v3

    .line 302
    check-cast v3, Lin/e0;

    .line 303
    .line 304
    invoke-virtual {v3, p0}, Lin/e0;->e(Lin/z1;)F

    .line 305
    .line 306
    .line 307
    move-result v3

    .line 308
    goto :goto_5

    .line 309
    :cond_14
    :goto_4
    move v3, v1

    .line 310
    :goto_5
    iget-object v4, p2, Lin/n1;->p:Ljava/util/ArrayList;

    .line 311
    .line 312
    if-eqz v4, :cond_16

    .line 313
    .line 314
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 315
    .line 316
    .line 317
    move-result v4

    .line 318
    if-nez v4, :cond_15

    .line 319
    .line 320
    goto :goto_6

    .line 321
    :cond_15
    iget-object v4, p2, Lin/n1;->p:Ljava/util/ArrayList;

    .line 322
    .line 323
    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v4

    .line 327
    check-cast v4, Lin/e0;

    .line 328
    .line 329
    invoke-virtual {v4, p0}, Lin/e0;->d(Lin/z1;)F

    .line 330
    .line 331
    .line 332
    move-result v4

    .line 333
    goto :goto_7

    .line 334
    :cond_16
    :goto_6
    move v4, v1

    .line 335
    :goto_7
    iget-object v5, p2, Lin/n1;->q:Ljava/util/ArrayList;

    .line 336
    .line 337
    if-eqz v5, :cond_18

    .line 338
    .line 339
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 340
    .line 341
    .line 342
    move-result v5

    .line 343
    if-nez v5, :cond_17

    .line 344
    .line 345
    goto :goto_8

    .line 346
    :cond_17
    iget-object v1, p2, Lin/n1;->q:Ljava/util/ArrayList;

    .line 347
    .line 348
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v1

    .line 352
    check-cast v1, Lin/e0;

    .line 353
    .line 354
    invoke-virtual {v1, p0}, Lin/e0;->e(Lin/z1;)F

    .line 355
    .line 356
    .line 357
    move-result v1

    .line 358
    :cond_18
    :goto_8
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 359
    .line 360
    check-cast v2, Lin/x1;

    .line 361
    .line 362
    iget-object v2, v2, Lin/x1;->a:Lin/s0;

    .line 363
    .line 364
    iget v2, v2, Lin/s0;->M:I

    .line 365
    .line 366
    const/4 v5, 0x1

    .line 367
    if-eq v2, v5, :cond_1a

    .line 368
    .line 369
    invoke-virtual {p0, p2}, Lin/z1;->l(Lin/l1;)F

    .line 370
    .line 371
    .line 372
    move-result v2

    .line 373
    iget-object v5, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 374
    .line 375
    check-cast v5, Lin/x1;

    .line 376
    .line 377
    iget-object v5, v5, Lin/x1;->a:Lin/s0;

    .line 378
    .line 379
    iget v5, v5, Lin/s0;->M:I

    .line 380
    .line 381
    const/4 v6, 0x2

    .line 382
    if-ne v5, v6, :cond_19

    .line 383
    .line 384
    const/high16 v5, 0x40000000    # 2.0f

    .line 385
    .line 386
    div-float/2addr v2, v5

    .line 387
    :cond_19
    sub-float/2addr v0, v2

    .line 388
    :cond_1a
    iget-object v2, p2, Lin/x0;->h:Ld3/a;

    .line 389
    .line 390
    if-nez v2, :cond_1b

    .line 391
    .line 392
    new-instance v2, Lin/w1;

    .line 393
    .line 394
    invoke-direct {v2, p0, v0, v3}, Lin/w1;-><init>(Lin/z1;FF)V

    .line 395
    .line 396
    .line 397
    invoke-virtual {p0, p2, v2}, Lin/z1;->v(Lin/l1;Llp/pa;)V

    .line 398
    .line 399
    .line 400
    new-instance v5, Ld3/a;

    .line 401
    .line 402
    iget-object v6, v2, Lin/w1;->e:Ljava/lang/Object;

    .line 403
    .line 404
    check-cast v6, Landroid/graphics/RectF;

    .line 405
    .line 406
    iget v7, v6, Landroid/graphics/RectF;->left:F

    .line 407
    .line 408
    iget v8, v6, Landroid/graphics/RectF;->top:F

    .line 409
    .line 410
    invoke-virtual {v6}, Landroid/graphics/RectF;->width()F

    .line 411
    .line 412
    .line 413
    move-result v6

    .line 414
    iget-object v2, v2, Lin/w1;->e:Ljava/lang/Object;

    .line 415
    .line 416
    check-cast v2, Landroid/graphics/RectF;

    .line 417
    .line 418
    invoke-virtual {v2}, Landroid/graphics/RectF;->height()F

    .line 419
    .line 420
    .line 421
    move-result v2

    .line 422
    invoke-direct {v5, v7, v8, v6, v2}, Ld3/a;-><init>(FFFF)V

    .line 423
    .line 424
    .line 425
    iput-object v5, p2, Lin/x0;->h:Ld3/a;

    .line 426
    .line 427
    :cond_1b
    new-instance v2, Landroid/graphics/Path;

    .line 428
    .line 429
    invoke-direct {v2}, Landroid/graphics/Path;-><init>()V

    .line 430
    .line 431
    .line 432
    new-instance v5, Lin/w1;

    .line 433
    .line 434
    add-float/2addr v0, v4

    .line 435
    add-float/2addr v3, v1

    .line 436
    invoke-direct {v5, p0, v0, v3, v2}, Lin/w1;-><init>(Lin/z1;FFLandroid/graphics/Path;)V

    .line 437
    .line 438
    .line 439
    invoke-virtual {p0, p2, v5}, Lin/z1;->v(Lin/l1;Llp/pa;)V

    .line 440
    .line 441
    .line 442
    iget-object p2, p2, Lin/j1;->r:Landroid/graphics/Matrix;

    .line 443
    .line 444
    if-eqz p2, :cond_1c

    .line 445
    .line 446
    invoke-virtual {v2, p2}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 447
    .line 448
    .line 449
    :cond_1c
    invoke-virtual {p0}, Lin/z1;->G()Landroid/graphics/Path$FillType;

    .line 450
    .line 451
    .line 452
    move-result-object p2

    .line 453
    invoke-virtual {v2, p2}, Landroid/graphics/Path;->setFillType(Landroid/graphics/Path$FillType;)V

    .line 454
    .line 455
    .line 456
    move-object v0, v2

    .line 457
    :cond_1d
    :goto_9
    iget-object p2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 458
    .line 459
    check-cast p2, Lin/x1;

    .line 460
    .line 461
    iget-object p2, p2, Lin/x1;->a:Lin/s0;

    .line 462
    .line 463
    iget-object p2, p2, Lin/s0;->A:Ljava/lang/String;

    .line 464
    .line 465
    if-eqz p2, :cond_1e

    .line 466
    .line 467
    iget-object p2, p1, Lin/x0;->h:Ld3/a;

    .line 468
    .line 469
    invoke-virtual {p0, p1, p2}, Lin/z1;->j(Lin/x0;Ld3/a;)Landroid/graphics/Path;

    .line 470
    .line 471
    .line 472
    move-result-object p1

    .line 473
    if-eqz p1, :cond_1e

    .line 474
    .line 475
    sget-object p2, Landroid/graphics/Path$Op;->INTERSECT:Landroid/graphics/Path$Op;

    .line 476
    .line 477
    invoke-virtual {v0, p1, p2}, Landroid/graphics/Path;->op(Landroid/graphics/Path;Landroid/graphics/Path$Op;)Z

    .line 478
    .line 479
    .line 480
    :cond_1e
    iget-object p1, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 481
    .line 482
    check-cast p1, Ljava/util/Stack;

    .line 483
    .line 484
    invoke-virtual {p1}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 485
    .line 486
    .line 487
    move-result-object p1

    .line 488
    check-cast p1, Lin/x1;

    .line 489
    .line 490
    iput-object p1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 491
    .line 492
    return-object v0

    .line 493
    :cond_1f
    invoke-virtual {p1}, Lin/a1;->o()Ljava/lang/String;

    .line 494
    .line 495
    .line 496
    move-result-object p0

    .line 497
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 498
    .line 499
    .line 500
    move-result-object p0

    .line 501
    const-string p1, "Invalid %s element found in clipPath definition"

    .line 502
    .line 503
    invoke-static {p1, p0}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 504
    .line 505
    .line 506
    return-object v1

    .line 507
    :cond_20
    :goto_a
    iget-object p1, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 508
    .line 509
    check-cast p1, Ljava/util/Stack;

    .line 510
    .line 511
    invoke-virtual {p1}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 512
    .line 513
    .line 514
    move-result-object p1

    .line 515
    check-cast p1, Lin/x1;

    .line 516
    .line 517
    iput-object p1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 518
    .line 519
    return-object v1
.end method

.method public R(Ld3/a;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/Canvas;

    .line 4
    .line 5
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lin/x1;

    .line 8
    .line 9
    iget-object v1, v1, Lin/x1;->a:Lin/s0;

    .line 10
    .line 11
    iget-object v1, v1, Lin/s0;->B:Ljava/lang/String;

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    new-instance v1, Landroid/graphics/Paint;

    .line 16
    .line 17
    invoke-direct {v1}, Landroid/graphics/Paint;-><init>()V

    .line 18
    .line 19
    .line 20
    new-instance v2, Landroid/graphics/PorterDuffXfermode;

    .line 21
    .line 22
    sget-object v3, Landroid/graphics/PorterDuff$Mode;->DST_IN:Landroid/graphics/PorterDuff$Mode;

    .line 23
    .line 24
    invoke-direct {v2, v3}, Landroid/graphics/PorterDuffXfermode;-><init>(Landroid/graphics/PorterDuff$Mode;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v1, v2}, Landroid/graphics/Paint;->setXfermode(Landroid/graphics/Xfermode;)Landroid/graphics/Xfermode;

    .line 28
    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    const/16 v4, 0x1f

    .line 32
    .line 33
    invoke-virtual {v0, v2, v1, v4}, Landroid/graphics/Canvas;->saveLayer(Landroid/graphics/RectF;Landroid/graphics/Paint;I)I

    .line 34
    .line 35
    .line 36
    new-instance v1, Landroid/graphics/Paint;

    .line 37
    .line 38
    invoke-direct {v1}, Landroid/graphics/Paint;-><init>()V

    .line 39
    .line 40
    .line 41
    new-instance v5, Landroid/graphics/ColorMatrix;

    .line 42
    .line 43
    const/16 v6, 0x14

    .line 44
    .line 45
    new-array v6, v6, [F

    .line 46
    .line 47
    fill-array-data v6, :array_0

    .line 48
    .line 49
    .line 50
    invoke-direct {v5, v6}, Landroid/graphics/ColorMatrix;-><init>([F)V

    .line 51
    .line 52
    .line 53
    new-instance v6, Landroid/graphics/ColorMatrixColorFilter;

    .line 54
    .line 55
    invoke-direct {v6, v5}, Landroid/graphics/ColorMatrixColorFilter;-><init>(Landroid/graphics/ColorMatrix;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v1, v6}, Landroid/graphics/Paint;->setColorFilter(Landroid/graphics/ColorFilter;)Landroid/graphics/ColorFilter;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0, v2, v1, v4}, Landroid/graphics/Canvas;->saveLayer(Landroid/graphics/RectF;Landroid/graphics/Paint;I)I

    .line 62
    .line 63
    .line 64
    iget-object v1, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v1, Lil/g;

    .line 67
    .line 68
    iget-object v5, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v5, Lin/x1;

    .line 71
    .line 72
    iget-object v5, v5, Lin/x1;->a:Lin/s0;

    .line 73
    .line 74
    iget-object v5, v5, Lin/s0;->B:Ljava/lang/String;

    .line 75
    .line 76
    invoke-virtual {v1, v5}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    check-cast v1, Lin/h0;

    .line 81
    .line 82
    invoke-virtual {p0, v1, p1}, Lin/z1;->Z(Lin/h0;Ld3/a;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v0}, Landroid/graphics/Canvas;->restore()V

    .line 86
    .line 87
    .line 88
    new-instance v5, Landroid/graphics/Paint;

    .line 89
    .line 90
    invoke-direct {v5}, Landroid/graphics/Paint;-><init>()V

    .line 91
    .line 92
    .line 93
    new-instance v6, Landroid/graphics/PorterDuffXfermode;

    .line 94
    .line 95
    invoke-direct {v6, v3}, Landroid/graphics/PorterDuffXfermode;-><init>(Landroid/graphics/PorterDuff$Mode;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v5, v6}, Landroid/graphics/Paint;->setXfermode(Landroid/graphics/Xfermode;)Landroid/graphics/Xfermode;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v0, v2, v5, v4}, Landroid/graphics/Canvas;->saveLayer(Landroid/graphics/RectF;Landroid/graphics/Paint;I)I

    .line 102
    .line 103
    .line 104
    invoke-virtual {p0, v1, p1}, Lin/z1;->Z(Lin/h0;Ld3/a;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v0}, Landroid/graphics/Canvas;->restore()V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v0}, Landroid/graphics/Canvas;->restore()V

    .line 111
    .line 112
    .line 113
    :cond_0
    invoke-virtual {p0}, Lin/z1;->e0()V

    .line 114
    .line 115
    .line 116
    return-void

    .line 117
    :array_0
    .array-data 4
        0x0
        0x0
        0x0
        0x0
        0x0
        0x0
        0x0
        0x0
        0x0
        0x0
        0x0
        0x0
        0x0
        0x0
        0x0
        0x3e59ce07    # 0.2127f
        0x3f3710cb    # 0.7151f
        0x3d93dd98    # 0.0722f
        0x0
        0x0
    .end array-data
.end method

.method public S()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lin/x1;

    .line 4
    .line 5
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 6
    .line 7
    iget-object v0, v0, Lin/s0;->m:Ljava/lang/Float;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/high16 v1, 0x3f800000    # 1.0f

    .line 14
    .line 15
    cmpg-float v0, v0, v1

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    if-ltz v0, :cond_1

    .line 19
    .line 20
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v0, Lin/x1;

    .line 23
    .line 24
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 25
    .line 26
    iget-object v0, v0, Lin/s0;->B:Ljava/lang/String;

    .line 27
    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    return v1

    .line 32
    :cond_1
    :goto_0
    iget-object v0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Landroid/graphics/Canvas;

    .line 35
    .line 36
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v2, Lin/x1;

    .line 39
    .line 40
    iget-object v2, v2, Lin/x1;->a:Lin/s0;

    .line 41
    .line 42
    iget-object v2, v2, Lin/s0;->m:Ljava/lang/Float;

    .line 43
    .line 44
    invoke-virtual {v2}, Ljava/lang/Float;->floatValue()F

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    const/high16 v3, 0x43800000    # 256.0f

    .line 49
    .line 50
    mul-float/2addr v2, v3

    .line 51
    float-to-int v2, v2

    .line 52
    if-gez v2, :cond_2

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_2
    const/16 v1, 0xff

    .line 56
    .line 57
    if-le v2, v1, :cond_3

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    move v1, v2

    .line 61
    :goto_1
    const/16 v2, 0x1f

    .line 62
    .line 63
    const/4 v3, 0x0

    .line 64
    invoke-virtual {v0, v3, v1, v2}, Landroid/graphics/Canvas;->saveLayerAlpha(Landroid/graphics/RectF;II)I

    .line 65
    .line 66
    .line 67
    iget-object v0, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v0, Ljava/util/Stack;

    .line 70
    .line 71
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v1, Lin/x1;

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    new-instance v0, Lin/x1;

    .line 79
    .line 80
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v1, Lin/x1;

    .line 83
    .line 84
    invoke-direct {v0, v1}, Lin/x1;-><init>(Lin/x1;)V

    .line 85
    .line 86
    .line 87
    iput-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 88
    .line 89
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 90
    .line 91
    iget-object v0, v0, Lin/s0;->B:Ljava/lang/String;

    .line 92
    .line 93
    const/4 v1, 0x1

    .line 94
    if-eqz v0, :cond_5

    .line 95
    .line 96
    iget-object v2, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v2, Lil/g;

    .line 99
    .line 100
    invoke-virtual {v2, v0}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    if-eqz v0, :cond_4

    .line 105
    .line 106
    instance-of v0, v0, Lin/h0;

    .line 107
    .line 108
    if-nez v0, :cond_5

    .line 109
    .line 110
    :cond_4
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast v0, Lin/x1;

    .line 113
    .line 114
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 115
    .line 116
    iget-object v0, v0, Lin/s0;->B:Ljava/lang/String;

    .line 117
    .line 118
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    const-string v2, "Mask reference \'%s\' not found"

    .line 123
    .line 124
    invoke-static {v2, v0}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    iget-object p0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast p0, Lin/x1;

    .line 130
    .line 131
    iget-object p0, p0, Lin/x1;->a:Lin/s0;

    .line 132
    .line 133
    iput-object v3, p0, Lin/s0;->B:Ljava/lang/String;

    .line 134
    .line 135
    :cond_5
    return v1
.end method

.method public T()V
    .locals 4

    .line 1
    :try_start_0
    invoke-virtual {p0}, Lin/z1;->K()Lu01/s;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 6
    .line 7
    .line 8
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 9
    :try_start_1
    invoke-virtual {v0}, Lu01/b0;->readInt()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    int-to-long v1, v1

    .line 14
    invoke-virtual {v0, v1, v2}, Lu01/b0;->S(J)Lu01/i;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-virtual {v0}, Lu01/b0;->readInt()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    int-to-long v2, v2

    .line 23
    invoke-virtual {v0, v2, v3}, Lu01/b0;->S(J)Lu01/i;

    .line 24
    .line 25
    .line 26
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 27
    :try_start_2
    invoke-virtual {v0}, Lu01/b0;->close()V

    .line 28
    .line 29
    .line 30
    monitor-enter p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 31
    :try_start_3
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iput-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 35
    .line 36
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iput-object v2, p0, Lin/z1;->d:Ljava/lang/Object;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 40
    .line 41
    :try_start_4
    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 42
    iget-object p0, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 45
    .line 46
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :catchall_0
    move-exception v0

    .line 51
    goto :goto_0

    .line 52
    :catchall_1
    move-exception v0

    .line 53
    :try_start_5
    monitor-exit p0

    .line 54
    throw v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 55
    :catchall_2
    move-exception v1

    .line 56
    :try_start_6
    throw v1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 57
    :catchall_3
    move-exception v2

    .line 58
    :try_start_7
    invoke-static {v0, v1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 59
    .line 60
    .line 61
    throw v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 62
    :goto_0
    iget-object p0, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 65
    .line 66
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 67
    .line 68
    .line 69
    throw v0
.end method

.method public U(Lin/t0;Ld3/a;Ld3/a;Lin/s;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/Canvas;

    .line 4
    .line 5
    iget v1, p2, Ld3/a;->d:F

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    cmpl-float v1, v1, v2

    .line 9
    .line 10
    if-eqz v1, :cond_7

    .line 11
    .line 12
    iget v1, p2, Ld3/a;->e:F

    .line 13
    .line 14
    cmpl-float v1, v1, v2

    .line 15
    .line 16
    if-nez v1, :cond_0

    .line 17
    .line 18
    goto/16 :goto_2

    .line 19
    .line 20
    :cond_0
    if-nez p4, :cond_2

    .line 21
    .line 22
    iget-object p4, p1, Lin/c1;->n:Lin/s;

    .line 23
    .line 24
    if-eqz p4, :cond_1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    sget-object p4, Lin/s;->d:Lin/s;

    .line 28
    .line 29
    :cond_2
    :goto_0
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v1, Lin/x1;

    .line 32
    .line 33
    invoke-virtual {p0, v1, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-nez v1, :cond_3

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_3
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v1, Lin/x1;

    .line 46
    .line 47
    iput-object p2, v1, Lin/x1;->f:Ld3/a;

    .line 48
    .line 49
    iget-object p2, v1, Lin/x1;->a:Lin/s0;

    .line 50
    .line 51
    iget-object p2, p2, Lin/s0;->r:Ljava/lang/Boolean;

    .line 52
    .line 53
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    if-nez p2, :cond_4

    .line 58
    .line 59
    iget-object p2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p2, Lin/x1;

    .line 62
    .line 63
    iget-object p2, p2, Lin/x1;->f:Ld3/a;

    .line 64
    .line 65
    iget v1, p2, Ld3/a;->b:F

    .line 66
    .line 67
    iget v2, p2, Ld3/a;->c:F

    .line 68
    .line 69
    iget v3, p2, Ld3/a;->d:F

    .line 70
    .line 71
    iget p2, p2, Ld3/a;->e:F

    .line 72
    .line 73
    invoke-virtual {p0, v1, v2, v3, p2}, Lin/z1;->a0(FFFF)V

    .line 74
    .line 75
    .line 76
    :cond_4
    iget-object p2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast p2, Lin/x1;

    .line 79
    .line 80
    iget-object p2, p2, Lin/x1;->f:Ld3/a;

    .line 81
    .line 82
    invoke-virtual {p0, p1, p2}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 83
    .line 84
    .line 85
    if-eqz p3, :cond_5

    .line 86
    .line 87
    iget-object p2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast p2, Lin/x1;

    .line 90
    .line 91
    iget-object p2, p2, Lin/x1;->f:Ld3/a;

    .line 92
    .line 93
    invoke-static {p2, p3, p4}, Lin/z1;->m(Ld3/a;Ld3/a;Lin/s;)Landroid/graphics/Matrix;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    invoke-virtual {v0, p2}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 98
    .line 99
    .line 100
    iget-object p2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p2, Lin/x1;

    .line 103
    .line 104
    iget-object p3, p1, Lin/e1;->o:Ld3/a;

    .line 105
    .line 106
    iput-object p3, p2, Lin/x1;->g:Ld3/a;

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_5
    iget-object p2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast p2, Lin/x1;

    .line 112
    .line 113
    iget-object p2, p2, Lin/x1;->f:Ld3/a;

    .line 114
    .line 115
    iget p3, p2, Ld3/a;->b:F

    .line 116
    .line 117
    iget p2, p2, Ld3/a;->c:F

    .line 118
    .line 119
    invoke-virtual {v0, p3, p2}, Landroid/graphics/Canvas;->translate(FF)V

    .line 120
    .line 121
    .line 122
    :goto_1
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 123
    .line 124
    .line 125
    move-result p2

    .line 126
    invoke-virtual {p0}, Lin/z1;->l0()V

    .line 127
    .line 128
    .line 129
    const/4 p3, 0x1

    .line 130
    invoke-virtual {p0, p1, p3}, Lin/z1;->W(Lin/v0;Z)V

    .line 131
    .line 132
    .line 133
    if-eqz p2, :cond_6

    .line 134
    .line 135
    iget-object p2, p1, Lin/x0;->h:Ld3/a;

    .line 136
    .line 137
    invoke-virtual {p0, p2}, Lin/z1;->R(Ld3/a;)V

    .line 138
    .line 139
    .line 140
    :cond_6
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 141
    .line 142
    .line 143
    :cond_7
    :goto_2
    return-void
.end method

.method public V(Lin/a1;)V
    .locals 13

    .line 1
    instance-of v0, p1, Lin/i0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    invoke-virtual {p0}, Lin/z1;->f0()V

    .line 7
    .line 8
    .line 9
    instance-of v0, p1, Lin/y0;

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_1
    move-object v0, p1

    .line 15
    check-cast v0, Lin/y0;

    .line 16
    .line 17
    iget-object v0, v0, Lin/y0;->d:Ljava/lang/Boolean;

    .line 18
    .line 19
    if-eqz v0, :cond_2

    .line 20
    .line 21
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v1, Lin/x1;

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iput-boolean v0, v1, Lin/x1;->h:Z

    .line 30
    .line 31
    :cond_2
    :goto_0
    instance-of v0, p1, Lin/t0;

    .line 32
    .line 33
    if-eqz v0, :cond_3

    .line 34
    .line 35
    check-cast p1, Lin/t0;

    .line 36
    .line 37
    iget-object v0, p1, Lin/t0;->p:Lin/e0;

    .line 38
    .line 39
    iget-object v1, p1, Lin/t0;->q:Lin/e0;

    .line 40
    .line 41
    iget-object v2, p1, Lin/t0;->r:Lin/e0;

    .line 42
    .line 43
    iget-object v3, p1, Lin/t0;->s:Lin/e0;

    .line 44
    .line 45
    invoke-virtual {p0, v0, v1, v2, v3}, Lin/z1;->P(Lin/e0;Lin/e0;Lin/e0;Lin/e0;)Ld3/a;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    iget-object v1, p1, Lin/e1;->o:Ld3/a;

    .line 50
    .line 51
    iget-object v2, p1, Lin/c1;->n:Lin/s;

    .line 52
    .line 53
    invoke-virtual {p0, p1, v0, v1, v2}, Lin/z1;->U(Lin/t0;Ld3/a;Ld3/a;Lin/s;)V

    .line 54
    .line 55
    .line 56
    goto/16 :goto_1d

    .line 57
    .line 58
    :cond_3
    instance-of v0, p1, Lin/p1;

    .line 59
    .line 60
    const/4 v1, 0x0

    .line 61
    const/4 v2, 0x1

    .line 62
    const/4 v3, 0x0

    .line 63
    if-eqz v0, :cond_16

    .line 64
    .line 65
    check-cast p1, Lin/p1;

    .line 66
    .line 67
    iget-object v0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v0, Landroid/graphics/Canvas;

    .line 70
    .line 71
    iget-object v4, p1, Lin/p1;->r:Lin/e0;

    .line 72
    .line 73
    if-eqz v4, :cond_4

    .line 74
    .line 75
    invoke-virtual {v4}, Lin/e0;->h()Z

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    if-nez v4, :cond_7f

    .line 80
    .line 81
    :cond_4
    iget-object v4, p1, Lin/p1;->s:Lin/e0;

    .line 82
    .line 83
    if-eqz v4, :cond_5

    .line 84
    .line 85
    invoke-virtual {v4}, Lin/e0;->h()Z

    .line 86
    .line 87
    .line 88
    move-result v4

    .line 89
    if-eqz v4, :cond_5

    .line 90
    .line 91
    goto/16 :goto_1d

    .line 92
    .line 93
    :cond_5
    iget-object v4, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v4, Lin/x1;

    .line 96
    .line 97
    invoke-virtual {p0, v4, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 101
    .line 102
    .line 103
    move-result v4

    .line 104
    if-nez v4, :cond_6

    .line 105
    .line 106
    goto/16 :goto_1d

    .line 107
    .line 108
    :cond_6
    iget-object v4, p1, Lin/a1;->a:Lil/g;

    .line 109
    .line 110
    iget-object v5, p1, Lin/p1;->o:Ljava/lang/String;

    .line 111
    .line 112
    invoke-virtual {v4, v5}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    if-nez v4, :cond_7

    .line 117
    .line 118
    const-string v0, "Use reference \'%s\' not found"

    .line 119
    .line 120
    iget-object p1, p1, Lin/p1;->o:Ljava/lang/String;

    .line 121
    .line 122
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    invoke-static {v0, p1}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    goto/16 :goto_1d

    .line 130
    .line 131
    :cond_7
    iget-object v5, p1, Lin/b0;->n:Landroid/graphics/Matrix;

    .line 132
    .line 133
    if-eqz v5, :cond_8

    .line 134
    .line 135
    invoke-virtual {v0, v5}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 136
    .line 137
    .line 138
    :cond_8
    iget-object v5, p1, Lin/p1;->p:Lin/e0;

    .line 139
    .line 140
    if-eqz v5, :cond_9

    .line 141
    .line 142
    invoke-virtual {v5, p0}, Lin/e0;->d(Lin/z1;)F

    .line 143
    .line 144
    .line 145
    move-result v5

    .line 146
    goto :goto_1

    .line 147
    :cond_9
    move v5, v3

    .line 148
    :goto_1
    iget-object v6, p1, Lin/p1;->q:Lin/e0;

    .line 149
    .line 150
    if-eqz v6, :cond_a

    .line 151
    .line 152
    invoke-virtual {v6, p0}, Lin/e0;->e(Lin/z1;)F

    .line 153
    .line 154
    .line 155
    move-result v6

    .line 156
    goto :goto_2

    .line 157
    :cond_a
    move v6, v3

    .line 158
    :goto_2
    invoke-virtual {v0, v5, v6}, Landroid/graphics/Canvas;->translate(FF)V

    .line 159
    .line 160
    .line 161
    iget-object v5, p1, Lin/x0;->h:Ld3/a;

    .line 162
    .line 163
    invoke-virtual {p0, p1, v5}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 167
    .line 168
    .line 169
    move-result v5

    .line 170
    iget-object v6, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast v6, Ljava/util/Stack;

    .line 173
    .line 174
    invoke-virtual {v6, p1}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    iget-object v6, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 178
    .line 179
    check-cast v6, Ljava/util/Stack;

    .line 180
    .line 181
    iget-object v7, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast v7, Landroid/graphics/Canvas;

    .line 184
    .line 185
    invoke-virtual {v7}, Landroid/graphics/Canvas;->getMatrix()Landroid/graphics/Matrix;

    .line 186
    .line 187
    .line 188
    move-result-object v7

    .line 189
    invoke-virtual {v6, v7}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    instance-of v6, v4, Lin/t0;

    .line 193
    .line 194
    if-eqz v6, :cond_b

    .line 195
    .line 196
    check-cast v4, Lin/t0;

    .line 197
    .line 198
    iget-object v0, p1, Lin/p1;->r:Lin/e0;

    .line 199
    .line 200
    iget-object v2, p1, Lin/p1;->s:Lin/e0;

    .line 201
    .line 202
    invoke-virtual {p0, v1, v1, v0, v2}, Lin/z1;->P(Lin/e0;Lin/e0;Lin/e0;Lin/e0;)Ld3/a;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    invoke-virtual {p0}, Lin/z1;->f0()V

    .line 207
    .line 208
    .line 209
    iget-object v1, v4, Lin/e1;->o:Ld3/a;

    .line 210
    .line 211
    iget-object v2, v4, Lin/c1;->n:Lin/s;

    .line 212
    .line 213
    invoke-virtual {p0, v4, v0, v1, v2}, Lin/z1;->U(Lin/t0;Ld3/a;Ld3/a;Lin/s;)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {p0}, Lin/z1;->e0()V

    .line 217
    .line 218
    .line 219
    goto/16 :goto_8

    .line 220
    .line 221
    :cond_b
    instance-of v6, v4, Lin/g1;

    .line 222
    .line 223
    if-eqz v6, :cond_14

    .line 224
    .line 225
    iget-object v6, p1, Lin/p1;->r:Lin/e0;

    .line 226
    .line 227
    const/16 v7, 0x9

    .line 228
    .line 229
    const/high16 v8, 0x42c80000    # 100.0f

    .line 230
    .line 231
    if-eqz v6, :cond_c

    .line 232
    .line 233
    goto :goto_3

    .line 234
    :cond_c
    new-instance v6, Lin/e0;

    .line 235
    .line 236
    invoke-direct {v6, v7, v8}, Lin/e0;-><init>(IF)V

    .line 237
    .line 238
    .line 239
    :goto_3
    iget-object v9, p1, Lin/p1;->s:Lin/e0;

    .line 240
    .line 241
    if-eqz v9, :cond_d

    .line 242
    .line 243
    goto :goto_4

    .line 244
    :cond_d
    new-instance v9, Lin/e0;

    .line 245
    .line 246
    invoke-direct {v9, v7, v8}, Lin/e0;-><init>(IF)V

    .line 247
    .line 248
    .line 249
    :goto_4
    invoke-virtual {p0, v1, v1, v6, v9}, Lin/z1;->P(Lin/e0;Lin/e0;Lin/e0;Lin/e0;)Ld3/a;

    .line 250
    .line 251
    .line 252
    move-result-object v1

    .line 253
    invoke-virtual {p0}, Lin/z1;->f0()V

    .line 254
    .line 255
    .line 256
    check-cast v4, Lin/g1;

    .line 257
    .line 258
    iget v6, v1, Ld3/a;->d:F

    .line 259
    .line 260
    cmpl-float v6, v6, v3

    .line 261
    .line 262
    if-eqz v6, :cond_13

    .line 263
    .line 264
    iget v6, v1, Ld3/a;->e:F

    .line 265
    .line 266
    cmpl-float v3, v6, v3

    .line 267
    .line 268
    if-nez v3, :cond_e

    .line 269
    .line 270
    goto :goto_7

    .line 271
    :cond_e
    iget-object v3, v4, Lin/c1;->n:Lin/s;

    .line 272
    .line 273
    if-eqz v3, :cond_f

    .line 274
    .line 275
    goto :goto_5

    .line 276
    :cond_f
    sget-object v3, Lin/s;->d:Lin/s;

    .line 277
    .line 278
    :goto_5
    iget-object v6, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 279
    .line 280
    check-cast v6, Lin/x1;

    .line 281
    .line 282
    invoke-virtual {p0, v6, v4}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 283
    .line 284
    .line 285
    iget-object v6, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 286
    .line 287
    check-cast v6, Lin/x1;

    .line 288
    .line 289
    iput-object v1, v6, Lin/x1;->f:Ld3/a;

    .line 290
    .line 291
    iget-object v1, v6, Lin/x1;->a:Lin/s0;

    .line 292
    .line 293
    iget-object v1, v1, Lin/s0;->r:Ljava/lang/Boolean;

    .line 294
    .line 295
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 296
    .line 297
    .line 298
    move-result v1

    .line 299
    if-nez v1, :cond_10

    .line 300
    .line 301
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 302
    .line 303
    check-cast v1, Lin/x1;

    .line 304
    .line 305
    iget-object v1, v1, Lin/x1;->f:Ld3/a;

    .line 306
    .line 307
    iget v6, v1, Ld3/a;->b:F

    .line 308
    .line 309
    iget v7, v1, Ld3/a;->c:F

    .line 310
    .line 311
    iget v8, v1, Ld3/a;->d:F

    .line 312
    .line 313
    iget v1, v1, Ld3/a;->e:F

    .line 314
    .line 315
    invoke-virtual {p0, v6, v7, v8, v1}, Lin/z1;->a0(FFFF)V

    .line 316
    .line 317
    .line 318
    :cond_10
    iget-object v1, v4, Lin/e1;->o:Ld3/a;

    .line 319
    .line 320
    if-eqz v1, :cond_11

    .line 321
    .line 322
    iget-object v6, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 323
    .line 324
    check-cast v6, Lin/x1;

    .line 325
    .line 326
    iget-object v6, v6, Lin/x1;->f:Ld3/a;

    .line 327
    .line 328
    invoke-static {v6, v1, v3}, Lin/z1;->m(Ld3/a;Ld3/a;Lin/s;)Landroid/graphics/Matrix;

    .line 329
    .line 330
    .line 331
    move-result-object v1

    .line 332
    invoke-virtual {v0, v1}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 333
    .line 334
    .line 335
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 336
    .line 337
    check-cast v0, Lin/x1;

    .line 338
    .line 339
    iget-object v1, v4, Lin/e1;->o:Ld3/a;

    .line 340
    .line 341
    iput-object v1, v0, Lin/x1;->g:Ld3/a;

    .line 342
    .line 343
    goto :goto_6

    .line 344
    :cond_11
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 345
    .line 346
    check-cast v1, Lin/x1;

    .line 347
    .line 348
    iget-object v1, v1, Lin/x1;->f:Ld3/a;

    .line 349
    .line 350
    iget v3, v1, Ld3/a;->b:F

    .line 351
    .line 352
    iget v1, v1, Ld3/a;->c:F

    .line 353
    .line 354
    invoke-virtual {v0, v3, v1}, Landroid/graphics/Canvas;->translate(FF)V

    .line 355
    .line 356
    .line 357
    :goto_6
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 358
    .line 359
    .line 360
    move-result v0

    .line 361
    invoke-virtual {p0, v4, v2}, Lin/z1;->W(Lin/v0;Z)V

    .line 362
    .line 363
    .line 364
    if-eqz v0, :cond_12

    .line 365
    .line 366
    iget-object v0, v4, Lin/x0;->h:Ld3/a;

    .line 367
    .line 368
    invoke-virtual {p0, v0}, Lin/z1;->R(Ld3/a;)V

    .line 369
    .line 370
    .line 371
    :cond_12
    invoke-virtual {p0, v4}, Lin/z1;->i0(Lin/x0;)V

    .line 372
    .line 373
    .line 374
    :cond_13
    :goto_7
    invoke-virtual {p0}, Lin/z1;->e0()V

    .line 375
    .line 376
    .line 377
    goto :goto_8

    .line 378
    :cond_14
    invoke-virtual {p0, v4}, Lin/z1;->V(Lin/a1;)V

    .line 379
    .line 380
    .line 381
    :goto_8
    iget-object v0, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 382
    .line 383
    check-cast v0, Ljava/util/Stack;

    .line 384
    .line 385
    invoke-virtual {v0}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 386
    .line 387
    .line 388
    iget-object v0, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 389
    .line 390
    check-cast v0, Ljava/util/Stack;

    .line 391
    .line 392
    invoke-virtual {v0}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 393
    .line 394
    .line 395
    if-eqz v5, :cond_15

    .line 396
    .line 397
    iget-object v0, p1, Lin/x0;->h:Ld3/a;

    .line 398
    .line 399
    invoke-virtual {p0, v0}, Lin/z1;->R(Ld3/a;)V

    .line 400
    .line 401
    .line 402
    :cond_15
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 403
    .line 404
    .line 405
    goto/16 :goto_1d

    .line 406
    .line 407
    :cond_16
    instance-of v0, p1, Lin/f1;

    .line 408
    .line 409
    if-eqz v0, :cond_23

    .line 410
    .line 411
    check-cast p1, Lin/f1;

    .line 412
    .line 413
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 414
    .line 415
    check-cast v0, Lin/x1;

    .line 416
    .line 417
    invoke-virtual {p0, v0, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 418
    .line 419
    .line 420
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 421
    .line 422
    .line 423
    move-result v0

    .line 424
    if-nez v0, :cond_17

    .line 425
    .line 426
    goto/16 :goto_1d

    .line 427
    .line 428
    :cond_17
    iget-object v0, p1, Lin/b0;->n:Landroid/graphics/Matrix;

    .line 429
    .line 430
    if-eqz v0, :cond_18

    .line 431
    .line 432
    iget-object v1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 433
    .line 434
    check-cast v1, Landroid/graphics/Canvas;

    .line 435
    .line 436
    invoke-virtual {v1, v0}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 437
    .line 438
    .line 439
    :cond_18
    iget-object v0, p1, Lin/x0;->h:Ld3/a;

    .line 440
    .line 441
    invoke-virtual {p0, p1, v0}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 442
    .line 443
    .line 444
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 445
    .line 446
    .line 447
    move-result v0

    .line 448
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 449
    .line 450
    .line 451
    move-result-object v1

    .line 452
    invoke-virtual {v1}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    .line 453
    .line 454
    .line 455
    move-result-object v1

    .line 456
    iget-object v2, p1, Lin/v0;->i:Ljava/util/List;

    .line 457
    .line 458
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 459
    .line 460
    .line 461
    move-result-object v2

    .line 462
    :cond_19
    :goto_9
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 463
    .line 464
    .line 465
    move-result v3

    .line 466
    if-eqz v3, :cond_21

    .line 467
    .line 468
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 469
    .line 470
    .line 471
    move-result-object v3

    .line 472
    check-cast v3, Lin/a1;

    .line 473
    .line 474
    instance-of v4, v3, Lin/u0;

    .line 475
    .line 476
    if-nez v4, :cond_1a

    .line 477
    .line 478
    goto :goto_9

    .line 479
    :cond_1a
    move-object v4, v3

    .line 480
    check-cast v4, Lin/u0;

    .line 481
    .line 482
    invoke-interface {v4}, Lin/u0;->c()Ljava/lang/String;

    .line 483
    .line 484
    .line 485
    move-result-object v5

    .line 486
    if-eqz v5, :cond_1b

    .line 487
    .line 488
    goto :goto_9

    .line 489
    :cond_1b
    invoke-interface {v4}, Lin/u0;->a()Ljava/util/Set;

    .line 490
    .line 491
    .line 492
    move-result-object v5

    .line 493
    if-eqz v5, :cond_1c

    .line 494
    .line 495
    invoke-interface {v5}, Ljava/util/Set;->isEmpty()Z

    .line 496
    .line 497
    .line 498
    move-result v6

    .line 499
    if-nez v6, :cond_19

    .line 500
    .line 501
    invoke-interface {v5, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 502
    .line 503
    .line 504
    move-result v5

    .line 505
    if-nez v5, :cond_1c

    .line 506
    .line 507
    goto :goto_9

    .line 508
    :cond_1c
    invoke-interface {v4}, Lin/u0;->g()Ljava/util/Set;

    .line 509
    .line 510
    .line 511
    move-result-object v5

    .line 512
    if-eqz v5, :cond_1e

    .line 513
    .line 514
    sget-object v6, Lin/z1;->g:Ljava/util/HashSet;

    .line 515
    .line 516
    if-nez v6, :cond_1d

    .line 517
    .line 518
    const-class v6, Lin/z1;

    .line 519
    .line 520
    monitor-enter v6

    .line 521
    :try_start_0
    new-instance v7, Ljava/util/HashSet;

    .line 522
    .line 523
    invoke-direct {v7}, Ljava/util/HashSet;-><init>()V

    .line 524
    .line 525
    .line 526
    sput-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 527
    .line 528
    const-string v8, "Structure"

    .line 529
    .line 530
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 531
    .line 532
    .line 533
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 534
    .line 535
    const-string v8, "BasicStructure"

    .line 536
    .line 537
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 538
    .line 539
    .line 540
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 541
    .line 542
    const-string v8, "ConditionalProcessing"

    .line 543
    .line 544
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 545
    .line 546
    .line 547
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 548
    .line 549
    const-string v8, "Image"

    .line 550
    .line 551
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 552
    .line 553
    .line 554
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 555
    .line 556
    const-string v8, "Style"

    .line 557
    .line 558
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 559
    .line 560
    .line 561
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 562
    .line 563
    const-string v8, "ViewportAttribute"

    .line 564
    .line 565
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 566
    .line 567
    .line 568
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 569
    .line 570
    const-string v8, "Shape"

    .line 571
    .line 572
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 573
    .line 574
    .line 575
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 576
    .line 577
    const-string v8, "BasicText"

    .line 578
    .line 579
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 580
    .line 581
    .line 582
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 583
    .line 584
    const-string v8, "PaintAttribute"

    .line 585
    .line 586
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 587
    .line 588
    .line 589
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 590
    .line 591
    const-string v8, "BasicPaintAttribute"

    .line 592
    .line 593
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 594
    .line 595
    .line 596
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 597
    .line 598
    const-string v8, "OpacityAttribute"

    .line 599
    .line 600
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 601
    .line 602
    .line 603
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 604
    .line 605
    const-string v8, "BasicGraphicsAttribute"

    .line 606
    .line 607
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 608
    .line 609
    .line 610
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 611
    .line 612
    const-string v8, "Marker"

    .line 613
    .line 614
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 615
    .line 616
    .line 617
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 618
    .line 619
    const-string v8, "Gradient"

    .line 620
    .line 621
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 622
    .line 623
    .line 624
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 625
    .line 626
    const-string v8, "Pattern"

    .line 627
    .line 628
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 629
    .line 630
    .line 631
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 632
    .line 633
    const-string v8, "Clip"

    .line 634
    .line 635
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 636
    .line 637
    .line 638
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 639
    .line 640
    const-string v8, "BasicClip"

    .line 641
    .line 642
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 643
    .line 644
    .line 645
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 646
    .line 647
    const-string v8, "Mask"

    .line 648
    .line 649
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 650
    .line 651
    .line 652
    sget-object v7, Lin/z1;->g:Ljava/util/HashSet;

    .line 653
    .line 654
    const-string v8, "View"

    .line 655
    .line 656
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 657
    .line 658
    .line 659
    monitor-exit v6

    .line 660
    goto :goto_a

    .line 661
    :catchall_0
    move-exception p0

    .line 662
    :try_start_1
    monitor-exit v6
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 663
    throw p0

    .line 664
    :cond_1d
    :goto_a
    invoke-interface {v5}, Ljava/util/Set;->isEmpty()Z

    .line 665
    .line 666
    .line 667
    move-result v6

    .line 668
    if-nez v6, :cond_19

    .line 669
    .line 670
    sget-object v6, Lin/z1;->g:Ljava/util/HashSet;

    .line 671
    .line 672
    invoke-virtual {v6, v5}, Ljava/util/AbstractCollection;->containsAll(Ljava/util/Collection;)Z

    .line 673
    .line 674
    .line 675
    move-result v5

    .line 676
    if-nez v5, :cond_1e

    .line 677
    .line 678
    goto/16 :goto_9

    .line 679
    .line 680
    :cond_1e
    invoke-interface {v4}, Lin/u0;->m()Ljava/util/Set;

    .line 681
    .line 682
    .line 683
    move-result-object v5

    .line 684
    if-eqz v5, :cond_1f

    .line 685
    .line 686
    invoke-interface {v5}, Ljava/util/Set;->isEmpty()Z

    .line 687
    .line 688
    .line 689
    goto/16 :goto_9

    .line 690
    .line 691
    :cond_1f
    invoke-interface {v4}, Lin/u0;->n()Ljava/util/Set;

    .line 692
    .line 693
    .line 694
    move-result-object v4

    .line 695
    if-eqz v4, :cond_20

    .line 696
    .line 697
    invoke-interface {v4}, Ljava/util/Set;->isEmpty()Z

    .line 698
    .line 699
    .line 700
    goto/16 :goto_9

    .line 701
    .line 702
    :cond_20
    invoke-virtual {p0, v3}, Lin/z1;->V(Lin/a1;)V

    .line 703
    .line 704
    .line 705
    :cond_21
    if-eqz v0, :cond_22

    .line 706
    .line 707
    iget-object v0, p1, Lin/x0;->h:Ld3/a;

    .line 708
    .line 709
    invoke-virtual {p0, v0}, Lin/z1;->R(Ld3/a;)V

    .line 710
    .line 711
    .line 712
    :cond_22
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 713
    .line 714
    .line 715
    goto/16 :goto_1d

    .line 716
    .line 717
    :cond_23
    instance-of v0, p1, Lin/b0;

    .line 718
    .line 719
    if-eqz v0, :cond_27

    .line 720
    .line 721
    check-cast p1, Lin/b0;

    .line 722
    .line 723
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 724
    .line 725
    check-cast v0, Lin/x1;

    .line 726
    .line 727
    invoke-virtual {p0, v0, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 728
    .line 729
    .line 730
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 731
    .line 732
    .line 733
    move-result v0

    .line 734
    if-nez v0, :cond_24

    .line 735
    .line 736
    goto/16 :goto_1d

    .line 737
    .line 738
    :cond_24
    iget-object v0, p1, Lin/b0;->n:Landroid/graphics/Matrix;

    .line 739
    .line 740
    if-eqz v0, :cond_25

    .line 741
    .line 742
    iget-object v1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 743
    .line 744
    check-cast v1, Landroid/graphics/Canvas;

    .line 745
    .line 746
    invoke-virtual {v1, v0}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 747
    .line 748
    .line 749
    :cond_25
    iget-object v0, p1, Lin/x0;->h:Ld3/a;

    .line 750
    .line 751
    invoke-virtual {p0, p1, v0}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 752
    .line 753
    .line 754
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 755
    .line 756
    .line 757
    move-result v0

    .line 758
    invoke-virtual {p0, p1, v2}, Lin/z1;->W(Lin/v0;Z)V

    .line 759
    .line 760
    .line 761
    if-eqz v0, :cond_26

    .line 762
    .line 763
    iget-object v0, p1, Lin/x0;->h:Ld3/a;

    .line 764
    .line 765
    invoke-virtual {p0, v0}, Lin/z1;->R(Ld3/a;)V

    .line 766
    .line 767
    .line 768
    :cond_26
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 769
    .line 770
    .line 771
    goto/16 :goto_1d

    .line 772
    .line 773
    :cond_27
    instance-of v0, p1, Lin/d0;

    .line 774
    .line 775
    const/4 v4, 0x0

    .line 776
    const/4 v5, 0x2

    .line 777
    if-eqz v0, :cond_37

    .line 778
    .line 779
    check-cast p1, Lin/d0;

    .line 780
    .line 781
    iget-object v0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 782
    .line 783
    check-cast v0, Landroid/graphics/Canvas;

    .line 784
    .line 785
    iget-object v6, p1, Lin/d0;->r:Lin/e0;

    .line 786
    .line 787
    if-eqz v6, :cond_7f

    .line 788
    .line 789
    invoke-virtual {v6}, Lin/e0;->h()Z

    .line 790
    .line 791
    .line 792
    move-result v6

    .line 793
    if-nez v6, :cond_7f

    .line 794
    .line 795
    iget-object v6, p1, Lin/d0;->s:Lin/e0;

    .line 796
    .line 797
    if-eqz v6, :cond_7f

    .line 798
    .line 799
    invoke-virtual {v6}, Lin/e0;->h()Z

    .line 800
    .line 801
    .line 802
    move-result v6

    .line 803
    if-eqz v6, :cond_28

    .line 804
    .line 805
    goto/16 :goto_1d

    .line 806
    .line 807
    :cond_28
    iget-object v6, p1, Lin/d0;->o:Ljava/lang/String;

    .line 808
    .line 809
    if-nez v6, :cond_29

    .line 810
    .line 811
    goto/16 :goto_1d

    .line 812
    .line 813
    :cond_29
    iget-object v7, p1, Lin/c1;->n:Lin/s;

    .line 814
    .line 815
    if-eqz v7, :cond_2a

    .line 816
    .line 817
    goto :goto_b

    .line 818
    :cond_2a
    sget-object v7, Lin/s;->d:Lin/s;

    .line 819
    .line 820
    :goto_b
    const-string v8, "data:"

    .line 821
    .line 822
    invoke-virtual {v6, v8}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 823
    .line 824
    .line 825
    move-result v8

    .line 826
    if-nez v8, :cond_2b

    .line 827
    .line 828
    goto :goto_c

    .line 829
    :cond_2b
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 830
    .line 831
    .line 832
    move-result v8

    .line 833
    const/16 v9, 0xe

    .line 834
    .line 835
    if-ge v8, v9, :cond_2c

    .line 836
    .line 837
    goto :goto_c

    .line 838
    :cond_2c
    const/16 v8, 0x2c

    .line 839
    .line 840
    invoke-virtual {v6, v8}, Ljava/lang/String;->indexOf(I)I

    .line 841
    .line 842
    .line 843
    move-result v8

    .line 844
    const/16 v9, 0xc

    .line 845
    .line 846
    if-ge v8, v9, :cond_2d

    .line 847
    .line 848
    goto :goto_c

    .line 849
    :cond_2d
    const-string v9, ";base64"

    .line 850
    .line 851
    add-int/lit8 v10, v8, -0x7

    .line 852
    .line 853
    invoke-virtual {v6, v10, v8}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 854
    .line 855
    .line 856
    move-result-object v10

    .line 857
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 858
    .line 859
    .line 860
    move-result v9

    .line 861
    if-nez v9, :cond_2e

    .line 862
    .line 863
    goto :goto_c

    .line 864
    :cond_2e
    add-int/2addr v8, v2

    .line 865
    :try_start_2
    invoke-virtual {v6, v8}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 866
    .line 867
    .line 868
    move-result-object v2

    .line 869
    invoke-static {v2, v4}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 870
    .line 871
    .line 872
    move-result-object v2

    .line 873
    array-length v6, v2

    .line 874
    invoke-static {v2, v4, v6}, Landroid/graphics/BitmapFactory;->decodeByteArray([BII)Landroid/graphics/Bitmap;

    .line 875
    .line 876
    .line 877
    move-result-object v1
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 878
    goto :goto_c

    .line 879
    :catch_0
    move-exception v2

    .line 880
    const-string v6, "SVGAndroidRenderer"

    .line 881
    .line 882
    const-string v8, "Could not decode bad Data URL"

    .line 883
    .line 884
    invoke-static {v6, v8, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 885
    .line 886
    .line 887
    :goto_c
    if-nez v1, :cond_2f

    .line 888
    .line 889
    goto/16 :goto_1d

    .line 890
    .line 891
    :cond_2f
    new-instance v2, Ld3/a;

    .line 892
    .line 893
    invoke-virtual {v1}, Landroid/graphics/Bitmap;->getWidth()I

    .line 894
    .line 895
    .line 896
    move-result v6

    .line 897
    int-to-float v6, v6

    .line 898
    invoke-virtual {v1}, Landroid/graphics/Bitmap;->getHeight()I

    .line 899
    .line 900
    .line 901
    move-result v8

    .line 902
    int-to-float v8, v8

    .line 903
    invoke-direct {v2, v3, v3, v6, v8}, Ld3/a;-><init>(FFFF)V

    .line 904
    .line 905
    .line 906
    iget-object v6, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 907
    .line 908
    check-cast v6, Lin/x1;

    .line 909
    .line 910
    invoke-virtual {p0, v6, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 911
    .line 912
    .line 913
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 914
    .line 915
    .line 916
    move-result v6

    .line 917
    if-nez v6, :cond_30

    .line 918
    .line 919
    goto/16 :goto_1d

    .line 920
    .line 921
    :cond_30
    invoke-virtual {p0}, Lin/z1;->m0()Z

    .line 922
    .line 923
    .line 924
    move-result v6

    .line 925
    if-nez v6, :cond_31

    .line 926
    .line 927
    goto/16 :goto_1d

    .line 928
    .line 929
    :cond_31
    iget-object v6, p1, Lin/d0;->t:Landroid/graphics/Matrix;

    .line 930
    .line 931
    if-eqz v6, :cond_32

    .line 932
    .line 933
    invoke-virtual {v0, v6}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 934
    .line 935
    .line 936
    :cond_32
    iget-object v6, p1, Lin/d0;->p:Lin/e0;

    .line 937
    .line 938
    if-eqz v6, :cond_33

    .line 939
    .line 940
    invoke-virtual {v6, p0}, Lin/e0;->d(Lin/z1;)F

    .line 941
    .line 942
    .line 943
    move-result v6

    .line 944
    goto :goto_d

    .line 945
    :cond_33
    move v6, v3

    .line 946
    :goto_d
    iget-object v8, p1, Lin/d0;->q:Lin/e0;

    .line 947
    .line 948
    if-eqz v8, :cond_34

    .line 949
    .line 950
    invoke-virtual {v8, p0}, Lin/e0;->e(Lin/z1;)F

    .line 951
    .line 952
    .line 953
    move-result v8

    .line 954
    goto :goto_e

    .line 955
    :cond_34
    move v8, v3

    .line 956
    :goto_e
    iget-object v9, p1, Lin/d0;->r:Lin/e0;

    .line 957
    .line 958
    invoke-virtual {v9, p0}, Lin/e0;->d(Lin/z1;)F

    .line 959
    .line 960
    .line 961
    move-result v9

    .line 962
    iget-object v10, p1, Lin/d0;->s:Lin/e0;

    .line 963
    .line 964
    invoke-virtual {v10, p0}, Lin/e0;->d(Lin/z1;)F

    .line 965
    .line 966
    .line 967
    move-result v10

    .line 968
    iget-object v11, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 969
    .line 970
    check-cast v11, Lin/x1;

    .line 971
    .line 972
    new-instance v12, Ld3/a;

    .line 973
    .line 974
    invoke-direct {v12, v6, v8, v9, v10}, Ld3/a;-><init>(FFFF)V

    .line 975
    .line 976
    .line 977
    iput-object v12, v11, Lin/x1;->f:Ld3/a;

    .line 978
    .line 979
    iget-object v6, v11, Lin/x1;->a:Lin/s0;

    .line 980
    .line 981
    iget-object v6, v6, Lin/s0;->r:Ljava/lang/Boolean;

    .line 982
    .line 983
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 984
    .line 985
    .line 986
    move-result v6

    .line 987
    if-nez v6, :cond_35

    .line 988
    .line 989
    iget-object v6, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 990
    .line 991
    check-cast v6, Lin/x1;

    .line 992
    .line 993
    iget-object v6, v6, Lin/x1;->f:Ld3/a;

    .line 994
    .line 995
    iget v8, v6, Ld3/a;->b:F

    .line 996
    .line 997
    iget v9, v6, Ld3/a;->c:F

    .line 998
    .line 999
    iget v10, v6, Ld3/a;->d:F

    .line 1000
    .line 1001
    iget v6, v6, Ld3/a;->e:F

    .line 1002
    .line 1003
    invoke-virtual {p0, v8, v9, v10, v6}, Lin/z1;->a0(FFFF)V

    .line 1004
    .line 1005
    .line 1006
    :cond_35
    iget-object v6, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1007
    .line 1008
    check-cast v6, Lin/x1;

    .line 1009
    .line 1010
    iget-object v6, v6, Lin/x1;->f:Ld3/a;

    .line 1011
    .line 1012
    iput-object v6, p1, Lin/x0;->h:Ld3/a;

    .line 1013
    .line 1014
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 1015
    .line 1016
    .line 1017
    iget-object v6, p1, Lin/x0;->h:Ld3/a;

    .line 1018
    .line 1019
    invoke-virtual {p0, p1, v6}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 1020
    .line 1021
    .line 1022
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 1023
    .line 1024
    .line 1025
    move-result v6

    .line 1026
    invoke-virtual {p0}, Lin/z1;->l0()V

    .line 1027
    .line 1028
    .line 1029
    invoke-virtual {v0}, Landroid/graphics/Canvas;->save()I

    .line 1030
    .line 1031
    .line 1032
    iget-object v8, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1033
    .line 1034
    check-cast v8, Lin/x1;

    .line 1035
    .line 1036
    iget-object v8, v8, Lin/x1;->f:Ld3/a;

    .line 1037
    .line 1038
    invoke-static {v8, v2, v7}, Lin/z1;->m(Ld3/a;Ld3/a;Lin/s;)Landroid/graphics/Matrix;

    .line 1039
    .line 1040
    .line 1041
    move-result-object v2

    .line 1042
    invoke-virtual {v0, v2}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 1043
    .line 1044
    .line 1045
    new-instance v2, Landroid/graphics/Paint;

    .line 1046
    .line 1047
    iget-object v7, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1048
    .line 1049
    check-cast v7, Lin/x1;

    .line 1050
    .line 1051
    iget-object v7, v7, Lin/x1;->a:Lin/s0;

    .line 1052
    .line 1053
    iget v7, v7, Lin/s0;->P:I

    .line 1054
    .line 1055
    const/4 v8, 0x3

    .line 1056
    if-ne v7, v8, :cond_36

    .line 1057
    .line 1058
    goto :goto_f

    .line 1059
    :cond_36
    move v4, v5

    .line 1060
    :goto_f
    invoke-direct {v2, v4}, Landroid/graphics/Paint;-><init>(I)V

    .line 1061
    .line 1062
    .line 1063
    invoke-virtual {v0, v1, v3, v3, v2}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;FFLandroid/graphics/Paint;)V

    .line 1064
    .line 1065
    .line 1066
    invoke-virtual {v0}, Landroid/graphics/Canvas;->restore()V

    .line 1067
    .line 1068
    .line 1069
    if-eqz v6, :cond_7f

    .line 1070
    .line 1071
    iget-object p1, p1, Lin/x0;->h:Ld3/a;

    .line 1072
    .line 1073
    invoke-virtual {p0, p1}, Lin/z1;->R(Ld3/a;)V

    .line 1074
    .line 1075
    .line 1076
    goto/16 :goto_1d

    .line 1077
    .line 1078
    :cond_37
    instance-of v0, p1, Lin/k0;

    .line 1079
    .line 1080
    if-eqz v0, :cond_41

    .line 1081
    .line 1082
    check-cast p1, Lin/k0;

    .line 1083
    .line 1084
    iget-object v0, p1, Lin/k0;->o:Li4/c;

    .line 1085
    .line 1086
    if-nez v0, :cond_38

    .line 1087
    .line 1088
    goto/16 :goto_1d

    .line 1089
    .line 1090
    :cond_38
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1091
    .line 1092
    check-cast v0, Lin/x1;

    .line 1093
    .line 1094
    invoke-virtual {p0, v0, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 1095
    .line 1096
    .line 1097
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 1098
    .line 1099
    .line 1100
    move-result v0

    .line 1101
    if-nez v0, :cond_39

    .line 1102
    .line 1103
    goto/16 :goto_1d

    .line 1104
    .line 1105
    :cond_39
    invoke-virtual {p0}, Lin/z1;->m0()Z

    .line 1106
    .line 1107
    .line 1108
    move-result v0

    .line 1109
    if-nez v0, :cond_3a

    .line 1110
    .line 1111
    goto/16 :goto_1d

    .line 1112
    .line 1113
    :cond_3a
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1114
    .line 1115
    check-cast v0, Lin/x1;

    .line 1116
    .line 1117
    iget-boolean v1, v0, Lin/x1;->c:Z

    .line 1118
    .line 1119
    if-nez v1, :cond_3b

    .line 1120
    .line 1121
    iget-boolean v0, v0, Lin/x1;->b:Z

    .line 1122
    .line 1123
    if-nez v0, :cond_3b

    .line 1124
    .line 1125
    goto/16 :goto_1d

    .line 1126
    .line 1127
    :cond_3b
    iget-object v0, p1, Lin/a0;->n:Landroid/graphics/Matrix;

    .line 1128
    .line 1129
    if-eqz v0, :cond_3c

    .line 1130
    .line 1131
    iget-object v1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 1132
    .line 1133
    check-cast v1, Landroid/graphics/Canvas;

    .line 1134
    .line 1135
    invoke-virtual {v1, v0}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 1136
    .line 1137
    .line 1138
    :cond_3c
    new-instance v0, Lin/t1;

    .line 1139
    .line 1140
    iget-object v1, p1, Lin/k0;->o:Li4/c;

    .line 1141
    .line 1142
    invoke-direct {v0, v1}, Lin/t1;-><init>(Li4/c;)V

    .line 1143
    .line 1144
    .line 1145
    iget-object v0, v0, Lin/t1;->c:Ljava/lang/Object;

    .line 1146
    .line 1147
    check-cast v0, Landroid/graphics/Path;

    .line 1148
    .line 1149
    iget-object v1, p1, Lin/x0;->h:Ld3/a;

    .line 1150
    .line 1151
    if-nez v1, :cond_3d

    .line 1152
    .line 1153
    invoke-static {v0}, Lin/z1;->k(Landroid/graphics/Path;)Ld3/a;

    .line 1154
    .line 1155
    .line 1156
    move-result-object v1

    .line 1157
    iput-object v1, p1, Lin/x0;->h:Ld3/a;

    .line 1158
    .line 1159
    :cond_3d
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 1160
    .line 1161
    .line 1162
    invoke-virtual {p0, p1}, Lin/z1;->o(Lin/x0;)V

    .line 1163
    .line 1164
    .line 1165
    iget-object v1, p1, Lin/x0;->h:Ld3/a;

    .line 1166
    .line 1167
    invoke-virtual {p0, p1, v1}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 1168
    .line 1169
    .line 1170
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 1171
    .line 1172
    .line 1173
    move-result v1

    .line 1174
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1175
    .line 1176
    check-cast v2, Lin/x1;

    .line 1177
    .line 1178
    iget-boolean v3, v2, Lin/x1;->b:Z

    .line 1179
    .line 1180
    if-eqz v3, :cond_3f

    .line 1181
    .line 1182
    iget-object v2, v2, Lin/x1;->a:Lin/s0;

    .line 1183
    .line 1184
    iget v2, v2, Lin/s0;->G:I

    .line 1185
    .line 1186
    if-eqz v2, :cond_3e

    .line 1187
    .line 1188
    if-ne v2, v5, :cond_3e

    .line 1189
    .line 1190
    sget-object v2, Landroid/graphics/Path$FillType;->EVEN_ODD:Landroid/graphics/Path$FillType;

    .line 1191
    .line 1192
    goto :goto_10

    .line 1193
    :cond_3e
    sget-object v2, Landroid/graphics/Path$FillType;->WINDING:Landroid/graphics/Path$FillType;

    .line 1194
    .line 1195
    :goto_10
    invoke-virtual {v0, v2}, Landroid/graphics/Path;->setFillType(Landroid/graphics/Path$FillType;)V

    .line 1196
    .line 1197
    .line 1198
    invoke-virtual {p0, p1, v0}, Lin/z1;->t(Lin/x0;Landroid/graphics/Path;)V

    .line 1199
    .line 1200
    .line 1201
    :cond_3f
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1202
    .line 1203
    check-cast v2, Lin/x1;

    .line 1204
    .line 1205
    iget-boolean v2, v2, Lin/x1;->c:Z

    .line 1206
    .line 1207
    if-eqz v2, :cond_40

    .line 1208
    .line 1209
    invoke-virtual {p0, v0}, Lin/z1;->u(Landroid/graphics/Path;)V

    .line 1210
    .line 1211
    .line 1212
    :cond_40
    invoke-virtual {p0, p1}, Lin/z1;->Y(Lin/a0;)V

    .line 1213
    .line 1214
    .line 1215
    if-eqz v1, :cond_7f

    .line 1216
    .line 1217
    iget-object p1, p1, Lin/x0;->h:Ld3/a;

    .line 1218
    .line 1219
    invoke-virtual {p0, p1}, Lin/z1;->R(Ld3/a;)V

    .line 1220
    .line 1221
    .line 1222
    goto/16 :goto_1d

    .line 1223
    .line 1224
    :cond_41
    instance-of v0, p1, Lin/p0;

    .line 1225
    .line 1226
    if-eqz v0, :cond_48

    .line 1227
    .line 1228
    check-cast p1, Lin/p0;

    .line 1229
    .line 1230
    iget-object v0, p1, Lin/p0;->q:Lin/e0;

    .line 1231
    .line 1232
    if-eqz v0, :cond_7f

    .line 1233
    .line 1234
    iget-object v1, p1, Lin/p0;->r:Lin/e0;

    .line 1235
    .line 1236
    if-eqz v1, :cond_7f

    .line 1237
    .line 1238
    invoke-virtual {v0}, Lin/e0;->h()Z

    .line 1239
    .line 1240
    .line 1241
    move-result v0

    .line 1242
    if-nez v0, :cond_7f

    .line 1243
    .line 1244
    iget-object v0, p1, Lin/p0;->r:Lin/e0;

    .line 1245
    .line 1246
    invoke-virtual {v0}, Lin/e0;->h()Z

    .line 1247
    .line 1248
    .line 1249
    move-result v0

    .line 1250
    if-eqz v0, :cond_42

    .line 1251
    .line 1252
    goto/16 :goto_1d

    .line 1253
    .line 1254
    :cond_42
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1255
    .line 1256
    check-cast v0, Lin/x1;

    .line 1257
    .line 1258
    invoke-virtual {p0, v0, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 1259
    .line 1260
    .line 1261
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 1262
    .line 1263
    .line 1264
    move-result v0

    .line 1265
    if-nez v0, :cond_43

    .line 1266
    .line 1267
    goto/16 :goto_1d

    .line 1268
    .line 1269
    :cond_43
    invoke-virtual {p0}, Lin/z1;->m0()Z

    .line 1270
    .line 1271
    .line 1272
    move-result v0

    .line 1273
    if-nez v0, :cond_44

    .line 1274
    .line 1275
    goto/16 :goto_1d

    .line 1276
    .line 1277
    :cond_44
    iget-object v0, p1, Lin/a0;->n:Landroid/graphics/Matrix;

    .line 1278
    .line 1279
    if-eqz v0, :cond_45

    .line 1280
    .line 1281
    iget-object v1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 1282
    .line 1283
    check-cast v1, Landroid/graphics/Canvas;

    .line 1284
    .line 1285
    invoke-virtual {v1, v0}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 1286
    .line 1287
    .line 1288
    :cond_45
    invoke-virtual {p0, p1}, Lin/z1;->O(Lin/p0;)Landroid/graphics/Path;

    .line 1289
    .line 1290
    .line 1291
    move-result-object v0

    .line 1292
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 1293
    .line 1294
    .line 1295
    invoke-virtual {p0, p1}, Lin/z1;->o(Lin/x0;)V

    .line 1296
    .line 1297
    .line 1298
    iget-object v1, p1, Lin/x0;->h:Ld3/a;

    .line 1299
    .line 1300
    invoke-virtual {p0, p1, v1}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 1301
    .line 1302
    .line 1303
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 1304
    .line 1305
    .line 1306
    move-result v1

    .line 1307
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1308
    .line 1309
    check-cast v2, Lin/x1;

    .line 1310
    .line 1311
    iget-boolean v2, v2, Lin/x1;->b:Z

    .line 1312
    .line 1313
    if-eqz v2, :cond_46

    .line 1314
    .line 1315
    invoke-virtual {p0, p1, v0}, Lin/z1;->t(Lin/x0;Landroid/graphics/Path;)V

    .line 1316
    .line 1317
    .line 1318
    :cond_46
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1319
    .line 1320
    check-cast v2, Lin/x1;

    .line 1321
    .line 1322
    iget-boolean v2, v2, Lin/x1;->c:Z

    .line 1323
    .line 1324
    if-eqz v2, :cond_47

    .line 1325
    .line 1326
    invoke-virtual {p0, v0}, Lin/z1;->u(Landroid/graphics/Path;)V

    .line 1327
    .line 1328
    .line 1329
    :cond_47
    if-eqz v1, :cond_7f

    .line 1330
    .line 1331
    iget-object p1, p1, Lin/x0;->h:Ld3/a;

    .line 1332
    .line 1333
    invoke-virtual {p0, p1}, Lin/z1;->R(Ld3/a;)V

    .line 1334
    .line 1335
    .line 1336
    goto/16 :goto_1d

    .line 1337
    .line 1338
    :cond_48
    instance-of v0, p1, Lin/t;

    .line 1339
    .line 1340
    if-eqz v0, :cond_4f

    .line 1341
    .line 1342
    check-cast p1, Lin/t;

    .line 1343
    .line 1344
    iget-object v0, p1, Lin/t;->q:Lin/e0;

    .line 1345
    .line 1346
    if-eqz v0, :cond_7f

    .line 1347
    .line 1348
    invoke-virtual {v0}, Lin/e0;->h()Z

    .line 1349
    .line 1350
    .line 1351
    move-result v0

    .line 1352
    if-eqz v0, :cond_49

    .line 1353
    .line 1354
    goto/16 :goto_1d

    .line 1355
    .line 1356
    :cond_49
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1357
    .line 1358
    check-cast v0, Lin/x1;

    .line 1359
    .line 1360
    invoke-virtual {p0, v0, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 1361
    .line 1362
    .line 1363
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 1364
    .line 1365
    .line 1366
    move-result v0

    .line 1367
    if-nez v0, :cond_4a

    .line 1368
    .line 1369
    goto/16 :goto_1d

    .line 1370
    .line 1371
    :cond_4a
    invoke-virtual {p0}, Lin/z1;->m0()Z

    .line 1372
    .line 1373
    .line 1374
    move-result v0

    .line 1375
    if-nez v0, :cond_4b

    .line 1376
    .line 1377
    goto/16 :goto_1d

    .line 1378
    .line 1379
    :cond_4b
    iget-object v0, p1, Lin/a0;->n:Landroid/graphics/Matrix;

    .line 1380
    .line 1381
    if-eqz v0, :cond_4c

    .line 1382
    .line 1383
    iget-object v1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 1384
    .line 1385
    check-cast v1, Landroid/graphics/Canvas;

    .line 1386
    .line 1387
    invoke-virtual {v1, v0}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 1388
    .line 1389
    .line 1390
    :cond_4c
    invoke-virtual {p0, p1}, Lin/z1;->L(Lin/t;)Landroid/graphics/Path;

    .line 1391
    .line 1392
    .line 1393
    move-result-object v0

    .line 1394
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 1395
    .line 1396
    .line 1397
    invoke-virtual {p0, p1}, Lin/z1;->o(Lin/x0;)V

    .line 1398
    .line 1399
    .line 1400
    iget-object v1, p1, Lin/x0;->h:Ld3/a;

    .line 1401
    .line 1402
    invoke-virtual {p0, p1, v1}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 1403
    .line 1404
    .line 1405
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 1406
    .line 1407
    .line 1408
    move-result v1

    .line 1409
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1410
    .line 1411
    check-cast v2, Lin/x1;

    .line 1412
    .line 1413
    iget-boolean v2, v2, Lin/x1;->b:Z

    .line 1414
    .line 1415
    if-eqz v2, :cond_4d

    .line 1416
    .line 1417
    invoke-virtual {p0, p1, v0}, Lin/z1;->t(Lin/x0;Landroid/graphics/Path;)V

    .line 1418
    .line 1419
    .line 1420
    :cond_4d
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1421
    .line 1422
    check-cast v2, Lin/x1;

    .line 1423
    .line 1424
    iget-boolean v2, v2, Lin/x1;->c:Z

    .line 1425
    .line 1426
    if-eqz v2, :cond_4e

    .line 1427
    .line 1428
    invoke-virtual {p0, v0}, Lin/z1;->u(Landroid/graphics/Path;)V

    .line 1429
    .line 1430
    .line 1431
    :cond_4e
    if-eqz v1, :cond_7f

    .line 1432
    .line 1433
    iget-object p1, p1, Lin/x0;->h:Ld3/a;

    .line 1434
    .line 1435
    invoke-virtual {p0, p1}, Lin/z1;->R(Ld3/a;)V

    .line 1436
    .line 1437
    .line 1438
    goto/16 :goto_1d

    .line 1439
    .line 1440
    :cond_4f
    instance-of v0, p1, Lin/y;

    .line 1441
    .line 1442
    if-eqz v0, :cond_56

    .line 1443
    .line 1444
    check-cast p1, Lin/y;

    .line 1445
    .line 1446
    iget-object v0, p1, Lin/y;->q:Lin/e0;

    .line 1447
    .line 1448
    if-eqz v0, :cond_7f

    .line 1449
    .line 1450
    iget-object v1, p1, Lin/y;->r:Lin/e0;

    .line 1451
    .line 1452
    if-eqz v1, :cond_7f

    .line 1453
    .line 1454
    invoke-virtual {v0}, Lin/e0;->h()Z

    .line 1455
    .line 1456
    .line 1457
    move-result v0

    .line 1458
    if-nez v0, :cond_7f

    .line 1459
    .line 1460
    iget-object v0, p1, Lin/y;->r:Lin/e0;

    .line 1461
    .line 1462
    invoke-virtual {v0}, Lin/e0;->h()Z

    .line 1463
    .line 1464
    .line 1465
    move-result v0

    .line 1466
    if-eqz v0, :cond_50

    .line 1467
    .line 1468
    goto/16 :goto_1d

    .line 1469
    .line 1470
    :cond_50
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1471
    .line 1472
    check-cast v0, Lin/x1;

    .line 1473
    .line 1474
    invoke-virtual {p0, v0, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 1475
    .line 1476
    .line 1477
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 1478
    .line 1479
    .line 1480
    move-result v0

    .line 1481
    if-nez v0, :cond_51

    .line 1482
    .line 1483
    goto/16 :goto_1d

    .line 1484
    .line 1485
    :cond_51
    invoke-virtual {p0}, Lin/z1;->m0()Z

    .line 1486
    .line 1487
    .line 1488
    move-result v0

    .line 1489
    if-nez v0, :cond_52

    .line 1490
    .line 1491
    goto/16 :goto_1d

    .line 1492
    .line 1493
    :cond_52
    iget-object v0, p1, Lin/a0;->n:Landroid/graphics/Matrix;

    .line 1494
    .line 1495
    if-eqz v0, :cond_53

    .line 1496
    .line 1497
    iget-object v1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 1498
    .line 1499
    check-cast v1, Landroid/graphics/Canvas;

    .line 1500
    .line 1501
    invoke-virtual {v1, v0}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 1502
    .line 1503
    .line 1504
    :cond_53
    invoke-virtual {p0, p1}, Lin/z1;->M(Lin/y;)Landroid/graphics/Path;

    .line 1505
    .line 1506
    .line 1507
    move-result-object v0

    .line 1508
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 1509
    .line 1510
    .line 1511
    invoke-virtual {p0, p1}, Lin/z1;->o(Lin/x0;)V

    .line 1512
    .line 1513
    .line 1514
    iget-object v1, p1, Lin/x0;->h:Ld3/a;

    .line 1515
    .line 1516
    invoke-virtual {p0, p1, v1}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 1517
    .line 1518
    .line 1519
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 1520
    .line 1521
    .line 1522
    move-result v1

    .line 1523
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1524
    .line 1525
    check-cast v2, Lin/x1;

    .line 1526
    .line 1527
    iget-boolean v2, v2, Lin/x1;->b:Z

    .line 1528
    .line 1529
    if-eqz v2, :cond_54

    .line 1530
    .line 1531
    invoke-virtual {p0, p1, v0}, Lin/z1;->t(Lin/x0;Landroid/graphics/Path;)V

    .line 1532
    .line 1533
    .line 1534
    :cond_54
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1535
    .line 1536
    check-cast v2, Lin/x1;

    .line 1537
    .line 1538
    iget-boolean v2, v2, Lin/x1;->c:Z

    .line 1539
    .line 1540
    if-eqz v2, :cond_55

    .line 1541
    .line 1542
    invoke-virtual {p0, v0}, Lin/z1;->u(Landroid/graphics/Path;)V

    .line 1543
    .line 1544
    .line 1545
    :cond_55
    if-eqz v1, :cond_7f

    .line 1546
    .line 1547
    iget-object p1, p1, Lin/x0;->h:Ld3/a;

    .line 1548
    .line 1549
    invoke-virtual {p0, p1}, Lin/z1;->R(Ld3/a;)V

    .line 1550
    .line 1551
    .line 1552
    goto/16 :goto_1d

    .line 1553
    .line 1554
    :cond_56
    instance-of v0, p1, Lin/f0;

    .line 1555
    .line 1556
    if-eqz v0, :cond_60

    .line 1557
    .line 1558
    check-cast p1, Lin/f0;

    .line 1559
    .line 1560
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1561
    .line 1562
    check-cast v0, Lin/x1;

    .line 1563
    .line 1564
    invoke-virtual {p0, v0, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 1565
    .line 1566
    .line 1567
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 1568
    .line 1569
    .line 1570
    move-result v0

    .line 1571
    if-nez v0, :cond_57

    .line 1572
    .line 1573
    goto/16 :goto_1d

    .line 1574
    .line 1575
    :cond_57
    invoke-virtual {p0}, Lin/z1;->m0()Z

    .line 1576
    .line 1577
    .line 1578
    move-result v0

    .line 1579
    if-nez v0, :cond_58

    .line 1580
    .line 1581
    goto/16 :goto_1d

    .line 1582
    .line 1583
    :cond_58
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1584
    .line 1585
    check-cast v0, Lin/x1;

    .line 1586
    .line 1587
    iget-boolean v0, v0, Lin/x1;->c:Z

    .line 1588
    .line 1589
    if-nez v0, :cond_59

    .line 1590
    .line 1591
    goto/16 :goto_1d

    .line 1592
    .line 1593
    :cond_59
    iget-object v0, p1, Lin/a0;->n:Landroid/graphics/Matrix;

    .line 1594
    .line 1595
    if-eqz v0, :cond_5a

    .line 1596
    .line 1597
    iget-object v1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 1598
    .line 1599
    check-cast v1, Landroid/graphics/Canvas;

    .line 1600
    .line 1601
    invoke-virtual {v1, v0}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 1602
    .line 1603
    .line 1604
    :cond_5a
    iget-object v0, p1, Lin/f0;->o:Lin/e0;

    .line 1605
    .line 1606
    if-nez v0, :cond_5b

    .line 1607
    .line 1608
    move v0, v3

    .line 1609
    goto :goto_11

    .line 1610
    :cond_5b
    invoke-virtual {v0, p0}, Lin/e0;->d(Lin/z1;)F

    .line 1611
    .line 1612
    .line 1613
    move-result v0

    .line 1614
    :goto_11
    iget-object v1, p1, Lin/f0;->p:Lin/e0;

    .line 1615
    .line 1616
    if-nez v1, :cond_5c

    .line 1617
    .line 1618
    move v1, v3

    .line 1619
    goto :goto_12

    .line 1620
    :cond_5c
    invoke-virtual {v1, p0}, Lin/e0;->e(Lin/z1;)F

    .line 1621
    .line 1622
    .line 1623
    move-result v1

    .line 1624
    :goto_12
    iget-object v2, p1, Lin/f0;->q:Lin/e0;

    .line 1625
    .line 1626
    if-nez v2, :cond_5d

    .line 1627
    .line 1628
    move v2, v3

    .line 1629
    goto :goto_13

    .line 1630
    :cond_5d
    invoke-virtual {v2, p0}, Lin/e0;->d(Lin/z1;)F

    .line 1631
    .line 1632
    .line 1633
    move-result v2

    .line 1634
    :goto_13
    iget-object v4, p1, Lin/f0;->r:Lin/e0;

    .line 1635
    .line 1636
    if-nez v4, :cond_5e

    .line 1637
    .line 1638
    goto :goto_14

    .line 1639
    :cond_5e
    invoke-virtual {v4, p0}, Lin/e0;->e(Lin/z1;)F

    .line 1640
    .line 1641
    .line 1642
    move-result v3

    .line 1643
    :goto_14
    iget-object v4, p1, Lin/x0;->h:Ld3/a;

    .line 1644
    .line 1645
    if-nez v4, :cond_5f

    .line 1646
    .line 1647
    new-instance v4, Ld3/a;

    .line 1648
    .line 1649
    invoke-static {v0, v2}, Ljava/lang/Math;->min(FF)F

    .line 1650
    .line 1651
    .line 1652
    move-result v5

    .line 1653
    invoke-static {v1, v3}, Ljava/lang/Math;->min(FF)F

    .line 1654
    .line 1655
    .line 1656
    move-result v6

    .line 1657
    sub-float v7, v2, v0

    .line 1658
    .line 1659
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    .line 1660
    .line 1661
    .line 1662
    move-result v7

    .line 1663
    sub-float v8, v3, v1

    .line 1664
    .line 1665
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    .line 1666
    .line 1667
    .line 1668
    move-result v8

    .line 1669
    invoke-direct {v4, v5, v6, v7, v8}, Ld3/a;-><init>(FFFF)V

    .line 1670
    .line 1671
    .line 1672
    iput-object v4, p1, Lin/x0;->h:Ld3/a;

    .line 1673
    .line 1674
    :cond_5f
    new-instance v4, Landroid/graphics/Path;

    .line 1675
    .line 1676
    invoke-direct {v4}, Landroid/graphics/Path;-><init>()V

    .line 1677
    .line 1678
    .line 1679
    invoke-virtual {v4, v0, v1}, Landroid/graphics/Path;->moveTo(FF)V

    .line 1680
    .line 1681
    .line 1682
    invoke-virtual {v4, v2, v3}, Landroid/graphics/Path;->lineTo(FF)V

    .line 1683
    .line 1684
    .line 1685
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 1686
    .line 1687
    .line 1688
    invoke-virtual {p0, p1}, Lin/z1;->o(Lin/x0;)V

    .line 1689
    .line 1690
    .line 1691
    iget-object v0, p1, Lin/x0;->h:Ld3/a;

    .line 1692
    .line 1693
    invoke-virtual {p0, p1, v0}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 1694
    .line 1695
    .line 1696
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 1697
    .line 1698
    .line 1699
    move-result v0

    .line 1700
    invoke-virtual {p0, v4}, Lin/z1;->u(Landroid/graphics/Path;)V

    .line 1701
    .line 1702
    .line 1703
    invoke-virtual {p0, p1}, Lin/z1;->Y(Lin/a0;)V

    .line 1704
    .line 1705
    .line 1706
    if-eqz v0, :cond_7f

    .line 1707
    .line 1708
    iget-object p1, p1, Lin/x0;->h:Ld3/a;

    .line 1709
    .line 1710
    invoke-virtual {p0, p1}, Lin/z1;->R(Ld3/a;)V

    .line 1711
    .line 1712
    .line 1713
    goto/16 :goto_1d

    .line 1714
    .line 1715
    :cond_60
    instance-of v0, p1, Lin/o0;

    .line 1716
    .line 1717
    if-eqz v0, :cond_68

    .line 1718
    .line 1719
    check-cast p1, Lin/o0;

    .line 1720
    .line 1721
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1722
    .line 1723
    check-cast v0, Lin/x1;

    .line 1724
    .line 1725
    invoke-virtual {p0, v0, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 1726
    .line 1727
    .line 1728
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 1729
    .line 1730
    .line 1731
    move-result v0

    .line 1732
    if-nez v0, :cond_61

    .line 1733
    .line 1734
    goto/16 :goto_1d

    .line 1735
    .line 1736
    :cond_61
    invoke-virtual {p0}, Lin/z1;->m0()Z

    .line 1737
    .line 1738
    .line 1739
    move-result v0

    .line 1740
    if-nez v0, :cond_62

    .line 1741
    .line 1742
    goto/16 :goto_1d

    .line 1743
    .line 1744
    :cond_62
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1745
    .line 1746
    check-cast v0, Lin/x1;

    .line 1747
    .line 1748
    iget-boolean v1, v0, Lin/x1;->c:Z

    .line 1749
    .line 1750
    if-nez v1, :cond_63

    .line 1751
    .line 1752
    iget-boolean v0, v0, Lin/x1;->b:Z

    .line 1753
    .line 1754
    if-nez v0, :cond_63

    .line 1755
    .line 1756
    goto/16 :goto_1d

    .line 1757
    .line 1758
    :cond_63
    iget-object v0, p1, Lin/a0;->n:Landroid/graphics/Matrix;

    .line 1759
    .line 1760
    if-eqz v0, :cond_64

    .line 1761
    .line 1762
    iget-object v1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 1763
    .line 1764
    check-cast v1, Landroid/graphics/Canvas;

    .line 1765
    .line 1766
    invoke-virtual {v1, v0}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 1767
    .line 1768
    .line 1769
    :cond_64
    iget-object v0, p1, Lin/n0;->o:[F

    .line 1770
    .line 1771
    array-length v0, v0

    .line 1772
    if-ge v0, v5, :cond_65

    .line 1773
    .line 1774
    goto/16 :goto_1d

    .line 1775
    .line 1776
    :cond_65
    invoke-static {p1}, Lin/z1;->N(Lin/n0;)Landroid/graphics/Path;

    .line 1777
    .line 1778
    .line 1779
    move-result-object v0

    .line 1780
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 1781
    .line 1782
    .line 1783
    invoke-virtual {p0, p1}, Lin/z1;->o(Lin/x0;)V

    .line 1784
    .line 1785
    .line 1786
    iget-object v1, p1, Lin/x0;->h:Ld3/a;

    .line 1787
    .line 1788
    invoke-virtual {p0, p1, v1}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 1789
    .line 1790
    .line 1791
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 1792
    .line 1793
    .line 1794
    move-result v1

    .line 1795
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1796
    .line 1797
    check-cast v2, Lin/x1;

    .line 1798
    .line 1799
    iget-boolean v2, v2, Lin/x1;->b:Z

    .line 1800
    .line 1801
    if-eqz v2, :cond_66

    .line 1802
    .line 1803
    invoke-virtual {p0, p1, v0}, Lin/z1;->t(Lin/x0;Landroid/graphics/Path;)V

    .line 1804
    .line 1805
    .line 1806
    :cond_66
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1807
    .line 1808
    check-cast v2, Lin/x1;

    .line 1809
    .line 1810
    iget-boolean v2, v2, Lin/x1;->c:Z

    .line 1811
    .line 1812
    if-eqz v2, :cond_67

    .line 1813
    .line 1814
    invoke-virtual {p0, v0}, Lin/z1;->u(Landroid/graphics/Path;)V

    .line 1815
    .line 1816
    .line 1817
    :cond_67
    invoke-virtual {p0, p1}, Lin/z1;->Y(Lin/a0;)V

    .line 1818
    .line 1819
    .line 1820
    if-eqz v1, :cond_7f

    .line 1821
    .line 1822
    iget-object p1, p1, Lin/x0;->h:Ld3/a;

    .line 1823
    .line 1824
    invoke-virtual {p0, p1}, Lin/z1;->R(Ld3/a;)V

    .line 1825
    .line 1826
    .line 1827
    goto/16 :goto_1d

    .line 1828
    .line 1829
    :cond_68
    instance-of v0, p1, Lin/n0;

    .line 1830
    .line 1831
    if-eqz v0, :cond_71

    .line 1832
    .line 1833
    check-cast p1, Lin/n0;

    .line 1834
    .line 1835
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1836
    .line 1837
    check-cast v0, Lin/x1;

    .line 1838
    .line 1839
    invoke-virtual {p0, v0, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 1840
    .line 1841
    .line 1842
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 1843
    .line 1844
    .line 1845
    move-result v0

    .line 1846
    if-nez v0, :cond_69

    .line 1847
    .line 1848
    goto/16 :goto_1d

    .line 1849
    .line 1850
    :cond_69
    invoke-virtual {p0}, Lin/z1;->m0()Z

    .line 1851
    .line 1852
    .line 1853
    move-result v0

    .line 1854
    if-nez v0, :cond_6a

    .line 1855
    .line 1856
    goto/16 :goto_1d

    .line 1857
    .line 1858
    :cond_6a
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1859
    .line 1860
    check-cast v0, Lin/x1;

    .line 1861
    .line 1862
    iget-boolean v1, v0, Lin/x1;->c:Z

    .line 1863
    .line 1864
    if-nez v1, :cond_6b

    .line 1865
    .line 1866
    iget-boolean v0, v0, Lin/x1;->b:Z

    .line 1867
    .line 1868
    if-nez v0, :cond_6b

    .line 1869
    .line 1870
    goto/16 :goto_1d

    .line 1871
    .line 1872
    :cond_6b
    iget-object v0, p1, Lin/a0;->n:Landroid/graphics/Matrix;

    .line 1873
    .line 1874
    if-eqz v0, :cond_6c

    .line 1875
    .line 1876
    iget-object v1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 1877
    .line 1878
    check-cast v1, Landroid/graphics/Canvas;

    .line 1879
    .line 1880
    invoke-virtual {v1, v0}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 1881
    .line 1882
    .line 1883
    :cond_6c
    iget-object v0, p1, Lin/n0;->o:[F

    .line 1884
    .line 1885
    array-length v0, v0

    .line 1886
    if-ge v0, v5, :cond_6d

    .line 1887
    .line 1888
    goto/16 :goto_1d

    .line 1889
    .line 1890
    :cond_6d
    invoke-static {p1}, Lin/z1;->N(Lin/n0;)Landroid/graphics/Path;

    .line 1891
    .line 1892
    .line 1893
    move-result-object v0

    .line 1894
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 1895
    .line 1896
    .line 1897
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1898
    .line 1899
    check-cast v1, Lin/x1;

    .line 1900
    .line 1901
    iget-object v1, v1, Lin/x1;->a:Lin/s0;

    .line 1902
    .line 1903
    iget v1, v1, Lin/s0;->G:I

    .line 1904
    .line 1905
    if-eqz v1, :cond_6e

    .line 1906
    .line 1907
    if-ne v1, v5, :cond_6e

    .line 1908
    .line 1909
    sget-object v1, Landroid/graphics/Path$FillType;->EVEN_ODD:Landroid/graphics/Path$FillType;

    .line 1910
    .line 1911
    goto :goto_15

    .line 1912
    :cond_6e
    sget-object v1, Landroid/graphics/Path$FillType;->WINDING:Landroid/graphics/Path$FillType;

    .line 1913
    .line 1914
    :goto_15
    invoke-virtual {v0, v1}, Landroid/graphics/Path;->setFillType(Landroid/graphics/Path$FillType;)V

    .line 1915
    .line 1916
    .line 1917
    invoke-virtual {p0, p1}, Lin/z1;->o(Lin/x0;)V

    .line 1918
    .line 1919
    .line 1920
    iget-object v1, p1, Lin/x0;->h:Ld3/a;

    .line 1921
    .line 1922
    invoke-virtual {p0, p1, v1}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 1923
    .line 1924
    .line 1925
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 1926
    .line 1927
    .line 1928
    move-result v1

    .line 1929
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1930
    .line 1931
    check-cast v2, Lin/x1;

    .line 1932
    .line 1933
    iget-boolean v2, v2, Lin/x1;->b:Z

    .line 1934
    .line 1935
    if-eqz v2, :cond_6f

    .line 1936
    .line 1937
    invoke-virtual {p0, p1, v0}, Lin/z1;->t(Lin/x0;Landroid/graphics/Path;)V

    .line 1938
    .line 1939
    .line 1940
    :cond_6f
    iget-object v2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1941
    .line 1942
    check-cast v2, Lin/x1;

    .line 1943
    .line 1944
    iget-boolean v2, v2, Lin/x1;->c:Z

    .line 1945
    .line 1946
    if-eqz v2, :cond_70

    .line 1947
    .line 1948
    invoke-virtual {p0, v0}, Lin/z1;->u(Landroid/graphics/Path;)V

    .line 1949
    .line 1950
    .line 1951
    :cond_70
    invoke-virtual {p0, p1}, Lin/z1;->Y(Lin/a0;)V

    .line 1952
    .line 1953
    .line 1954
    if-eqz v1, :cond_7f

    .line 1955
    .line 1956
    iget-object p1, p1, Lin/x0;->h:Ld3/a;

    .line 1957
    .line 1958
    invoke-virtual {p0, p1}, Lin/z1;->R(Ld3/a;)V

    .line 1959
    .line 1960
    .line 1961
    goto/16 :goto_1d

    .line 1962
    .line 1963
    :cond_71
    instance-of v0, p1, Lin/j1;

    .line 1964
    .line 1965
    if-eqz v0, :cond_7f

    .line 1966
    .line 1967
    check-cast p1, Lin/j1;

    .line 1968
    .line 1969
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 1970
    .line 1971
    check-cast v0, Lin/x1;

    .line 1972
    .line 1973
    invoke-virtual {p0, v0, p1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 1974
    .line 1975
    .line 1976
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 1977
    .line 1978
    .line 1979
    move-result v0

    .line 1980
    if-nez v0, :cond_72

    .line 1981
    .line 1982
    goto/16 :goto_1d

    .line 1983
    .line 1984
    :cond_72
    iget-object v0, p1, Lin/j1;->r:Landroid/graphics/Matrix;

    .line 1985
    .line 1986
    if-eqz v0, :cond_73

    .line 1987
    .line 1988
    iget-object v1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 1989
    .line 1990
    check-cast v1, Landroid/graphics/Canvas;

    .line 1991
    .line 1992
    invoke-virtual {v1, v0}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 1993
    .line 1994
    .line 1995
    :cond_73
    iget-object v0, p1, Lin/n1;->n:Ljava/util/ArrayList;

    .line 1996
    .line 1997
    if-eqz v0, :cond_75

    .line 1998
    .line 1999
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 2000
    .line 2001
    .line 2002
    move-result v0

    .line 2003
    if-nez v0, :cond_74

    .line 2004
    .line 2005
    goto :goto_16

    .line 2006
    :cond_74
    iget-object v0, p1, Lin/n1;->n:Ljava/util/ArrayList;

    .line 2007
    .line 2008
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 2009
    .line 2010
    .line 2011
    move-result-object v0

    .line 2012
    check-cast v0, Lin/e0;

    .line 2013
    .line 2014
    invoke-virtual {v0, p0}, Lin/e0;->d(Lin/z1;)F

    .line 2015
    .line 2016
    .line 2017
    move-result v0

    .line 2018
    goto :goto_17

    .line 2019
    :cond_75
    :goto_16
    move v0, v3

    .line 2020
    :goto_17
    iget-object v1, p1, Lin/n1;->o:Ljava/util/ArrayList;

    .line 2021
    .line 2022
    if-eqz v1, :cond_77

    .line 2023
    .line 2024
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 2025
    .line 2026
    .line 2027
    move-result v1

    .line 2028
    if-nez v1, :cond_76

    .line 2029
    .line 2030
    goto :goto_18

    .line 2031
    :cond_76
    iget-object v1, p1, Lin/n1;->o:Ljava/util/ArrayList;

    .line 2032
    .line 2033
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 2034
    .line 2035
    .line 2036
    move-result-object v1

    .line 2037
    check-cast v1, Lin/e0;

    .line 2038
    .line 2039
    invoke-virtual {v1, p0}, Lin/e0;->e(Lin/z1;)F

    .line 2040
    .line 2041
    .line 2042
    move-result v1

    .line 2043
    goto :goto_19

    .line 2044
    :cond_77
    :goto_18
    move v1, v3

    .line 2045
    :goto_19
    iget-object v6, p1, Lin/n1;->p:Ljava/util/ArrayList;

    .line 2046
    .line 2047
    if-eqz v6, :cond_79

    .line 2048
    .line 2049
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 2050
    .line 2051
    .line 2052
    move-result v6

    .line 2053
    if-nez v6, :cond_78

    .line 2054
    .line 2055
    goto :goto_1a

    .line 2056
    :cond_78
    iget-object v6, p1, Lin/n1;->p:Ljava/util/ArrayList;

    .line 2057
    .line 2058
    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 2059
    .line 2060
    .line 2061
    move-result-object v6

    .line 2062
    check-cast v6, Lin/e0;

    .line 2063
    .line 2064
    invoke-virtual {v6, p0}, Lin/e0;->d(Lin/z1;)F

    .line 2065
    .line 2066
    .line 2067
    move-result v6

    .line 2068
    goto :goto_1b

    .line 2069
    :cond_79
    :goto_1a
    move v6, v3

    .line 2070
    :goto_1b
    iget-object v7, p1, Lin/n1;->q:Ljava/util/ArrayList;

    .line 2071
    .line 2072
    if-eqz v7, :cond_7b

    .line 2073
    .line 2074
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 2075
    .line 2076
    .line 2077
    move-result v7

    .line 2078
    if-nez v7, :cond_7a

    .line 2079
    .line 2080
    goto :goto_1c

    .line 2081
    :cond_7a
    iget-object v3, p1, Lin/n1;->q:Ljava/util/ArrayList;

    .line 2082
    .line 2083
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 2084
    .line 2085
    .line 2086
    move-result-object v3

    .line 2087
    check-cast v3, Lin/e0;

    .line 2088
    .line 2089
    invoke-virtual {v3, p0}, Lin/e0;->e(Lin/z1;)F

    .line 2090
    .line 2091
    .line 2092
    move-result v3

    .line 2093
    :cond_7b
    :goto_1c
    invoke-virtual {p0}, Lin/z1;->F()I

    .line 2094
    .line 2095
    .line 2096
    move-result v4

    .line 2097
    if-eq v4, v2, :cond_7d

    .line 2098
    .line 2099
    invoke-virtual {p0, p1}, Lin/z1;->l(Lin/l1;)F

    .line 2100
    .line 2101
    .line 2102
    move-result v2

    .line 2103
    if-ne v4, v5, :cond_7c

    .line 2104
    .line 2105
    const/high16 v4, 0x40000000    # 2.0f

    .line 2106
    .line 2107
    div-float/2addr v2, v4

    .line 2108
    :cond_7c
    sub-float/2addr v0, v2

    .line 2109
    :cond_7d
    iget-object v2, p1, Lin/x0;->h:Ld3/a;

    .line 2110
    .line 2111
    if-nez v2, :cond_7e

    .line 2112
    .line 2113
    new-instance v2, Lin/w1;

    .line 2114
    .line 2115
    invoke-direct {v2, p0, v0, v1}, Lin/w1;-><init>(Lin/z1;FF)V

    .line 2116
    .line 2117
    .line 2118
    invoke-virtual {p0, p1, v2}, Lin/z1;->v(Lin/l1;Llp/pa;)V

    .line 2119
    .line 2120
    .line 2121
    new-instance v4, Ld3/a;

    .line 2122
    .line 2123
    iget-object v5, v2, Lin/w1;->e:Ljava/lang/Object;

    .line 2124
    .line 2125
    check-cast v5, Landroid/graphics/RectF;

    .line 2126
    .line 2127
    iget v7, v5, Landroid/graphics/RectF;->left:F

    .line 2128
    .line 2129
    iget v8, v5, Landroid/graphics/RectF;->top:F

    .line 2130
    .line 2131
    invoke-virtual {v5}, Landroid/graphics/RectF;->width()F

    .line 2132
    .line 2133
    .line 2134
    move-result v5

    .line 2135
    iget-object v2, v2, Lin/w1;->e:Ljava/lang/Object;

    .line 2136
    .line 2137
    check-cast v2, Landroid/graphics/RectF;

    .line 2138
    .line 2139
    invoke-virtual {v2}, Landroid/graphics/RectF;->height()F

    .line 2140
    .line 2141
    .line 2142
    move-result v2

    .line 2143
    invoke-direct {v4, v7, v8, v5, v2}, Ld3/a;-><init>(FFFF)V

    .line 2144
    .line 2145
    .line 2146
    iput-object v4, p1, Lin/x0;->h:Ld3/a;

    .line 2147
    .line 2148
    :cond_7e
    invoke-virtual {p0, p1}, Lin/z1;->i0(Lin/x0;)V

    .line 2149
    .line 2150
    .line 2151
    invoke-virtual {p0, p1}, Lin/z1;->o(Lin/x0;)V

    .line 2152
    .line 2153
    .line 2154
    iget-object v2, p1, Lin/x0;->h:Ld3/a;

    .line 2155
    .line 2156
    invoke-virtual {p0, p1, v2}, Lin/z1;->n(Lin/x0;Ld3/a;)V

    .line 2157
    .line 2158
    .line 2159
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 2160
    .line 2161
    .line 2162
    move-result v2

    .line 2163
    new-instance v4, Lin/v1;

    .line 2164
    .line 2165
    add-float/2addr v0, v6

    .line 2166
    add-float/2addr v1, v3

    .line 2167
    invoke-direct {v4, p0, v0, v1}, Lin/v1;-><init>(Lin/z1;FF)V

    .line 2168
    .line 2169
    .line 2170
    invoke-virtual {p0, p1, v4}, Lin/z1;->v(Lin/l1;Llp/pa;)V

    .line 2171
    .line 2172
    .line 2173
    if-eqz v2, :cond_7f

    .line 2174
    .line 2175
    iget-object p1, p1, Lin/x0;->h:Ld3/a;

    .line 2176
    .line 2177
    invoke-virtual {p0, p1}, Lin/z1;->R(Ld3/a;)V

    .line 2178
    .line 2179
    .line 2180
    :cond_7f
    :goto_1d
    invoke-virtual {p0}, Lin/z1;->e0()V

    .line 2181
    .line 2182
    .line 2183
    return-void
.end method

.method public W(Lin/v0;Z)V
    .locals 2

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Ljava/util/Stack;

    .line 6
    .line 7
    invoke-virtual {v0, p1}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Ljava/util/Stack;

    .line 13
    .line 14
    iget-object v1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Landroid/graphics/Canvas;

    .line 17
    .line 18
    invoke-virtual {v1}, Landroid/graphics/Canvas;->getMatrix()Landroid/graphics/Matrix;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {v0, v1}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    :cond_0
    iget-object p1, p1, Lin/v0;->i:Ljava/util/List;

    .line 26
    .line 27
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_1

    .line 36
    .line 37
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    check-cast v0, Lin/a1;

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Lin/z1;->V(Lin/a1;)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    if-eqz p2, :cond_2

    .line 48
    .line 49
    iget-object p1, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p1, Ljava/util/Stack;

    .line 52
    .line 53
    invoke-virtual {p1}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p0, Ljava/util/Stack;

    .line 59
    .line 60
    invoke-virtual {p0}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    :cond_2
    return-void
.end method

.method public X(Lin/g0;Lin/s1;)V
    .locals 12

    .line 1
    iget-object v0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/Canvas;

    .line 4
    .line 5
    invoke-virtual {p0}, Lin/z1;->f0()V

    .line 6
    .line 7
    .line 8
    iget-object v1, p1, Lin/g0;->u:Ljava/lang/Float;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    if-eqz v1, :cond_2

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    iget v1, p2, Lin/s1;->c:F

    .line 24
    .line 25
    cmpl-float v3, v1, v2

    .line 26
    .line 27
    if-nez v3, :cond_0

    .line 28
    .line 29
    iget v3, p2, Lin/s1;->d:F

    .line 30
    .line 31
    cmpl-float v3, v3, v2

    .line 32
    .line 33
    if-eqz v3, :cond_2

    .line 34
    .line 35
    :cond_0
    iget v3, p2, Lin/s1;->d:F

    .line 36
    .line 37
    float-to-double v3, v3

    .line 38
    float-to-double v5, v1

    .line 39
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Math;->atan2(DD)D

    .line 40
    .line 41
    .line 42
    move-result-wide v3

    .line 43
    invoke-static {v3, v4}, Ljava/lang/Math;->toDegrees(D)D

    .line 44
    .line 45
    .line 46
    move-result-wide v3

    .line 47
    double-to-float v1, v3

    .line 48
    goto :goto_0

    .line 49
    :cond_1
    iget-object v1, p1, Lin/g0;->u:Ljava/lang/Float;

    .line 50
    .line 51
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    goto :goto_0

    .line 56
    :cond_2
    move v1, v2

    .line 57
    :goto_0
    iget-boolean v3, p1, Lin/g0;->p:Z

    .line 58
    .line 59
    if-eqz v3, :cond_3

    .line 60
    .line 61
    const/high16 v3, 0x3f800000    # 1.0f

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_3
    iget-object v3, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v3, Lin/x1;

    .line 67
    .line 68
    iget-object v3, v3, Lin/x1;->a:Lin/s0;

    .line 69
    .line 70
    iget-object v3, v3, Lin/s0;->i:Lin/e0;

    .line 71
    .line 72
    invoke-virtual {v3}, Lin/e0;->c()F

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    :goto_1
    invoke-virtual {p0, p1}, Lin/z1;->D(Lin/y0;)Lin/x1;

    .line 77
    .line 78
    .line 79
    move-result-object v4

    .line 80
    iput-object v4, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 81
    .line 82
    new-instance v4, Landroid/graphics/Matrix;

    .line 83
    .line 84
    invoke-direct {v4}, Landroid/graphics/Matrix;-><init>()V

    .line 85
    .line 86
    .line 87
    iget v5, p2, Lin/s1;->a:F

    .line 88
    .line 89
    iget p2, p2, Lin/s1;->b:F

    .line 90
    .line 91
    invoke-virtual {v4, v5, p2}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 92
    .line 93
    .line 94
    invoke-virtual {v4, v1}, Landroid/graphics/Matrix;->preRotate(F)Z

    .line 95
    .line 96
    .line 97
    invoke-virtual {v4, v3, v3}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 98
    .line 99
    .line 100
    iget-object p2, p1, Lin/g0;->q:Lin/e0;

    .line 101
    .line 102
    if-eqz p2, :cond_4

    .line 103
    .line 104
    invoke-virtual {p2, p0}, Lin/e0;->d(Lin/z1;)F

    .line 105
    .line 106
    .line 107
    move-result p2

    .line 108
    goto :goto_2

    .line 109
    :cond_4
    move p2, v2

    .line 110
    :goto_2
    iget-object v1, p1, Lin/g0;->r:Lin/e0;

    .line 111
    .line 112
    if-eqz v1, :cond_5

    .line 113
    .line 114
    invoke-virtual {v1, p0}, Lin/e0;->e(Lin/z1;)F

    .line 115
    .line 116
    .line 117
    move-result v1

    .line 118
    goto :goto_3

    .line 119
    :cond_5
    move v1, v2

    .line 120
    :goto_3
    iget-object v3, p1, Lin/g0;->s:Lin/e0;

    .line 121
    .line 122
    const/high16 v5, 0x40400000    # 3.0f

    .line 123
    .line 124
    if-eqz v3, :cond_6

    .line 125
    .line 126
    invoke-virtual {v3, p0}, Lin/e0;->d(Lin/z1;)F

    .line 127
    .line 128
    .line 129
    move-result v3

    .line 130
    goto :goto_4

    .line 131
    :cond_6
    move v3, v5

    .line 132
    :goto_4
    iget-object v6, p1, Lin/g0;->t:Lin/e0;

    .line 133
    .line 134
    if-eqz v6, :cond_7

    .line 135
    .line 136
    invoke-virtual {v6, p0}, Lin/e0;->e(Lin/z1;)F

    .line 137
    .line 138
    .line 139
    move-result v5

    .line 140
    :cond_7
    iget-object v6, p1, Lin/e1;->o:Ld3/a;

    .line 141
    .line 142
    if-eqz v6, :cond_e

    .line 143
    .line 144
    iget v7, v6, Ld3/a;->d:F

    .line 145
    .line 146
    div-float v7, v3, v7

    .line 147
    .line 148
    iget v6, v6, Ld3/a;->e:F

    .line 149
    .line 150
    div-float v6, v5, v6

    .line 151
    .line 152
    iget-object v8, p1, Lin/c1;->n:Lin/s;

    .line 153
    .line 154
    if-eqz v8, :cond_8

    .line 155
    .line 156
    goto :goto_5

    .line 157
    :cond_8
    sget-object v8, Lin/s;->d:Lin/s;

    .line 158
    .line 159
    :goto_5
    sget-object v9, Lin/s;->c:Lin/s;

    .line 160
    .line 161
    invoke-virtual {v8, v9}, Lin/s;->equals(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result v9

    .line 165
    iget-object v10, v8, Lin/s;->a:Lin/r;

    .line 166
    .line 167
    const/4 v11, 0x2

    .line 168
    if-nez v9, :cond_a

    .line 169
    .line 170
    iget v8, v8, Lin/s;->b:I

    .line 171
    .line 172
    if-ne v8, v11, :cond_9

    .line 173
    .line 174
    invoke-static {v7, v6}, Ljava/lang/Math;->max(FF)F

    .line 175
    .line 176
    .line 177
    move-result v6

    .line 178
    :goto_6
    move v7, v6

    .line 179
    goto :goto_7

    .line 180
    :cond_9
    invoke-static {v7, v6}, Ljava/lang/Math;->min(FF)F

    .line 181
    .line 182
    .line 183
    move-result v6

    .line 184
    goto :goto_6

    .line 185
    :goto_7
    move v6, v7

    .line 186
    :cond_a
    neg-float p2, p2

    .line 187
    mul-float/2addr p2, v7

    .line 188
    neg-float v1, v1

    .line 189
    mul-float/2addr v1, v6

    .line 190
    invoke-virtual {v4, p2, v1}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 191
    .line 192
    .line 193
    invoke-virtual {v0, v4}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 194
    .line 195
    .line 196
    iget-object p2, p1, Lin/e1;->o:Ld3/a;

    .line 197
    .line 198
    iget v1, p2, Ld3/a;->d:F

    .line 199
    .line 200
    mul-float/2addr v1, v7

    .line 201
    iget p2, p2, Ld3/a;->e:F

    .line 202
    .line 203
    mul-float/2addr p2, v6

    .line 204
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 205
    .line 206
    .line 207
    move-result v8

    .line 208
    const/high16 v9, 0x40000000    # 2.0f

    .line 209
    .line 210
    if-eq v8, v11, :cond_c

    .line 211
    .line 212
    const/4 v11, 0x3

    .line 213
    if-eq v8, v11, :cond_b

    .line 214
    .line 215
    const/4 v11, 0x5

    .line 216
    if-eq v8, v11, :cond_c

    .line 217
    .line 218
    const/4 v11, 0x6

    .line 219
    if-eq v8, v11, :cond_b

    .line 220
    .line 221
    const/16 v11, 0x8

    .line 222
    .line 223
    if-eq v8, v11, :cond_c

    .line 224
    .line 225
    const/16 v11, 0x9

    .line 226
    .line 227
    if-eq v8, v11, :cond_b

    .line 228
    .line 229
    move v1, v2

    .line 230
    goto :goto_9

    .line 231
    :cond_b
    sub-float v1, v3, v1

    .line 232
    .line 233
    :goto_8
    sub-float v1, v2, v1

    .line 234
    .line 235
    goto :goto_9

    .line 236
    :cond_c
    sub-float v1, v3, v1

    .line 237
    .line 238
    div-float/2addr v1, v9

    .line 239
    goto :goto_8

    .line 240
    :goto_9
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 241
    .line 242
    .line 243
    move-result v8

    .line 244
    packed-switch v8, :pswitch_data_0

    .line 245
    .line 246
    .line 247
    goto :goto_b

    .line 248
    :pswitch_0
    sub-float p2, v5, p2

    .line 249
    .line 250
    :goto_a
    sub-float/2addr v2, p2

    .line 251
    goto :goto_b

    .line 252
    :pswitch_1
    sub-float p2, v5, p2

    .line 253
    .line 254
    div-float/2addr p2, v9

    .line 255
    goto :goto_a

    .line 256
    :goto_b
    iget-object p2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 257
    .line 258
    check-cast p2, Lin/x1;

    .line 259
    .line 260
    iget-object p2, p2, Lin/x1;->a:Lin/s0;

    .line 261
    .line 262
    iget-object p2, p2, Lin/s0;->r:Ljava/lang/Boolean;

    .line 263
    .line 264
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 265
    .line 266
    .line 267
    move-result p2

    .line 268
    if-nez p2, :cond_d

    .line 269
    .line 270
    invoke-virtual {p0, v1, v2, v3, v5}, Lin/z1;->a0(FFFF)V

    .line 271
    .line 272
    .line 273
    :cond_d
    invoke-virtual {v4}, Landroid/graphics/Matrix;->reset()V

    .line 274
    .line 275
    .line 276
    invoke-virtual {v4, v7, v6}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 277
    .line 278
    .line 279
    invoke-virtual {v0, v4}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 280
    .line 281
    .line 282
    goto :goto_c

    .line 283
    :cond_e
    neg-float p2, p2

    .line 284
    neg-float v1, v1

    .line 285
    invoke-virtual {v4, p2, v1}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 286
    .line 287
    .line 288
    invoke-virtual {v0, v4}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 289
    .line 290
    .line 291
    iget-object p2, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 292
    .line 293
    check-cast p2, Lin/x1;

    .line 294
    .line 295
    iget-object p2, p2, Lin/x1;->a:Lin/s0;

    .line 296
    .line 297
    iget-object p2, p2, Lin/s0;->r:Ljava/lang/Boolean;

    .line 298
    .line 299
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 300
    .line 301
    .line 302
    move-result p2

    .line 303
    if-nez p2, :cond_f

    .line 304
    .line 305
    invoke-virtual {p0, v2, v2, v3, v5}, Lin/z1;->a0(FFFF)V

    .line 306
    .line 307
    .line 308
    :cond_f
    :goto_c
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 309
    .line 310
    .line 311
    move-result p2

    .line 312
    const/4 v0, 0x0

    .line 313
    invoke-virtual {p0, p1, v0}, Lin/z1;->W(Lin/v0;Z)V

    .line 314
    .line 315
    .line 316
    if-eqz p2, :cond_10

    .line 317
    .line 318
    iget-object p1, p1, Lin/x0;->h:Ld3/a;

    .line 319
    .line 320
    invoke-virtual {p0, p1}, Lin/z1;->R(Ld3/a;)V

    .line 321
    .line 322
    .line 323
    :cond_10
    invoke-virtual {p0}, Lin/z1;->e0()V

    .line 324
    .line 325
    .line 326
    return-void

    .line 327
    :pswitch_data_0
    .packed-switch 0x4
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public Y(Lin/a0;)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lin/x1;

    .line 8
    .line 9
    iget-object v2, v2, Lin/x1;->a:Lin/s0;

    .line 10
    .line 11
    iget-object v3, v2, Lin/s0;->t:Ljava/lang/String;

    .line 12
    .line 13
    if-nez v3, :cond_0

    .line 14
    .line 15
    iget-object v4, v2, Lin/s0;->u:Ljava/lang/String;

    .line 16
    .line 17
    if-nez v4, :cond_0

    .line 18
    .line 19
    iget-object v2, v2, Lin/s0;->v:Ljava/lang/String;

    .line 20
    .line 21
    if-nez v2, :cond_0

    .line 22
    .line 23
    goto/16 :goto_c

    .line 24
    .line 25
    :cond_0
    const-string v2, "Marker reference \'%s\' not found"

    .line 26
    .line 27
    const/4 v4, 0x0

    .line 28
    if-eqz v3, :cond_2

    .line 29
    .line 30
    iget-object v5, v1, Lin/a1;->a:Lil/g;

    .line 31
    .line 32
    invoke-virtual {v5, v3}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    check-cast v3, Lin/g0;

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    iget-object v3, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v3, Lin/x1;

    .line 44
    .line 45
    iget-object v3, v3, Lin/x1;->a:Lin/s0;

    .line 46
    .line 47
    iget-object v3, v3, Lin/s0;->t:Ljava/lang/String;

    .line 48
    .line 49
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    invoke-static {v2, v3}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    :cond_2
    move-object v3, v4

    .line 57
    :goto_0
    iget-object v5, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v5, Lin/x1;

    .line 60
    .line 61
    iget-object v5, v5, Lin/x1;->a:Lin/s0;

    .line 62
    .line 63
    iget-object v5, v5, Lin/s0;->u:Ljava/lang/String;

    .line 64
    .line 65
    if-eqz v5, :cond_4

    .line 66
    .line 67
    iget-object v6, v1, Lin/a1;->a:Lil/g;

    .line 68
    .line 69
    invoke-virtual {v6, v5}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    if-eqz v5, :cond_3

    .line 74
    .line 75
    check-cast v5, Lin/g0;

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_3
    iget-object v5, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v5, Lin/x1;

    .line 81
    .line 82
    iget-object v5, v5, Lin/x1;->a:Lin/s0;

    .line 83
    .line 84
    iget-object v5, v5, Lin/s0;->u:Ljava/lang/String;

    .line 85
    .line 86
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v5

    .line 90
    invoke-static {v2, v5}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    :cond_4
    move-object v5, v4

    .line 94
    :goto_1
    iget-object v6, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v6, Lin/x1;

    .line 97
    .line 98
    iget-object v6, v6, Lin/x1;->a:Lin/s0;

    .line 99
    .line 100
    iget-object v6, v6, Lin/s0;->v:Ljava/lang/String;

    .line 101
    .line 102
    if-eqz v6, :cond_6

    .line 103
    .line 104
    iget-object v7, v1, Lin/a1;->a:Lil/g;

    .line 105
    .line 106
    invoke-virtual {v7, v6}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 107
    .line 108
    .line 109
    move-result-object v6

    .line 110
    if-eqz v6, :cond_5

    .line 111
    .line 112
    check-cast v6, Lin/g0;

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_5
    iget-object v6, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast v6, Lin/x1;

    .line 118
    .line 119
    iget-object v6, v6, Lin/x1;->a:Lin/s0;

    .line 120
    .line 121
    iget-object v6, v6, Lin/s0;->v:Ljava/lang/String;

    .line 122
    .line 123
    filled-new-array {v6}, [Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v6

    .line 127
    invoke-static {v2, v6}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    :cond_6
    move-object v6, v4

    .line 131
    :goto_2
    instance-of v2, v1, Lin/k0;

    .line 132
    .line 133
    const/4 v7, 0x0

    .line 134
    const/4 v8, 0x2

    .line 135
    const/4 v9, 0x0

    .line 136
    if-eqz v2, :cond_7

    .line 137
    .line 138
    new-instance v2, Lin/r1;

    .line 139
    .line 140
    check-cast v1, Lin/k0;

    .line 141
    .line 142
    iget-object v1, v1, Lin/k0;->o:Li4/c;

    .line 143
    .line 144
    invoke-direct {v2, v0, v1}, Lin/r1;-><init>(Lin/z1;Li4/c;)V

    .line 145
    .line 146
    .line 147
    iget-object v1, v2, Lin/r1;->a:Ljava/util/ArrayList;

    .line 148
    .line 149
    move/from16 v17, v9

    .line 150
    .line 151
    const/16 v16, 0x1

    .line 152
    .line 153
    goto/16 :goto_9

    .line 154
    .line 155
    :cond_7
    instance-of v2, v1, Lin/f0;

    .line 156
    .line 157
    if-eqz v2, :cond_c

    .line 158
    .line 159
    check-cast v1, Lin/f0;

    .line 160
    .line 161
    iget-object v2, v1, Lin/f0;->o:Lin/e0;

    .line 162
    .line 163
    if-eqz v2, :cond_8

    .line 164
    .line 165
    invoke-virtual {v2, v0}, Lin/e0;->d(Lin/z1;)F

    .line 166
    .line 167
    .line 168
    move-result v2

    .line 169
    goto :goto_3

    .line 170
    :cond_8
    move v2, v9

    .line 171
    :goto_3
    iget-object v11, v1, Lin/f0;->p:Lin/e0;

    .line 172
    .line 173
    if-eqz v11, :cond_9

    .line 174
    .line 175
    invoke-virtual {v11, v0}, Lin/e0;->e(Lin/z1;)F

    .line 176
    .line 177
    .line 178
    move-result v11

    .line 179
    goto :goto_4

    .line 180
    :cond_9
    move v11, v9

    .line 181
    :goto_4
    iget-object v12, v1, Lin/f0;->q:Lin/e0;

    .line 182
    .line 183
    if-eqz v12, :cond_a

    .line 184
    .line 185
    invoke-virtual {v12, v0}, Lin/e0;->d(Lin/z1;)F

    .line 186
    .line 187
    .line 188
    move-result v12

    .line 189
    goto :goto_5

    .line 190
    :cond_a
    move v12, v9

    .line 191
    :goto_5
    iget-object v1, v1, Lin/f0;->r:Lin/e0;

    .line 192
    .line 193
    if-eqz v1, :cond_b

    .line 194
    .line 195
    invoke-virtual {v1, v0}, Lin/e0;->e(Lin/z1;)F

    .line 196
    .line 197
    .line 198
    move-result v1

    .line 199
    goto :goto_6

    .line 200
    :cond_b
    move v1, v9

    .line 201
    :goto_6
    new-instance v13, Ljava/util/ArrayList;

    .line 202
    .line 203
    invoke-direct {v13, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 204
    .line 205
    .line 206
    new-instance v14, Lin/s1;

    .line 207
    .line 208
    sub-float v15, v12, v2

    .line 209
    .line 210
    const/16 v16, 0x1

    .line 211
    .line 212
    sub-float v10, v1, v11

    .line 213
    .line 214
    invoke-direct {v14, v2, v11, v15, v10}, Lin/s1;-><init>(FFFF)V

    .line 215
    .line 216
    .line 217
    invoke-virtual {v13, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    new-instance v2, Lin/s1;

    .line 221
    .line 222
    invoke-direct {v2, v12, v1, v15, v10}, Lin/s1;-><init>(FFFF)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v13, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 226
    .line 227
    .line 228
    move/from16 v17, v9

    .line 229
    .line 230
    move-object v1, v13

    .line 231
    goto/16 :goto_9

    .line 232
    .line 233
    :cond_c
    const/16 v16, 0x1

    .line 234
    .line 235
    check-cast v1, Lin/n0;

    .line 236
    .line 237
    iget-object v2, v1, Lin/n0;->o:[F

    .line 238
    .line 239
    array-length v2, v2

    .line 240
    if-ge v2, v8, :cond_d

    .line 241
    .line 242
    move-object v1, v4

    .line 243
    move/from16 v17, v9

    .line 244
    .line 245
    goto/16 :goto_9

    .line 246
    .line 247
    :cond_d
    new-instance v10, Ljava/util/ArrayList;

    .line 248
    .line 249
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 250
    .line 251
    .line 252
    new-instance v11, Lin/s1;

    .line 253
    .line 254
    iget-object v12, v1, Lin/n0;->o:[F

    .line 255
    .line 256
    aget v13, v12, v7

    .line 257
    .line 258
    aget v12, v12, v16

    .line 259
    .line 260
    invoke-direct {v11, v13, v12, v9, v9}, Lin/s1;-><init>(FFFF)V

    .line 261
    .line 262
    .line 263
    move v12, v8

    .line 264
    move v13, v9

    .line 265
    move v14, v13

    .line 266
    :goto_7
    iget v15, v11, Lin/s1;->b:F

    .line 267
    .line 268
    move/from16 v17, v9

    .line 269
    .line 270
    iget v9, v11, Lin/s1;->a:F

    .line 271
    .line 272
    if-ge v12, v2, :cond_e

    .line 273
    .line 274
    iget-object v13, v1, Lin/n0;->o:[F

    .line 275
    .line 276
    aget v14, v13, v12

    .line 277
    .line 278
    add-int/lit8 v18, v12, 0x1

    .line 279
    .line 280
    aget v13, v13, v18

    .line 281
    .line 282
    invoke-virtual {v11, v14, v13}, Lin/s1;->a(FF)V

    .line 283
    .line 284
    .line 285
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    new-instance v11, Lin/s1;

    .line 289
    .line 290
    sub-float v9, v14, v9

    .line 291
    .line 292
    sub-float v15, v13, v15

    .line 293
    .line 294
    invoke-direct {v11, v14, v13, v9, v15}, Lin/s1;-><init>(FFFF)V

    .line 295
    .line 296
    .line 297
    add-int/lit8 v12, v12, 0x2

    .line 298
    .line 299
    move v9, v14

    .line 300
    move v14, v13

    .line 301
    move v13, v9

    .line 302
    move/from16 v9, v17

    .line 303
    .line 304
    goto :goto_7

    .line 305
    :cond_e
    instance-of v2, v1, Lin/o0;

    .line 306
    .line 307
    if-eqz v2, :cond_10

    .line 308
    .line 309
    iget-object v1, v1, Lin/n0;->o:[F

    .line 310
    .line 311
    aget v2, v1, v7

    .line 312
    .line 313
    cmpl-float v12, v13, v2

    .line 314
    .line 315
    if-eqz v12, :cond_f

    .line 316
    .line 317
    aget v1, v1, v16

    .line 318
    .line 319
    cmpl-float v12, v14, v1

    .line 320
    .line 321
    if-eqz v12, :cond_f

    .line 322
    .line 323
    invoke-virtual {v11, v2, v1}, Lin/s1;->a(FF)V

    .line 324
    .line 325
    .line 326
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 327
    .line 328
    .line 329
    new-instance v11, Lin/s1;

    .line 330
    .line 331
    sub-float v9, v2, v9

    .line 332
    .line 333
    sub-float v12, v1, v15

    .line 334
    .line 335
    invoke-direct {v11, v2, v1, v9, v12}, Lin/s1;-><init>(FFFF)V

    .line 336
    .line 337
    .line 338
    invoke-virtual {v10, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    move-result-object v1

    .line 342
    check-cast v1, Lin/s1;

    .line 343
    .line 344
    invoke-virtual {v11, v1}, Lin/s1;->b(Lin/s1;)V

    .line 345
    .line 346
    .line 347
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 348
    .line 349
    .line 350
    invoke-virtual {v10, v7, v11}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    :cond_f
    :goto_8
    move-object v1, v10

    .line 354
    goto :goto_9

    .line 355
    :cond_10
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 356
    .line 357
    .line 358
    goto :goto_8

    .line 359
    :goto_9
    if-nez v1, :cond_11

    .line 360
    .line 361
    goto/16 :goto_c

    .line 362
    .line 363
    :cond_11
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 364
    .line 365
    .line 366
    move-result v2

    .line 367
    if-nez v2, :cond_12

    .line 368
    .line 369
    goto/16 :goto_c

    .line 370
    .line 371
    :cond_12
    iget-object v9, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 372
    .line 373
    check-cast v9, Lin/x1;

    .line 374
    .line 375
    iget-object v9, v9, Lin/x1;->a:Lin/s0;

    .line 376
    .line 377
    iput-object v4, v9, Lin/s0;->v:Ljava/lang/String;

    .line 378
    .line 379
    iput-object v4, v9, Lin/s0;->u:Ljava/lang/String;

    .line 380
    .line 381
    iput-object v4, v9, Lin/s0;->t:Ljava/lang/String;

    .line 382
    .line 383
    if-eqz v3, :cond_13

    .line 384
    .line 385
    invoke-interface {v1, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 386
    .line 387
    .line 388
    move-result-object v4

    .line 389
    check-cast v4, Lin/s1;

    .line 390
    .line 391
    invoke-virtual {v0, v3, v4}, Lin/z1;->X(Lin/g0;Lin/s1;)V

    .line 392
    .line 393
    .line 394
    :cond_13
    if-eqz v5, :cond_18

    .line 395
    .line 396
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 397
    .line 398
    .line 399
    move-result v3

    .line 400
    if-le v3, v8, :cond_18

    .line 401
    .line 402
    invoke-interface {v1, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 403
    .line 404
    .line 405
    move-result-object v3

    .line 406
    check-cast v3, Lin/s1;

    .line 407
    .line 408
    move/from16 v4, v16

    .line 409
    .line 410
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 411
    .line 412
    .line 413
    move-result-object v7

    .line 414
    check-cast v7, Lin/s1;

    .line 415
    .line 416
    move-object v4, v3

    .line 417
    move-object v3, v7

    .line 418
    const/4 v7, 0x1

    .line 419
    :goto_a
    add-int/lit8 v8, v2, -0x1

    .line 420
    .line 421
    if-ge v7, v8, :cond_18

    .line 422
    .line 423
    add-int/lit8 v7, v7, 0x1

    .line 424
    .line 425
    invoke-interface {v1, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 426
    .line 427
    .line 428
    move-result-object v8

    .line 429
    check-cast v8, Lin/s1;

    .line 430
    .line 431
    iget-boolean v9, v3, Lin/s1;->e:Z

    .line 432
    .line 433
    if-eqz v9, :cond_17

    .line 434
    .line 435
    iget v9, v3, Lin/s1;->c:F

    .line 436
    .line 437
    iget v10, v3, Lin/s1;->d:F

    .line 438
    .line 439
    iget v11, v3, Lin/s1;->a:F

    .line 440
    .line 441
    iget v12, v4, Lin/s1;->a:F

    .line 442
    .line 443
    sub-float v12, v11, v12

    .line 444
    .line 445
    iget v13, v3, Lin/s1;->b:F

    .line 446
    .line 447
    iget v4, v4, Lin/s1;->b:F

    .line 448
    .line 449
    sub-float v4, v13, v4

    .line 450
    .line 451
    mul-float/2addr v12, v9

    .line 452
    mul-float/2addr v4, v10

    .line 453
    add-float/2addr v4, v12

    .line 454
    cmpl-float v12, v4, v17

    .line 455
    .line 456
    if-nez v12, :cond_14

    .line 457
    .line 458
    iget v4, v8, Lin/s1;->a:F

    .line 459
    .line 460
    sub-float/2addr v4, v11

    .line 461
    iget v11, v8, Lin/s1;->b:F

    .line 462
    .line 463
    sub-float/2addr v11, v13

    .line 464
    mul-float/2addr v4, v9

    .line 465
    mul-float/2addr v11, v10

    .line 466
    add-float/2addr v4, v11

    .line 467
    :cond_14
    cmpl-float v4, v4, v17

    .line 468
    .line 469
    if-lez v4, :cond_15

    .line 470
    .line 471
    goto :goto_b

    .line 472
    :cond_15
    if-nez v4, :cond_16

    .line 473
    .line 474
    cmpl-float v4, v9, v17

    .line 475
    .line 476
    if-gtz v4, :cond_17

    .line 477
    .line 478
    cmpl-float v4, v10, v17

    .line 479
    .line 480
    if-ltz v4, :cond_16

    .line 481
    .line 482
    goto :goto_b

    .line 483
    :cond_16
    neg-float v4, v9

    .line 484
    iput v4, v3, Lin/s1;->c:F

    .line 485
    .line 486
    neg-float v4, v10

    .line 487
    iput v4, v3, Lin/s1;->d:F

    .line 488
    .line 489
    :cond_17
    :goto_b
    invoke-virtual {v0, v5, v3}, Lin/z1;->X(Lin/g0;Lin/s1;)V

    .line 490
    .line 491
    .line 492
    move-object v4, v3

    .line 493
    move-object v3, v8

    .line 494
    goto :goto_a

    .line 495
    :cond_18
    if-eqz v6, :cond_19

    .line 496
    .line 497
    const/16 v16, 0x1

    .line 498
    .line 499
    add-int/lit8 v2, v2, -0x1

    .line 500
    .line 501
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 502
    .line 503
    .line 504
    move-result-object v1

    .line 505
    check-cast v1, Lin/s1;

    .line 506
    .line 507
    invoke-virtual {v0, v6, v1}, Lin/z1;->X(Lin/g0;Lin/s1;)V

    .line 508
    .line 509
    .line 510
    :cond_19
    :goto_c
    return-void
.end method

.method public Z(Lin/h0;Ld3/a;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/Canvas;

    .line 4
    .line 5
    iget-object v1, p1, Lin/h0;->n:Ljava/lang/Boolean;

    .line 6
    .line 7
    const/high16 v2, 0x3f800000    # 1.0f

    .line 8
    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_2

    .line 16
    .line 17
    iget-object v1, p1, Lin/h0;->p:Lin/e0;

    .line 18
    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-virtual {v1, p0}, Lin/e0;->d(Lin/z1;)F

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    iget v1, p2, Ld3/a;->d:F

    .line 27
    .line 28
    :goto_0
    iget-object v3, p1, Lin/h0;->q:Lin/e0;

    .line 29
    .line 30
    if-eqz v3, :cond_1

    .line 31
    .line 32
    invoke-virtual {v3, p0}, Lin/e0;->e(Lin/z1;)F

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    goto :goto_2

    .line 37
    :cond_1
    iget v3, p2, Ld3/a;->e:F

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_2
    iget-object v1, p1, Lin/h0;->p:Lin/e0;

    .line 41
    .line 42
    const v3, 0x3f99999a    # 1.2f

    .line 43
    .line 44
    .line 45
    if-eqz v1, :cond_3

    .line 46
    .line 47
    invoke-virtual {v1, p0, v2}, Lin/e0;->b(Lin/z1;F)F

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    goto :goto_1

    .line 52
    :cond_3
    move v1, v3

    .line 53
    :goto_1
    iget-object v4, p1, Lin/h0;->q:Lin/e0;

    .line 54
    .line 55
    if-eqz v4, :cond_4

    .line 56
    .line 57
    invoke-virtual {v4, p0, v2}, Lin/e0;->b(Lin/z1;F)F

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    :cond_4
    iget v4, p2, Ld3/a;->d:F

    .line 62
    .line 63
    mul-float/2addr v1, v4

    .line 64
    iget v4, p2, Ld3/a;->e:F

    .line 65
    .line 66
    mul-float/2addr v3, v4

    .line 67
    :goto_2
    const/4 v4, 0x0

    .line 68
    cmpl-float v1, v1, v4

    .line 69
    .line 70
    if-eqz v1, :cond_9

    .line 71
    .line 72
    cmpl-float v1, v3, v4

    .line 73
    .line 74
    if-nez v1, :cond_5

    .line 75
    .line 76
    goto :goto_4

    .line 77
    :cond_5
    invoke-virtual {p0}, Lin/z1;->f0()V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p0, p1}, Lin/z1;->D(Lin/y0;)Lin/x1;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    iput-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 85
    .line 86
    iget-object v1, v1, Lin/x1;->a:Lin/s0;

    .line 87
    .line 88
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    iput-object v2, v1, Lin/s0;->m:Ljava/lang/Float;

    .line 93
    .line 94
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    invoke-virtual {v0}, Landroid/graphics/Canvas;->save()I

    .line 99
    .line 100
    .line 101
    iget-object v2, p1, Lin/h0;->o:Ljava/lang/Boolean;

    .line 102
    .line 103
    if-eqz v2, :cond_7

    .line 104
    .line 105
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    if-eqz v2, :cond_6

    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_6
    iget v2, p2, Ld3/a;->b:F

    .line 113
    .line 114
    iget v3, p2, Ld3/a;->c:F

    .line 115
    .line 116
    invoke-virtual {v0, v2, v3}, Landroid/graphics/Canvas;->translate(FF)V

    .line 117
    .line 118
    .line 119
    iget v2, p2, Ld3/a;->d:F

    .line 120
    .line 121
    iget v3, p2, Ld3/a;->e:F

    .line 122
    .line 123
    invoke-virtual {v0, v2, v3}, Landroid/graphics/Canvas;->scale(FF)V

    .line 124
    .line 125
    .line 126
    :cond_7
    :goto_3
    const/4 v2, 0x0

    .line 127
    invoke-virtual {p0, p1, v2}, Lin/z1;->W(Lin/v0;Z)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v0}, Landroid/graphics/Canvas;->restore()V

    .line 131
    .line 132
    .line 133
    if-eqz v1, :cond_8

    .line 134
    .line 135
    invoke-virtual {p0, p2}, Lin/z1;->R(Ld3/a;)V

    .line 136
    .line 137
    .line 138
    :cond_8
    invoke-virtual {p0}, Lin/z1;->e0()V

    .line 139
    .line 140
    .line 141
    :cond_9
    :goto_4
    return-void
.end method

.method public a(Ljava/lang/Class;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/Set;

    .line 4
    .line 5
    invoke-static {p1}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-interface {v0, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    iget-object p0, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lgs/c;

    .line 18
    .line 19
    invoke-interface {p0, p1}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-class v0, Ldt/b;

    .line 24
    .line 25
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    if-nez p1, :cond_0

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_0
    new-instance p1, Lgs/t;

    .line 33
    .line 34
    check-cast p0, Ldt/b;

    .line 35
    .line 36
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 37
    .line 38
    .line 39
    return-object p1

    .line 40
    :cond_1
    new-instance p0, La8/r0;

    .line 41
    .line 42
    new-instance v0, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    const-string v1, "Attempting to request an undeclared dependency "

    .line 45
    .line 46
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string p1, "."

    .line 53
    .line 54
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p0
.end method

.method public a0(FFFF)V
    .locals 1

    .line 1
    add-float/2addr p3, p1

    .line 2
    add-float/2addr p4, p2

    .line 3
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lin/x1;

    .line 6
    .line 7
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 8
    .line 9
    iget-object v0, v0, Lin/s0;->s:Lcom/google/firebase/messaging/w;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Lin/e0;

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Lin/e0;->d(Lin/z1;)F

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    add-float/2addr p1, v0

    .line 22
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Lin/x1;

    .line 25
    .line 26
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 27
    .line 28
    iget-object v0, v0, Lin/s0;->s:Lcom/google/firebase/messaging/w;

    .line 29
    .line 30
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v0, Lin/e0;

    .line 33
    .line 34
    invoke-virtual {v0, p0}, Lin/e0;->e(Lin/z1;)F

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    add-float/2addr p2, v0

    .line 39
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Lin/x1;

    .line 42
    .line 43
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 44
    .line 45
    iget-object v0, v0, Lin/s0;->s:Lcom/google/firebase/messaging/w;

    .line 46
    .line 47
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v0, Lin/e0;

    .line 50
    .line 51
    invoke-virtual {v0, p0}, Lin/e0;->d(Lin/z1;)F

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    sub-float/2addr p3, v0

    .line 56
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v0, Lin/x1;

    .line 59
    .line 60
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 61
    .line 62
    iget-object v0, v0, Lin/s0;->s:Lcom/google/firebase/messaging/w;

    .line 63
    .line 64
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v0, Lin/e0;

    .line 67
    .line 68
    invoke-virtual {v0, p0}, Lin/e0;->e(Lin/z1;)F

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    sub-float/2addr p4, v0

    .line 73
    :cond_0
    iget-object p0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast p0, Landroid/graphics/Canvas;

    .line 76
    .line 77
    invoke-virtual {p0, p1, p2, p3, p4}, Landroid/graphics/Canvas;->clipRect(FFFF)Z

    .line 78
    .line 79
    .line 80
    return-void
.end method

.method public b(Lgs/s;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/Set;

    .line 4
    .line 5
    invoke-interface {v0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lgs/c;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lgs/c;->b(Lgs/s;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_0
    new-instance p0, La8/r0;

    .line 21
    .line 22
    new-instance v0, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v1, "Attempting to request an undeclared dependency "

    .line 25
    .line 26
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string p1, "."

    .line 33
    .line 34
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method

.method public b0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 5

    .line 1
    const-string v0, "scope"

    .line 2
    .line 3
    invoke-virtual {p3, v0, p2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p2, "sender"

    .line 7
    .line 8
    invoke-virtual {p3, p2, p1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p2, "subtype"

    .line 12
    .line 13
    invoke-virtual {p3, p2, p1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p1, "gmp_app_id"

    .line 17
    .line 18
    iget-object p2, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p2, Lsr/f;

    .line 21
    .line 22
    invoke-virtual {p2}, Lsr/f;->a()V

    .line 23
    .line 24
    .line 25
    iget-object p2, p2, Lsr/f;->c:Lsr/i;

    .line 26
    .line 27
    iget-object p2, p2, Lsr/i;->b:Ljava/lang/String;

    .line 28
    .line 29
    invoke-virtual {p3, p1, p2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const-string p1, "gmsv"

    .line 33
    .line 34
    iget-object p2, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p2, Lcom/google/firebase/messaging/r;

    .line 37
    .line 38
    monitor-enter p2

    .line 39
    :try_start_0
    iget v0, p2, Lcom/google/firebase/messaging/r;->a:I

    .line 40
    .line 41
    if-nez v0, :cond_0

    .line 42
    .line 43
    const-string v0, "com.google.android.gms"

    .line 44
    .line 45
    invoke-virtual {p2, v0}, Lcom/google/firebase/messaging/r;->d(Ljava/lang/String;)Landroid/content/pm/PackageInfo;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    if-eqz v0, :cond_0

    .line 50
    .line 51
    iget v0, v0, Landroid/content/pm/PackageInfo;->versionCode:I

    .line 52
    .line 53
    iput v0, p2, Lcom/google/firebase/messaging/r;->a:I

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :catchall_0
    move-exception p0

    .line 57
    goto/16 :goto_8

    .line 58
    .line 59
    :cond_0
    :goto_0
    iget v0, p2, Lcom/google/firebase/messaging/r;->a:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 60
    .line 61
    monitor-exit p2

    .line 62
    invoke-static {v0}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p2

    .line 66
    invoke-virtual {p3, p1, p2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    const-string p1, "osv"

    .line 70
    .line 71
    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 72
    .line 73
    invoke-static {p2}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p2

    .line 77
    invoke-virtual {p3, p1, p2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    const-string p1, "app_ver"

    .line 81
    .line 82
    iget-object p2, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast p2, Lcom/google/firebase/messaging/r;

    .line 85
    .line 86
    invoke-virtual {p2}, Lcom/google/firebase/messaging/r;->b()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    invoke-virtual {p3, p1, p2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    const-string p1, "app_ver_name"

    .line 94
    .line 95
    iget-object p2, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 96
    .line 97
    move-object v0, p2

    .line 98
    check-cast v0, Lcom/google/firebase/messaging/r;

    .line 99
    .line 100
    monitor-enter v0

    .line 101
    :try_start_1
    iget-object p2, v0, Lcom/google/firebase/messaging/r;->e:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast p2, Ljava/lang/String;

    .line 104
    .line 105
    if-nez p2, :cond_1

    .line 106
    .line 107
    invoke-virtual {v0}, Lcom/google/firebase/messaging/r;->f()V

    .line 108
    .line 109
    .line 110
    goto :goto_1

    .line 111
    :catchall_1
    move-exception p0

    .line 112
    goto/16 :goto_7

    .line 113
    .line 114
    :cond_1
    :goto_1
    iget-object p2, v0, Lcom/google/firebase/messaging/r;->e:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast p2, Ljava/lang/String;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 117
    .line 118
    monitor-exit v0

    .line 119
    invoke-virtual {p3, p1, p2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    const-string p1, "firebase-app-name-hash"

    .line 123
    .line 124
    iget-object p2, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast p2, Lsr/f;

    .line 127
    .line 128
    invoke-virtual {p2}, Lsr/f;->a()V

    .line 129
    .line 130
    .line 131
    iget-object p2, p2, Lsr/f;->b:Ljava/lang/String;

    .line 132
    .line 133
    const-string v0, "SHA-1"

    .line 134
    .line 135
    :try_start_2
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    invoke-virtual {p2}, Ljava/lang/String;->getBytes()[B

    .line 140
    .line 141
    .line 142
    move-result-object p2

    .line 143
    invoke-virtual {v0, p2}, Ljava/security/MessageDigest;->digest([B)[B

    .line 144
    .line 145
    .line 146
    move-result-object p2

    .line 147
    const/16 v0, 0xb

    .line 148
    .line 149
    invoke-static {p2, v0}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object p2
    :try_end_2
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_2 .. :try_end_2} :catch_0

    .line 153
    goto :goto_2

    .line 154
    :catch_0
    const-string p2, "[HASH-ERROR]"

    .line 155
    .line 156
    :goto_2
    invoke-virtual {p3, p1, p2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    :try_start_3
    iget-object p1, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 160
    .line 161
    check-cast p1, Lht/d;

    .line 162
    .line 163
    check-cast p1, Lht/c;

    .line 164
    .line 165
    invoke-virtual {p1}, Lht/c;->d()Laq/t;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    invoke-static {p1}, Ljp/l1;->a(Laq/j;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    check-cast p1, Lht/a;

    .line 174
    .line 175
    iget-object p1, p1, Lht/a;->a:Ljava/lang/String;

    .line 176
    .line 177
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 178
    .line 179
    .line 180
    move-result p2

    .line 181
    if-nez p2, :cond_2

    .line 182
    .line 183
    const-string p2, "Goog-Firebase-Installations-Auth"

    .line 184
    .line 185
    invoke-virtual {p3, p2, p1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    goto :goto_4

    .line 189
    :catch_1
    move-exception p1

    .line 190
    goto :goto_3

    .line 191
    :cond_2
    const-string p1, "FirebaseMessaging"

    .line 192
    .line 193
    const-string p2, "FIS auth token is empty"

    .line 194
    .line 195
    invoke-static {p1, p2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_3
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_1

    .line 196
    .line 197
    .line 198
    goto :goto_4

    .line 199
    :goto_3
    const-string p2, "FirebaseMessaging"

    .line 200
    .line 201
    const-string v0, "Failed to get FIS auth token"

    .line 202
    .line 203
    invoke-static {p2, v0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 204
    .line 205
    .line 206
    :goto_4
    const-string p1, "appid"

    .line 207
    .line 208
    iget-object p2, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast p2, Lht/d;

    .line 211
    .line 212
    check-cast p2, Lht/c;

    .line 213
    .line 214
    invoke-virtual {p2}, Lht/c;->c()Laq/t;

    .line 215
    .line 216
    .line 217
    move-result-object p2

    .line 218
    invoke-static {p2}, Ljp/l1;->a(Laq/j;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object p2

    .line 222
    check-cast p2, Ljava/lang/String;

    .line 223
    .line 224
    invoke-virtual {p3, p1, p2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    const-string p1, "cliv"

    .line 228
    .line 229
    const-string p2, "fcm-25.0.1"

    .line 230
    .line 231
    invoke-virtual {p3, p1, p2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    iget-object p1, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 235
    .line 236
    check-cast p1, Lgt/b;

    .line 237
    .line 238
    invoke-interface {p1}, Lgt/b;->get()Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object p1

    .line 242
    check-cast p1, Let/f;

    .line 243
    .line 244
    iget-object p0, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 245
    .line 246
    check-cast p0, Lgt/b;

    .line 247
    .line 248
    invoke-interface {p0}, Lgt/b;->get()Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    check-cast p0, Lbu/b;

    .line 253
    .line 254
    if-eqz p1, :cond_4

    .line 255
    .line 256
    if-eqz p0, :cond_4

    .line 257
    .line 258
    check-cast p1, Let/c;

    .line 259
    .line 260
    monitor-enter p1

    .line 261
    :try_start_4
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 262
    .line 263
    .line 264
    move-result-wide v0

    .line 265
    iget-object p2, p1, Let/c;->a:Lgs/o;

    .line 266
    .line 267
    invoke-virtual {p2}, Lgs/o;->get()Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object p2

    .line 271
    check-cast p2, Let/h;

    .line 272
    .line 273
    monitor-enter p2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 274
    :try_start_5
    sget-object v2, Let/h;->b:Lq6/e;

    .line 275
    .line 276
    invoke-virtual {p2, v2, v0, v1}, Let/h;->e(Lq6/e;J)Z

    .line 277
    .line 278
    .line 279
    move-result v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 280
    :try_start_6
    monitor-exit p2

    .line 281
    const/4 v1, 0x1

    .line 282
    if-eqz v0, :cond_3

    .line 283
    .line 284
    monitor-enter p2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_4

    .line 285
    :try_start_7
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 286
    .line 287
    .line 288
    move-result-wide v2

    .line 289
    invoke-virtual {p2, v2, v3}, Let/h;->b(J)Ljava/lang/String;

    .line 290
    .line 291
    .line 292
    move-result-object v0

    .line 293
    iget-object v2, p2, Let/h;->a:Lws/c;

    .line 294
    .line 295
    new-instance v3, Let/g;

    .line 296
    .line 297
    const/4 v4, 0x0

    .line 298
    invoke-direct {v3, v4, p2, v0}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v2, v3}, Lws/c;->a(Lay0/k;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 302
    .line 303
    .line 304
    :try_start_8
    monitor-exit p2
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_4

    .line 305
    monitor-exit p1

    .line 306
    const/4 p1, 0x3

    .line 307
    goto :goto_5

    .line 308
    :catchall_2
    move-exception p0

    .line 309
    :try_start_9
    monitor-exit p2
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 310
    :try_start_a
    throw p0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_4

    .line 311
    :cond_3
    monitor-exit p1

    .line 312
    move p1, v1

    .line 313
    :goto_5
    if-eq p1, v1, :cond_4

    .line 314
    .line 315
    const-string p2, "Firebase-Client-Log-Type"

    .line 316
    .line 317
    invoke-static {p1}, Lu/w;->o(I)I

    .line 318
    .line 319
    .line 320
    move-result p1

    .line 321
    invoke-static {p1}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 322
    .line 323
    .line 324
    move-result-object p1

    .line 325
    invoke-virtual {p3, p2, p1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 326
    .line 327
    .line 328
    const-string p1, "Firebase-Client"

    .line 329
    .line 330
    invoke-virtual {p0}, Lbu/b;->a()Ljava/lang/String;

    .line 331
    .line 332
    .line 333
    move-result-object p0

    .line 334
    invoke-virtual {p3, p1, p0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 335
    .line 336
    .line 337
    goto :goto_6

    .line 338
    :catchall_3
    move-exception p0

    .line 339
    :try_start_b
    monitor-exit p2
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_3

    .line 340
    :try_start_c
    throw p0

    .line 341
    :catchall_4
    move-exception p0

    .line 342
    monitor-exit p1
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_4

    .line 343
    throw p0

    .line 344
    :cond_4
    :goto_6
    return-void

    .line 345
    :goto_7
    :try_start_d
    monitor-exit v0
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_1

    .line 346
    throw p0

    .line 347
    :goto_8
    :try_start_e
    monitor-exit p2
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_0

    .line 348
    throw p0
.end method

.method public c(Lgs/s;)Ljava/util/Set;
    .locals 2

    .line 1
    iget-object v0, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/Set;

    .line 4
    .line 5
    invoke-interface {v0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lgs/c;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lgs/c;->c(Lgs/s;)Ljava/util/Set;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_0
    new-instance p0, La8/r0;

    .line 21
    .line 22
    new-instance v0, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v1, "Attempting to request an undeclared dependency Set<"

    .line 25
    .line 26
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string p1, ">."

    .line 33
    .line 34
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method

.method public d(Lgs/s;)Lgt/b;
    .locals 2

    .line 1
    iget-object v0, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/Set;

    .line 4
    .line 5
    invoke-interface {v0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lgs/c;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lgs/c;->d(Lgs/s;)Lgt/b;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_0
    new-instance p0, La8/r0;

    .line 21
    .line 22
    new-instance v0, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v1, "Attempting to request an undeclared dependency Provider<Set<"

    .line 25
    .line 26
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string p1, ">>."

    .line 33
    .line 34
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method

.method public d0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Laq/t;
    .locals 3

    .line 1
    :try_start_0
    invoke-virtual {p0, p1, p2, p3}, Lin/z1;->b0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lio/b;

    .line 7
    .line 8
    sget-object p1, Lio/h;->f:Lio/h;

    .line 9
    .line 10
    iget-object p2, p0, Lio/b;->c:Lc1/m2;

    .line 11
    .line 12
    invoke-virtual {p2}, Lc1/m2;->q()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const v1, 0xb71b00

    .line 17
    .line 18
    .line 19
    if-ge v0, v1, :cond_1

    .line 20
    .line 21
    invoke-virtual {p2}, Lc1/m2;->r()I

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    if-eqz p2, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0, p3}, Lio/b;->a(Landroid/os/Bundle;)Laq/t;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    new-instance v0, Lvp/y1;

    .line 32
    .line 33
    const/16 v1, 0xa

    .line 34
    .line 35
    const/4 v2, 0x0

    .line 36
    invoke-direct {v0, p0, p3, v2, v1}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p2, p1, v0}, Laq/t;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :cond_0
    new-instance p0, Ljava/io/IOException;

    .line 45
    .line 46
    const-string p1, "MISSING_INSTANCEID_SERVICE"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-static {p0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :cond_1
    iget-object p0, p0, Lio/b;->b:Landroid/content/Context;

    .line 57
    .line 58
    invoke-static {p0}, Lio/o;->d(Landroid/content/Context;)Lio/o;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    new-instance p2, Lio/n;

    .line 63
    .line 64
    monitor-enter p0

    .line 65
    :try_start_1
    iget v0, p0, Lio/o;->d:I

    .line 66
    .line 67
    add-int/lit8 v1, v0, 0x1

    .line 68
    .line 69
    iput v1, p0, Lio/o;->d:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 70
    .line 71
    monitor-exit p0

    .line 72
    const/4 v1, 0x1

    .line 73
    const/4 v2, 0x1

    .line 74
    invoke-direct {p2, v0, v2, p3, v1}, Lio/n;-><init>(IILandroid/os/Bundle;I)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p0, p2}, Lio/o;->e(Lio/n;)Laq/t;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    sget-object p2, Lio/d;->e:Lio/d;

    .line 82
    .line 83
    invoke-virtual {p0, p1, p2}, Laq/t;->m(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :catchall_0
    move-exception p1

    .line 89
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 90
    throw p1

    .line 91
    :catch_0
    move-exception p0

    .line 92
    invoke-static {p0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0
.end method

.method public e(Lgs/s;)Lgt/b;
    .locals 2

    .line 1
    iget-object v0, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/Set;

    .line 4
    .line 5
    invoke-interface {v0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lgs/c;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lgs/c;->e(Lgs/s;)Lgt/b;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_0
    new-instance p0, La8/r0;

    .line 21
    .line 22
    new-instance v0, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v1, "Attempting to request an undeclared dependency Provider<"

    .line 25
    .line 26
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string p1, ">."

    .line 33
    .line 34
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method

.method public e0()V
    .locals 1

    .line 1
    iget-object v0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/Canvas;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroid/graphics/Canvas;->restore()V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Ljava/util/Stack;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Lin/x1;

    .line 17
    .line 18
    iput-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 19
    .line 20
    return-void
.end method

.method public f(Ljava/lang/Class;)Lgt/b;
    .locals 0

    .line 1
    invoke-static {p1}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p0, p1}, Lin/z1;->e(Lgs/s;)Lgt/b;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public f0()V
    .locals 2

    .line 1
    iget-object v0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/Canvas;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroid/graphics/Canvas;->save()I

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Ljava/util/Stack;

    .line 11
    .line 12
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Lin/x1;

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    new-instance v0, Lin/x1;

    .line 20
    .line 21
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v1, Lin/x1;

    .line 24
    .line 25
    invoke-direct {v0, v1}, Lin/x1;-><init>(Lin/x1;)V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 29
    .line 30
    return-void
.end method

.method public g(Lgs/s;)Lgs/q;
    .locals 2

    .line 1
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/Set;

    .line 4
    .line 5
    invoke-interface {v0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lgs/c;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lgs/c;->g(Lgs/s;)Lgs/q;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_0
    new-instance p0, La8/r0;

    .line 21
    .line 22
    new-instance v0, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v1, "Attempting to request an undeclared dependency Deferred<"

    .line 25
    .line 26
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string p1, ">."

    .line 33
    .line 34
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method

.method public g0(Ljava/lang/String;ZZ)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lin/x1;

    .line 4
    .line 5
    iget-boolean p0, p0, Lin/x1;->h:Z

    .line 6
    .line 7
    const-string v0, " "

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const-string p0, "[\\n\\t]"

    .line 12
    .line 13
    invoke-virtual {p1, p0, v0}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    const-string p0, "\\n"

    .line 19
    .line 20
    const-string v1, ""

    .line 21
    .line 22
    invoke-virtual {p1, p0, v1}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    const-string p1, "\\t"

    .line 27
    .line 28
    invoke-virtual {p0, p1, v0}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    if-eqz p2, :cond_1

    .line 33
    .line 34
    const-string p1, "^\\s+"

    .line 35
    .line 36
    invoke-virtual {p0, p1, v1}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    :cond_1
    if-eqz p3, :cond_2

    .line 41
    .line 42
    const-string p1, "\\s+$"

    .line 43
    .line 44
    invoke-virtual {p0, p1, v1}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    :cond_2
    const-string p1, "\\s{2,}"

    .line 49
    .line 50
    invoke-virtual {p0, p1, v0}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0
.end method

.method public h0(Lt7/p0;)V
    .locals 3

    .line 1
    new-instance v0, Lbb/g0;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-direct {v0, v1}, Lbb/g0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v1, Lhr/h0;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    iget-object v1, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lh8/b0;

    .line 20
    .line 21
    invoke-virtual {p0, v0, v1, p1}, Lin/z1;->i(Lbb/g0;Lh8/b0;Lt7/p0;)V

    .line 22
    .line 23
    .line 24
    iget-object v1, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Lh8/b0;

    .line 27
    .line 28
    iget-object v2, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v2, Lh8/b0;

    .line 31
    .line 32
    invoke-static {v1, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-nez v1, :cond_0

    .line 37
    .line 38
    iget-object v1, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v1, Lh8/b0;

    .line 41
    .line 42
    invoke-virtual {p0, v0, v1, p1}, Lin/z1;->i(Lbb/g0;Lh8/b0;Lt7/p0;)V

    .line 43
    .line 44
    .line 45
    :cond_0
    iget-object v1, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v1, Lh8/b0;

    .line 48
    .line 49
    iget-object v2, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v2, Lh8/b0;

    .line 52
    .line 53
    invoke-static {v1, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-nez v1, :cond_3

    .line 58
    .line 59
    iget-object v1, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v1, Lh8/b0;

    .line 62
    .line 63
    iget-object v2, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v2, Lh8/b0;

    .line 66
    .line 67
    invoke-static {v1, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_3

    .line 72
    .line 73
    iget-object v1, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v1, Lh8/b0;

    .line 76
    .line 77
    invoke-virtual {p0, v0, v1, p1}, Lin/z1;->i(Lbb/g0;Lh8/b0;Lt7/p0;)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_1
    const/4 v1, 0x0

    .line 82
    :goto_0
    iget-object v2, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v2, Lhr/h0;

    .line 85
    .line 86
    invoke-virtual {v2}, Ljava/util/AbstractCollection;->size()I

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    if-ge v1, v2, :cond_2

    .line 91
    .line 92
    iget-object v2, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v2, Lhr/h0;

    .line 95
    .line 96
    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    check-cast v2, Lh8/b0;

    .line 101
    .line 102
    invoke-virtual {p0, v0, v2, p1}, Lin/z1;->i(Lbb/g0;Lh8/b0;Lt7/p0;)V

    .line 103
    .line 104
    .line 105
    add-int/lit8 v1, v1, 0x1

    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_2
    iget-object v1, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v1, Lhr/h0;

    .line 111
    .line 112
    iget-object v2, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast v2, Lh8/b0;

    .line 115
    .line 116
    invoke-virtual {v1, v2}, Lhr/h0;->contains(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-nez v1, :cond_3

    .line 121
    .line 122
    iget-object v1, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v1, Lh8/b0;

    .line 125
    .line 126
    invoke-virtual {p0, v0, v1, p1}, Lin/z1;->i(Lbb/g0;Lh8/b0;Lt7/p0;)V

    .line 127
    .line 128
    .line 129
    :cond_3
    :goto_1
    invoke-virtual {v0}, Lbb/g0;->e()Lhr/c1;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    iput-object p1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 134
    .line 135
    return-void
.end method

.method public i(Lbb/g0;Lh8/b0;Lt7/p0;)V
    .locals 2

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    iget-object v0, p2, Lh8/b0;->a:Ljava/lang/Object;

    .line 5
    .line 6
    invoke-virtual {p3, v0}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, -0x1

    .line 11
    if-eq v0, v1, :cond_1

    .line 12
    .line 13
    invoke-virtual {p1, p2, p3}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_1
    iget-object p0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lhr/c1;

    .line 20
    .line 21
    invoke-virtual {p0, p2}, Lhr/c1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lt7/p0;

    .line 26
    .line 27
    if-eqz p0, :cond_2

    .line 28
    .line 29
    invoke-virtual {p1, p2, p0}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_2
    :goto_0
    return-void
.end method

.method public i0(Lin/x0;)V
    .locals 10

    .line 1
    iget-object v0, p1, Lin/a1;->b:Lin/w0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto/16 :goto_1

    .line 6
    .line 7
    :cond_0
    iget-object v0, p1, Lin/x0;->h:Ld3/a;

    .line 8
    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    goto/16 :goto_1

    .line 12
    .line 13
    :cond_1
    new-instance v0, Landroid/graphics/Matrix;

    .line 14
    .line 15
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Ljava/util/Stack;

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/util/Stack;->peek()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v1, Landroid/graphics/Matrix;

    .line 27
    .line 28
    invoke-virtual {v1, v0}, Landroid/graphics/Matrix;->invert(Landroid/graphics/Matrix;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_b

    .line 33
    .line 34
    iget-object v1, p1, Lin/x0;->h:Ld3/a;

    .line 35
    .line 36
    iget v2, v1, Ld3/a;->b:F

    .line 37
    .line 38
    iget v3, v1, Ld3/a;->c:F

    .line 39
    .line 40
    invoke-virtual {v1}, Ld3/a;->h()F

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    iget-object v4, p1, Lin/x0;->h:Ld3/a;

    .line 45
    .line 46
    iget v5, v4, Ld3/a;->c:F

    .line 47
    .line 48
    invoke-virtual {v4}, Ld3/a;->h()F

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    iget-object v6, p1, Lin/x0;->h:Ld3/a;

    .line 53
    .line 54
    invoke-virtual {v6}, Ld3/a;->i()F

    .line 55
    .line 56
    .line 57
    move-result v6

    .line 58
    iget-object p1, p1, Lin/x0;->h:Ld3/a;

    .line 59
    .line 60
    iget v7, p1, Ld3/a;->b:F

    .line 61
    .line 62
    invoke-virtual {p1}, Ld3/a;->i()F

    .line 63
    .line 64
    .line 65
    move-result p1

    .line 66
    const/16 v8, 0x8

    .line 67
    .line 68
    new-array v8, v8, [F

    .line 69
    .line 70
    const/4 v9, 0x0

    .line 71
    aput v2, v8, v9

    .line 72
    .line 73
    const/4 v2, 0x1

    .line 74
    aput v3, v8, v2

    .line 75
    .line 76
    const/4 v3, 0x2

    .line 77
    aput v1, v8, v3

    .line 78
    .line 79
    const/4 v1, 0x3

    .line 80
    aput v5, v8, v1

    .line 81
    .line 82
    const/4 v1, 0x4

    .line 83
    aput v4, v8, v1

    .line 84
    .line 85
    const/4 v1, 0x5

    .line 86
    aput v6, v8, v1

    .line 87
    .line 88
    const/4 v1, 0x6

    .line 89
    aput v7, v8, v1

    .line 90
    .line 91
    const/4 v4, 0x7

    .line 92
    aput p1, v8, v4

    .line 93
    .line 94
    iget-object p1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast p1, Landroid/graphics/Canvas;

    .line 97
    .line 98
    invoke-virtual {p1}, Landroid/graphics/Canvas;->getMatrix()Landroid/graphics/Matrix;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    invoke-virtual {v0, p1}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0, v8}, Landroid/graphics/Matrix;->mapPoints([F)V

    .line 106
    .line 107
    .line 108
    new-instance p1, Landroid/graphics/RectF;

    .line 109
    .line 110
    aget v0, v8, v9

    .line 111
    .line 112
    aget v2, v8, v2

    .line 113
    .line 114
    invoke-direct {p1, v0, v2, v0, v2}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 115
    .line 116
    .line 117
    :goto_0
    if-gt v3, v1, :cond_6

    .line 118
    .line 119
    aget v0, v8, v3

    .line 120
    .line 121
    iget v2, p1, Landroid/graphics/RectF;->left:F

    .line 122
    .line 123
    cmpg-float v2, v0, v2

    .line 124
    .line 125
    if-gez v2, :cond_2

    .line 126
    .line 127
    iput v0, p1, Landroid/graphics/RectF;->left:F

    .line 128
    .line 129
    :cond_2
    iget v2, p1, Landroid/graphics/RectF;->right:F

    .line 130
    .line 131
    cmpl-float v2, v0, v2

    .line 132
    .line 133
    if-lez v2, :cond_3

    .line 134
    .line 135
    iput v0, p1, Landroid/graphics/RectF;->right:F

    .line 136
    .line 137
    :cond_3
    add-int/lit8 v0, v3, 0x1

    .line 138
    .line 139
    aget v0, v8, v0

    .line 140
    .line 141
    iget v2, p1, Landroid/graphics/RectF;->top:F

    .line 142
    .line 143
    cmpg-float v2, v0, v2

    .line 144
    .line 145
    if-gez v2, :cond_4

    .line 146
    .line 147
    iput v0, p1, Landroid/graphics/RectF;->top:F

    .line 148
    .line 149
    :cond_4
    iget v2, p1, Landroid/graphics/RectF;->bottom:F

    .line 150
    .line 151
    cmpl-float v2, v0, v2

    .line 152
    .line 153
    if-lez v2, :cond_5

    .line 154
    .line 155
    iput v0, p1, Landroid/graphics/RectF;->bottom:F

    .line 156
    .line 157
    :cond_5
    add-int/lit8 v3, v3, 0x2

    .line 158
    .line 159
    goto :goto_0

    .line 160
    :cond_6
    iget-object p0, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast p0, Ljava/util/Stack;

    .line 163
    .line 164
    invoke-virtual {p0}, Ljava/util/Stack;->peek()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    check-cast p0, Lin/x0;

    .line 169
    .line 170
    iget-object v0, p0, Lin/x0;->h:Ld3/a;

    .line 171
    .line 172
    if-nez v0, :cond_7

    .line 173
    .line 174
    iget v0, p1, Landroid/graphics/RectF;->left:F

    .line 175
    .line 176
    iget v1, p1, Landroid/graphics/RectF;->top:F

    .line 177
    .line 178
    iget v2, p1, Landroid/graphics/RectF;->right:F

    .line 179
    .line 180
    iget p1, p1, Landroid/graphics/RectF;->bottom:F

    .line 181
    .line 182
    new-instance v3, Ld3/a;

    .line 183
    .line 184
    sub-float/2addr v2, v0

    .line 185
    sub-float/2addr p1, v1

    .line 186
    invoke-direct {v3, v0, v1, v2, p1}, Ld3/a;-><init>(FFFF)V

    .line 187
    .line 188
    .line 189
    iput-object v3, p0, Lin/x0;->h:Ld3/a;

    .line 190
    .line 191
    return-void

    .line 192
    :cond_7
    iget p0, p1, Landroid/graphics/RectF;->left:F

    .line 193
    .line 194
    iget v1, p1, Landroid/graphics/RectF;->top:F

    .line 195
    .line 196
    iget v2, p1, Landroid/graphics/RectF;->right:F

    .line 197
    .line 198
    iget p1, p1, Landroid/graphics/RectF;->bottom:F

    .line 199
    .line 200
    sub-float/2addr v2, p0

    .line 201
    sub-float/2addr p1, v1

    .line 202
    iget v3, v0, Ld3/a;->b:F

    .line 203
    .line 204
    cmpg-float v3, p0, v3

    .line 205
    .line 206
    if-gez v3, :cond_8

    .line 207
    .line 208
    iput p0, v0, Ld3/a;->b:F

    .line 209
    .line 210
    :cond_8
    iget v3, v0, Ld3/a;->c:F

    .line 211
    .line 212
    cmpg-float v3, v1, v3

    .line 213
    .line 214
    if-gez v3, :cond_9

    .line 215
    .line 216
    iput v1, v0, Ld3/a;->c:F

    .line 217
    .line 218
    :cond_9
    add-float v3, p0, v2

    .line 219
    .line 220
    invoke-virtual {v0}, Ld3/a;->h()F

    .line 221
    .line 222
    .line 223
    move-result v4

    .line 224
    cmpl-float v3, v3, v4

    .line 225
    .line 226
    if-lez v3, :cond_a

    .line 227
    .line 228
    add-float/2addr p0, v2

    .line 229
    iget v2, v0, Ld3/a;->b:F

    .line 230
    .line 231
    sub-float/2addr p0, v2

    .line 232
    iput p0, v0, Ld3/a;->d:F

    .line 233
    .line 234
    :cond_a
    add-float p0, v1, p1

    .line 235
    .line 236
    invoke-virtual {v0}, Ld3/a;->i()F

    .line 237
    .line 238
    .line 239
    move-result v2

    .line 240
    cmpl-float p0, p0, v2

    .line 241
    .line 242
    if-lez p0, :cond_b

    .line 243
    .line 244
    add-float/2addr v1, p1

    .line 245
    iget p0, v0, Ld3/a;->c:F

    .line 246
    .line 247
    sub-float/2addr v1, p0

    .line 248
    iput v1, v0, Ld3/a;->e:F

    .line 249
    .line 250
    :cond_b
    :goto_1
    return-void
.end method

.method public j(Lin/x0;Ld3/a;)Landroid/graphics/Path;
    .locals 5

    .line 1
    iget-object p1, p1, Lin/a1;->a:Lil/g;

    .line 2
    .line 3
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lin/x1;

    .line 6
    .line 7
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 8
    .line 9
    iget-object v0, v0, Lin/s0;->A:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {p1, v0}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    if-nez p1, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lin/x1;

    .line 20
    .line 21
    iget-object p0, p0, Lin/x1;->a:Lin/s0;

    .line 22
    .line 23
    iget-object p0, p0, Lin/s0;->A:Ljava/lang/String;

    .line 24
    .line 25
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    const-string p1, "ClipPath reference \'%s\' not found"

    .line 30
    .line 31
    invoke-static {p1, p0}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    const/4 p0, 0x0

    .line 35
    return-object p0

    .line 36
    :cond_0
    check-cast p1, Lin/u;

    .line 37
    .line 38
    iget-object v0, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v0, Ljava/util/Stack;

    .line 41
    .line 42
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v1, Lin/x1;

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0, p1}, Lin/z1;->D(Lin/y0;)Lin/x1;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    iput-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 54
    .line 55
    iget-object v0, p1, Lin/u;->o:Ljava/lang/Boolean;

    .line 56
    .line 57
    const/4 v1, 0x1

    .line 58
    if-eqz v0, :cond_2

    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-eqz v0, :cond_1

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_1
    const/4 v0, 0x0

    .line 68
    goto :goto_1

    .line 69
    :cond_2
    :goto_0
    move v0, v1

    .line 70
    :goto_1
    new-instance v2, Landroid/graphics/Matrix;

    .line 71
    .line 72
    invoke-direct {v2}, Landroid/graphics/Matrix;-><init>()V

    .line 73
    .line 74
    .line 75
    if-nez v0, :cond_3

    .line 76
    .line 77
    iget v0, p2, Ld3/a;->b:F

    .line 78
    .line 79
    iget v3, p2, Ld3/a;->c:F

    .line 80
    .line 81
    invoke-virtual {v2, v0, v3}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 82
    .line 83
    .line 84
    iget v0, p2, Ld3/a;->d:F

    .line 85
    .line 86
    iget p2, p2, Ld3/a;->e:F

    .line 87
    .line 88
    invoke-virtual {v2, v0, p2}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 89
    .line 90
    .line 91
    :cond_3
    iget-object p2, p1, Lin/b0;->n:Landroid/graphics/Matrix;

    .line 92
    .line 93
    if-eqz p2, :cond_4

    .line 94
    .line 95
    invoke-virtual {v2, p2}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 96
    .line 97
    .line 98
    :cond_4
    new-instance p2, Landroid/graphics/Path;

    .line 99
    .line 100
    invoke-direct {p2}, Landroid/graphics/Path;-><init>()V

    .line 101
    .line 102
    .line 103
    iget-object v0, p1, Lin/v0;->i:Ljava/util/List;

    .line 104
    .line 105
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    :cond_5
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    if-eqz v3, :cond_7

    .line 114
    .line 115
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    check-cast v3, Lin/a1;

    .line 120
    .line 121
    instance-of v4, v3, Lin/x0;

    .line 122
    .line 123
    if-nez v4, :cond_6

    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_6
    check-cast v3, Lin/x0;

    .line 127
    .line 128
    invoke-virtual {p0, v3, v1}, Lin/z1;->Q(Lin/x0;Z)Landroid/graphics/Path;

    .line 129
    .line 130
    .line 131
    move-result-object v3

    .line 132
    if-eqz v3, :cond_5

    .line 133
    .line 134
    sget-object v4, Landroid/graphics/Path$Op;->UNION:Landroid/graphics/Path$Op;

    .line 135
    .line 136
    invoke-virtual {p2, v3, v4}, Landroid/graphics/Path;->op(Landroid/graphics/Path;Landroid/graphics/Path$Op;)Z

    .line 137
    .line 138
    .line 139
    goto :goto_2

    .line 140
    :cond_7
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v0, Lin/x1;

    .line 143
    .line 144
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 145
    .line 146
    iget-object v0, v0, Lin/s0;->A:Ljava/lang/String;

    .line 147
    .line 148
    if-eqz v0, :cond_9

    .line 149
    .line 150
    iget-object v0, p1, Lin/x0;->h:Ld3/a;

    .line 151
    .line 152
    if-nez v0, :cond_8

    .line 153
    .line 154
    invoke-static {p2}, Lin/z1;->k(Landroid/graphics/Path;)Ld3/a;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    iput-object v0, p1, Lin/x0;->h:Ld3/a;

    .line 159
    .line 160
    :cond_8
    iget-object v0, p1, Lin/x0;->h:Ld3/a;

    .line 161
    .line 162
    invoke-virtual {p0, p1, v0}, Lin/z1;->j(Lin/x0;Ld3/a;)Landroid/graphics/Path;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    if-eqz p1, :cond_9

    .line 167
    .line 168
    sget-object v0, Landroid/graphics/Path$Op;->INTERSECT:Landroid/graphics/Path$Op;

    .line 169
    .line 170
    invoke-virtual {p2, p1, v0}, Landroid/graphics/Path;->op(Landroid/graphics/Path;Landroid/graphics/Path$Op;)Z

    .line 171
    .line 172
    .line 173
    :cond_9
    invoke-virtual {p2, v2}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 174
    .line 175
    .line 176
    iget-object p1, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast p1, Ljava/util/Stack;

    .line 179
    .line 180
    invoke-virtual {p1}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    check-cast p1, Lin/x1;

    .line 185
    .line 186
    iput-object p1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 187
    .line 188
    return-object p2
.end method

.method public j0(Lin/x1;Lin/s0;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    const-wide/16 v3, 0x1000

    .line 8
    .line 9
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    if-eqz v3, :cond_0

    .line 14
    .line 15
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 16
    .line 17
    iget-object v4, v2, Lin/s0;->n:Lin/v;

    .line 18
    .line 19
    iput-object v4, v3, Lin/s0;->n:Lin/v;

    .line 20
    .line 21
    :cond_0
    const-wide/16 v3, 0x800

    .line 22
    .line 23
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-eqz v3, :cond_1

    .line 28
    .line 29
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 30
    .line 31
    iget-object v4, v2, Lin/s0;->m:Ljava/lang/Float;

    .line 32
    .line 33
    iput-object v4, v3, Lin/s0;->m:Ljava/lang/Float;

    .line 34
    .line 35
    :cond_1
    const-wide/16 v3, 0x1

    .line 36
    .line 37
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    sget-object v4, Lin/v;->f:Lin/v;

    .line 42
    .line 43
    const/4 v5, 0x0

    .line 44
    const/4 v6, 0x1

    .line 45
    if-eqz v3, :cond_3

    .line 46
    .line 47
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 48
    .line 49
    iget-object v7, v2, Lin/s0;->e:Lin/b1;

    .line 50
    .line 51
    iput-object v7, v3, Lin/s0;->e:Lin/b1;

    .line 52
    .line 53
    iget-object v3, v2, Lin/s0;->e:Lin/b1;

    .line 54
    .line 55
    if-eqz v3, :cond_2

    .line 56
    .line 57
    if-eq v3, v4, :cond_2

    .line 58
    .line 59
    move v3, v6

    .line 60
    goto :goto_0

    .line 61
    :cond_2
    move v3, v5

    .line 62
    :goto_0
    iput-boolean v3, v1, Lin/x1;->b:Z

    .line 63
    .line 64
    :cond_3
    const-wide/16 v7, 0x4

    .line 65
    .line 66
    invoke-static {v2, v7, v8}, Lin/z1;->J(Lin/s0;J)Z

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    if-eqz v3, :cond_4

    .line 71
    .line 72
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 73
    .line 74
    iget-object v7, v2, Lin/s0;->f:Ljava/lang/Float;

    .line 75
    .line 76
    iput-object v7, v3, Lin/s0;->f:Ljava/lang/Float;

    .line 77
    .line 78
    :cond_4
    const-wide/16 v7, 0x1805

    .line 79
    .line 80
    invoke-static {v2, v7, v8}, Lin/z1;->J(Lin/s0;J)Z

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    if-eqz v3, :cond_5

    .line 85
    .line 86
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 87
    .line 88
    iget-object v3, v3, Lin/s0;->e:Lin/b1;

    .line 89
    .line 90
    invoke-static {v1, v6, v3}, Lin/z1;->c0(Lin/x1;ZLin/b1;)V

    .line 91
    .line 92
    .line 93
    :cond_5
    const-wide/16 v7, 0x2

    .line 94
    .line 95
    invoke-static {v2, v7, v8}, Lin/z1;->J(Lin/s0;J)Z

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    if-eqz v3, :cond_6

    .line 100
    .line 101
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 102
    .line 103
    iget v7, v2, Lin/s0;->G:I

    .line 104
    .line 105
    iput v7, v3, Lin/s0;->G:I

    .line 106
    .line 107
    :cond_6
    const-wide/16 v7, 0x8

    .line 108
    .line 109
    invoke-static {v2, v7, v8}, Lin/z1;->J(Lin/s0;J)Z

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    if-eqz v3, :cond_8

    .line 114
    .line 115
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 116
    .line 117
    iget-object v7, v2, Lin/s0;->g:Lin/b1;

    .line 118
    .line 119
    iput-object v7, v3, Lin/s0;->g:Lin/b1;

    .line 120
    .line 121
    iget-object v3, v2, Lin/s0;->g:Lin/b1;

    .line 122
    .line 123
    if-eqz v3, :cond_7

    .line 124
    .line 125
    if-eq v3, v4, :cond_7

    .line 126
    .line 127
    move v3, v6

    .line 128
    goto :goto_1

    .line 129
    :cond_7
    move v3, v5

    .line 130
    :goto_1
    iput-boolean v3, v1, Lin/x1;->c:Z

    .line 131
    .line 132
    :cond_8
    const-wide/16 v3, 0x10

    .line 133
    .line 134
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 135
    .line 136
    .line 137
    move-result v3

    .line 138
    if-eqz v3, :cond_9

    .line 139
    .line 140
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 141
    .line 142
    iget-object v4, v2, Lin/s0;->h:Ljava/lang/Float;

    .line 143
    .line 144
    iput-object v4, v3, Lin/s0;->h:Ljava/lang/Float;

    .line 145
    .line 146
    :cond_9
    const-wide/16 v3, 0x1818

    .line 147
    .line 148
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 149
    .line 150
    .line 151
    move-result v3

    .line 152
    if-eqz v3, :cond_a

    .line 153
    .line 154
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 155
    .line 156
    iget-object v3, v3, Lin/s0;->g:Lin/b1;

    .line 157
    .line 158
    invoke-static {v1, v5, v3}, Lin/z1;->c0(Lin/x1;ZLin/b1;)V

    .line 159
    .line 160
    .line 161
    :cond_a
    const-wide v3, 0x800000000L

    .line 162
    .line 163
    .line 164
    .line 165
    .line 166
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 167
    .line 168
    .line 169
    move-result v3

    .line 170
    if-eqz v3, :cond_b

    .line 171
    .line 172
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 173
    .line 174
    iget v4, v2, Lin/s0;->O:I

    .line 175
    .line 176
    iput v4, v3, Lin/s0;->O:I

    .line 177
    .line 178
    :cond_b
    const-wide/16 v3, 0x20

    .line 179
    .line 180
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 181
    .line 182
    .line 183
    move-result v3

    .line 184
    if-eqz v3, :cond_c

    .line 185
    .line 186
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 187
    .line 188
    iget-object v4, v2, Lin/s0;->i:Lin/e0;

    .line 189
    .line 190
    iput-object v4, v3, Lin/s0;->i:Lin/e0;

    .line 191
    .line 192
    iget-object v3, v1, Lin/x1;->e:Landroid/graphics/Paint;

    .line 193
    .line 194
    invoke-virtual {v4, v0}, Lin/e0;->a(Lin/z1;)F

    .line 195
    .line 196
    .line 197
    move-result v4

    .line 198
    invoke-virtual {v3, v4}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 199
    .line 200
    .line 201
    :cond_c
    const-wide/16 v3, 0x40

    .line 202
    .line 203
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 204
    .line 205
    .line 206
    move-result v3

    .line 207
    const/4 v4, 0x2

    .line 208
    if-eqz v3, :cond_10

    .line 209
    .line 210
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 211
    .line 212
    iget-object v7, v1, Lin/x1;->e:Landroid/graphics/Paint;

    .line 213
    .line 214
    iget v8, v2, Lin/s0;->H:I

    .line 215
    .line 216
    iput v8, v3, Lin/s0;->H:I

    .line 217
    .line 218
    iget v3, v2, Lin/s0;->H:I

    .line 219
    .line 220
    invoke-static {v3}, Lu/w;->o(I)I

    .line 221
    .line 222
    .line 223
    move-result v3

    .line 224
    if-eqz v3, :cond_f

    .line 225
    .line 226
    if-eq v3, v6, :cond_e

    .line 227
    .line 228
    if-eq v3, v4, :cond_d

    .line 229
    .line 230
    goto :goto_2

    .line 231
    :cond_d
    sget-object v3, Landroid/graphics/Paint$Cap;->SQUARE:Landroid/graphics/Paint$Cap;

    .line 232
    .line 233
    invoke-virtual {v7, v3}, Landroid/graphics/Paint;->setStrokeCap(Landroid/graphics/Paint$Cap;)V

    .line 234
    .line 235
    .line 236
    goto :goto_2

    .line 237
    :cond_e
    sget-object v3, Landroid/graphics/Paint$Cap;->ROUND:Landroid/graphics/Paint$Cap;

    .line 238
    .line 239
    invoke-virtual {v7, v3}, Landroid/graphics/Paint;->setStrokeCap(Landroid/graphics/Paint$Cap;)V

    .line 240
    .line 241
    .line 242
    goto :goto_2

    .line 243
    :cond_f
    sget-object v3, Landroid/graphics/Paint$Cap;->BUTT:Landroid/graphics/Paint$Cap;

    .line 244
    .line 245
    invoke-virtual {v7, v3}, Landroid/graphics/Paint;->setStrokeCap(Landroid/graphics/Paint$Cap;)V

    .line 246
    .line 247
    .line 248
    :cond_10
    :goto_2
    const-wide/16 v7, 0x80

    .line 249
    .line 250
    invoke-static {v2, v7, v8}, Lin/z1;->J(Lin/s0;J)Z

    .line 251
    .line 252
    .line 253
    move-result v3

    .line 254
    if-eqz v3, :cond_14

    .line 255
    .line 256
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 257
    .line 258
    iget-object v7, v1, Lin/x1;->e:Landroid/graphics/Paint;

    .line 259
    .line 260
    iget v8, v2, Lin/s0;->I:I

    .line 261
    .line 262
    iput v8, v3, Lin/s0;->I:I

    .line 263
    .line 264
    iget v3, v2, Lin/s0;->I:I

    .line 265
    .line 266
    invoke-static {v3}, Lu/w;->o(I)I

    .line 267
    .line 268
    .line 269
    move-result v3

    .line 270
    if-eqz v3, :cond_13

    .line 271
    .line 272
    if-eq v3, v6, :cond_12

    .line 273
    .line 274
    if-eq v3, v4, :cond_11

    .line 275
    .line 276
    goto :goto_3

    .line 277
    :cond_11
    sget-object v3, Landroid/graphics/Paint$Join;->BEVEL:Landroid/graphics/Paint$Join;

    .line 278
    .line 279
    invoke-virtual {v7, v3}, Landroid/graphics/Paint;->setStrokeJoin(Landroid/graphics/Paint$Join;)V

    .line 280
    .line 281
    .line 282
    goto :goto_3

    .line 283
    :cond_12
    sget-object v3, Landroid/graphics/Paint$Join;->ROUND:Landroid/graphics/Paint$Join;

    .line 284
    .line 285
    invoke-virtual {v7, v3}, Landroid/graphics/Paint;->setStrokeJoin(Landroid/graphics/Paint$Join;)V

    .line 286
    .line 287
    .line 288
    goto :goto_3

    .line 289
    :cond_13
    sget-object v3, Landroid/graphics/Paint$Join;->MITER:Landroid/graphics/Paint$Join;

    .line 290
    .line 291
    invoke-virtual {v7, v3}, Landroid/graphics/Paint;->setStrokeJoin(Landroid/graphics/Paint$Join;)V

    .line 292
    .line 293
    .line 294
    :cond_14
    :goto_3
    const-wide/16 v7, 0x100

    .line 295
    .line 296
    invoke-static {v2, v7, v8}, Lin/z1;->J(Lin/s0;J)Z

    .line 297
    .line 298
    .line 299
    move-result v3

    .line 300
    if-eqz v3, :cond_15

    .line 301
    .line 302
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 303
    .line 304
    iget-object v7, v2, Lin/s0;->j:Ljava/lang/Float;

    .line 305
    .line 306
    iput-object v7, v3, Lin/s0;->j:Ljava/lang/Float;

    .line 307
    .line 308
    iget-object v3, v1, Lin/x1;->e:Landroid/graphics/Paint;

    .line 309
    .line 310
    iget-object v7, v2, Lin/s0;->j:Ljava/lang/Float;

    .line 311
    .line 312
    invoke-virtual {v7}, Ljava/lang/Float;->floatValue()F

    .line 313
    .line 314
    .line 315
    move-result v7

    .line 316
    invoke-virtual {v3, v7}, Landroid/graphics/Paint;->setStrokeMiter(F)V

    .line 317
    .line 318
    .line 319
    :cond_15
    const-wide/16 v7, 0x200

    .line 320
    .line 321
    invoke-static {v2, v7, v8}, Lin/z1;->J(Lin/s0;J)Z

    .line 322
    .line 323
    .line 324
    move-result v3

    .line 325
    if-eqz v3, :cond_16

    .line 326
    .line 327
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 328
    .line 329
    iget-object v7, v2, Lin/s0;->k:[Lin/e0;

    .line 330
    .line 331
    iput-object v7, v3, Lin/s0;->k:[Lin/e0;

    .line 332
    .line 333
    :cond_16
    const-wide/16 v7, 0x400

    .line 334
    .line 335
    invoke-static {v2, v7, v8}, Lin/z1;->J(Lin/s0;J)Z

    .line 336
    .line 337
    .line 338
    move-result v3

    .line 339
    if-eqz v3, :cond_17

    .line 340
    .line 341
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 342
    .line 343
    iget-object v7, v2, Lin/s0;->l:Lin/e0;

    .line 344
    .line 345
    iput-object v7, v3, Lin/s0;->l:Lin/e0;

    .line 346
    .line 347
    :cond_17
    const-wide/16 v7, 0x600

    .line 348
    .line 349
    invoke-static {v2, v7, v8}, Lin/z1;->J(Lin/s0;J)Z

    .line 350
    .line 351
    .line 352
    move-result v3

    .line 353
    const/4 v7, 0x0

    .line 354
    if-eqz v3, :cond_1d

    .line 355
    .line 356
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 357
    .line 358
    iget-object v8, v1, Lin/x1;->e:Landroid/graphics/Paint;

    .line 359
    .line 360
    iget-object v9, v3, Lin/s0;->k:[Lin/e0;

    .line 361
    .line 362
    if-nez v9, :cond_18

    .line 363
    .line 364
    invoke-virtual {v8, v7}, Landroid/graphics/Paint;->setPathEffect(Landroid/graphics/PathEffect;)Landroid/graphics/PathEffect;

    .line 365
    .line 366
    .line 367
    goto :goto_6

    .line 368
    :cond_18
    array-length v9, v9

    .line 369
    rem-int/lit8 v10, v9, 0x2

    .line 370
    .line 371
    if-nez v10, :cond_19

    .line 372
    .line 373
    move v10, v9

    .line 374
    goto :goto_4

    .line 375
    :cond_19
    mul-int/lit8 v10, v9, 0x2

    .line 376
    .line 377
    :goto_4
    new-array v11, v10, [F

    .line 378
    .line 379
    const/4 v12, 0x0

    .line 380
    move v13, v5

    .line 381
    move v14, v12

    .line 382
    :goto_5
    if-ge v13, v10, :cond_1a

    .line 383
    .line 384
    iget-object v15, v3, Lin/s0;->k:[Lin/e0;

    .line 385
    .line 386
    rem-int v16, v13, v9

    .line 387
    .line 388
    aget-object v15, v15, v16

    .line 389
    .line 390
    invoke-virtual {v15, v0}, Lin/e0;->a(Lin/z1;)F

    .line 391
    .line 392
    .line 393
    move-result v15

    .line 394
    aput v15, v11, v13

    .line 395
    .line 396
    add-float/2addr v14, v15

    .line 397
    add-int/lit8 v13, v13, 0x1

    .line 398
    .line 399
    goto :goto_5

    .line 400
    :cond_1a
    cmpl-float v9, v14, v12

    .line 401
    .line 402
    if-nez v9, :cond_1b

    .line 403
    .line 404
    invoke-virtual {v8, v7}, Landroid/graphics/Paint;->setPathEffect(Landroid/graphics/PathEffect;)Landroid/graphics/PathEffect;

    .line 405
    .line 406
    .line 407
    goto :goto_6

    .line 408
    :cond_1b
    iget-object v3, v3, Lin/s0;->l:Lin/e0;

    .line 409
    .line 410
    invoke-virtual {v3, v0}, Lin/e0;->a(Lin/z1;)F

    .line 411
    .line 412
    .line 413
    move-result v3

    .line 414
    cmpg-float v9, v3, v12

    .line 415
    .line 416
    if-gez v9, :cond_1c

    .line 417
    .line 418
    rem-float/2addr v3, v14

    .line 419
    add-float/2addr v3, v14

    .line 420
    :cond_1c
    new-instance v9, Landroid/graphics/DashPathEffect;

    .line 421
    .line 422
    invoke-direct {v9, v11, v3}, Landroid/graphics/DashPathEffect;-><init>([FF)V

    .line 423
    .line 424
    .line 425
    invoke-virtual {v8, v9}, Landroid/graphics/Paint;->setPathEffect(Landroid/graphics/PathEffect;)Landroid/graphics/PathEffect;

    .line 426
    .line 427
    .line 428
    :cond_1d
    :goto_6
    const-wide/16 v8, 0x4000

    .line 429
    .line 430
    invoke-static {v2, v8, v9}, Lin/z1;->J(Lin/s0;J)Z

    .line 431
    .line 432
    .line 433
    move-result v3

    .line 434
    if-eqz v3, :cond_1e

    .line 435
    .line 436
    iget-object v3, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 437
    .line 438
    check-cast v3, Lin/x1;

    .line 439
    .line 440
    iget-object v3, v3, Lin/x1;->d:Landroid/graphics/Paint;

    .line 441
    .line 442
    invoke-virtual {v3}, Landroid/graphics/Paint;->getTextSize()F

    .line 443
    .line 444
    .line 445
    move-result v3

    .line 446
    iget-object v8, v1, Lin/x1;->a:Lin/s0;

    .line 447
    .line 448
    iget-object v9, v2, Lin/s0;->p:Lin/e0;

    .line 449
    .line 450
    iput-object v9, v8, Lin/s0;->p:Lin/e0;

    .line 451
    .line 452
    iget-object v8, v1, Lin/x1;->d:Landroid/graphics/Paint;

    .line 453
    .line 454
    iget-object v9, v2, Lin/s0;->p:Lin/e0;

    .line 455
    .line 456
    invoke-virtual {v9, v0, v3}, Lin/e0;->b(Lin/z1;F)F

    .line 457
    .line 458
    .line 459
    move-result v9

    .line 460
    invoke-virtual {v8, v9}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 461
    .line 462
    .line 463
    iget-object v8, v1, Lin/x1;->e:Landroid/graphics/Paint;

    .line 464
    .line 465
    iget-object v9, v2, Lin/s0;->p:Lin/e0;

    .line 466
    .line 467
    invoke-virtual {v9, v0, v3}, Lin/e0;->b(Lin/z1;F)F

    .line 468
    .line 469
    .line 470
    move-result v3

    .line 471
    invoke-virtual {v8, v3}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 472
    .line 473
    .line 474
    :cond_1e
    const-wide/16 v8, 0x2000

    .line 475
    .line 476
    invoke-static {v2, v8, v9}, Lin/z1;->J(Lin/s0;J)Z

    .line 477
    .line 478
    .line 479
    move-result v3

    .line 480
    if-eqz v3, :cond_1f

    .line 481
    .line 482
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 483
    .line 484
    iget-object v8, v2, Lin/s0;->o:Ljava/util/ArrayList;

    .line 485
    .line 486
    iput-object v8, v3, Lin/s0;->o:Ljava/util/ArrayList;

    .line 487
    .line 488
    :cond_1f
    const-wide/32 v8, 0x8000

    .line 489
    .line 490
    .line 491
    invoke-static {v2, v8, v9}, Lin/z1;->J(Lin/s0;J)Z

    .line 492
    .line 493
    .line 494
    move-result v3

    .line 495
    if-eqz v3, :cond_22

    .line 496
    .line 497
    iget-object v3, v2, Lin/s0;->q:Ljava/lang/Integer;

    .line 498
    .line 499
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 500
    .line 501
    .line 502
    move-result v3

    .line 503
    const/4 v8, -0x1

    .line 504
    const/16 v9, 0x64

    .line 505
    .line 506
    if-ne v3, v8, :cond_20

    .line 507
    .line 508
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 509
    .line 510
    iget-object v3, v3, Lin/s0;->q:Ljava/lang/Integer;

    .line 511
    .line 512
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 513
    .line 514
    .line 515
    move-result v3

    .line 516
    if-le v3, v9, :cond_20

    .line 517
    .line 518
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 519
    .line 520
    iget-object v8, v3, Lin/s0;->q:Ljava/lang/Integer;

    .line 521
    .line 522
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 523
    .line 524
    .line 525
    move-result v8

    .line 526
    sub-int/2addr v8, v9

    .line 527
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 528
    .line 529
    .line 530
    move-result-object v8

    .line 531
    iput-object v8, v3, Lin/s0;->q:Ljava/lang/Integer;

    .line 532
    .line 533
    goto :goto_7

    .line 534
    :cond_20
    iget-object v3, v2, Lin/s0;->q:Ljava/lang/Integer;

    .line 535
    .line 536
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 537
    .line 538
    .line 539
    move-result v3

    .line 540
    if-ne v3, v6, :cond_21

    .line 541
    .line 542
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 543
    .line 544
    iget-object v3, v3, Lin/s0;->q:Ljava/lang/Integer;

    .line 545
    .line 546
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 547
    .line 548
    .line 549
    move-result v3

    .line 550
    const/16 v8, 0x384

    .line 551
    .line 552
    if-ge v3, v8, :cond_21

    .line 553
    .line 554
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 555
    .line 556
    iget-object v8, v3, Lin/s0;->q:Ljava/lang/Integer;

    .line 557
    .line 558
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 559
    .line 560
    .line 561
    move-result v8

    .line 562
    add-int/2addr v8, v9

    .line 563
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 564
    .line 565
    .line 566
    move-result-object v8

    .line 567
    iput-object v8, v3, Lin/s0;->q:Ljava/lang/Integer;

    .line 568
    .line 569
    goto :goto_7

    .line 570
    :cond_21
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 571
    .line 572
    iget-object v8, v2, Lin/s0;->q:Ljava/lang/Integer;

    .line 573
    .line 574
    iput-object v8, v3, Lin/s0;->q:Ljava/lang/Integer;

    .line 575
    .line 576
    :cond_22
    :goto_7
    const-wide/32 v8, 0x10000

    .line 577
    .line 578
    .line 579
    invoke-static {v2, v8, v9}, Lin/z1;->J(Lin/s0;J)Z

    .line 580
    .line 581
    .line 582
    move-result v3

    .line 583
    if-eqz v3, :cond_23

    .line 584
    .line 585
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 586
    .line 587
    iget v8, v2, Lin/s0;->J:I

    .line 588
    .line 589
    iput v8, v3, Lin/s0;->J:I

    .line 590
    .line 591
    :cond_23
    const-wide/32 v8, 0x1a000

    .line 592
    .line 593
    .line 594
    invoke-static {v2, v8, v9}, Lin/z1;->J(Lin/s0;J)Z

    .line 595
    .line 596
    .line 597
    move-result v3

    .line 598
    if-eqz v3, :cond_27

    .line 599
    .line 600
    iget-object v3, v1, Lin/x1;->a:Lin/s0;

    .line 601
    .line 602
    iget-object v8, v3, Lin/s0;->o:Ljava/util/ArrayList;

    .line 603
    .line 604
    if-eqz v8, :cond_25

    .line 605
    .line 606
    iget-object v0, v0, Lin/z1;->b:Ljava/lang/Object;

    .line 607
    .line 608
    check-cast v0, Lil/g;

    .line 609
    .line 610
    if-eqz v0, :cond_25

    .line 611
    .line 612
    invoke-interface {v8}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 613
    .line 614
    .line 615
    move-result-object v0

    .line 616
    :cond_24
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 617
    .line 618
    .line 619
    move-result v8

    .line 620
    if-eqz v8, :cond_25

    .line 621
    .line 622
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 623
    .line 624
    .line 625
    move-result-object v7

    .line 626
    check-cast v7, Ljava/lang/String;

    .line 627
    .line 628
    iget-object v8, v3, Lin/s0;->q:Ljava/lang/Integer;

    .line 629
    .line 630
    iget v9, v3, Lin/s0;->J:I

    .line 631
    .line 632
    invoke-static {v7, v8, v9}, Lin/z1;->p(Ljava/lang/String;Ljava/lang/Integer;I)Landroid/graphics/Typeface;

    .line 633
    .line 634
    .line 635
    move-result-object v7

    .line 636
    if-eqz v7, :cond_24

    .line 637
    .line 638
    :cond_25
    if-nez v7, :cond_26

    .line 639
    .line 640
    iget-object v0, v3, Lin/s0;->q:Ljava/lang/Integer;

    .line 641
    .line 642
    iget v3, v3, Lin/s0;->J:I

    .line 643
    .line 644
    const-string v7, "serif"

    .line 645
    .line 646
    invoke-static {v7, v0, v3}, Lin/z1;->p(Ljava/lang/String;Ljava/lang/Integer;I)Landroid/graphics/Typeface;

    .line 647
    .line 648
    .line 649
    move-result-object v7

    .line 650
    :cond_26
    iget-object v0, v1, Lin/x1;->d:Landroid/graphics/Paint;

    .line 651
    .line 652
    invoke-virtual {v0, v7}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 653
    .line 654
    .line 655
    iget-object v0, v1, Lin/x1;->e:Landroid/graphics/Paint;

    .line 656
    .line 657
    invoke-virtual {v0, v7}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 658
    .line 659
    .line 660
    :cond_27
    const-wide/32 v7, 0x20000

    .line 661
    .line 662
    .line 663
    invoke-static {v2, v7, v8}, Lin/z1;->J(Lin/s0;J)Z

    .line 664
    .line 665
    .line 666
    move-result v0

    .line 667
    if-eqz v0, :cond_2c

    .line 668
    .line 669
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 670
    .line 671
    iget-object v3, v1, Lin/x1;->e:Landroid/graphics/Paint;

    .line 672
    .line 673
    iget-object v7, v1, Lin/x1;->d:Landroid/graphics/Paint;

    .line 674
    .line 675
    iget v8, v2, Lin/s0;->K:I

    .line 676
    .line 677
    iput v8, v0, Lin/s0;->K:I

    .line 678
    .line 679
    iget v0, v2, Lin/s0;->K:I

    .line 680
    .line 681
    const/4 v8, 0x4

    .line 682
    if-ne v0, v8, :cond_28

    .line 683
    .line 684
    move v0, v6

    .line 685
    goto :goto_8

    .line 686
    :cond_28
    move v0, v5

    .line 687
    :goto_8
    invoke-virtual {v7, v0}, Landroid/graphics/Paint;->setStrikeThruText(Z)V

    .line 688
    .line 689
    .line 690
    iget v0, v2, Lin/s0;->K:I

    .line 691
    .line 692
    if-ne v0, v4, :cond_29

    .line 693
    .line 694
    move v0, v6

    .line 695
    goto :goto_9

    .line 696
    :cond_29
    move v0, v5

    .line 697
    :goto_9
    invoke-virtual {v7, v0}, Landroid/graphics/Paint;->setUnderlineText(Z)V

    .line 698
    .line 699
    .line 700
    iget v0, v2, Lin/s0;->K:I

    .line 701
    .line 702
    if-ne v0, v8, :cond_2a

    .line 703
    .line 704
    move v0, v6

    .line 705
    goto :goto_a

    .line 706
    :cond_2a
    move v0, v5

    .line 707
    :goto_a
    invoke-virtual {v3, v0}, Landroid/graphics/Paint;->setStrikeThruText(Z)V

    .line 708
    .line 709
    .line 710
    iget v0, v2, Lin/s0;->K:I

    .line 711
    .line 712
    if-ne v0, v4, :cond_2b

    .line 713
    .line 714
    move v5, v6

    .line 715
    :cond_2b
    invoke-virtual {v3, v5}, Landroid/graphics/Paint;->setUnderlineText(Z)V

    .line 716
    .line 717
    .line 718
    :cond_2c
    const-wide v3, 0x1000000000L

    .line 719
    .line 720
    .line 721
    .line 722
    .line 723
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 724
    .line 725
    .line 726
    move-result v0

    .line 727
    if-eqz v0, :cond_2d

    .line 728
    .line 729
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 730
    .line 731
    iget v3, v2, Lin/s0;->L:I

    .line 732
    .line 733
    iput v3, v0, Lin/s0;->L:I

    .line 734
    .line 735
    :cond_2d
    const-wide/32 v3, 0x40000

    .line 736
    .line 737
    .line 738
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 739
    .line 740
    .line 741
    move-result v0

    .line 742
    if-eqz v0, :cond_2e

    .line 743
    .line 744
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 745
    .line 746
    iget v3, v2, Lin/s0;->M:I

    .line 747
    .line 748
    iput v3, v0, Lin/s0;->M:I

    .line 749
    .line 750
    :cond_2e
    const-wide/32 v3, 0x80000

    .line 751
    .line 752
    .line 753
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 754
    .line 755
    .line 756
    move-result v0

    .line 757
    if-eqz v0, :cond_2f

    .line 758
    .line 759
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 760
    .line 761
    iget-object v3, v2, Lin/s0;->r:Ljava/lang/Boolean;

    .line 762
    .line 763
    iput-object v3, v0, Lin/s0;->r:Ljava/lang/Boolean;

    .line 764
    .line 765
    :cond_2f
    const-wide/32 v3, 0x200000

    .line 766
    .line 767
    .line 768
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 769
    .line 770
    .line 771
    move-result v0

    .line 772
    if-eqz v0, :cond_30

    .line 773
    .line 774
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 775
    .line 776
    iget-object v3, v2, Lin/s0;->t:Ljava/lang/String;

    .line 777
    .line 778
    iput-object v3, v0, Lin/s0;->t:Ljava/lang/String;

    .line 779
    .line 780
    :cond_30
    const-wide/32 v3, 0x400000

    .line 781
    .line 782
    .line 783
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 784
    .line 785
    .line 786
    move-result v0

    .line 787
    if-eqz v0, :cond_31

    .line 788
    .line 789
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 790
    .line 791
    iget-object v3, v2, Lin/s0;->u:Ljava/lang/String;

    .line 792
    .line 793
    iput-object v3, v0, Lin/s0;->u:Ljava/lang/String;

    .line 794
    .line 795
    :cond_31
    const-wide/32 v3, 0x800000

    .line 796
    .line 797
    .line 798
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 799
    .line 800
    .line 801
    move-result v0

    .line 802
    if-eqz v0, :cond_32

    .line 803
    .line 804
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 805
    .line 806
    iget-object v3, v2, Lin/s0;->v:Ljava/lang/String;

    .line 807
    .line 808
    iput-object v3, v0, Lin/s0;->v:Ljava/lang/String;

    .line 809
    .line 810
    :cond_32
    const-wide/32 v3, 0x1000000

    .line 811
    .line 812
    .line 813
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 814
    .line 815
    .line 816
    move-result v0

    .line 817
    if-eqz v0, :cond_33

    .line 818
    .line 819
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 820
    .line 821
    iget-object v3, v2, Lin/s0;->w:Ljava/lang/Boolean;

    .line 822
    .line 823
    iput-object v3, v0, Lin/s0;->w:Ljava/lang/Boolean;

    .line 824
    .line 825
    :cond_33
    const-wide/32 v3, 0x2000000

    .line 826
    .line 827
    .line 828
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 829
    .line 830
    .line 831
    move-result v0

    .line 832
    if-eqz v0, :cond_34

    .line 833
    .line 834
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 835
    .line 836
    iget-object v3, v2, Lin/s0;->x:Ljava/lang/Boolean;

    .line 837
    .line 838
    iput-object v3, v0, Lin/s0;->x:Ljava/lang/Boolean;

    .line 839
    .line 840
    :cond_34
    const-wide/32 v3, 0x100000

    .line 841
    .line 842
    .line 843
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 844
    .line 845
    .line 846
    move-result v0

    .line 847
    if-eqz v0, :cond_35

    .line 848
    .line 849
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 850
    .line 851
    iget-object v3, v2, Lin/s0;->s:Lcom/google/firebase/messaging/w;

    .line 852
    .line 853
    iput-object v3, v0, Lin/s0;->s:Lcom/google/firebase/messaging/w;

    .line 854
    .line 855
    :cond_35
    const-wide/32 v3, 0x10000000

    .line 856
    .line 857
    .line 858
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 859
    .line 860
    .line 861
    move-result v0

    .line 862
    if-eqz v0, :cond_36

    .line 863
    .line 864
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 865
    .line 866
    iget-object v3, v2, Lin/s0;->A:Ljava/lang/String;

    .line 867
    .line 868
    iput-object v3, v0, Lin/s0;->A:Ljava/lang/String;

    .line 869
    .line 870
    :cond_36
    const-wide/32 v3, 0x20000000

    .line 871
    .line 872
    .line 873
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 874
    .line 875
    .line 876
    move-result v0

    .line 877
    if-eqz v0, :cond_37

    .line 878
    .line 879
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 880
    .line 881
    iget v3, v2, Lin/s0;->N:I

    .line 882
    .line 883
    iput v3, v0, Lin/s0;->N:I

    .line 884
    .line 885
    :cond_37
    const-wide/32 v3, 0x40000000

    .line 886
    .line 887
    .line 888
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 889
    .line 890
    .line 891
    move-result v0

    .line 892
    if-eqz v0, :cond_38

    .line 893
    .line 894
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 895
    .line 896
    iget-object v3, v2, Lin/s0;->B:Ljava/lang/String;

    .line 897
    .line 898
    iput-object v3, v0, Lin/s0;->B:Ljava/lang/String;

    .line 899
    .line 900
    :cond_38
    const-wide/32 v3, 0x4000000

    .line 901
    .line 902
    .line 903
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 904
    .line 905
    .line 906
    move-result v0

    .line 907
    if-eqz v0, :cond_39

    .line 908
    .line 909
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 910
    .line 911
    iget-object v3, v2, Lin/s0;->y:Lin/b1;

    .line 912
    .line 913
    iput-object v3, v0, Lin/s0;->y:Lin/b1;

    .line 914
    .line 915
    :cond_39
    const-wide/32 v3, 0x8000000

    .line 916
    .line 917
    .line 918
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 919
    .line 920
    .line 921
    move-result v0

    .line 922
    if-eqz v0, :cond_3a

    .line 923
    .line 924
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 925
    .line 926
    iget-object v3, v2, Lin/s0;->z:Ljava/lang/Float;

    .line 927
    .line 928
    iput-object v3, v0, Lin/s0;->z:Ljava/lang/Float;

    .line 929
    .line 930
    :cond_3a
    const-wide v3, 0x200000000L

    .line 931
    .line 932
    .line 933
    .line 934
    .line 935
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 936
    .line 937
    .line 938
    move-result v0

    .line 939
    if-eqz v0, :cond_3b

    .line 940
    .line 941
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 942
    .line 943
    iget-object v3, v2, Lin/s0;->E:Lin/b1;

    .line 944
    .line 945
    iput-object v3, v0, Lin/s0;->E:Lin/b1;

    .line 946
    .line 947
    :cond_3b
    const-wide v3, 0x400000000L

    .line 948
    .line 949
    .line 950
    .line 951
    .line 952
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 953
    .line 954
    .line 955
    move-result v0

    .line 956
    if-eqz v0, :cond_3c

    .line 957
    .line 958
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 959
    .line 960
    iget-object v3, v2, Lin/s0;->F:Ljava/lang/Float;

    .line 961
    .line 962
    iput-object v3, v0, Lin/s0;->F:Ljava/lang/Float;

    .line 963
    .line 964
    :cond_3c
    const-wide v3, 0x2000000000L

    .line 965
    .line 966
    .line 967
    .line 968
    .line 969
    invoke-static {v2, v3, v4}, Lin/z1;->J(Lin/s0;J)Z

    .line 970
    .line 971
    .line 972
    move-result v0

    .line 973
    if-eqz v0, :cond_3d

    .line 974
    .line 975
    iget-object v0, v1, Lin/x1;->a:Lin/s0;

    .line 976
    .line 977
    iget v1, v2, Lin/s0;->P:I

    .line 978
    .line 979
    iput v1, v0, Lin/s0;->P:I

    .line 980
    .line 981
    :cond_3d
    return-void
.end method

.method public k0(Lin/x1;Lin/y0;)V
    .locals 5

    .line 1
    iget-object v0, p2, Lin/a1;->b:Lin/w0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    :goto_0
    iget-object v2, p1, Lin/x1;->a:Lin/s0;

    .line 10
    .line 11
    const/high16 v3, 0x3f800000    # 1.0f

    .line 12
    .line 13
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 18
    .line 19
    iput-object v4, v2, Lin/s0;->w:Ljava/lang/Boolean;

    .line 20
    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_1
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 25
    .line 26
    :goto_1
    iput-object v4, v2, Lin/s0;->r:Ljava/lang/Boolean;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    iput-object v0, v2, Lin/s0;->s:Lcom/google/firebase/messaging/w;

    .line 30
    .line 31
    iput-object v0, v2, Lin/s0;->A:Ljava/lang/String;

    .line 32
    .line 33
    iput-object v3, v2, Lin/s0;->m:Ljava/lang/Float;

    .line 34
    .line 35
    sget-object v4, Lin/v;->e:Lin/v;

    .line 36
    .line 37
    iput-object v4, v2, Lin/s0;->y:Lin/b1;

    .line 38
    .line 39
    iput-object v3, v2, Lin/s0;->z:Ljava/lang/Float;

    .line 40
    .line 41
    iput-object v0, v2, Lin/s0;->B:Ljava/lang/String;

    .line 42
    .line 43
    iput-object v0, v2, Lin/s0;->C:Lin/b1;

    .line 44
    .line 45
    iput-object v3, v2, Lin/s0;->D:Ljava/lang/Float;

    .line 46
    .line 47
    iput-object v0, v2, Lin/s0;->E:Lin/b1;

    .line 48
    .line 49
    iput-object v3, v2, Lin/s0;->F:Ljava/lang/Float;

    .line 50
    .line 51
    iput v1, v2, Lin/s0;->O:I

    .line 52
    .line 53
    iget-object v0, p2, Lin/y0;->e:Lin/s0;

    .line 54
    .line 55
    if-eqz v0, :cond_2

    .line 56
    .line 57
    invoke-virtual {p0, p1, v0}, Lin/z1;->j0(Lin/x1;Lin/s0;)V

    .line 58
    .line 59
    .line 60
    :cond_2
    iget-object v0, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v0, Lil/g;

    .line 63
    .line 64
    iget-object v0, v0, Lil/g;->f:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v0, Ld01/x;

    .line 67
    .line 68
    iget-object v0, v0, Ld01/x;->b:Ljava/util/ArrayList;

    .line 69
    .line 70
    if-eqz v0, :cond_5

    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    if-eqz v0, :cond_3

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_3
    iget-object v0, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v0, Lil/g;

    .line 82
    .line 83
    iget-object v0, v0, Lil/g;->f:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v0, Ld01/x;

    .line 86
    .line 87
    iget-object v0, v0, Ld01/x;->b:Ljava/util/ArrayList;

    .line 88
    .line 89
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    :cond_4
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    if-eqz v1, :cond_5

    .line 98
    .line 99
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    check-cast v1, Lin/l;

    .line 104
    .line 105
    iget-object v2, v1, Lin/l;->a:Lin/m;

    .line 106
    .line 107
    invoke-static {v2, p2}, Lin/o;->n(Lin/m;Lin/y0;)Z

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    if-eqz v2, :cond_4

    .line 112
    .line 113
    iget-object v1, v1, Lin/l;->b:Lin/s0;

    .line 114
    .line 115
    invoke-virtual {p0, p1, v1}, Lin/z1;->j0(Lin/x1;Lin/s0;)V

    .line 116
    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_5
    :goto_3
    iget-object p2, p2, Lin/y0;->f:Lin/s0;

    .line 120
    .line 121
    if-eqz p2, :cond_6

    .line 122
    .line 123
    invoke-virtual {p0, p1, p2}, Lin/z1;->j0(Lin/x1;Lin/s0;)V

    .line 124
    .line 125
    .line 126
    :cond_6
    return-void
.end method

.method public l(Lin/l1;)F
    .locals 1

    .line 1
    new-instance v0, Lin/y1;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lin/y1;-><init>(Lin/z1;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, v0}, Lin/z1;->v(Lin/l1;Llp/pa;)V

    .line 7
    .line 8
    .line 9
    iget p0, v0, Lin/y1;->a:F

    .line 10
    .line 11
    return p0
.end method

.method public l0()V
    .locals 3

    .line 1
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lin/x1;

    .line 4
    .line 5
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 6
    .line 7
    iget-object v1, v0, Lin/s0;->E:Lin/b1;

    .line 8
    .line 9
    instance-of v2, v1, Lin/v;

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    check-cast v1, Lin/v;

    .line 14
    .line 15
    iget v1, v1, Lin/v;->d:I

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    instance-of v1, v1, Lin/w;

    .line 19
    .line 20
    if-eqz v1, :cond_2

    .line 21
    .line 22
    iget-object v1, v0, Lin/s0;->n:Lin/v;

    .line 23
    .line 24
    iget v1, v1, Lin/v;->d:I

    .line 25
    .line 26
    :goto_0
    iget-object v0, v0, Lin/s0;->F:Ljava/lang/Float;

    .line 27
    .line 28
    if-eqz v0, :cond_1

    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    invoke-static {v1, v0}, Lin/z1;->q(IF)I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    :cond_1
    iget-object p0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Landroid/graphics/Canvas;

    .line 41
    .line 42
    invoke-virtual {p0, v1}, Landroid/graphics/Canvas;->drawColor(I)V

    .line 43
    .line 44
    .line 45
    :cond_2
    return-void
.end method

.method public m0()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lin/x1;

    .line 4
    .line 5
    iget-object p0, p0, Lin/x1;->a:Lin/s0;

    .line 6
    .line 7
    iget-object p0, p0, Lin/s0;->x:Ljava/lang/Boolean;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public n(Lin/x0;Ld3/a;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lin/x1;

    .line 4
    .line 5
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 6
    .line 7
    iget-object v0, v0, Lin/s0;->A:Ljava/lang/String;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {p0, p1, p2}, Lin/z1;->j(Lin/x0;Ld3/a;)Landroid/graphics/Path;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    if-eqz p1, :cond_1

    .line 17
    .line 18
    iget-object p0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Landroid/graphics/Canvas;

    .line 21
    .line 22
    invoke-virtual {p0, p1}, Landroid/graphics/Canvas;->clipPath(Landroid/graphics/Path;)Z

    .line 23
    .line 24
    .line 25
    :cond_1
    :goto_0
    return-void
.end method

.method public o(Lin/x0;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lin/x1;

    .line 4
    .line 5
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 6
    .line 7
    iget-object v0, v0, Lin/s0;->e:Lin/b1;

    .line 8
    .line 9
    instance-of v1, v0, Lin/j0;

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    iget-object v1, p1, Lin/x0;->h:Ld3/a;

    .line 14
    .line 15
    check-cast v0, Lin/j0;

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    invoke-virtual {p0, v2, v1, v0}, Lin/z1;->r(ZLd3/a;Lin/j0;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    iget-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v0, Lin/x1;

    .line 24
    .line 25
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 26
    .line 27
    iget-object v0, v0, Lin/s0;->g:Lin/b1;

    .line 28
    .line 29
    instance-of v1, v0, Lin/j0;

    .line 30
    .line 31
    if-eqz v1, :cond_1

    .line 32
    .line 33
    iget-object p1, p1, Lin/x0;->h:Ld3/a;

    .line 34
    .line 35
    check-cast v0, Lin/j0;

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    invoke-virtual {p0, v1, p1, v0}, Lin/z1;->r(ZLd3/a;Lin/j0;)V

    .line 39
    .line 40
    .line 41
    :cond_1
    return-void
.end method

.method public r(ZLd3/a;Lin/j0;)V
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    iget-object v4, v0, Lin/z1;->b:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v4, Lil/g;

    .line 12
    .line 13
    iget-object v5, v3, Lin/j0;->d:Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {v4, v5}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    const/4 v5, 0x0

    .line 20
    if-nez v4, :cond_3

    .line 21
    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    const-string v2, "Fill"

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const-string v2, "Stroke"

    .line 28
    .line 29
    :goto_0
    iget-object v4, v3, Lin/j0;->d:Ljava/lang/String;

    .line 30
    .line 31
    filled-new-array {v2, v4}, [Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    const-string v4, "%s reference \'%s\' not found"

    .line 36
    .line 37
    invoke-static {v4, v2}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    iget-object v2, v3, Lin/j0;->e:Lin/b1;

    .line 41
    .line 42
    if-eqz v2, :cond_1

    .line 43
    .line 44
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v0, Lin/x1;

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, Lin/z1;->c0(Lin/x1;ZLin/b1;)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :cond_1
    if-eqz v1, :cond_2

    .line 53
    .line 54
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v0, Lin/x1;

    .line 57
    .line 58
    iput-boolean v5, v0, Lin/x1;->b:Z

    .line 59
    .line 60
    return-void

    .line 61
    :cond_2
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v0, Lin/x1;

    .line 64
    .line 65
    iput-boolean v5, v0, Lin/x1;->c:Z

    .line 66
    .line 67
    return-void

    .line 68
    :cond_3
    instance-of v3, v4, Lin/z0;

    .line 69
    .line 70
    const/4 v8, 0x3

    .line 71
    const/4 v9, 0x2

    .line 72
    sget-object v10, Lin/v;->e:Lin/v;

    .line 73
    .line 74
    const/high16 v13, 0x3f800000    # 1.0f

    .line 75
    .line 76
    const/4 v14, 0x1

    .line 77
    if-eqz v3, :cond_21

    .line 78
    .line 79
    check-cast v4, Lin/z0;

    .line 80
    .line 81
    iget-object v3, v4, Lin/z;->l:Ljava/lang/String;

    .line 82
    .line 83
    if-eqz v3, :cond_4

    .line 84
    .line 85
    invoke-static {v4, v3}, Lin/z1;->z(Lin/z;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    :cond_4
    iget-object v3, v4, Lin/z;->i:Ljava/lang/Boolean;

    .line 89
    .line 90
    if-eqz v3, :cond_5

    .line 91
    .line 92
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    if-eqz v3, :cond_5

    .line 97
    .line 98
    move v3, v14

    .line 99
    goto :goto_1

    .line 100
    :cond_5
    move v3, v5

    .line 101
    :goto_1
    iget-object v15, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast v15, Lin/x1;

    .line 104
    .line 105
    if-eqz v1, :cond_6

    .line 106
    .line 107
    iget-object v15, v15, Lin/x1;->d:Landroid/graphics/Paint;

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_6
    iget-object v15, v15, Lin/x1;->e:Landroid/graphics/Paint;

    .line 111
    .line 112
    :goto_2
    if-eqz v3, :cond_c

    .line 113
    .line 114
    iget-object v13, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast v13, Lin/x1;

    .line 117
    .line 118
    const/high16 p3, 0x43800000    # 256.0f

    .line 119
    .line 120
    iget-object v6, v13, Lin/x1;->g:Ld3/a;

    .line 121
    .line 122
    if-eqz v6, :cond_7

    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_7
    iget-object v6, v13, Lin/x1;->f:Ld3/a;

    .line 126
    .line 127
    :goto_3
    iget-object v13, v4, Lin/z0;->m:Lin/e0;

    .line 128
    .line 129
    if-eqz v13, :cond_8

    .line 130
    .line 131
    invoke-virtual {v13, v0}, Lin/e0;->d(Lin/z1;)F

    .line 132
    .line 133
    .line 134
    move-result v13

    .line 135
    goto :goto_4

    .line 136
    :cond_8
    const/4 v13, 0x0

    .line 137
    :goto_4
    iget-object v11, v4, Lin/z0;->n:Lin/e0;

    .line 138
    .line 139
    if-eqz v11, :cond_9

    .line 140
    .line 141
    invoke-virtual {v11, v0}, Lin/e0;->e(Lin/z1;)F

    .line 142
    .line 143
    .line 144
    move-result v11

    .line 145
    :goto_5
    const/16 v17, 0x0

    .line 146
    .line 147
    goto :goto_6

    .line 148
    :cond_9
    const/4 v11, 0x0

    .line 149
    goto :goto_5

    .line 150
    :goto_6
    iget-object v12, v4, Lin/z0;->o:Lin/e0;

    .line 151
    .line 152
    if-eqz v12, :cond_a

    .line 153
    .line 154
    invoke-virtual {v12, v0}, Lin/e0;->d(Lin/z1;)F

    .line 155
    .line 156
    .line 157
    move-result v6

    .line 158
    goto :goto_7

    .line 159
    :cond_a
    iget v6, v6, Ld3/a;->d:F

    .line 160
    .line 161
    :goto_7
    iget-object v12, v4, Lin/z0;->p:Lin/e0;

    .line 162
    .line 163
    if-eqz v12, :cond_b

    .line 164
    .line 165
    invoke-virtual {v12, v0}, Lin/e0;->e(Lin/z1;)F

    .line 166
    .line 167
    .line 168
    move-result v12

    .line 169
    goto :goto_8

    .line 170
    :cond_b
    move/from16 v12, v17

    .line 171
    .line 172
    :goto_8
    move/from16 v21, v6

    .line 173
    .line 174
    move/from16 v22, v12

    .line 175
    .line 176
    move/from16 v19, v13

    .line 177
    .line 178
    :goto_9
    move/from16 v20, v11

    .line 179
    .line 180
    goto :goto_e

    .line 181
    :cond_c
    const/high16 p3, 0x43800000    # 256.0f

    .line 182
    .line 183
    const/16 v17, 0x0

    .line 184
    .line 185
    iget-object v6, v4, Lin/z0;->m:Lin/e0;

    .line 186
    .line 187
    if-eqz v6, :cond_d

    .line 188
    .line 189
    invoke-virtual {v6, v0, v13}, Lin/e0;->b(Lin/z1;F)F

    .line 190
    .line 191
    .line 192
    move-result v6

    .line 193
    goto :goto_a

    .line 194
    :cond_d
    move/from16 v6, v17

    .line 195
    .line 196
    :goto_a
    iget-object v11, v4, Lin/z0;->n:Lin/e0;

    .line 197
    .line 198
    if-eqz v11, :cond_e

    .line 199
    .line 200
    invoke-virtual {v11, v0, v13}, Lin/e0;->b(Lin/z1;F)F

    .line 201
    .line 202
    .line 203
    move-result v11

    .line 204
    goto :goto_b

    .line 205
    :cond_e
    move/from16 v11, v17

    .line 206
    .line 207
    :goto_b
    iget-object v12, v4, Lin/z0;->o:Lin/e0;

    .line 208
    .line 209
    if-eqz v12, :cond_f

    .line 210
    .line 211
    invoke-virtual {v12, v0, v13}, Lin/e0;->b(Lin/z1;F)F

    .line 212
    .line 213
    .line 214
    move-result v12

    .line 215
    goto :goto_c

    .line 216
    :cond_f
    move v12, v13

    .line 217
    :goto_c
    iget-object v7, v4, Lin/z0;->p:Lin/e0;

    .line 218
    .line 219
    if-eqz v7, :cond_10

    .line 220
    .line 221
    invoke-virtual {v7, v0, v13}, Lin/e0;->b(Lin/z1;F)F

    .line 222
    .line 223
    .line 224
    move-result v7

    .line 225
    goto :goto_d

    .line 226
    :cond_10
    move/from16 v7, v17

    .line 227
    .line 228
    :goto_d
    move/from16 v19, v6

    .line 229
    .line 230
    move/from16 v22, v7

    .line 231
    .line 232
    move/from16 v21, v12

    .line 233
    .line 234
    goto :goto_9

    .line 235
    :goto_e
    invoke-virtual {v0}, Lin/z1;->f0()V

    .line 236
    .line 237
    .line 238
    invoke-virtual {v0, v4}, Lin/z1;->D(Lin/y0;)Lin/x1;

    .line 239
    .line 240
    .line 241
    move-result-object v6

    .line 242
    iput-object v6, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 243
    .line 244
    new-instance v6, Landroid/graphics/Matrix;

    .line 245
    .line 246
    invoke-direct {v6}, Landroid/graphics/Matrix;-><init>()V

    .line 247
    .line 248
    .line 249
    if-nez v3, :cond_11

    .line 250
    .line 251
    iget v3, v2, Ld3/a;->b:F

    .line 252
    .line 253
    iget v7, v2, Ld3/a;->c:F

    .line 254
    .line 255
    invoke-virtual {v6, v3, v7}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 256
    .line 257
    .line 258
    iget v3, v2, Ld3/a;->d:F

    .line 259
    .line 260
    iget v2, v2, Ld3/a;->e:F

    .line 261
    .line 262
    invoke-virtual {v6, v3, v2}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 263
    .line 264
    .line 265
    :cond_11
    iget-object v2, v4, Lin/z;->j:Landroid/graphics/Matrix;

    .line 266
    .line 267
    if-eqz v2, :cond_12

    .line 268
    .line 269
    invoke-virtual {v6, v2}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 270
    .line 271
    .line 272
    :cond_12
    iget-object v2, v4, Lin/z;->h:Ljava/util/List;

    .line 273
    .line 274
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 275
    .line 276
    .line 277
    move-result v2

    .line 278
    if-nez v2, :cond_14

    .line 279
    .line 280
    invoke-virtual {v0}, Lin/z1;->e0()V

    .line 281
    .line 282
    .line 283
    if-eqz v1, :cond_13

    .line 284
    .line 285
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 286
    .line 287
    check-cast v0, Lin/x1;

    .line 288
    .line 289
    iput-boolean v5, v0, Lin/x1;->b:Z

    .line 290
    .line 291
    return-void

    .line 292
    :cond_13
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 293
    .line 294
    check-cast v0, Lin/x1;

    .line 295
    .line 296
    iput-boolean v5, v0, Lin/x1;->c:Z

    .line 297
    .line 298
    return-void

    .line 299
    :cond_14
    new-array v1, v2, [I

    .line 300
    .line 301
    new-array v3, v2, [F

    .line 302
    .line 303
    iget-object v7, v4, Lin/z;->h:Ljava/util/List;

    .line 304
    .line 305
    invoke-interface {v7}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 306
    .line 307
    .line 308
    move-result-object v7

    .line 309
    move v12, v5

    .line 310
    const/high16 v11, -0x40800000    # -1.0f

    .line 311
    .line 312
    :goto_f
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 313
    .line 314
    .line 315
    move-result v13

    .line 316
    if-eqz v13, :cond_19

    .line 317
    .line 318
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    move-result-object v13

    .line 322
    check-cast v13, Lin/a1;

    .line 323
    .line 324
    check-cast v13, Lin/r0;

    .line 325
    .line 326
    iget-object v5, v13, Lin/r0;->h:Ljava/lang/Float;

    .line 327
    .line 328
    if-eqz v5, :cond_15

    .line 329
    .line 330
    invoke-virtual {v5}, Ljava/lang/Float;->floatValue()F

    .line 331
    .line 332
    .line 333
    move-result v5

    .line 334
    goto :goto_10

    .line 335
    :cond_15
    move/from16 v5, v17

    .line 336
    .line 337
    :goto_10
    if-eqz v12, :cond_17

    .line 338
    .line 339
    cmpl-float v16, v5, v11

    .line 340
    .line 341
    if-ltz v16, :cond_16

    .line 342
    .line 343
    goto :goto_11

    .line 344
    :cond_16
    aput v11, v3, v12

    .line 345
    .line 346
    goto :goto_12

    .line 347
    :cond_17
    :goto_11
    aput v5, v3, v12

    .line 348
    .line 349
    move v11, v5

    .line 350
    :goto_12
    invoke-virtual {v0}, Lin/z1;->f0()V

    .line 351
    .line 352
    .line 353
    iget-object v5, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 354
    .line 355
    check-cast v5, Lin/x1;

    .line 356
    .line 357
    invoke-virtual {v0, v5, v13}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 358
    .line 359
    .line 360
    iget-object v5, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 361
    .line 362
    check-cast v5, Lin/x1;

    .line 363
    .line 364
    iget-object v5, v5, Lin/x1;->a:Lin/s0;

    .line 365
    .line 366
    iget-object v13, v5, Lin/s0;->y:Lin/b1;

    .line 367
    .line 368
    check-cast v13, Lin/v;

    .line 369
    .line 370
    if-nez v13, :cond_18

    .line 371
    .line 372
    move-object v13, v10

    .line 373
    :cond_18
    iget v13, v13, Lin/v;->d:I

    .line 374
    .line 375
    iget-object v5, v5, Lin/s0;->z:Ljava/lang/Float;

    .line 376
    .line 377
    invoke-virtual {v5}, Ljava/lang/Float;->floatValue()F

    .line 378
    .line 379
    .line 380
    move-result v5

    .line 381
    invoke-static {v13, v5}, Lin/z1;->q(IF)I

    .line 382
    .line 383
    .line 384
    move-result v5

    .line 385
    aput v5, v1, v12

    .line 386
    .line 387
    add-int/lit8 v12, v12, 0x1

    .line 388
    .line 389
    invoke-virtual {v0}, Lin/z1;->e0()V

    .line 390
    .line 391
    .line 392
    const/4 v5, 0x0

    .line 393
    goto :goto_f

    .line 394
    :cond_19
    cmpl-float v5, v19, v21

    .line 395
    .line 396
    if-nez v5, :cond_1a

    .line 397
    .line 398
    cmpl-float v5, v20, v22

    .line 399
    .line 400
    if-eqz v5, :cond_1b

    .line 401
    .line 402
    :cond_1a
    if-ne v2, v14, :cond_1c

    .line 403
    .line 404
    :cond_1b
    invoke-virtual {v0}, Lin/z1;->e0()V

    .line 405
    .line 406
    .line 407
    sub-int/2addr v2, v14

    .line 408
    aget v0, v1, v2

    .line 409
    .line 410
    invoke-virtual {v15, v0}, Landroid/graphics/Paint;->setColor(I)V

    .line 411
    .line 412
    .line 413
    return-void

    .line 414
    :cond_1c
    sget-object v2, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    .line 415
    .line 416
    iget v4, v4, Lin/z;->k:I

    .line 417
    .line 418
    if-eqz v4, :cond_1d

    .line 419
    .line 420
    if-ne v4, v9, :cond_1e

    .line 421
    .line 422
    sget-object v2, Landroid/graphics/Shader$TileMode;->MIRROR:Landroid/graphics/Shader$TileMode;

    .line 423
    .line 424
    :cond_1d
    :goto_13
    move-object/from16 v25, v2

    .line 425
    .line 426
    goto :goto_14

    .line 427
    :cond_1e
    if-ne v4, v8, :cond_1d

    .line 428
    .line 429
    sget-object v2, Landroid/graphics/Shader$TileMode;->REPEAT:Landroid/graphics/Shader$TileMode;

    .line 430
    .line 431
    goto :goto_13

    .line 432
    :goto_14
    invoke-virtual {v0}, Lin/z1;->e0()V

    .line 433
    .line 434
    .line 435
    new-instance v18, Landroid/graphics/LinearGradient;

    .line 436
    .line 437
    move-object/from16 v23, v1

    .line 438
    .line 439
    move-object/from16 v24, v3

    .line 440
    .line 441
    invoke-direct/range {v18 .. v25}, Landroid/graphics/LinearGradient;-><init>(FFFF[I[FLandroid/graphics/Shader$TileMode;)V

    .line 442
    .line 443
    .line 444
    move-object/from16 v1, v18

    .line 445
    .line 446
    invoke-virtual {v1, v6}, Landroid/graphics/Shader;->setLocalMatrix(Landroid/graphics/Matrix;)V

    .line 447
    .line 448
    .line 449
    invoke-virtual {v15, v1}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 450
    .line 451
    .line 452
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 453
    .line 454
    check-cast v0, Lin/x1;

    .line 455
    .line 456
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 457
    .line 458
    iget-object v0, v0, Lin/s0;->f:Ljava/lang/Float;

    .line 459
    .line 460
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 461
    .line 462
    .line 463
    move-result v0

    .line 464
    mul-float v0, v0, p3

    .line 465
    .line 466
    float-to-int v0, v0

    .line 467
    if-gez v0, :cond_1f

    .line 468
    .line 469
    const/4 v5, 0x0

    .line 470
    goto :goto_15

    .line 471
    :cond_1f
    const/16 v1, 0xff

    .line 472
    .line 473
    if-le v0, v1, :cond_20

    .line 474
    .line 475
    const/16 v5, 0xff

    .line 476
    .line 477
    goto :goto_15

    .line 478
    :cond_20
    move v5, v0

    .line 479
    :goto_15
    invoke-virtual {v15, v5}, Landroid/graphics/Paint;->setAlpha(I)V

    .line 480
    .line 481
    .line 482
    return-void

    .line 483
    :cond_21
    const/high16 p3, 0x43800000    # 256.0f

    .line 484
    .line 485
    const/16 v17, 0x0

    .line 486
    .line 487
    instance-of v3, v4, Lin/d1;

    .line 488
    .line 489
    if-eqz v3, :cond_3b

    .line 490
    .line 491
    check-cast v4, Lin/d1;

    .line 492
    .line 493
    iget-object v3, v4, Lin/z;->l:Ljava/lang/String;

    .line 494
    .line 495
    if-eqz v3, :cond_22

    .line 496
    .line 497
    invoke-static {v4, v3}, Lin/z1;->z(Lin/z;Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    :cond_22
    iget-object v3, v4, Lin/z;->i:Ljava/lang/Boolean;

    .line 501
    .line 502
    if-eqz v3, :cond_23

    .line 503
    .line 504
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 505
    .line 506
    .line 507
    move-result v3

    .line 508
    if-eqz v3, :cond_23

    .line 509
    .line 510
    move v3, v14

    .line 511
    goto :goto_16

    .line 512
    :cond_23
    const/4 v3, 0x0

    .line 513
    :goto_16
    iget-object v5, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 514
    .line 515
    check-cast v5, Lin/x1;

    .line 516
    .line 517
    if-eqz v1, :cond_24

    .line 518
    .line 519
    iget-object v5, v5, Lin/x1;->d:Landroid/graphics/Paint;

    .line 520
    .line 521
    goto :goto_17

    .line 522
    :cond_24
    iget-object v5, v5, Lin/x1;->e:Landroid/graphics/Paint;

    .line 523
    .line 524
    :goto_17
    if-eqz v3, :cond_28

    .line 525
    .line 526
    new-instance v6, Lin/e0;

    .line 527
    .line 528
    const/high16 v7, 0x42480000    # 50.0f

    .line 529
    .line 530
    const/16 v11, 0x9

    .line 531
    .line 532
    invoke-direct {v6, v11, v7}, Lin/e0;-><init>(IF)V

    .line 533
    .line 534
    .line 535
    iget-object v7, v4, Lin/d1;->m:Lin/e0;

    .line 536
    .line 537
    if-eqz v7, :cond_25

    .line 538
    .line 539
    invoke-virtual {v7, v0}, Lin/e0;->d(Lin/z1;)F

    .line 540
    .line 541
    .line 542
    move-result v7

    .line 543
    goto :goto_18

    .line 544
    :cond_25
    invoke-virtual {v6, v0}, Lin/e0;->d(Lin/z1;)F

    .line 545
    .line 546
    .line 547
    move-result v7

    .line 548
    :goto_18
    iget-object v11, v4, Lin/d1;->n:Lin/e0;

    .line 549
    .line 550
    if-eqz v11, :cond_26

    .line 551
    .line 552
    invoke-virtual {v11, v0}, Lin/e0;->e(Lin/z1;)F

    .line 553
    .line 554
    .line 555
    move-result v11

    .line 556
    goto :goto_19

    .line 557
    :cond_26
    invoke-virtual {v6, v0}, Lin/e0;->e(Lin/z1;)F

    .line 558
    .line 559
    .line 560
    move-result v11

    .line 561
    :goto_19
    iget-object v12, v4, Lin/d1;->o:Lin/e0;

    .line 562
    .line 563
    if-eqz v12, :cond_27

    .line 564
    .line 565
    invoke-virtual {v12, v0}, Lin/e0;->a(Lin/z1;)F

    .line 566
    .line 567
    .line 568
    move-result v6

    .line 569
    goto :goto_1a

    .line 570
    :cond_27
    invoke-virtual {v6, v0}, Lin/e0;->a(Lin/z1;)F

    .line 571
    .line 572
    .line 573
    move-result v6

    .line 574
    :goto_1a
    move/from16 v21, v6

    .line 575
    .line 576
    move/from16 v19, v7

    .line 577
    .line 578
    :goto_1b
    move/from16 v20, v11

    .line 579
    .line 580
    goto :goto_1e

    .line 581
    :cond_28
    iget-object v6, v4, Lin/d1;->m:Lin/e0;

    .line 582
    .line 583
    const/high16 v7, 0x3f000000    # 0.5f

    .line 584
    .line 585
    if-eqz v6, :cond_29

    .line 586
    .line 587
    invoke-virtual {v6, v0, v13}, Lin/e0;->b(Lin/z1;F)F

    .line 588
    .line 589
    .line 590
    move-result v6

    .line 591
    goto :goto_1c

    .line 592
    :cond_29
    move v6, v7

    .line 593
    :goto_1c
    iget-object v11, v4, Lin/d1;->n:Lin/e0;

    .line 594
    .line 595
    if-eqz v11, :cond_2a

    .line 596
    .line 597
    invoke-virtual {v11, v0, v13}, Lin/e0;->b(Lin/z1;F)F

    .line 598
    .line 599
    .line 600
    move-result v11

    .line 601
    goto :goto_1d

    .line 602
    :cond_2a
    move v11, v7

    .line 603
    :goto_1d
    iget-object v12, v4, Lin/d1;->o:Lin/e0;

    .line 604
    .line 605
    if-eqz v12, :cond_2b

    .line 606
    .line 607
    invoke-virtual {v12, v0, v13}, Lin/e0;->b(Lin/z1;F)F

    .line 608
    .line 609
    .line 610
    move-result v7

    .line 611
    :cond_2b
    move/from16 v19, v6

    .line 612
    .line 613
    move/from16 v21, v7

    .line 614
    .line 615
    goto :goto_1b

    .line 616
    :goto_1e
    invoke-virtual {v0}, Lin/z1;->f0()V

    .line 617
    .line 618
    .line 619
    invoke-virtual {v0, v4}, Lin/z1;->D(Lin/y0;)Lin/x1;

    .line 620
    .line 621
    .line 622
    move-result-object v6

    .line 623
    iput-object v6, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 624
    .line 625
    new-instance v6, Landroid/graphics/Matrix;

    .line 626
    .line 627
    invoke-direct {v6}, Landroid/graphics/Matrix;-><init>()V

    .line 628
    .line 629
    .line 630
    if-nez v3, :cond_2c

    .line 631
    .line 632
    iget v3, v2, Ld3/a;->b:F

    .line 633
    .line 634
    iget v7, v2, Ld3/a;->c:F

    .line 635
    .line 636
    invoke-virtual {v6, v3, v7}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 637
    .line 638
    .line 639
    iget v3, v2, Ld3/a;->d:F

    .line 640
    .line 641
    iget v2, v2, Ld3/a;->e:F

    .line 642
    .line 643
    invoke-virtual {v6, v3, v2}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 644
    .line 645
    .line 646
    :cond_2c
    iget-object v2, v4, Lin/z;->j:Landroid/graphics/Matrix;

    .line 647
    .line 648
    if-eqz v2, :cond_2d

    .line 649
    .line 650
    invoke-virtual {v6, v2}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 651
    .line 652
    .line 653
    :cond_2d
    iget-object v2, v4, Lin/z;->h:Ljava/util/List;

    .line 654
    .line 655
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 656
    .line 657
    .line 658
    move-result v2

    .line 659
    if-nez v2, :cond_2f

    .line 660
    .line 661
    invoke-virtual {v0}, Lin/z1;->e0()V

    .line 662
    .line 663
    .line 664
    if-eqz v1, :cond_2e

    .line 665
    .line 666
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 667
    .line 668
    check-cast v0, Lin/x1;

    .line 669
    .line 670
    const/4 v3, 0x0

    .line 671
    iput-boolean v3, v0, Lin/x1;->b:Z

    .line 672
    .line 673
    return-void

    .line 674
    :cond_2e
    const/4 v3, 0x0

    .line 675
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 676
    .line 677
    check-cast v0, Lin/x1;

    .line 678
    .line 679
    iput-boolean v3, v0, Lin/x1;->c:Z

    .line 680
    .line 681
    return-void

    .line 682
    :cond_2f
    const/4 v3, 0x0

    .line 683
    new-array v1, v2, [I

    .line 684
    .line 685
    new-array v7, v2, [F

    .line 686
    .line 687
    iget-object v11, v4, Lin/z;->h:Ljava/util/List;

    .line 688
    .line 689
    invoke-interface {v11}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 690
    .line 691
    .line 692
    move-result-object v11

    .line 693
    move v12, v3

    .line 694
    const/high16 v16, -0x40800000    # -1.0f

    .line 695
    .line 696
    :goto_1f
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 697
    .line 698
    .line 699
    move-result v13

    .line 700
    if-eqz v13, :cond_34

    .line 701
    .line 702
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 703
    .line 704
    .line 705
    move-result-object v13

    .line 706
    check-cast v13, Lin/a1;

    .line 707
    .line 708
    check-cast v13, Lin/r0;

    .line 709
    .line 710
    iget-object v15, v13, Lin/r0;->h:Ljava/lang/Float;

    .line 711
    .line 712
    if-eqz v15, :cond_30

    .line 713
    .line 714
    invoke-virtual {v15}, Ljava/lang/Float;->floatValue()F

    .line 715
    .line 716
    .line 717
    move-result v15

    .line 718
    goto :goto_20

    .line 719
    :cond_30
    move/from16 v15, v17

    .line 720
    .line 721
    :goto_20
    if-eqz v12, :cond_32

    .line 722
    .line 723
    cmpl-float v18, v15, v16

    .line 724
    .line 725
    if-ltz v18, :cond_31

    .line 726
    .line 727
    goto :goto_21

    .line 728
    :cond_31
    aput v16, v7, v12

    .line 729
    .line 730
    goto :goto_22

    .line 731
    :cond_32
    :goto_21
    aput v15, v7, v12

    .line 732
    .line 733
    move/from16 v16, v15

    .line 734
    .line 735
    :goto_22
    invoke-virtual {v0}, Lin/z1;->f0()V

    .line 736
    .line 737
    .line 738
    iget-object v15, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 739
    .line 740
    check-cast v15, Lin/x1;

    .line 741
    .line 742
    invoke-virtual {v0, v15, v13}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 743
    .line 744
    .line 745
    iget-object v13, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 746
    .line 747
    check-cast v13, Lin/x1;

    .line 748
    .line 749
    iget-object v13, v13, Lin/x1;->a:Lin/s0;

    .line 750
    .line 751
    iget-object v15, v13, Lin/s0;->y:Lin/b1;

    .line 752
    .line 753
    check-cast v15, Lin/v;

    .line 754
    .line 755
    if-nez v15, :cond_33

    .line 756
    .line 757
    move-object v15, v10

    .line 758
    :cond_33
    iget v15, v15, Lin/v;->d:I

    .line 759
    .line 760
    iget-object v13, v13, Lin/s0;->z:Ljava/lang/Float;

    .line 761
    .line 762
    invoke-virtual {v13}, Ljava/lang/Float;->floatValue()F

    .line 763
    .line 764
    .line 765
    move-result v13

    .line 766
    invoke-static {v15, v13}, Lin/z1;->q(IF)I

    .line 767
    .line 768
    .line 769
    move-result v13

    .line 770
    aput v13, v1, v12

    .line 771
    .line 772
    add-int/lit8 v12, v12, 0x1

    .line 773
    .line 774
    invoke-virtual {v0}, Lin/z1;->e0()V

    .line 775
    .line 776
    .line 777
    goto :goto_1f

    .line 778
    :cond_34
    cmpl-float v10, v21, v17

    .line 779
    .line 780
    if-eqz v10, :cond_35

    .line 781
    .line 782
    if-ne v2, v14, :cond_36

    .line 783
    .line 784
    :cond_35
    move-object/from16 v22, v1

    .line 785
    .line 786
    goto :goto_26

    .line 787
    :cond_36
    sget-object v2, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    .line 788
    .line 789
    iget v4, v4, Lin/z;->k:I

    .line 790
    .line 791
    if-eqz v4, :cond_37

    .line 792
    .line 793
    if-ne v4, v9, :cond_38

    .line 794
    .line 795
    sget-object v2, Landroid/graphics/Shader$TileMode;->MIRROR:Landroid/graphics/Shader$TileMode;

    .line 796
    .line 797
    :cond_37
    :goto_23
    move-object/from16 v24, v2

    .line 798
    .line 799
    goto :goto_24

    .line 800
    :cond_38
    if-ne v4, v8, :cond_37

    .line 801
    .line 802
    sget-object v2, Landroid/graphics/Shader$TileMode;->REPEAT:Landroid/graphics/Shader$TileMode;

    .line 803
    .line 804
    goto :goto_23

    .line 805
    :goto_24
    invoke-virtual {v0}, Lin/z1;->e0()V

    .line 806
    .line 807
    .line 808
    new-instance v18, Landroid/graphics/RadialGradient;

    .line 809
    .line 810
    move-object/from16 v22, v1

    .line 811
    .line 812
    move-object/from16 v23, v7

    .line 813
    .line 814
    invoke-direct/range {v18 .. v24}, Landroid/graphics/RadialGradient;-><init>(FFF[I[FLandroid/graphics/Shader$TileMode;)V

    .line 815
    .line 816
    .line 817
    move-object/from16 v1, v18

    .line 818
    .line 819
    invoke-virtual {v1, v6}, Landroid/graphics/Shader;->setLocalMatrix(Landroid/graphics/Matrix;)V

    .line 820
    .line 821
    .line 822
    invoke-virtual {v5, v1}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 823
    .line 824
    .line 825
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 826
    .line 827
    check-cast v0, Lin/x1;

    .line 828
    .line 829
    iget-object v0, v0, Lin/x1;->a:Lin/s0;

    .line 830
    .line 831
    iget-object v0, v0, Lin/s0;->f:Ljava/lang/Float;

    .line 832
    .line 833
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 834
    .line 835
    .line 836
    move-result v0

    .line 837
    mul-float v0, v0, p3

    .line 838
    .line 839
    float-to-int v0, v0

    .line 840
    if-gez v0, :cond_39

    .line 841
    .line 842
    move v0, v3

    .line 843
    goto :goto_25

    .line 844
    :cond_39
    const/16 v1, 0xff

    .line 845
    .line 846
    if-le v0, v1, :cond_3a

    .line 847
    .line 848
    move v0, v1

    .line 849
    :cond_3a
    :goto_25
    invoke-virtual {v5, v0}, Landroid/graphics/Paint;->setAlpha(I)V

    .line 850
    .line 851
    .line 852
    return-void

    .line 853
    :goto_26
    invoke-virtual {v0}, Lin/z1;->e0()V

    .line 854
    .line 855
    .line 856
    sub-int/2addr v2, v14

    .line 857
    aget v0, v22, v2

    .line 858
    .line 859
    invoke-virtual {v5, v0}, Landroid/graphics/Paint;->setColor(I)V

    .line 860
    .line 861
    .line 862
    return-void

    .line 863
    :cond_3b
    const/4 v3, 0x0

    .line 864
    instance-of v2, v4, Lin/q0;

    .line 865
    .line 866
    if-eqz v2, :cond_43

    .line 867
    .line 868
    check-cast v4, Lin/q0;

    .line 869
    .line 870
    const-wide v5, 0x180000000L

    .line 871
    .line 872
    .line 873
    .line 874
    .line 875
    const-wide v7, 0x100000000L

    .line 876
    .line 877
    .line 878
    .line 879
    .line 880
    const-wide v9, 0x80000000L

    .line 881
    .line 882
    .line 883
    .line 884
    .line 885
    if-eqz v1, :cond_3f

    .line 886
    .line 887
    iget-object v2, v4, Lin/y0;->e:Lin/s0;

    .line 888
    .line 889
    invoke-static {v2, v9, v10}, Lin/z1;->J(Lin/s0;J)Z

    .line 890
    .line 891
    .line 892
    move-result v2

    .line 893
    if-eqz v2, :cond_3d

    .line 894
    .line 895
    iget-object v2, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 896
    .line 897
    check-cast v2, Lin/x1;

    .line 898
    .line 899
    iget-object v9, v2, Lin/x1;->a:Lin/s0;

    .line 900
    .line 901
    iget-object v10, v4, Lin/y0;->e:Lin/s0;

    .line 902
    .line 903
    iget-object v10, v10, Lin/s0;->C:Lin/b1;

    .line 904
    .line 905
    iput-object v10, v9, Lin/s0;->e:Lin/b1;

    .line 906
    .line 907
    if-eqz v10, :cond_3c

    .line 908
    .line 909
    goto :goto_27

    .line 910
    :cond_3c
    move v14, v3

    .line 911
    :goto_27
    iput-boolean v14, v2, Lin/x1;->b:Z

    .line 912
    .line 913
    :cond_3d
    iget-object v2, v4, Lin/y0;->e:Lin/s0;

    .line 914
    .line 915
    invoke-static {v2, v7, v8}, Lin/z1;->J(Lin/s0;J)Z

    .line 916
    .line 917
    .line 918
    move-result v2

    .line 919
    if-eqz v2, :cond_3e

    .line 920
    .line 921
    iget-object v2, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 922
    .line 923
    check-cast v2, Lin/x1;

    .line 924
    .line 925
    iget-object v2, v2, Lin/x1;->a:Lin/s0;

    .line 926
    .line 927
    iget-object v3, v4, Lin/y0;->e:Lin/s0;

    .line 928
    .line 929
    iget-object v3, v3, Lin/s0;->D:Ljava/lang/Float;

    .line 930
    .line 931
    iput-object v3, v2, Lin/s0;->f:Ljava/lang/Float;

    .line 932
    .line 933
    :cond_3e
    iget-object v2, v4, Lin/y0;->e:Lin/s0;

    .line 934
    .line 935
    invoke-static {v2, v5, v6}, Lin/z1;->J(Lin/s0;J)Z

    .line 936
    .line 937
    .line 938
    move-result v2

    .line 939
    if-eqz v2, :cond_43

    .line 940
    .line 941
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 942
    .line 943
    check-cast v0, Lin/x1;

    .line 944
    .line 945
    iget-object v2, v0, Lin/x1;->a:Lin/s0;

    .line 946
    .line 947
    iget-object v2, v2, Lin/s0;->e:Lin/b1;

    .line 948
    .line 949
    invoke-static {v0, v1, v2}, Lin/z1;->c0(Lin/x1;ZLin/b1;)V

    .line 950
    .line 951
    .line 952
    return-void

    .line 953
    :cond_3f
    iget-object v2, v4, Lin/y0;->e:Lin/s0;

    .line 954
    .line 955
    invoke-static {v2, v9, v10}, Lin/z1;->J(Lin/s0;J)Z

    .line 956
    .line 957
    .line 958
    move-result v2

    .line 959
    if-eqz v2, :cond_41

    .line 960
    .line 961
    iget-object v2, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 962
    .line 963
    check-cast v2, Lin/x1;

    .line 964
    .line 965
    iget-object v9, v2, Lin/x1;->a:Lin/s0;

    .line 966
    .line 967
    iget-object v10, v4, Lin/y0;->e:Lin/s0;

    .line 968
    .line 969
    iget-object v10, v10, Lin/s0;->C:Lin/b1;

    .line 970
    .line 971
    iput-object v10, v9, Lin/s0;->g:Lin/b1;

    .line 972
    .line 973
    if-eqz v10, :cond_40

    .line 974
    .line 975
    goto :goto_28

    .line 976
    :cond_40
    move v14, v3

    .line 977
    :goto_28
    iput-boolean v14, v2, Lin/x1;->c:Z

    .line 978
    .line 979
    :cond_41
    iget-object v2, v4, Lin/y0;->e:Lin/s0;

    .line 980
    .line 981
    invoke-static {v2, v7, v8}, Lin/z1;->J(Lin/s0;J)Z

    .line 982
    .line 983
    .line 984
    move-result v2

    .line 985
    if-eqz v2, :cond_42

    .line 986
    .line 987
    iget-object v2, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 988
    .line 989
    check-cast v2, Lin/x1;

    .line 990
    .line 991
    iget-object v2, v2, Lin/x1;->a:Lin/s0;

    .line 992
    .line 993
    iget-object v3, v4, Lin/y0;->e:Lin/s0;

    .line 994
    .line 995
    iget-object v3, v3, Lin/s0;->D:Ljava/lang/Float;

    .line 996
    .line 997
    iput-object v3, v2, Lin/s0;->h:Ljava/lang/Float;

    .line 998
    .line 999
    :cond_42
    iget-object v2, v4, Lin/y0;->e:Lin/s0;

    .line 1000
    .line 1001
    invoke-static {v2, v5, v6}, Lin/z1;->J(Lin/s0;J)Z

    .line 1002
    .line 1003
    .line 1004
    move-result v2

    .line 1005
    if-eqz v2, :cond_43

    .line 1006
    .line 1007
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 1008
    .line 1009
    check-cast v0, Lin/x1;

    .line 1010
    .line 1011
    iget-object v2, v0, Lin/x1;->a:Lin/s0;

    .line 1012
    .line 1013
    iget-object v2, v2, Lin/s0;->g:Lin/b1;

    .line 1014
    .line 1015
    invoke-static {v0, v1, v2}, Lin/z1;->c0(Lin/x1;ZLin/b1;)V

    .line 1016
    .line 1017
    .line 1018
    :cond_43
    return-void
.end method

.method public s()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lin/x1;

    .line 4
    .line 5
    iget-object p0, p0, Lin/x1;->a:Lin/s0;

    .line 6
    .line 7
    iget-object p0, p0, Lin/s0;->w:Ljava/lang/Boolean;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public t(Lin/x0;Landroid/graphics/Path;)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    iget-object v3, v0, Lin/z1;->a:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Landroid/graphics/Canvas;

    .line 10
    .line 11
    iget-object v4, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v4, Lin/x1;

    .line 14
    .line 15
    iget-object v4, v4, Lin/x1;->a:Lin/s0;

    .line 16
    .line 17
    iget-object v4, v4, Lin/s0;->e:Lin/b1;

    .line 18
    .line 19
    instance-of v5, v4, Lin/j0;

    .line 20
    .line 21
    if-eqz v5, :cond_1d

    .line 22
    .line 23
    iget-object v5, v0, Lin/z1;->b:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v5, Lil/g;

    .line 26
    .line 27
    check-cast v4, Lin/j0;

    .line 28
    .line 29
    iget-object v4, v4, Lin/j0;->d:Ljava/lang/String;

    .line 30
    .line 31
    invoke-virtual {v5, v4}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 32
    .line 33
    .line 34
    move-result-object v4

    .line 35
    instance-of v5, v4, Lin/m0;

    .line 36
    .line 37
    if-eqz v5, :cond_1d

    .line 38
    .line 39
    check-cast v4, Lin/m0;

    .line 40
    .line 41
    iget-object v5, v4, Lin/m0;->p:Ljava/lang/Boolean;

    .line 42
    .line 43
    if-eqz v5, :cond_0

    .line 44
    .line 45
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    if-eqz v5, :cond_0

    .line 50
    .line 51
    const/4 v5, 0x1

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    const/4 v5, 0x0

    .line 54
    :goto_0
    iget-object v8, v4, Lin/m0;->w:Ljava/lang/String;

    .line 55
    .line 56
    if-eqz v8, :cond_1

    .line 57
    .line 58
    invoke-static {v4, v8}, Lin/z1;->B(Lin/m0;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    :cond_1
    const/4 v8, 0x0

    .line 62
    if-eqz v5, :cond_6

    .line 63
    .line 64
    iget-object v5, v4, Lin/m0;->s:Lin/e0;

    .line 65
    .line 66
    if-eqz v5, :cond_2

    .line 67
    .line 68
    invoke-virtual {v5, v0}, Lin/e0;->d(Lin/z1;)F

    .line 69
    .line 70
    .line 71
    move-result v5

    .line 72
    goto :goto_1

    .line 73
    :cond_2
    move v5, v8

    .line 74
    :goto_1
    iget-object v9, v4, Lin/m0;->t:Lin/e0;

    .line 75
    .line 76
    if-eqz v9, :cond_3

    .line 77
    .line 78
    invoke-virtual {v9, v0}, Lin/e0;->e(Lin/z1;)F

    .line 79
    .line 80
    .line 81
    move-result v9

    .line 82
    goto :goto_2

    .line 83
    :cond_3
    move v9, v8

    .line 84
    :goto_2
    iget-object v10, v4, Lin/m0;->u:Lin/e0;

    .line 85
    .line 86
    if-eqz v10, :cond_4

    .line 87
    .line 88
    invoke-virtual {v10, v0}, Lin/e0;->d(Lin/z1;)F

    .line 89
    .line 90
    .line 91
    move-result v10

    .line 92
    goto :goto_3

    .line 93
    :cond_4
    move v10, v8

    .line 94
    :goto_3
    iget-object v11, v4, Lin/m0;->v:Lin/e0;

    .line 95
    .line 96
    if-eqz v11, :cond_5

    .line 97
    .line 98
    invoke-virtual {v11, v0}, Lin/e0;->e(Lin/z1;)F

    .line 99
    .line 100
    .line 101
    move-result v11

    .line 102
    goto :goto_8

    .line 103
    :cond_5
    move v11, v8

    .line 104
    goto :goto_8

    .line 105
    :cond_6
    iget-object v5, v4, Lin/m0;->s:Lin/e0;

    .line 106
    .line 107
    const/high16 v9, 0x3f800000    # 1.0f

    .line 108
    .line 109
    if-eqz v5, :cond_7

    .line 110
    .line 111
    invoke-virtual {v5, v0, v9}, Lin/e0;->b(Lin/z1;F)F

    .line 112
    .line 113
    .line 114
    move-result v5

    .line 115
    goto :goto_4

    .line 116
    :cond_7
    move v5, v8

    .line 117
    :goto_4
    iget-object v10, v4, Lin/m0;->t:Lin/e0;

    .line 118
    .line 119
    if-eqz v10, :cond_8

    .line 120
    .line 121
    invoke-virtual {v10, v0, v9}, Lin/e0;->b(Lin/z1;F)F

    .line 122
    .line 123
    .line 124
    move-result v10

    .line 125
    goto :goto_5

    .line 126
    :cond_8
    move v10, v8

    .line 127
    :goto_5
    iget-object v11, v4, Lin/m0;->u:Lin/e0;

    .line 128
    .line 129
    if-eqz v11, :cond_9

    .line 130
    .line 131
    invoke-virtual {v11, v0, v9}, Lin/e0;->b(Lin/z1;F)F

    .line 132
    .line 133
    .line 134
    move-result v11

    .line 135
    goto :goto_6

    .line 136
    :cond_9
    move v11, v8

    .line 137
    :goto_6
    iget-object v12, v4, Lin/m0;->v:Lin/e0;

    .line 138
    .line 139
    if-eqz v12, :cond_a

    .line 140
    .line 141
    invoke-virtual {v12, v0, v9}, Lin/e0;->b(Lin/z1;F)F

    .line 142
    .line 143
    .line 144
    move-result v9

    .line 145
    goto :goto_7

    .line 146
    :cond_a
    move v9, v8

    .line 147
    :goto_7
    iget-object v12, v1, Lin/x0;->h:Ld3/a;

    .line 148
    .line 149
    iget v13, v12, Ld3/a;->b:F

    .line 150
    .line 151
    iget v14, v12, Ld3/a;->d:F

    .line 152
    .line 153
    mul-float/2addr v5, v14

    .line 154
    add-float/2addr v5, v13

    .line 155
    iget v13, v12, Ld3/a;->c:F

    .line 156
    .line 157
    iget v12, v12, Ld3/a;->e:F

    .line 158
    .line 159
    mul-float/2addr v10, v12

    .line 160
    add-float/2addr v10, v13

    .line 161
    mul-float/2addr v11, v14

    .line 162
    mul-float/2addr v9, v12

    .line 163
    move/from16 v21, v11

    .line 164
    .line 165
    move v11, v9

    .line 166
    move v9, v10

    .line 167
    move/from16 v10, v21

    .line 168
    .line 169
    :goto_8
    cmpl-float v12, v10, v8

    .line 170
    .line 171
    if-eqz v12, :cond_1c

    .line 172
    .line 173
    cmpl-float v12, v11, v8

    .line 174
    .line 175
    if-nez v12, :cond_b

    .line 176
    .line 177
    goto/16 :goto_13

    .line 178
    .line 179
    :cond_b
    iget-object v12, v4, Lin/c1;->n:Lin/s;

    .line 180
    .line 181
    if-eqz v12, :cond_c

    .line 182
    .line 183
    goto :goto_9

    .line 184
    :cond_c
    sget-object v12, Lin/s;->d:Lin/s;

    .line 185
    .line 186
    :goto_9
    invoke-virtual {v0}, Lin/z1;->f0()V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v3, v2}, Landroid/graphics/Canvas;->clipPath(Landroid/graphics/Path;)Z

    .line 190
    .line 191
    .line 192
    new-instance v2, Lin/x1;

    .line 193
    .line 194
    invoke-direct {v2}, Lin/x1;-><init>()V

    .line 195
    .line 196
    .line 197
    invoke-static {}, Lin/s0;->a()Lin/s0;

    .line 198
    .line 199
    .line 200
    move-result-object v13

    .line 201
    invoke-virtual {v0, v2, v13}, Lin/z1;->j0(Lin/x1;Lin/s0;)V

    .line 202
    .line 203
    .line 204
    iget-object v13, v2, Lin/x1;->a:Lin/s0;

    .line 205
    .line 206
    sget-object v14, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 207
    .line 208
    iput-object v14, v13, Lin/s0;->r:Ljava/lang/Boolean;

    .line 209
    .line 210
    invoke-virtual {v0, v4, v2}, Lin/z1;->E(Lin/a1;Lin/x1;)V

    .line 211
    .line 212
    .line 213
    iput-object v2, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 214
    .line 215
    iget-object v2, v1, Lin/x0;->h:Ld3/a;

    .line 216
    .line 217
    iget-object v13, v4, Lin/m0;->r:Landroid/graphics/Matrix;

    .line 218
    .line 219
    if-eqz v13, :cond_12

    .line 220
    .line 221
    invoke-virtual {v3, v13}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 222
    .line 223
    .line 224
    new-instance v13, Landroid/graphics/Matrix;

    .line 225
    .line 226
    invoke-direct {v13}, Landroid/graphics/Matrix;-><init>()V

    .line 227
    .line 228
    .line 229
    iget-object v14, v4, Lin/m0;->r:Landroid/graphics/Matrix;

    .line 230
    .line 231
    invoke-virtual {v14, v13}, Landroid/graphics/Matrix;->invert(Landroid/graphics/Matrix;)Z

    .line 232
    .line 233
    .line 234
    move-result v14

    .line 235
    if-eqz v14, :cond_12

    .line 236
    .line 237
    iget-object v2, v1, Lin/x0;->h:Ld3/a;

    .line 238
    .line 239
    iget v14, v2, Ld3/a;->b:F

    .line 240
    .line 241
    iget v15, v2, Ld3/a;->c:F

    .line 242
    .line 243
    invoke-virtual {v2}, Ld3/a;->h()F

    .line 244
    .line 245
    .line 246
    move-result v2

    .line 247
    const/16 v16, 0x1

    .line 248
    .line 249
    iget-object v6, v1, Lin/x0;->h:Ld3/a;

    .line 250
    .line 251
    const/16 v17, 0x0

    .line 252
    .line 253
    iget v7, v6, Ld3/a;->c:F

    .line 254
    .line 255
    invoke-virtual {v6}, Ld3/a;->h()F

    .line 256
    .line 257
    .line 258
    move-result v6

    .line 259
    iget-object v8, v1, Lin/x0;->h:Ld3/a;

    .line 260
    .line 261
    invoke-virtual {v8}, Ld3/a;->i()F

    .line 262
    .line 263
    .line 264
    move-result v8

    .line 265
    move/from16 p2, v2

    .line 266
    .line 267
    iget-object v2, v1, Lin/x0;->h:Ld3/a;

    .line 268
    .line 269
    move/from16 v19, v5

    .line 270
    .line 271
    iget v5, v2, Ld3/a;->b:F

    .line 272
    .line 273
    invoke-virtual {v2}, Ld3/a;->i()F

    .line 274
    .line 275
    .line 276
    move-result v2

    .line 277
    move/from16 v20, v2

    .line 278
    .line 279
    const/16 v2, 0x8

    .line 280
    .line 281
    new-array v2, v2, [F

    .line 282
    .line 283
    aput v14, v2, v17

    .line 284
    .line 285
    aput v15, v2, v16

    .line 286
    .line 287
    const/4 v14, 0x2

    .line 288
    aput p2, v2, v14

    .line 289
    .line 290
    const/4 v15, 0x3

    .line 291
    aput v7, v2, v15

    .line 292
    .line 293
    const/4 v7, 0x4

    .line 294
    aput v6, v2, v7

    .line 295
    .line 296
    const/4 v6, 0x5

    .line 297
    aput v8, v2, v6

    .line 298
    .line 299
    const/4 v6, 0x6

    .line 300
    aput v5, v2, v6

    .line 301
    .line 302
    const/4 v5, 0x7

    .line 303
    aput v20, v2, v5

    .line 304
    .line 305
    invoke-virtual {v13, v2}, Landroid/graphics/Matrix;->mapPoints([F)V

    .line 306
    .line 307
    .line 308
    new-instance v5, Landroid/graphics/RectF;

    .line 309
    .line 310
    aget v7, v2, v17

    .line 311
    .line 312
    aget v8, v2, v16

    .line 313
    .line 314
    invoke-direct {v5, v7, v8, v7, v8}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 315
    .line 316
    .line 317
    :goto_a
    if-gt v14, v6, :cond_11

    .line 318
    .line 319
    aget v7, v2, v14

    .line 320
    .line 321
    iget v8, v5, Landroid/graphics/RectF;->left:F

    .line 322
    .line 323
    cmpg-float v8, v7, v8

    .line 324
    .line 325
    if-gez v8, :cond_d

    .line 326
    .line 327
    iput v7, v5, Landroid/graphics/RectF;->left:F

    .line 328
    .line 329
    :cond_d
    iget v8, v5, Landroid/graphics/RectF;->right:F

    .line 330
    .line 331
    cmpl-float v8, v7, v8

    .line 332
    .line 333
    if-lez v8, :cond_e

    .line 334
    .line 335
    iput v7, v5, Landroid/graphics/RectF;->right:F

    .line 336
    .line 337
    :cond_e
    add-int/lit8 v7, v14, 0x1

    .line 338
    .line 339
    aget v7, v2, v7

    .line 340
    .line 341
    iget v8, v5, Landroid/graphics/RectF;->top:F

    .line 342
    .line 343
    cmpg-float v8, v7, v8

    .line 344
    .line 345
    if-gez v8, :cond_f

    .line 346
    .line 347
    iput v7, v5, Landroid/graphics/RectF;->top:F

    .line 348
    .line 349
    :cond_f
    iget v8, v5, Landroid/graphics/RectF;->bottom:F

    .line 350
    .line 351
    cmpl-float v8, v7, v8

    .line 352
    .line 353
    if-lez v8, :cond_10

    .line 354
    .line 355
    iput v7, v5, Landroid/graphics/RectF;->bottom:F

    .line 356
    .line 357
    :cond_10
    add-int/lit8 v14, v14, 0x2

    .line 358
    .line 359
    goto :goto_a

    .line 360
    :cond_11
    new-instance v2, Ld3/a;

    .line 361
    .line 362
    iget v6, v5, Landroid/graphics/RectF;->left:F

    .line 363
    .line 364
    iget v7, v5, Landroid/graphics/RectF;->top:F

    .line 365
    .line 366
    iget v8, v5, Landroid/graphics/RectF;->right:F

    .line 367
    .line 368
    sub-float/2addr v8, v6

    .line 369
    iget v5, v5, Landroid/graphics/RectF;->bottom:F

    .line 370
    .line 371
    sub-float/2addr v5, v7

    .line 372
    invoke-direct {v2, v6, v7, v8, v5}, Ld3/a;-><init>(FFFF)V

    .line 373
    .line 374
    .line 375
    goto :goto_b

    .line 376
    :cond_12
    move/from16 v19, v5

    .line 377
    .line 378
    const/16 v16, 0x1

    .line 379
    .line 380
    const/16 v17, 0x0

    .line 381
    .line 382
    :goto_b
    iget v5, v2, Ld3/a;->b:F

    .line 383
    .line 384
    sub-float v5, v5, v19

    .line 385
    .line 386
    div-float/2addr v5, v10

    .line 387
    float-to-double v5, v5

    .line 388
    invoke-static {v5, v6}, Ljava/lang/Math;->floor(D)D

    .line 389
    .line 390
    .line 391
    move-result-wide v5

    .line 392
    double-to-float v5, v5

    .line 393
    mul-float/2addr v5, v10

    .line 394
    add-float v5, v5, v19

    .line 395
    .line 396
    iget v6, v2, Ld3/a;->c:F

    .line 397
    .line 398
    sub-float/2addr v6, v9

    .line 399
    div-float/2addr v6, v11

    .line 400
    float-to-double v6, v6

    .line 401
    invoke-static {v6, v7}, Ljava/lang/Math;->floor(D)D

    .line 402
    .line 403
    .line 404
    move-result-wide v6

    .line 405
    double-to-float v6, v6

    .line 406
    mul-float/2addr v6, v11

    .line 407
    add-float/2addr v6, v9

    .line 408
    invoke-virtual {v2}, Ld3/a;->h()F

    .line 409
    .line 410
    .line 411
    move-result v7

    .line 412
    invoke-virtual {v2}, Ld3/a;->i()F

    .line 413
    .line 414
    .line 415
    move-result v2

    .line 416
    new-instance v8, Ld3/a;

    .line 417
    .line 418
    const/4 v9, 0x0

    .line 419
    invoke-direct {v8, v9, v9, v10, v11}, Ld3/a;-><init>(FFFF)V

    .line 420
    .line 421
    .line 422
    invoke-virtual {v0}, Lin/z1;->S()Z

    .line 423
    .line 424
    .line 425
    move-result v9

    .line 426
    :goto_c
    cmpg-float v13, v6, v2

    .line 427
    .line 428
    if-gez v13, :cond_1a

    .line 429
    .line 430
    move v13, v5

    .line 431
    :goto_d
    cmpg-float v14, v13, v7

    .line 432
    .line 433
    if-gez v14, :cond_19

    .line 434
    .line 435
    iput v13, v8, Ld3/a;->b:F

    .line 436
    .line 437
    iput v6, v8, Ld3/a;->c:F

    .line 438
    .line 439
    invoke-virtual {v0}, Lin/z1;->f0()V

    .line 440
    .line 441
    .line 442
    iget-object v14, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 443
    .line 444
    check-cast v14, Lin/x1;

    .line 445
    .line 446
    iget-object v14, v14, Lin/x1;->a:Lin/s0;

    .line 447
    .line 448
    iget-object v14, v14, Lin/s0;->r:Ljava/lang/Boolean;

    .line 449
    .line 450
    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    .line 451
    .line 452
    .line 453
    move-result v14

    .line 454
    if-nez v14, :cond_13

    .line 455
    .line 456
    iget v14, v8, Ld3/a;->b:F

    .line 457
    .line 458
    iget v15, v8, Ld3/a;->c:F

    .line 459
    .line 460
    move/from16 p2, v2

    .line 461
    .line 462
    iget v2, v8, Ld3/a;->d:F

    .line 463
    .line 464
    move/from16 v18, v5

    .line 465
    .line 466
    iget v5, v8, Ld3/a;->e:F

    .line 467
    .line 468
    invoke-virtual {v0, v14, v15, v2, v5}, Lin/z1;->a0(FFFF)V

    .line 469
    .line 470
    .line 471
    goto :goto_e

    .line 472
    :cond_13
    move/from16 p2, v2

    .line 473
    .line 474
    move/from16 v18, v5

    .line 475
    .line 476
    :goto_e
    iget-object v2, v4, Lin/e1;->o:Ld3/a;

    .line 477
    .line 478
    if-eqz v2, :cond_14

    .line 479
    .line 480
    invoke-static {v8, v2, v12}, Lin/z1;->m(Ld3/a;Ld3/a;Lin/s;)Landroid/graphics/Matrix;

    .line 481
    .line 482
    .line 483
    move-result-object v2

    .line 484
    invoke-virtual {v3, v2}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 485
    .line 486
    .line 487
    goto :goto_11

    .line 488
    :cond_14
    iget-object v2, v4, Lin/m0;->q:Ljava/lang/Boolean;

    .line 489
    .line 490
    if-eqz v2, :cond_16

    .line 491
    .line 492
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 493
    .line 494
    .line 495
    move-result v2

    .line 496
    if-eqz v2, :cond_15

    .line 497
    .line 498
    goto :goto_f

    .line 499
    :cond_15
    move/from16 v2, v17

    .line 500
    .line 501
    goto :goto_10

    .line 502
    :cond_16
    :goto_f
    move/from16 v2, v16

    .line 503
    .line 504
    :goto_10
    invoke-virtual {v3, v13, v6}, Landroid/graphics/Canvas;->translate(FF)V

    .line 505
    .line 506
    .line 507
    if-nez v2, :cond_17

    .line 508
    .line 509
    iget-object v2, v1, Lin/x0;->h:Ld3/a;

    .line 510
    .line 511
    iget v5, v2, Ld3/a;->d:F

    .line 512
    .line 513
    iget v2, v2, Ld3/a;->e:F

    .line 514
    .line 515
    invoke-virtual {v3, v5, v2}, Landroid/graphics/Canvas;->scale(FF)V

    .line 516
    .line 517
    .line 518
    :cond_17
    :goto_11
    iget-object v2, v4, Lin/v0;->i:Ljava/util/List;

    .line 519
    .line 520
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 521
    .line 522
    .line 523
    move-result-object v2

    .line 524
    :goto_12
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 525
    .line 526
    .line 527
    move-result v5

    .line 528
    if-eqz v5, :cond_18

    .line 529
    .line 530
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 531
    .line 532
    .line 533
    move-result-object v5

    .line 534
    check-cast v5, Lin/a1;

    .line 535
    .line 536
    invoke-virtual {v0, v5}, Lin/z1;->V(Lin/a1;)V

    .line 537
    .line 538
    .line 539
    goto :goto_12

    .line 540
    :cond_18
    invoke-virtual {v0}, Lin/z1;->e0()V

    .line 541
    .line 542
    .line 543
    add-float/2addr v13, v10

    .line 544
    move/from16 v2, p2

    .line 545
    .line 546
    move/from16 v5, v18

    .line 547
    .line 548
    goto :goto_d

    .line 549
    :cond_19
    move/from16 p2, v2

    .line 550
    .line 551
    move/from16 v18, v5

    .line 552
    .line 553
    add-float/2addr v6, v11

    .line 554
    goto/16 :goto_c

    .line 555
    .line 556
    :cond_1a
    if-eqz v9, :cond_1b

    .line 557
    .line 558
    iget-object v1, v4, Lin/x0;->h:Ld3/a;

    .line 559
    .line 560
    invoke-virtual {v0, v1}, Lin/z1;->R(Ld3/a;)V

    .line 561
    .line 562
    .line 563
    :cond_1b
    invoke-virtual {v0}, Lin/z1;->e0()V

    .line 564
    .line 565
    .line 566
    :cond_1c
    :goto_13
    return-void

    .line 567
    :cond_1d
    iget-object v0, v0, Lin/z1;->c:Ljava/lang/Object;

    .line 568
    .line 569
    check-cast v0, Lin/x1;

    .line 570
    .line 571
    iget-object v0, v0, Lin/x1;->d:Landroid/graphics/Paint;

    .line 572
    .line 573
    invoke-virtual {v3, v2, v0}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 574
    .line 575
    .line 576
    return-void
.end method

.method public u(Landroid/graphics/Path;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/Canvas;

    .line 4
    .line 5
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lin/x1;

    .line 8
    .line 9
    iget-object v2, v1, Lin/x1;->a:Lin/s0;

    .line 10
    .line 11
    iget v2, v2, Lin/s0;->O:I

    .line 12
    .line 13
    const/4 v3, 0x2

    .line 14
    if-ne v2, v3, :cond_2

    .line 15
    .line 16
    invoke-virtual {v0}, Landroid/graphics/Canvas;->getMatrix()Landroid/graphics/Matrix;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    new-instance v2, Landroid/graphics/Path;

    .line 21
    .line 22
    invoke-direct {v2}, Landroid/graphics/Path;-><init>()V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, v1, v2}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;Landroid/graphics/Path;)V

    .line 26
    .line 27
    .line 28
    new-instance p1, Landroid/graphics/Matrix;

    .line 29
    .line 30
    invoke-direct {p1}, Landroid/graphics/Matrix;-><init>()V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, p1}, Landroid/graphics/Canvas;->setMatrix(Landroid/graphics/Matrix;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p1, Lin/x1;

    .line 39
    .line 40
    iget-object p1, p1, Lin/x1;->e:Landroid/graphics/Paint;

    .line 41
    .line 42
    invoke-virtual {p1}, Landroid/graphics/Paint;->getShader()Landroid/graphics/Shader;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    new-instance v3, Landroid/graphics/Matrix;

    .line 47
    .line 48
    invoke-direct {v3}, Landroid/graphics/Matrix;-><init>()V

    .line 49
    .line 50
    .line 51
    if-eqz p1, :cond_0

    .line 52
    .line 53
    invoke-virtual {p1, v3}, Landroid/graphics/Shader;->getLocalMatrix(Landroid/graphics/Matrix;)Z

    .line 54
    .line 55
    .line 56
    new-instance v4, Landroid/graphics/Matrix;

    .line 57
    .line 58
    invoke-direct {v4, v3}, Landroid/graphics/Matrix;-><init>(Landroid/graphics/Matrix;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v4, v1}, Landroid/graphics/Matrix;->postConcat(Landroid/graphics/Matrix;)Z

    .line 62
    .line 63
    .line 64
    invoke-virtual {p1, v4}, Landroid/graphics/Shader;->setLocalMatrix(Landroid/graphics/Matrix;)V

    .line 65
    .line 66
    .line 67
    :cond_0
    iget-object p0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast p0, Lin/x1;

    .line 70
    .line 71
    iget-object p0, p0, Lin/x1;->e:Landroid/graphics/Paint;

    .line 72
    .line 73
    invoke-virtual {v0, v2, p0}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v0, v1}, Landroid/graphics/Canvas;->setMatrix(Landroid/graphics/Matrix;)V

    .line 77
    .line 78
    .line 79
    if-eqz p1, :cond_1

    .line 80
    .line 81
    invoke-virtual {p1, v3}, Landroid/graphics/Shader;->setLocalMatrix(Landroid/graphics/Matrix;)V

    .line 82
    .line 83
    .line 84
    :cond_1
    return-void

    .line 85
    :cond_2
    iget-object p0, v1, Lin/x1;->e:Landroid/graphics/Paint;

    .line 86
    .line 87
    invoke-virtual {v0, p1, p0}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 88
    .line 89
    .line 90
    return-void
.end method

.method public v(Lin/l1;Llp/pa;)V
    .locals 13

    .line 1
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto/16 :goto_c

    .line 8
    .line 9
    :cond_0
    iget-object p1, p1, Lin/v0;->i:Ljava/util/List;

    .line 10
    .line 11
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    const/4 v0, 0x1

    .line 16
    move v1, v0

    .line 17
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_1d

    .line 22
    .line 23
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Lin/a1;

    .line 28
    .line 29
    instance-of v3, v2, Lin/o1;

    .line 30
    .line 31
    const/4 v4, 0x0

    .line 32
    if-eqz v3, :cond_1

    .line 33
    .line 34
    check-cast v2, Lin/o1;

    .line 35
    .line 36
    iget-object v2, v2, Lin/o1;->c:Ljava/lang/String;

    .line 37
    .line 38
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    xor-int/2addr v3, v0

    .line 43
    invoke-virtual {p0, v2, v1, v3}, Lin/z1;->g0(Ljava/lang/String;ZZ)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-virtual {p2, v1}, Llp/pa;->d(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    goto/16 :goto_b

    .line 51
    .line 52
    :cond_1
    move-object v1, v2

    .line 53
    check-cast v1, Lin/l1;

    .line 54
    .line 55
    invoke-virtual {p2, v1}, Llp/pa;->a(Lin/l1;)Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-nez v1, :cond_2

    .line 60
    .line 61
    goto/16 :goto_b

    .line 62
    .line 63
    :cond_2
    instance-of v1, v2, Lin/m1;

    .line 64
    .line 65
    const/high16 v3, 0x40000000    # 2.0f

    .line 66
    .line 67
    const/4 v5, 0x2

    .line 68
    const/4 v6, 0x0

    .line 69
    if-eqz v1, :cond_b

    .line 70
    .line 71
    invoke-virtual {p0}, Lin/z1;->f0()V

    .line 72
    .line 73
    .line 74
    check-cast v2, Lin/m1;

    .line 75
    .line 76
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v1, Lin/x1;

    .line 79
    .line 80
    invoke-virtual {p0, v1, v2}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_3

    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_3
    invoke-virtual {p0}, Lin/z1;->m0()Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-nez v1, :cond_4

    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_4
    iget-object v1, v2, Lin/a1;->a:Lil/g;

    .line 98
    .line 99
    iget-object v7, v2, Lin/m1;->n:Ljava/lang/String;

    .line 100
    .line 101
    invoke-virtual {v1, v7}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    if-nez v1, :cond_5

    .line 106
    .line 107
    iget-object v1, v2, Lin/m1;->n:Ljava/lang/String;

    .line 108
    .line 109
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    const-string v2, "TextPath reference \'%s\' not found"

    .line 114
    .line 115
    invoke-static {v2, v1}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_5
    check-cast v1, Lin/k0;

    .line 120
    .line 121
    new-instance v7, Lin/t1;

    .line 122
    .line 123
    iget-object v8, v1, Lin/k0;->o:Li4/c;

    .line 124
    .line 125
    invoke-direct {v7, v8}, Lin/t1;-><init>(Li4/c;)V

    .line 126
    .line 127
    .line 128
    iget-object v7, v7, Lin/t1;->c:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast v7, Landroid/graphics/Path;

    .line 131
    .line 132
    iget-object v1, v1, Lin/a0;->n:Landroid/graphics/Matrix;

    .line 133
    .line 134
    if-eqz v1, :cond_6

    .line 135
    .line 136
    invoke-virtual {v7, v1}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 137
    .line 138
    .line 139
    :cond_6
    new-instance v1, Landroid/graphics/PathMeasure;

    .line 140
    .line 141
    invoke-direct {v1, v7, v4}, Landroid/graphics/PathMeasure;-><init>(Landroid/graphics/Path;Z)V

    .line 142
    .line 143
    .line 144
    iget-object v8, v2, Lin/m1;->o:Lin/e0;

    .line 145
    .line 146
    if-eqz v8, :cond_7

    .line 147
    .line 148
    invoke-virtual {v1}, Landroid/graphics/PathMeasure;->getLength()F

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    invoke-virtual {v8, p0, v1}, Lin/e0;->b(Lin/z1;F)F

    .line 153
    .line 154
    .line 155
    move-result v6

    .line 156
    :cond_7
    invoke-virtual {p0}, Lin/z1;->F()I

    .line 157
    .line 158
    .line 159
    move-result v1

    .line 160
    if-eq v1, v0, :cond_9

    .line 161
    .line 162
    invoke-virtual {p0, v2}, Lin/z1;->l(Lin/l1;)F

    .line 163
    .line 164
    .line 165
    move-result v8

    .line 166
    if-ne v1, v5, :cond_8

    .line 167
    .line 168
    div-float/2addr v8, v3

    .line 169
    :cond_8
    sub-float/2addr v6, v8

    .line 170
    :cond_9
    iget-object v1, v2, Lin/m1;->p:Lin/j1;

    .line 171
    .line 172
    invoke-virtual {p0, v1}, Lin/z1;->o(Lin/x0;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 176
    .line 177
    .line 178
    move-result v1

    .line 179
    new-instance v3, Lin/u1;

    .line 180
    .line 181
    invoke-direct {v3, p0, v7, v6}, Lin/u1;-><init>(Lin/z1;Landroid/graphics/Path;F)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {p0, v2, v3}, Lin/z1;->v(Lin/l1;Llp/pa;)V

    .line 185
    .line 186
    .line 187
    if-eqz v1, :cond_a

    .line 188
    .line 189
    iget-object v1, v2, Lin/x0;->h:Ld3/a;

    .line 190
    .line 191
    invoke-virtual {p0, v1}, Lin/z1;->R(Ld3/a;)V

    .line 192
    .line 193
    .line 194
    :cond_a
    :goto_1
    invoke-virtual {p0}, Lin/z1;->e0()V

    .line 195
    .line 196
    .line 197
    goto/16 :goto_b

    .line 198
    .line 199
    :cond_b
    instance-of v1, v2, Lin/i1;

    .line 200
    .line 201
    if-eqz v1, :cond_19

    .line 202
    .line 203
    invoke-virtual {p0}, Lin/z1;->f0()V

    .line 204
    .line 205
    .line 206
    check-cast v2, Lin/i1;

    .line 207
    .line 208
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast v1, Lin/x1;

    .line 211
    .line 212
    invoke-virtual {p0, v1, v2}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 216
    .line 217
    .line 218
    move-result v1

    .line 219
    if-eqz v1, :cond_18

    .line 220
    .line 221
    iget-object v1, v2, Lin/n1;->n:Ljava/util/ArrayList;

    .line 222
    .line 223
    if-eqz v1, :cond_c

    .line 224
    .line 225
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 226
    .line 227
    .line 228
    move-result v1

    .line 229
    if-lez v1, :cond_c

    .line 230
    .line 231
    move v1, v0

    .line 232
    goto :goto_2

    .line 233
    :cond_c
    move v1, v4

    .line 234
    :goto_2
    instance-of v7, p2, Lin/v1;

    .line 235
    .line 236
    if-eqz v7, :cond_14

    .line 237
    .line 238
    if-nez v1, :cond_d

    .line 239
    .line 240
    move-object v8, p2

    .line 241
    check-cast v8, Lin/v1;

    .line 242
    .line 243
    iget v8, v8, Lin/v1;->a:F

    .line 244
    .line 245
    goto :goto_3

    .line 246
    :cond_d
    iget-object v8, v2, Lin/n1;->n:Ljava/util/ArrayList;

    .line 247
    .line 248
    invoke-virtual {v8, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v8

    .line 252
    check-cast v8, Lin/e0;

    .line 253
    .line 254
    invoke-virtual {v8, p0}, Lin/e0;->d(Lin/z1;)F

    .line 255
    .line 256
    .line 257
    move-result v8

    .line 258
    :goto_3
    iget-object v9, v2, Lin/n1;->o:Ljava/util/ArrayList;

    .line 259
    .line 260
    if-eqz v9, :cond_f

    .line 261
    .line 262
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 263
    .line 264
    .line 265
    move-result v9

    .line 266
    if-nez v9, :cond_e

    .line 267
    .line 268
    goto :goto_4

    .line 269
    :cond_e
    iget-object v9, v2, Lin/n1;->o:Ljava/util/ArrayList;

    .line 270
    .line 271
    invoke-virtual {v9, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v9

    .line 275
    check-cast v9, Lin/e0;

    .line 276
    .line 277
    invoke-virtual {v9, p0}, Lin/e0;->e(Lin/z1;)F

    .line 278
    .line 279
    .line 280
    move-result v9

    .line 281
    goto :goto_5

    .line 282
    :cond_f
    :goto_4
    move-object v9, p2

    .line 283
    check-cast v9, Lin/v1;

    .line 284
    .line 285
    iget v9, v9, Lin/v1;->b:F

    .line 286
    .line 287
    :goto_5
    iget-object v10, v2, Lin/n1;->p:Ljava/util/ArrayList;

    .line 288
    .line 289
    if-eqz v10, :cond_11

    .line 290
    .line 291
    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    .line 292
    .line 293
    .line 294
    move-result v10

    .line 295
    if-nez v10, :cond_10

    .line 296
    .line 297
    goto :goto_6

    .line 298
    :cond_10
    iget-object v10, v2, Lin/n1;->p:Ljava/util/ArrayList;

    .line 299
    .line 300
    invoke-virtual {v10, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v10

    .line 304
    check-cast v10, Lin/e0;

    .line 305
    .line 306
    invoke-virtual {v10, p0}, Lin/e0;->d(Lin/z1;)F

    .line 307
    .line 308
    .line 309
    move-result v10

    .line 310
    goto :goto_7

    .line 311
    :cond_11
    :goto_6
    move v10, v6

    .line 312
    :goto_7
    iget-object v11, v2, Lin/n1;->q:Ljava/util/ArrayList;

    .line 313
    .line 314
    if-eqz v11, :cond_13

    .line 315
    .line 316
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 317
    .line 318
    .line 319
    move-result v11

    .line 320
    if-nez v11, :cond_12

    .line 321
    .line 322
    goto :goto_8

    .line 323
    :cond_12
    iget-object v6, v2, Lin/n1;->q:Ljava/util/ArrayList;

    .line 324
    .line 325
    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v6

    .line 329
    check-cast v6, Lin/e0;

    .line 330
    .line 331
    invoke-virtual {v6, p0}, Lin/e0;->e(Lin/z1;)F

    .line 332
    .line 333
    .line 334
    move-result v6

    .line 335
    :cond_13
    :goto_8
    move v12, v8

    .line 336
    move v8, v6

    .line 337
    move v6, v12

    .line 338
    goto :goto_9

    .line 339
    :cond_14
    move v8, v6

    .line 340
    move v9, v8

    .line 341
    move v10, v9

    .line 342
    :goto_9
    if-eqz v1, :cond_16

    .line 343
    .line 344
    invoke-virtual {p0}, Lin/z1;->F()I

    .line 345
    .line 346
    .line 347
    move-result v1

    .line 348
    if-eq v1, v0, :cond_16

    .line 349
    .line 350
    invoke-virtual {p0, v2}, Lin/z1;->l(Lin/l1;)F

    .line 351
    .line 352
    .line 353
    move-result v11

    .line 354
    if-ne v1, v5, :cond_15

    .line 355
    .line 356
    div-float/2addr v11, v3

    .line 357
    :cond_15
    sub-float/2addr v6, v11

    .line 358
    :cond_16
    iget-object v1, v2, Lin/i1;->r:Lin/j1;

    .line 359
    .line 360
    invoke-virtual {p0, v1}, Lin/z1;->o(Lin/x0;)V

    .line 361
    .line 362
    .line 363
    if-eqz v7, :cond_17

    .line 364
    .line 365
    move-object v1, p2

    .line 366
    check-cast v1, Lin/v1;

    .line 367
    .line 368
    add-float/2addr v6, v10

    .line 369
    iput v6, v1, Lin/v1;->a:F

    .line 370
    .line 371
    add-float/2addr v9, v8

    .line 372
    iput v9, v1, Lin/v1;->b:F

    .line 373
    .line 374
    :cond_17
    invoke-virtual {p0}, Lin/z1;->S()Z

    .line 375
    .line 376
    .line 377
    move-result v1

    .line 378
    invoke-virtual {p0, v2, p2}, Lin/z1;->v(Lin/l1;Llp/pa;)V

    .line 379
    .line 380
    .line 381
    if-eqz v1, :cond_18

    .line 382
    .line 383
    iget-object v1, v2, Lin/x0;->h:Ld3/a;

    .line 384
    .line 385
    invoke-virtual {p0, v1}, Lin/z1;->R(Ld3/a;)V

    .line 386
    .line 387
    .line 388
    :cond_18
    invoke-virtual {p0}, Lin/z1;->e0()V

    .line 389
    .line 390
    .line 391
    goto :goto_b

    .line 392
    :cond_19
    instance-of v1, v2, Lin/h1;

    .line 393
    .line 394
    if-eqz v1, :cond_1c

    .line 395
    .line 396
    invoke-virtual {p0}, Lin/z1;->f0()V

    .line 397
    .line 398
    .line 399
    move-object v1, v2

    .line 400
    check-cast v1, Lin/h1;

    .line 401
    .line 402
    iget-object v3, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 403
    .line 404
    check-cast v3, Lin/x1;

    .line 405
    .line 406
    invoke-virtual {p0, v3, v1}, Lin/z1;->k0(Lin/x1;Lin/y0;)V

    .line 407
    .line 408
    .line 409
    invoke-virtual {p0}, Lin/z1;->s()Z

    .line 410
    .line 411
    .line 412
    move-result v3

    .line 413
    if-eqz v3, :cond_1b

    .line 414
    .line 415
    iget-object v3, v1, Lin/h1;->o:Lin/j1;

    .line 416
    .line 417
    invoke-virtual {p0, v3}, Lin/z1;->o(Lin/x0;)V

    .line 418
    .line 419
    .line 420
    iget-object v2, v2, Lin/a1;->a:Lil/g;

    .line 421
    .line 422
    iget-object v3, v1, Lin/h1;->n:Ljava/lang/String;

    .line 423
    .line 424
    invoke-virtual {v2, v3}, Lil/g;->V(Ljava/lang/String;)Lin/y0;

    .line 425
    .line 426
    .line 427
    move-result-object v2

    .line 428
    if-eqz v2, :cond_1a

    .line 429
    .line 430
    instance-of v3, v2, Lin/l1;

    .line 431
    .line 432
    if-eqz v3, :cond_1a

    .line 433
    .line 434
    new-instance v1, Ljava/lang/StringBuilder;

    .line 435
    .line 436
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 437
    .line 438
    .line 439
    check-cast v2, Lin/l1;

    .line 440
    .line 441
    invoke-virtual {p0, v2, v1}, Lin/z1;->x(Lin/l1;Ljava/lang/StringBuilder;)V

    .line 442
    .line 443
    .line 444
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->length()I

    .line 445
    .line 446
    .line 447
    move-result v2

    .line 448
    if-lez v2, :cond_1b

    .line 449
    .line 450
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 451
    .line 452
    .line 453
    move-result-object v1

    .line 454
    invoke-virtual {p2, v1}, Llp/pa;->d(Ljava/lang/String;)V

    .line 455
    .line 456
    .line 457
    goto :goto_a

    .line 458
    :cond_1a
    iget-object v1, v1, Lin/h1;->n:Ljava/lang/String;

    .line 459
    .line 460
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 461
    .line 462
    .line 463
    move-result-object v1

    .line 464
    const-string v2, "Tref reference \'%s\' not found"

    .line 465
    .line 466
    invoke-static {v2, v1}, Lin/z1;->w(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 467
    .line 468
    .line 469
    :cond_1b
    :goto_a
    invoke-virtual {p0}, Lin/z1;->e0()V

    .line 470
    .line 471
    .line 472
    :cond_1c
    :goto_b
    move v1, v4

    .line 473
    goto/16 :goto_0

    .line 474
    .line 475
    :cond_1d
    :goto_c
    return-void
.end method

.method public x(Lin/l1;Ljava/lang/StringBuilder;)V
    .locals 4

    .line 1
    iget-object p1, p1, Lin/v0;->i:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v0, 0x1

    .line 8
    move v1, v0

    .line 9
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-eqz v2, :cond_2

    .line 14
    .line 15
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Lin/a1;

    .line 20
    .line 21
    instance-of v3, v2, Lin/l1;

    .line 22
    .line 23
    if-eqz v3, :cond_0

    .line 24
    .line 25
    check-cast v2, Lin/l1;

    .line 26
    .line 27
    invoke-virtual {p0, v2, p2}, Lin/z1;->x(Lin/l1;Ljava/lang/StringBuilder;)V

    .line 28
    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_0
    instance-of v3, v2, Lin/o1;

    .line 32
    .line 33
    if-eqz v3, :cond_1

    .line 34
    .line 35
    check-cast v2, Lin/o1;

    .line 36
    .line 37
    iget-object v2, v2, Lin/o1;->c:Ljava/lang/String;

    .line 38
    .line 39
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    xor-int/2addr v3, v0

    .line 44
    invoke-virtual {p0, v2, v1, v3}, Lin/z1;->g0(Ljava/lang/String;ZZ)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    :cond_1
    :goto_1
    const/4 v1, 0x0

    .line 52
    goto :goto_0

    .line 53
    :cond_2
    return-void
.end method

.method public y(Laq/t;)Laq/t;
    .locals 2

    .line 1
    new-instance v0, Lha/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lha/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Lc1/y;

    .line 8
    .line 9
    invoke-direct {v1, p0}, Lc1/y;-><init>(Lin/z1;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1, v0, v1}, Laq/t;->m(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
