.class public final Llw/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ldy0/c;


# static fields
.field public static final e:Lfv/b;


# instance fields
.field public d:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfv/b;

    .line 2
    .line 3
    const/16 v1, 0xd

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Llw/k;->e:Lfv/b;

    .line 9
    .line 10
    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Llw/k;->d:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a(Lkw/g;DDFFI)Ljava/util/List;
    .locals 9

    .line 1
    iget-object p0, p0, Llw/k;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lay0/k;

    .line 4
    .line 5
    invoke-interface {p1}, Lkw/g;->g()Lmw/a;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v0, v0, Lmw/a;->c:Lrw/b;

    .line 10
    .line 11
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Ljava/lang/Double;

    .line 16
    .line 17
    if-eqz p0, :cond_1

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Number;->doubleValue()D

    .line 20
    .line 21
    .line 22
    move-result-wide v0

    .line 23
    const-wide/16 v2, 0x0

    .line 24
    .line 25
    cmpl-double v0, v0, v2

    .line 26
    .line 27
    if-lez v0, :cond_0

    .line 28
    .line 29
    :goto_0
    move-object v0, p0

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 32
    .line 33
    const-string p1, "`step` must return a positive value."

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_1
    const/4 p0, 0x0

    .line 40
    goto :goto_0

    .line 41
    :goto_1
    invoke-interface {p1}, Lpw/f;->i()Lc2/k;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-static {p4, p5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    invoke-static {p6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    invoke-static/range {p7 .. p7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    invoke-static/range {p8 .. p8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    filled-new-array/range {v0 .. v5}, [Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    new-instance v1, Llw/j;

    .line 70
    .line 71
    move-object v2, v1

    .line 72
    move-object v1, v0

    .line 73
    move-object v0, v2

    .line 74
    move-wide v5, p2

    .line 75
    move-wide v2, p4

    .line 76
    move v7, p6

    .line 77
    move/from16 v4, p7

    .line 78
    .line 79
    move/from16 v8, p8

    .line 80
    .line 81
    invoke-direct/range {v0 .. v8}, Llw/j;-><init>(Ljava/lang/Double;DFDFI)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    array-length p2, p1

    .line 88
    invoke-static {p1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p2

    .line 92
    sget-object p3, Llw/k;->e:Lfv/b;

    .line 93
    .line 94
    invoke-virtual {p0, p3, p2}, Lc2/k;->w(Lfv/b;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p2

    .line 98
    if-nez p2, :cond_2

    .line 99
    .line 100
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p2

    .line 104
    array-length v0, p1

    .line 105
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    invoke-virtual {p0, p3, p1, p2}, Lc2/k;->A(Lfv/b;[Ljava/lang/Object;Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    :cond_2
    check-cast p2, Ljava/util/List;

    .line 113
    .line 114
    return-object p2
.end method

.method public b(Lkw/g;FFLlw/e;)Ljava/util/ArrayList;
    .locals 11

    .line 1
    const-string v0, "position"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Llw/k;->d:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v0, p0

    .line 9
    check-cast v0, Llw/k;

    .line 10
    .line 11
    invoke-interface {p1}, Lkw/g;->j()Lmw/b;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-interface {p0, p4}, Lmw/b;->e(Llw/e;)Lmw/k;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    iget-wide v1, p0, Lmw/k;->a:D

    .line 20
    .line 21
    iget-wide v3, p0, Lmw/k;->b:D

    .line 22
    .line 23
    mul-double/2addr v1, v3

    .line 24
    const-wide/16 v9, 0x0

    .line 25
    .line 26
    cmpl-double p0, v1, v9

    .line 27
    .line 28
    if-ltz p0, :cond_1

    .line 29
    .line 30
    invoke-interface {p1}, Lkw/g;->j()Lmw/b;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-interface {p0, p4}, Lmw/b;->e(Llw/e;)Lmw/k;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    iget-wide v4, p0, Lmw/k;->b:D

    .line 39
    .line 40
    cmpl-double p4, v4, v9

    .line 41
    .line 42
    if-lez p4, :cond_0

    .line 43
    .line 44
    iget-wide v2, p0, Lmw/k;->a:D

    .line 45
    .line 46
    const/4 v8, 0x1

    .line 47
    move-object v1, p1

    .line 48
    move v6, p2

    .line 49
    move v7, p3

    .line 50
    invoke-virtual/range {v0 .. v8}, Llw/k;->a(Lkw/g;DDFFI)Ljava/util/List;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    check-cast p1, Ljava/util/Collection;

    .line 55
    .line 56
    iget-wide p2, p0, Lmw/k;->a:D

    .line 57
    .line 58
    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-static {p1, p0}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0

    .line 67
    :cond_0
    move-object v1, p1

    .line 68
    move v6, p2

    .line 69
    move v7, p3

    .line 70
    invoke-static {v4, v5}, Ljava/lang/Math;->abs(D)D

    .line 71
    .line 72
    .line 73
    move-result-wide v2

    .line 74
    iget-wide p1, p0, Lmw/k;->a:D

    .line 75
    .line 76
    invoke-static {p1, p2}, Ljava/lang/Math;->abs(D)D

    .line 77
    .line 78
    .line 79
    move-result-wide v4

    .line 80
    const/4 v8, -0x1

    .line 81
    invoke-virtual/range {v0 .. v8}, Llw/k;->a(Lkw/g;DDFFI)Ljava/util/List;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    check-cast p1, Ljava/util/Collection;

    .line 86
    .line 87
    iget-wide p2, p0, Lmw/k;->b:D

    .line 88
    .line 89
    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-static {p1, p0}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    return-object p0

    .line 98
    :cond_1
    move-object v1, p1

    .line 99
    move p0, p2

    .line 100
    move v7, p3

    .line 101
    invoke-interface {v1}, Lkw/g;->j()Lmw/b;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    invoke-interface {p1, p4}, Lmw/b;->e(Llw/e;)Lmw/k;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    iget-wide v4, p1, Lmw/k;->b:D

    .line 110
    .line 111
    invoke-virtual {p1}, Lmw/k;->a()D

    .line 112
    .line 113
    .line 114
    move-result-wide p2

    .line 115
    div-double p2, v4, p2

    .line 116
    .line 117
    double-to-float p2, p2

    .line 118
    mul-float v6, p2, p0

    .line 119
    .line 120
    const/4 v8, 0x1

    .line 121
    const-wide/16 v2, 0x0

    .line 122
    .line 123
    invoke-virtual/range {v0 .. v8}, Llw/k;->a(Lkw/g;DDFFI)Ljava/util/List;

    .line 124
    .line 125
    .line 126
    move-result-object p2

    .line 127
    iget-wide p3, p1, Lmw/k;->a:D

    .line 128
    .line 129
    invoke-static {p3, p4}, Ljava/lang/Math;->abs(D)D

    .line 130
    .line 131
    .line 132
    move-result-wide v4

    .line 133
    iget-wide p3, p1, Lmw/k;->a:D

    .line 134
    .line 135
    neg-double p3, p3

    .line 136
    invoke-virtual {p1}, Lmw/k;->a()D

    .line 137
    .line 138
    .line 139
    move-result-wide v2

    .line 140
    div-double/2addr p3, v2

    .line 141
    double-to-float p1, p3

    .line 142
    mul-float v6, p1, p0

    .line 143
    .line 144
    const/4 v8, -0x1

    .line 145
    const-wide/16 v2, 0x0

    .line 146
    .line 147
    invoke-virtual/range {v0 .. v8}, Llw/k;->a(Lkw/g;DDFFI)Ljava/util/List;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    check-cast p2, Ljava/util/Collection;

    .line 152
    .line 153
    check-cast p0, Ljava/lang/Iterable;

    .line 154
    .line 155
    invoke-static {p0, p2}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    invoke-static {p0, p1}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    return-object p0
.end method

.method public getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Llw/g;

    .line 2
    .line 3
    const-string v0, "thisRef"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p1, "property"

    .line 9
    .line 10
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Llw/k;->d:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Llw/i;

    .line 16
    .line 17
    return-object p0
.end method

.method public setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p1, Llw/g;

    .line 2
    .line 3
    check-cast p3, Llw/i;

    .line 4
    .line 5
    const-string v0, "thisRef"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object p1, p1, Llw/g;->a:Ljava/util/ArrayList;

    .line 11
    .line 12
    const-string v0, "property"

    .line 13
    .line 14
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object p2, p0, Llw/k;->d:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p2, Llw/i;

    .line 20
    .line 21
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    if-eqz p2, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    iget-object p2, p0, Llw/k;->d:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p2, Llw/i;

    .line 31
    .line 32
    if-eqz p2, :cond_1

    .line 33
    .line 34
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    :cond_1
    iput-object p3, p0, Llw/k;->d:Ljava/lang/Object;

    .line 38
    .line 39
    if-eqz p3, :cond_2

    .line 40
    .line 41
    invoke-virtual {p1, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    :cond_2
    :goto_0
    return-void
.end method
