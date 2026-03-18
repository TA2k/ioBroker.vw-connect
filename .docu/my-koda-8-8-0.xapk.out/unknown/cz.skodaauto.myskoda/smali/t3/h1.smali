.class public final Lt3/h1;
.super Lv3/e0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lt3/h1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lt3/h1;

    .line 2
    .line 3
    const-string v1, "Undefined intrinsics block and it is required"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lv3/e0;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lt3/h1;->b:Lt3/h1;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 7

    .line 1
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    sget-object v0, Lmx0/t;->d:Lmx0/t;

    .line 6
    .line 7
    if-eqz p0, :cond_2

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    if-eq p0, v1, :cond_1

    .line 12
    .line 13
    new-instance p0, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-direct {p0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 20
    .line 21
    .line 22
    move-object v1, p2

    .line 23
    check-cast v1, Ljava/util/Collection;

    .line 24
    .line 25
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    move v3, v2

    .line 30
    move v4, v3

    .line 31
    :goto_0
    if-ge v2, v1, :cond_0

    .line 32
    .line 33
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    check-cast v5, Lt3/p0;

    .line 38
    .line 39
    invoke-interface {v5, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    iget v6, v5, Lt3/e1;->d:I

    .line 44
    .line 45
    invoke-static {v6, v3}, Ljava/lang/Math;->max(II)I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    iget v6, v5, Lt3/e1;->e:I

    .line 50
    .line 51
    invoke-static {v6, v4}, Ljava/lang/Math;->max(II)I

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    invoke-virtual {p0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    add-int/lit8 v2, v2, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    invoke-static {v3, p3, p4}, Lt4/b;->g(IJ)I

    .line 62
    .line 63
    .line 64
    move-result p2

    .line 65
    invoke-static {v4, p3, p4}, Lt4/b;->f(IJ)I

    .line 66
    .line 67
    .line 68
    move-result p3

    .line 69
    new-instance p4, Lb1/u;

    .line 70
    .line 71
    const/4 v1, 0x3

    .line 72
    invoke-direct {p4, p0, v1}, Lb1/u;-><init>(Ljava/util/ArrayList;I)V

    .line 73
    .line 74
    .line 75
    invoke-interface {p1, p2, p3, v0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    return-object p0

    .line 80
    :cond_1
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    check-cast p0, Lt3/p0;

    .line 85
    .line 86
    invoke-interface {p0, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    iget p2, p0, Lt3/e1;->d:I

    .line 91
    .line 92
    invoke-static {p2, p3, p4}, Lt4/b;->g(IJ)I

    .line 93
    .line 94
    .line 95
    move-result p2

    .line 96
    iget v1, p0, Lt3/e1;->e:I

    .line 97
    .line 98
    invoke-static {v1, p3, p4}, Lt4/b;->f(IJ)I

    .line 99
    .line 100
    .line 101
    move-result p3

    .line 102
    new-instance p4, Lb1/y;

    .line 103
    .line 104
    const/4 v1, 0x4

    .line 105
    invoke-direct {p4, p0, v1}, Lb1/y;-><init>(Lt3/e1;I)V

    .line 106
    .line 107
    .line 108
    invoke-interface {p1, p2, p3, v0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    return-object p0

    .line 113
    :cond_2
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 114
    .line 115
    .line 116
    move-result p0

    .line 117
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 118
    .line 119
    .line 120
    move-result p2

    .line 121
    sget-object p3, Lt3/f1;->h:Lt3/f1;

    .line 122
    .line 123
    invoke-interface {p1, p0, p2, v0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    return-object p0
.end method
