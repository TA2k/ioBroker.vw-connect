.class public final Ljn/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final synthetic a:Ll2/b1;


# direct methods
.method public constructor <init>(Ll2/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljn/k;->a:Ll2/b1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lt3/t;Ljava/util/List;I)I
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lt3/q0;->h(Ljn/k;Lt3/t;Ljava/util/List;I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 2

    .line 1
    const-string v0, "$this$Layout"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "measurables"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p2, Ljava/lang/Iterable;

    .line 12
    .line 13
    new-instance v0, Ljava/util/ArrayList;

    .line 14
    .line 15
    const/16 v1, 0xa

    .line 16
    .line 17
    invoke-static {p2, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_0

    .line 33
    .line 34
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    check-cast v1, Lt3/p0;

    .line 39
    .line 40
    invoke-interface {v1, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    const/4 p2, 0x1

    .line 49
    invoke-static {v0, p2}, Lmx0/q;->D(Ljava/lang/Iterable;I)Ljava/util/List;

    .line 50
    .line 51
    .line 52
    move-result-object p2

    .line 53
    invoke-static {p2}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    check-cast p2, Lt3/e1;

    .line 58
    .line 59
    iget p2, p2, Lt3/e1;->d:I

    .line 60
    .line 61
    invoke-interface {p1, p2}, Lt4/c;->n0(I)F

    .line 62
    .line 63
    .line 64
    move-result p2

    .line 65
    new-instance p3, Lt4/f;

    .line 66
    .line 67
    invoke-direct {p3, p2}, Lt4/f;-><init>(F)V

    .line 68
    .line 69
    .line 70
    iget-object p0, p0, Ljn/k;->a:Ll2/b1;

    .line 71
    .line 72
    invoke-interface {p0, p3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Lt4/f;

    .line 80
    .line 81
    iget p0, p0, Lt4/f;->d:F

    .line 82
    .line 83
    invoke-interface {p1, p0}, Lt4/c;->w0(F)F

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    float-to-int p0, p0

    .line 88
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 89
    .line 90
    .line 91
    move-result-object p2

    .line 92
    const/4 p3, 0x0

    .line 93
    :goto_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 94
    .line 95
    .line 96
    move-result p4

    .line 97
    if-eqz p4, :cond_1

    .line 98
    .line 99
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p4

    .line 103
    check-cast p4, Lt3/e1;

    .line 104
    .line 105
    iget p4, p4, Lt3/e1;->e:I

    .line 106
    .line 107
    add-int/2addr p3, p4

    .line 108
    goto :goto_1

    .line 109
    :cond_1
    new-instance p2, Lb1/u;

    .line 110
    .line 111
    const/4 p4, 0x1

    .line 112
    invoke-direct {p2, v0, p4}, Lb1/u;-><init>(Ljava/util/ArrayList;I)V

    .line 113
    .line 114
    .line 115
    sget-object p4, Lmx0/t;->d:Lmx0/t;

    .line 116
    .line 117
    invoke-interface {p1, p0, p3, p4, p2}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    return-object p0
.end method

.method public final c(Lt3/t;Ljava/util/List;I)I
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lt3/q0;->j(Ljn/k;Lt3/t;Ljava/util/List;I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final d(Lt3/t;Ljava/util/List;I)I
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lt3/q0;->n(Ljn/k;Lt3/t;Ljava/util/List;I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final e(Lt3/t;Ljava/util/List;I)I
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lt3/q0;->g(Ljn/k;Lt3/t;Ljava/util/List;I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method
