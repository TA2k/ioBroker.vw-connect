.class public final Lkn/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# static fields
.field public static final a:Lkn/h0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lkn/h0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lkn/h0;->a:Lkn/h0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 8

    .line 1
    const-string p0, "$this$Layout"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "measurables"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/4 v1, 0x0

    .line 25
    move v2, v1

    .line 26
    :goto_0
    if-ge v2, v0, :cond_0

    .line 27
    .line 28
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    check-cast v3, Lt3/p0;

    .line 33
    .line 34
    invoke-interface {v3, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    add-int/lit8 v2, v2, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    const/4 v0, 0x0

    .line 49
    const/4 v2, 0x1

    .line 50
    if-eqz p2, :cond_1

    .line 51
    .line 52
    move-object p2, v0

    .line 53
    goto :goto_2

    .line 54
    :cond_1
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    move-object v3, p2

    .line 59
    check-cast v3, Lt3/e1;

    .line 60
    .line 61
    iget v3, v3, Lt3/e1;->d:I

    .line 62
    .line 63
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    if-gt v2, v4, :cond_3

    .line 68
    .line 69
    move v5, v2

    .line 70
    :goto_1
    invoke-virtual {p0, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v6

    .line 74
    move-object v7, v6

    .line 75
    check-cast v7, Lt3/e1;

    .line 76
    .line 77
    iget v7, v7, Lt3/e1;->d:I

    .line 78
    .line 79
    if-ge v3, v7, :cond_2

    .line 80
    .line 81
    move-object p2, v6

    .line 82
    move v3, v7

    .line 83
    :cond_2
    if-eq v5, v4, :cond_3

    .line 84
    .line 85
    add-int/lit8 v5, v5, 0x1

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_3
    :goto_2
    check-cast p2, Lt3/e1;

    .line 89
    .line 90
    if-eqz p2, :cond_4

    .line 91
    .line 92
    iget p2, p2, Lt3/e1;->d:I

    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_4
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 96
    .line 97
    .line 98
    move-result p2

    .line 99
    :goto_3
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    if-eqz v3, :cond_5

    .line 104
    .line 105
    goto :goto_5

    .line 106
    :cond_5
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    move-object v1, v0

    .line 111
    check-cast v1, Lt3/e1;

    .line 112
    .line 113
    iget v1, v1, Lt3/e1;->e:I

    .line 114
    .line 115
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 116
    .line 117
    .line 118
    move-result v3

    .line 119
    if-gt v2, v3, :cond_7

    .line 120
    .line 121
    :goto_4
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    move-object v5, v4

    .line 126
    check-cast v5, Lt3/e1;

    .line 127
    .line 128
    iget v5, v5, Lt3/e1;->e:I

    .line 129
    .line 130
    if-ge v1, v5, :cond_6

    .line 131
    .line 132
    move-object v0, v4

    .line 133
    move v1, v5

    .line 134
    :cond_6
    if-eq v2, v3, :cond_7

    .line 135
    .line 136
    add-int/lit8 v2, v2, 0x1

    .line 137
    .line 138
    goto :goto_4

    .line 139
    :cond_7
    :goto_5
    check-cast v0, Lt3/e1;

    .line 140
    .line 141
    if-eqz v0, :cond_8

    .line 142
    .line 143
    iget p3, v0, Lt3/e1;->e:I

    .line 144
    .line 145
    goto :goto_6

    .line 146
    :cond_8
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 147
    .line 148
    .line 149
    move-result p3

    .line 150
    :goto_6
    new-instance p4, Lb1/u;

    .line 151
    .line 152
    const/4 v0, 0x2

    .line 153
    invoke-direct {p4, p0, v0}, Lb1/u;-><init>(Ljava/util/ArrayList;I)V

    .line 154
    .line 155
    .line 156
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 157
    .line 158
    invoke-interface {p1, p2, p3, p0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    return-object p0
.end method
