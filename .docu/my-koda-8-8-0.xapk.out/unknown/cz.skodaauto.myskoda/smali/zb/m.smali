.class public final Lzb/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# static fields
.field public static final a:Lzb/m;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lzb/m;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lzb/m;->a:Lzb/m;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 9

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
    move-object v0, p2

    .line 21
    check-cast v0, Ljava/util/Collection;

    .line 22
    .line 23
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    const/4 v1, 0x0

    .line 28
    move v2, v1

    .line 29
    :goto_0
    if-ge v2, v0, :cond_0

    .line 30
    .line 31
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    check-cast v3, Lt3/p0;

    .line 36
    .line 37
    invoke-interface {v3, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    add-int/lit8 v2, v2, 0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    const/4 v0, 0x0

    .line 52
    const/4 v2, 0x1

    .line 53
    if-eqz p2, :cond_1

    .line 54
    .line 55
    move-object p2, v0

    .line 56
    goto :goto_2

    .line 57
    :cond_1
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    move-object v3, p2

    .line 62
    check-cast v3, Lt3/e1;

    .line 63
    .line 64
    iget v3, v3, Lt3/e1;->d:I

    .line 65
    .line 66
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 67
    .line 68
    .line 69
    move-result v4

    .line 70
    if-gt v2, v4, :cond_3

    .line 71
    .line 72
    move v5, v2

    .line 73
    :goto_1
    invoke-virtual {p0, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v6

    .line 77
    move-object v7, v6

    .line 78
    check-cast v7, Lt3/e1;

    .line 79
    .line 80
    iget v7, v7, Lt3/e1;->d:I

    .line 81
    .line 82
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->g(II)I

    .line 83
    .line 84
    .line 85
    move-result v8

    .line 86
    if-gez v8, :cond_2

    .line 87
    .line 88
    move-object p2, v6

    .line 89
    move v3, v7

    .line 90
    :cond_2
    if-eq v5, v4, :cond_3

    .line 91
    .line 92
    add-int/lit8 v5, v5, 0x1

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :cond_3
    :goto_2
    check-cast p2, Lt3/e1;

    .line 96
    .line 97
    if-eqz p2, :cond_4

    .line 98
    .line 99
    iget p2, p2, Lt3/e1;->d:I

    .line 100
    .line 101
    goto :goto_3

    .line 102
    :cond_4
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 103
    .line 104
    .line 105
    move-result p2

    .line 106
    :goto_3
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 107
    .line 108
    .line 109
    move-result v3

    .line 110
    if-eqz v3, :cond_5

    .line 111
    .line 112
    goto :goto_5

    .line 113
    :cond_5
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    move-object v1, v0

    .line 118
    check-cast v1, Lt3/e1;

    .line 119
    .line 120
    iget v1, v1, Lt3/e1;->e:I

    .line 121
    .line 122
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    if-gt v2, v3, :cond_7

    .line 127
    .line 128
    :goto_4
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v4

    .line 132
    move-object v5, v4

    .line 133
    check-cast v5, Lt3/e1;

    .line 134
    .line 135
    iget v5, v5, Lt3/e1;->e:I

    .line 136
    .line 137
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->g(II)I

    .line 138
    .line 139
    .line 140
    move-result v6

    .line 141
    if-gez v6, :cond_6

    .line 142
    .line 143
    move-object v0, v4

    .line 144
    move v1, v5

    .line 145
    :cond_6
    if-eq v2, v3, :cond_7

    .line 146
    .line 147
    add-int/lit8 v2, v2, 0x1

    .line 148
    .line 149
    goto :goto_4

    .line 150
    :cond_7
    :goto_5
    check-cast v0, Lt3/e1;

    .line 151
    .line 152
    if-eqz v0, :cond_8

    .line 153
    .line 154
    iget p3, v0, Lt3/e1;->e:I

    .line 155
    .line 156
    goto :goto_6

    .line 157
    :cond_8
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 158
    .line 159
    .line 160
    move-result p3

    .line 161
    :goto_6
    new-instance p4, Le2/j0;

    .line 162
    .line 163
    const/4 v0, 0x6

    .line 164
    invoke-direct {p4, p0, v0}, Le2/j0;-><init>(Ljava/util/ArrayList;I)V

    .line 165
    .line 166
    .line 167
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 168
    .line 169
    invoke-interface {p1, p2, p3, p0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    return-object p0
.end method
