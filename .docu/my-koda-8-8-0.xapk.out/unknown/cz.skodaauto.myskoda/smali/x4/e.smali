.class public final Lx4/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# static fields
.field public static final b:Lx4/e;

.field public static final c:Lx4/e;


# instance fields
.field public final synthetic a:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lx4/e;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lx4/e;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lx4/e;->b:Lx4/e;

    .line 8
    .line 9
    new-instance v0, Lx4/e;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lx4/e;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lx4/e;->c:Lx4/e;

    .line 16
    .line 17
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lx4/e;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 7

    .line 1
    iget p0, p0, Lx4/e;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    sget-object v0, Lmx0/t;->d:Lmx0/t;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    if-eqz p0, :cond_2

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    if-eq p0, v2, :cond_1

    .line 17
    .line 18
    new-instance p0, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    invoke-direct {p0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 25
    .line 26
    .line 27
    move-object v2, p2

    .line 28
    check-cast v2, Ljava/util/Collection;

    .line 29
    .line 30
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    move v3, v1

    .line 35
    move v4, v3

    .line 36
    :goto_0
    if-ge v1, v2, :cond_0

    .line 37
    .line 38
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v5

    .line 42
    check-cast v5, Lt3/p0;

    .line 43
    .line 44
    invoke-interface {v5, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    iget v6, v5, Lt3/e1;->d:I

    .line 49
    .line 50
    invoke-static {v3, v6}, Ljava/lang/Math;->max(II)I

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    iget v6, v5, Lt3/e1;->e:I

    .line 55
    .line 56
    invoke-static {v4, v6}, Ljava/lang/Math;->max(II)I

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    invoke-virtual {p0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    add-int/lit8 v1, v1, 0x1

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    new-instance p2, Lb1/u;

    .line 67
    .line 68
    const/4 p3, 0x5

    .line 69
    invoke-direct {p2, p0, p3}, Lb1/u;-><init>(Ljava/util/ArrayList;I)V

    .line 70
    .line 71
    .line 72
    invoke-interface {p1, v3, v4, v0, p2}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    goto :goto_1

    .line 77
    :cond_1
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    check-cast p0, Lt3/p0;

    .line 82
    .line 83
    invoke-interface {p0, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    iget p2, p0, Lt3/e1;->d:I

    .line 88
    .line 89
    iget p3, p0, Lt3/e1;->e:I

    .line 90
    .line 91
    new-instance p4, Lb1/y;

    .line 92
    .line 93
    const/4 v1, 0x6

    .line 94
    invoke-direct {p4, p0, v1}, Lb1/y;-><init>(Lt3/e1;I)V

    .line 95
    .line 96
    .line 97
    invoke-interface {p1, p2, p3, v0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    goto :goto_1

    .line 102
    :cond_2
    sget-object p0, Lx4/c;->k:Lx4/c;

    .line 103
    .line 104
    invoke-interface {p1, v1, v1, v0, p0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    :goto_1
    return-object p0

    .line 109
    :pswitch_0
    new-instance p0, Ljava/util/ArrayList;

    .line 110
    .line 111
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 116
    .line 117
    .line 118
    move-object v0, p2

    .line 119
    check-cast v0, Ljava/util/Collection;

    .line 120
    .line 121
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    const/4 v1, 0x0

    .line 126
    move v2, v1

    .line 127
    move v3, v2

    .line 128
    :goto_2
    if-ge v1, v0, :cond_3

    .line 129
    .line 130
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v4

    .line 134
    check-cast v4, Lt3/p0;

    .line 135
    .line 136
    invoke-interface {v4, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 137
    .line 138
    .line 139
    move-result-object v4

    .line 140
    iget v5, v4, Lt3/e1;->d:I

    .line 141
    .line 142
    invoke-static {v2, v5}, Ljava/lang/Math;->max(II)I

    .line 143
    .line 144
    .line 145
    move-result v2

    .line 146
    iget v5, v4, Lt3/e1;->e:I

    .line 147
    .line 148
    invoke-static {v3, v5}, Ljava/lang/Math;->max(II)I

    .line 149
    .line 150
    .line 151
    move-result v3

    .line 152
    invoke-virtual {p0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    add-int/lit8 v1, v1, 0x1

    .line 156
    .line 157
    goto :goto_2

    .line 158
    :cond_3
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 159
    .line 160
    .line 161
    move-result p2

    .line 162
    if-eqz p2, :cond_4

    .line 163
    .line 164
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 165
    .line 166
    .line 167
    move-result v2

    .line 168
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 169
    .line 170
    .line 171
    move-result v3

    .line 172
    :cond_4
    new-instance p2, Lb1/u;

    .line 173
    .line 174
    const/4 p3, 0x4

    .line 175
    invoke-direct {p2, p0, p3}, Lb1/u;-><init>(Ljava/util/ArrayList;I)V

    .line 176
    .line 177
    .line 178
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 179
    .line 180
    invoke-interface {p1, v2, v3, p0, p2}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    return-object p0

    .line 185
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
