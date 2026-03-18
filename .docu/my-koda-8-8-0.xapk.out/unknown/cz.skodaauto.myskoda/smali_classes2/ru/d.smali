.class public final Lru/d;
.super Lru/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lru/f;


# static fields
.field public static final l:Lyu/b;


# instance fields
.field public i:I

.field public j:I

.field public k:Lcom/google/android/gms/maps/model/LatLng;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lyu/b;

    .line 2
    .line 3
    const-wide/high16 v1, 0x3ff0000000000000L    # 1.0

    .line 4
    .line 5
    invoke-direct {v0, v1, v2}, Lyu/b;-><init>(D)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lru/d;->l:Lyu/b;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final b0(Lzu/a;F)Ljava/util/Collection;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lru/d;->k:Lcom/google/android/gms/maps/model/LatLng;

    .line 6
    .line 7
    if-nez v2, :cond_0

    .line 8
    .line 9
    new-instance v3, Lxu/a;

    .line 10
    .line 11
    const-wide/16 v8, 0x0

    .line 12
    .line 13
    const-wide/16 v10, 0x0

    .line 14
    .line 15
    const-wide/16 v4, 0x0

    .line 16
    .line 17
    const-wide/16 v6, 0x0

    .line 18
    .line 19
    invoke-direct/range {v3 .. v11}, Lxu/a;-><init>(DDDD)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    sget-object v3, Lru/d;->l:Lyu/b;

    .line 24
    .line 25
    invoke-virtual {v3, v2}, Lyu/b;->b(Lcom/google/android/gms/maps/model/LatLng;)Lyu/a;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    iget v3, v0, Lru/d;->i:I

    .line 30
    .line 31
    int-to-double v3, v3

    .line 32
    move/from16 v5, p2

    .line 33
    .line 34
    float-to-double v5, v5

    .line 35
    const-wide/high16 v7, 0x4000000000000000L    # 2.0

    .line 36
    .line 37
    invoke-static {v7, v8, v5, v6}, Ljava/lang/Math;->pow(DD)D

    .line 38
    .line 39
    .line 40
    move-result-wide v9

    .line 41
    div-double/2addr v3, v9

    .line 42
    const-wide/high16 v9, 0x4070000000000000L    # 256.0

    .line 43
    .line 44
    div-double/2addr v3, v9

    .line 45
    div-double/2addr v3, v7

    .line 46
    iget v0, v0, Lru/d;->j:I

    .line 47
    .line 48
    int-to-double v11, v0

    .line 49
    invoke-static {v7, v8, v5, v6}, Ljava/lang/Math;->pow(DD)D

    .line 50
    .line 51
    .line 52
    move-result-wide v5

    .line 53
    div-double/2addr v11, v5

    .line 54
    div-double/2addr v11, v9

    .line 55
    div-double/2addr v11, v7

    .line 56
    new-instance v13, Lxu/a;

    .line 57
    .line 58
    iget-wide v5, v2, Lyu/a;->a:D

    .line 59
    .line 60
    sub-double v14, v5, v3

    .line 61
    .line 62
    add-double v16, v5, v3

    .line 63
    .line 64
    iget-wide v2, v2, Lyu/a;->b:D

    .line 65
    .line 66
    sub-double v18, v2, v11

    .line 67
    .line 68
    add-double v20, v2, v11

    .line 69
    .line 70
    invoke-direct/range {v13 .. v21}, Lxu/a;-><init>(DDDD)V

    .line 71
    .line 72
    .line 73
    move-object v3, v13

    .line 74
    :goto_0
    new-instance v0, Ljava/util/ArrayList;

    .line 75
    .line 76
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 77
    .line 78
    .line 79
    const-wide/16 v4, 0x0

    .line 80
    .line 81
    iget-wide v6, v3, Lxu/a;->a:D

    .line 82
    .line 83
    cmpg-double v2, v6, v4

    .line 84
    .line 85
    const-wide/high16 v4, 0x3ff0000000000000L    # 1.0

    .line 86
    .line 87
    if-gez v2, :cond_1

    .line 88
    .line 89
    new-instance v8, Lxu/a;

    .line 90
    .line 91
    add-double v9, v6, v4

    .line 92
    .line 93
    iget-wide v13, v3, Lxu/a;->b:D

    .line 94
    .line 95
    iget-wide v6, v3, Lxu/a;->d:D

    .line 96
    .line 97
    const-wide/high16 v11, 0x3ff0000000000000L    # 1.0

    .line 98
    .line 99
    move-wide v15, v6

    .line 100
    invoke-direct/range {v8 .. v16}, Lxu/a;-><init>(DDDD)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    new-instance v2, Ljava/util/ArrayList;

    .line 107
    .line 108
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v1, v8, v2}, Lzu/a;->b(Lxu/a;Ljava/util/ArrayList;)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 115
    .line 116
    .line 117
    new-instance v9, Lxu/a;

    .line 118
    .line 119
    iget-wide v14, v3, Lxu/a;->b:D

    .line 120
    .line 121
    iget-wide v6, v3, Lxu/a;->d:D

    .line 122
    .line 123
    const-wide/16 v10, 0x0

    .line 124
    .line 125
    iget-wide v12, v3, Lxu/a;->c:D

    .line 126
    .line 127
    move-wide/from16 v16, v6

    .line 128
    .line 129
    invoke-direct/range {v9 .. v17}, Lxu/a;-><init>(DDDD)V

    .line 130
    .line 131
    .line 132
    move-object v3, v9

    .line 133
    :cond_1
    iget-wide v6, v3, Lxu/a;->c:D

    .line 134
    .line 135
    cmpl-double v2, v6, v4

    .line 136
    .line 137
    if-lez v2, :cond_2

    .line 138
    .line 139
    new-instance v8, Lxu/a;

    .line 140
    .line 141
    sub-double v11, v6, v4

    .line 142
    .line 143
    iget-wide v13, v3, Lxu/a;->b:D

    .line 144
    .line 145
    iget-wide v4, v3, Lxu/a;->d:D

    .line 146
    .line 147
    const-wide/16 v9, 0x0

    .line 148
    .line 149
    move-wide v15, v4

    .line 150
    invoke-direct/range {v8 .. v16}, Lxu/a;-><init>(DDDD)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    new-instance v2, Ljava/util/ArrayList;

    .line 157
    .line 158
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v1, v8, v2}, Lzu/a;->b(Lxu/a;Ljava/util/ArrayList;)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 165
    .line 166
    .line 167
    new-instance v9, Lxu/a;

    .line 168
    .line 169
    iget-wide v14, v3, Lxu/a;->b:D

    .line 170
    .line 171
    iget-wide v4, v3, Lxu/a;->d:D

    .line 172
    .line 173
    iget-wide v10, v3, Lxu/a;->a:D

    .line 174
    .line 175
    const-wide/high16 v12, 0x3ff0000000000000L    # 1.0

    .line 176
    .line 177
    move-wide/from16 v16, v4

    .line 178
    .line 179
    invoke-direct/range {v9 .. v17}, Lxu/a;-><init>(DDDD)V

    .line 180
    .line 181
    .line 182
    move-object v3, v9

    .line 183
    :cond_2
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 184
    .line 185
    .line 186
    new-instance v2, Ljava/util/ArrayList;

    .line 187
    .line 188
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v1, v3, v2}, Lzu/a;->b(Lxu/a;Ljava/util/ArrayList;)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 195
    .line 196
    .line 197
    return-object v0
.end method

.method public final c(Lcom/google/android/gms/maps/model/CameraPosition;)V
    .locals 0

    .line 1
    iget-object p1, p1, Lcom/google/android/gms/maps/model/CameraPosition;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 2
    .line 3
    iput-object p1, p0, Lru/d;->k:Lcom/google/android/gms/maps/model/LatLng;

    .line 4
    .line 5
    return-void
.end method

.method public final k()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method
