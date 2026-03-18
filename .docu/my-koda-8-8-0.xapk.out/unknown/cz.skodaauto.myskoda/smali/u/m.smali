.class public final Lu/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/y;


# instance fields
.field public final b:Lu/k;

.field public final c:Lj0/h;

.field public final d:Ljava/lang/Object;

.field public final e:Lv/b;

.field public final f:Lro/f;

.field public final g:Lh0/v1;

.field public final h:Lu/r0;

.field public final i:Lh8/o;

.field public final j:Lu/i1;

.field public final k:Lb6/f;

.field public final l:Lb6/f;

.field public final m:Lu/l1;

.field public final n:La0/e;

.field public final o:Lip/v;

.field public final p:Lt1/j0;

.field public q:I

.field public volatile r:I

.field public volatile s:I

.field public volatile t:I

.field public final u:Lk1/c0;

.field public final v:Ljava/util/concurrent/atomic/AtomicLong;

.field public w:I

.field public x:J

.field public final y:Lu/j;


# direct methods
.method public constructor <init>(Lv/b;Lj0/c;Lj0/h;Lro/f;Ld01/x;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lu/m;->d:Ljava/lang/Object;

    .line 10
    .line 11
    new-instance v0, Lh0/v1;

    .line 12
    .line 13
    invoke-direct {v0}, Lh0/u1;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lu/m;->g:Lh0/v1;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    iput v1, p0, Lu/m;->q:I

    .line 20
    .line 21
    iput v1, p0, Lu/m;->r:I

    .line 22
    .line 23
    const/4 v1, 0x2

    .line 24
    iput v1, p0, Lu/m;->t:I

    .line 25
    .line 26
    new-instance v1, Ljava/util/concurrent/atomic/AtomicLong;

    .line 27
    .line 28
    const-wide/16 v2, 0x0

    .line 29
    .line 30
    invoke-direct {v1, v2, v3}, Ljava/util/concurrent/atomic/AtomicLong;-><init>(J)V

    .line 31
    .line 32
    .line 33
    iput-object v1, p0, Lu/m;->v:Ljava/util/concurrent/atomic/AtomicLong;

    .line 34
    .line 35
    const/4 v1, 0x1

    .line 36
    iput v1, p0, Lu/m;->w:I

    .line 37
    .line 38
    iput-wide v2, p0, Lu/m;->x:J

    .line 39
    .line 40
    new-instance v1, Lu/j;

    .line 41
    .line 42
    invoke-direct {v1}, Lu/j;-><init>()V

    .line 43
    .line 44
    .line 45
    new-instance v2, Ljava/util/HashSet;

    .line 46
    .line 47
    invoke-direct {v2}, Ljava/util/HashSet;-><init>()V

    .line 48
    .line 49
    .line 50
    iput-object v2, v1, Lu/j;->b:Ljava/lang/Object;

    .line 51
    .line 52
    new-instance v2, Landroid/util/ArrayMap;

    .line 53
    .line 54
    invoke-direct {v2}, Landroid/util/ArrayMap;-><init>()V

    .line 55
    .line 56
    .line 57
    iput-object v2, v1, Lu/j;->c:Ljava/lang/Object;

    .line 58
    .line 59
    iput-object v1, p0, Lu/m;->y:Lu/j;

    .line 60
    .line 61
    iput-object p1, p0, Lu/m;->e:Lv/b;

    .line 62
    .line 63
    iput-object p4, p0, Lu/m;->f:Lro/f;

    .line 64
    .line 65
    iput-object p3, p0, Lu/m;->c:Lj0/h;

    .line 66
    .line 67
    new-instance p4, Lt1/j0;

    .line 68
    .line 69
    invoke-direct {p4, p3}, Lt1/j0;-><init>(Lj0/h;)V

    .line 70
    .line 71
    .line 72
    iput-object p4, p0, Lu/m;->p:Lt1/j0;

    .line 73
    .line 74
    new-instance p4, Lu/k;

    .line 75
    .line 76
    invoke-direct {p4, p3}, Lu/k;-><init>(Lj0/h;)V

    .line 77
    .line 78
    .line 79
    iput-object p4, p0, Lu/m;->b:Lu/k;

    .line 80
    .line 81
    iget v2, p0, Lu/m;->w:I

    .line 82
    .line 83
    iget-object v3, v0, Lh0/u1;->b:Lb0/n1;

    .line 84
    .line 85
    iput v2, v3, Lb0/n1;->d:I

    .line 86
    .line 87
    new-instance v2, Lu/l0;

    .line 88
    .line 89
    invoke-direct {v2, p4}, Lu/l0;-><init>(Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;)V

    .line 90
    .line 91
    .line 92
    iget-object p4, v0, Lh0/u1;->b:Lb0/n1;

    .line 93
    .line 94
    invoke-virtual {p4, v2}, Lb0/n1;->c(Lh0/m;)V

    .line 95
    .line 96
    .line 97
    iget-object p4, v0, Lh0/u1;->b:Lb0/n1;

    .line 98
    .line 99
    invoke-virtual {p4, v1}, Lb0/n1;->c(Lh0/m;)V

    .line 100
    .line 101
    .line 102
    new-instance p4, Lb6/f;

    .line 103
    .line 104
    invoke-direct {p4}, Ljava/lang/Object;-><init>()V

    .line 105
    .line 106
    .line 107
    const/4 v0, 0x0

    .line 108
    iput-boolean v0, p4, Lb6/f;->d:Z

    .line 109
    .line 110
    new-instance v0, Ld8/c;

    .line 111
    .line 112
    const/4 v1, 0x4

    .line 113
    invoke-direct {v0, v1}, Ld8/c;-><init>(I)V

    .line 114
    .line 115
    .line 116
    iput-object v0, p4, Lb6/f;->e:Ljava/lang/Object;

    .line 117
    .line 118
    iput-object p4, p0, Lu/m;->l:Lb6/f;

    .line 119
    .line 120
    new-instance p4, Lu/r0;

    .line 121
    .line 122
    invoke-direct {p4, p0, p3}, Lu/r0;-><init>(Lu/m;Lj0/h;)V

    .line 123
    .line 124
    .line 125
    iput-object p4, p0, Lu/m;->h:Lu/r0;

    .line 126
    .line 127
    new-instance p4, Lh8/o;

    .line 128
    .line 129
    invoke-direct {p4, p0, p1, p3}, Lh8/o;-><init>(Lu/m;Lv/b;Lj0/h;)V

    .line 130
    .line 131
    .line 132
    iput-object p4, p0, Lu/m;->i:Lh8/o;

    .line 133
    .line 134
    new-instance p4, Lu/i1;

    .line 135
    .line 136
    invoke-direct {p4, p0, p1, p3}, Lu/i1;-><init>(Lu/m;Lv/b;Lj0/h;)V

    .line 137
    .line 138
    .line 139
    iput-object p4, p0, Lu/m;->j:Lu/i1;

    .line 140
    .line 141
    invoke-virtual {p1}, Lv/b;->b()I

    .line 142
    .line 143
    .line 144
    move-result p4

    .line 145
    iput p4, p0, Lu/m;->s:I

    .line 146
    .line 147
    new-instance p4, Lb6/f;

    .line 148
    .line 149
    invoke-direct {p4}, Ljava/lang/Object;-><init>()V

    .line 150
    .line 151
    .line 152
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 153
    .line 154
    const/4 v1, -0x1

    .line 155
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 156
    .line 157
    .line 158
    new-instance v0, Ljava/lang/Object;

    .line 159
    .line 160
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 161
    .line 162
    .line 163
    iput-object v0, p4, Lb6/f;->e:Ljava/lang/Object;

    .line 164
    .line 165
    invoke-static {p1}, Lb6/f;->j(Lv/b;)Z

    .line 166
    .line 167
    .line 168
    move-result v0

    .line 169
    new-instance v2, Landroidx/lifecycle/i0;

    .line 170
    .line 171
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    invoke-direct {v2, v1}, Landroidx/lifecycle/g0;-><init>(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    new-instance v1, Lu/v0;

    .line 179
    .line 180
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 181
    .line 182
    .line 183
    if-eqz v0, :cond_0

    .line 184
    .line 185
    invoke-virtual {p0, v1}, Lu/m;->h(Lu/l;)V

    .line 186
    .line 187
    .line 188
    :cond_0
    iput-object p4, p0, Lu/m;->k:Lb6/f;

    .line 189
    .line 190
    new-instance p4, Lu/l1;

    .line 191
    .line 192
    invoke-direct {p4, p1, p3}, Lu/l1;-><init>(Lv/b;Lj0/h;)V

    .line 193
    .line 194
    .line 195
    iput-object p4, p0, Lu/m;->m:Lu/l1;

    .line 196
    .line 197
    new-instance p4, Lk1/c0;

    .line 198
    .line 199
    const/4 v0, 0x1

    .line 200
    invoke-direct {p4, p5, v0}, Lk1/c0;-><init>(Ld01/x;I)V

    .line 201
    .line 202
    .line 203
    iput-object p4, p0, Lu/m;->u:Lk1/c0;

    .line 204
    .line 205
    new-instance p4, La0/e;

    .line 206
    .line 207
    invoke-direct {p4, p0, p3}, La0/e;-><init>(Lu/m;Lj0/h;)V

    .line 208
    .line 209
    .line 210
    iput-object p4, p0, Lu/m;->n:La0/e;

    .line 211
    .line 212
    new-instance v0, Lip/v;

    .line 213
    .line 214
    move-object v1, p0

    .line 215
    move-object v2, p1

    .line 216
    move-object v5, p2

    .line 217
    move-object v4, p3

    .line 218
    move-object v3, p5

    .line 219
    invoke-direct/range {v0 .. v5}, Lip/v;-><init>(Lu/m;Lv/b;Ld01/x;Lj0/h;Lj0/c;)V

    .line 220
    .line 221
    .line 222
    iput-object v0, v1, Lu/m;->o:Lip/v;

    .line 223
    .line 224
    return-void
.end method

.method public static k(Lv/b;I)I
    .locals 2

    .line 1
    sget-object v0, Landroid/hardware/camera2/CameraCharacteristics;->CONTROL_AE_AVAILABLE_MODES:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, [I

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    return v0

    .line 13
    :cond_0
    invoke-static {p1, p0}, Lu/m;->l(I[I)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-eqz v1, :cond_1

    .line 18
    .line 19
    return p1

    .line 20
    :cond_1
    const/4 p1, 0x1

    .line 21
    invoke-static {p1, p0}, Lu/m;->l(I[I)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_2

    .line 26
    .line 27
    return p1

    .line 28
    :cond_2
    return v0
.end method

.method public static l(I[I)Z
    .locals 4

    .line 1
    array-length v0, p1

    .line 2
    const/4 v1, 0x0

    .line 3
    move v2, v1

    .line 4
    :goto_0
    if-ge v2, v0, :cond_1

    .line 5
    .line 6
    aget v3, p1, v2

    .line 7
    .line 8
    if-ne p0, v3, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    return p0

    .line 12
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    return v1
.end method


# virtual methods
.method public final a(Lh0/v1;)V
    .locals 16

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    iget-object v2, v1, Lh0/u1;->b:Lb0/n1;

    .line 4
    .line 5
    move-object/from16 v0, p0

    .line 6
    .line 7
    iget-object v3, v0, Lu/m;->m:Lu/l1;

    .line 8
    .line 9
    iget-object v4, v3, Lu/l1;->b:Lj0/h;

    .line 10
    .line 11
    iget-object v5, v3, Lu/l1;->a:Lv/b;

    .line 12
    .line 13
    const/16 v6, 0x22

    .line 14
    .line 15
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object v7

    .line 19
    invoke-virtual {v3}, Lu/l1;->a()V

    .line 20
    .line 21
    .line 22
    iget-boolean v0, v3, Lu/l1;->d:Z

    .line 23
    .line 24
    const/4 v8, 0x1

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    iput v8, v2, Lb0/n1;->d:I

    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    iget-boolean v0, v3, Lu/l1;->f:Z

    .line 31
    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    iput v8, v2, Lb0/n1;->d:I

    .line 35
    .line 36
    return-void

    .line 37
    :cond_1
    :try_start_0
    sget-object v0, Landroid/hardware/camera2/CameraCharacteristics;->SCALER_STREAM_CONFIGURATION_MAP:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 38
    .line 39
    invoke-virtual {v5, v0}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    check-cast v0, Landroid/hardware/camera2/params/StreamConfigurationMap;
    :try_end_0
    .catch Ljava/lang/AssertionError; {:try_start_0 .. :try_end_0} :catch_0

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :catch_0
    move-exception v0

    .line 47
    new-instance v9, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    const-string v10, "Failed to retrieve StreamConfigurationMap, error = "

    .line 50
    .line 51
    invoke-direct {v9, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    const-string v9, "ZslControlImpl"

    .line 66
    .line 67
    invoke-static {v9, v0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const/4 v0, 0x0

    .line 71
    :goto_0
    if-eqz v0, :cond_2

    .line 72
    .line 73
    invoke-virtual {v0}, Landroid/hardware/camera2/params/StreamConfigurationMap;->getInputFormats()[I

    .line 74
    .line 75
    .line 76
    move-result-object v10

    .line 77
    if-nez v10, :cond_3

    .line 78
    .line 79
    :cond_2
    const/16 p0, 0x0

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_3
    new-instance v10, Ljava/util/HashMap;

    .line 83
    .line 84
    invoke-direct {v10}, Ljava/util/HashMap;-><init>()V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v0}, Landroid/hardware/camera2/params/StreamConfigurationMap;->getInputFormats()[I

    .line 88
    .line 89
    .line 90
    move-result-object v11

    .line 91
    array-length v12, v11

    .line 92
    const/4 v13, 0x0

    .line 93
    :goto_1
    if-ge v13, v12, :cond_5

    .line 94
    .line 95
    aget v14, v11, v13

    .line 96
    .line 97
    invoke-virtual {v0, v14}, Landroid/hardware/camera2/params/StreamConfigurationMap;->getInputSizes(I)[Landroid/util/Size;

    .line 98
    .line 99
    .line 100
    move-result-object v15

    .line 101
    const/16 p0, 0x0

    .line 102
    .line 103
    if-eqz v15, :cond_4

    .line 104
    .line 105
    new-instance v9, Li0/c;

    .line 106
    .line 107
    invoke-direct {v9, v8}, Li0/c;-><init>(Z)V

    .line 108
    .line 109
    .line 110
    invoke-static {v15, v9}, Ljava/util/Arrays;->sort([Ljava/lang/Object;Ljava/util/Comparator;)V

    .line 111
    .line 112
    .line 113
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 114
    .line 115
    .line 116
    move-result-object v9

    .line 117
    aget-object v14, v15, p0

    .line 118
    .line 119
    invoke-virtual {v10, v9, v14}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    :cond_4
    add-int/lit8 v13, v13, 0x1

    .line 123
    .line 124
    goto :goto_1

    .line 125
    :cond_5
    const/16 p0, 0x0

    .line 126
    .line 127
    goto :goto_3

    .line 128
    :goto_2
    new-instance v10, Ljava/util/HashMap;

    .line 129
    .line 130
    invoke-direct {v10}, Ljava/util/HashMap;-><init>()V

    .line 131
    .line 132
    .line 133
    :goto_3
    iget-boolean v0, v3, Lu/l1;->e:Z

    .line 134
    .line 135
    if-eqz v0, :cond_b

    .line 136
    .line 137
    invoke-interface {v10}, Ljava/util/Map;->isEmpty()Z

    .line 138
    .line 139
    .line 140
    move-result v0

    .line 141
    if-nez v0, :cond_b

    .line 142
    .line 143
    invoke-interface {v10, v7}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v0

    .line 147
    if-eqz v0, :cond_b

    .line 148
    .line 149
    sget-object v0, Landroid/hardware/camera2/CameraCharacteristics;->SCALER_STREAM_CONFIGURATION_MAP:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 150
    .line 151
    invoke-virtual {v5, v0}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    check-cast v0, Landroid/hardware/camera2/params/StreamConfigurationMap;

    .line 156
    .line 157
    if-nez v0, :cond_6

    .line 158
    .line 159
    goto/16 :goto_6

    .line 160
    .line 161
    :cond_6
    invoke-virtual {v0, v6}, Landroid/hardware/camera2/params/StreamConfigurationMap;->getValidOutputFormatsForInput(I)[I

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    if-nez v0, :cond_7

    .line 166
    .line 167
    goto/16 :goto_6

    .line 168
    .line 169
    :cond_7
    array-length v5, v0

    .line 170
    move/from16 v9, p0

    .line 171
    .line 172
    :goto_4
    if-ge v9, v5, :cond_b

    .line 173
    .line 174
    aget v11, v0, v9

    .line 175
    .line 176
    const/16 v12, 0x100

    .line 177
    .line 178
    if-ne v11, v12, :cond_a

    .line 179
    .line 180
    invoke-interface {v10, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    check-cast v0, Landroid/util/Size;

    .line 185
    .line 186
    new-instance v5, Lb0/f1;

    .line 187
    .line 188
    invoke-virtual {v0}, Landroid/util/Size;->getWidth()I

    .line 189
    .line 190
    .line 191
    move-result v7

    .line 192
    invoke-virtual {v0}, Landroid/util/Size;->getHeight()I

    .line 193
    .line 194
    .line 195
    move-result v0

    .line 196
    const/16 v8, 0x9

    .line 197
    .line 198
    invoke-direct {v5, v7, v0, v6, v8}, Lb0/f1;-><init>(IIII)V

    .line 199
    .line 200
    .line 201
    new-instance v0, Lb0/n1;

    .line 202
    .line 203
    invoke-direct {v0, v5}, Lb0/n1;-><init>(Lh0/c1;)V

    .line 204
    .line 205
    .line 206
    new-instance v7, Lb0/u1;

    .line 207
    .line 208
    invoke-virtual {v0}, Lb0/n1;->getSurface()Landroid/view/Surface;

    .line 209
    .line 210
    .line 211
    move-result-object v8

    .line 212
    invoke-static {v8}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    new-instance v9, Landroid/util/Size;

    .line 216
    .line 217
    invoke-virtual {v0}, Lb0/n1;->o()I

    .line 218
    .line 219
    .line 220
    move-result v10

    .line 221
    invoke-virtual {v0}, Lb0/n1;->m()I

    .line 222
    .line 223
    .line 224
    move-result v11

    .line 225
    invoke-direct {v9, v10, v11}, Landroid/util/Size;-><init>(II)V

    .line 226
    .line 227
    .line 228
    invoke-direct {v7, v8, v9, v6}, Lb0/u1;-><init>(Landroid/view/Surface;Landroid/util/Size;I)V

    .line 229
    .line 230
    .line 231
    new-instance v6, Lc2/k;

    .line 232
    .line 233
    invoke-direct {v6, v4}, Lc2/k;-><init>(Lj0/h;)V

    .line 234
    .line 235
    .line 236
    iput-object v0, v3, Lu/l1;->g:Lb0/n1;

    .line 237
    .line 238
    iput-object v7, v3, Lu/l1;->h:Lb0/u1;

    .line 239
    .line 240
    iput-object v6, v3, Lu/l1;->i:Lc2/k;

    .line 241
    .line 242
    new-instance v8, Lrx/b;

    .line 243
    .line 244
    const/4 v9, 0x7

    .line 245
    invoke-direct {v8, v3, v9}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 246
    .line 247
    .line 248
    invoke-static {}, Llp/hb;->c()Lj0/f;

    .line 249
    .line 250
    .line 251
    move-result-object v3

    .line 252
    invoke-virtual {v0, v8, v3}, Lb0/n1;->g(Lh0/b1;Ljava/util/concurrent/Executor;)V

    .line 253
    .line 254
    .line 255
    iget-object v3, v7, Lh0/t0;->e:Ly4/k;

    .line 256
    .line 257
    invoke-static {v3}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 258
    .line 259
    .line 260
    move-result-object v3

    .line 261
    new-instance v8, Lno/nordicsemi/android/ble/o0;

    .line 262
    .line 263
    const/16 v9, 0x13

    .line 264
    .line 265
    invoke-direct {v8, v9, v0, v6}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    invoke-interface {v3, v4, v8}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 269
    .line 270
    .line 271
    sget-object v3, Lb0/y;->d:Lb0/y;

    .line 272
    .line 273
    const/4 v4, -0x1

    .line 274
    invoke-virtual {v1, v7, v3, v4}, Lh0/v1;->b(Lh0/t0;Lb0/y;I)V

    .line 275
    .line 276
    .line 277
    iget-object v3, v5, Lb0/f1;->e:Lb0/e1;

    .line 278
    .line 279
    invoke-virtual {v2, v3}, Lb0/n1;->c(Lh0/m;)V

    .line 280
    .line 281
    .line 282
    iget-object v2, v1, Lh0/u1;->e:Ljava/util/ArrayList;

    .line 283
    .line 284
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 285
    .line 286
    .line 287
    move-result v4

    .line 288
    if-nez v4, :cond_8

    .line 289
    .line 290
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 291
    .line 292
    .line 293
    :cond_8
    new-instance v2, Lu/h0;

    .line 294
    .line 295
    const/4 v3, 0x2

    .line 296
    invoke-direct {v2, v6, v3}, Lu/h0;-><init>(Ljava/lang/Object;I)V

    .line 297
    .line 298
    .line 299
    iget-object v3, v1, Lh0/u1;->d:Ljava/util/ArrayList;

    .line 300
    .line 301
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 302
    .line 303
    .line 304
    move-result v4

    .line 305
    if-eqz v4, :cond_9

    .line 306
    .line 307
    goto :goto_5

    .line 308
    :cond_9
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 309
    .line 310
    .line 311
    :goto_5
    new-instance v2, Landroid/hardware/camera2/params/InputConfiguration;

    .line 312
    .line 313
    invoke-virtual {v0}, Lb0/n1;->o()I

    .line 314
    .line 315
    .line 316
    move-result v3

    .line 317
    invoke-virtual {v0}, Lb0/n1;->m()I

    .line 318
    .line 319
    .line 320
    move-result v4

    .line 321
    invoke-virtual {v0}, Lb0/n1;->d()I

    .line 322
    .line 323
    .line 324
    move-result v0

    .line 325
    invoke-direct {v2, v3, v4, v0}, Landroid/hardware/camera2/params/InputConfiguration;-><init>(III)V

    .line 326
    .line 327
    .line 328
    iput-object v2, v1, Lh0/u1;->g:Landroid/hardware/camera2/params/InputConfiguration;

    .line 329
    .line 330
    goto :goto_7

    .line 331
    :cond_a
    add-int/lit8 v9, v9, 0x1

    .line 332
    .line 333
    goto/16 :goto_4

    .line 334
    .line 335
    :cond_b
    :goto_6
    iput v8, v2, Lb0/n1;->d:I

    .line 336
    .line 337
    :goto_7
    return-void
.end method

.method public final b(I)V
    .locals 3

    .line 1
    const-string v0, "Camera2CameraControlImp"

    .line 2
    .line 3
    iget-object v1, p0, Lu/m;->d:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    iget v2, p0, Lu/m;->q:I

    .line 7
    .line 8
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 9
    if-lez v2, :cond_0

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v1, 0x0

    .line 14
    :goto_0
    if-nez v1, :cond_1

    .line 15
    .line 16
    const-string p0, "Camera is not active."

    .line 17
    .line 18
    invoke-static {v0, p0}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_1
    iput p1, p0, Lu/m;->t:I

    .line 23
    .line 24
    new-instance p1, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    const-string v1, "setFlashMode: mFlashMode = "

    .line 27
    .line 28
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    iget v1, p0, Lu/m;->t:I

    .line 32
    .line 33
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-static {v0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    iget-object p1, p0, Lu/m;->m:Lu/l1;

    .line 44
    .line 45
    iget v0, p0, Lu/m;->t:I

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    if-eq v0, v1, :cond_2

    .line 49
    .line 50
    iget v0, p0, Lu/m;->t:I

    .line 51
    .line 52
    :cond_2
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    new-instance p1, Lrx/b;

    .line 56
    .line 57
    const/4 v0, 0x4

    .line 58
    invoke-direct {p1, p0, v0}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 59
    .line 60
    .line 61
    invoke-static {p1}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-static {p0}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :catchall_0
    move-exception p0

    .line 70
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 71
    throw p0
.end method

.method public final c()Lh0/q0;
    .locals 3

    .line 1
    iget-object p0, p0, Lu/m;->n:La0/e;

    .line 2
    .line 3
    iget-object v0, p0, La0/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-object p0, p0, La0/e;->f:Lb0/h1;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    new-instance v1, Lt/a;

    .line 12
    .line 13
    iget-object p0, p0, Lb0/h1;->b:Lh0/j1;

    .line 14
    .line 15
    invoke-static {p0}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-direct {v1, p0, v2}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    monitor-exit v0

    .line 24
    return-object v1

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    throw p0
.end method

.method public final d()V
    .locals 0

    .line 1
    iget-object p0, p0, Lu/m;->m:Lu/l1;

    .line 2
    .line 3
    invoke-virtual {p0}, Lu/l1;->a()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final e(Lb0/s0;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final f(Lh0/q0;)V
    .locals 7

    .line 1
    iget-object p0, p0, Lu/m;->n:La0/e;

    .line 2
    .line 3
    invoke-static {p1}, La0/i;->d(Lh0/q0;)La0/i;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p1}, La0/i;->c()La0/j;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iget-object v0, p0, La0/e;->e:Ljava/lang/Object;

    .line 12
    .line 13
    monitor-enter v0

    .line 14
    :try_start_0
    iget-object v1, p0, La0/e;->f:Lb0/h1;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    sget-object v2, Lh0/p0;->g:Lh0/p0;

    .line 20
    .line 21
    invoke-interface {p1}, Lh0/q0;->d()Ljava/util/Set;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    if-eqz v4, :cond_0

    .line 34
    .line 35
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    check-cast v4, Lh0/g;

    .line 40
    .line 41
    iget-object v5, v1, Lb0/h1;->b:Lh0/j1;

    .line 42
    .line 43
    invoke-interface {p1, v4}, Lh0/q0;->f(Lh0/g;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    invoke-virtual {v5, v4, v2, v6}, Lh0/j1;->m(Lh0/g;Lh0/p0;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 52
    new-instance p1, La0/a;

    .line 53
    .line 54
    const/4 v0, 0x0

    .line 55
    invoke-direct {p1, p0, v0}, La0/a;-><init>(La0/e;I)V

    .line 56
    .line 57
    .line 58
    invoke-static {p1}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-static {p0}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    new-instance p1, Lu/g;

    .line 67
    .line 68
    invoke-direct {p1, v0}, Lu/g;-><init>(I)V

    .line 69
    .line 70
    .line 71
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-interface {p0, v0, p1}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 76
    .line 77
    .line 78
    return-void

    .line 79
    :catchall_0
    move-exception p0

    .line 80
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 81
    throw p0
.end method

.method public final g()V
    .locals 3

    .line 1
    iget-object p0, p0, Lu/m;->n:La0/e;

    .line 2
    .line 3
    iget-object v0, p0, La0/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    new-instance v1, Lb0/h1;

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    invoke-direct {v1, v2}, Lb0/h1;-><init>(I)V

    .line 10
    .line 11
    .line 12
    iput-object v1, p0, La0/e;->f:Lb0/h1;

    .line 13
    .line 14
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    new-instance v0, La0/a;

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    invoke-direct {v0, p0, v1}, La0/a;-><init>(La0/e;I)V

    .line 19
    .line 20
    .line 21
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {p0}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    new-instance v0, Lu/g;

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    invoke-direct {v0, v1}, Lu/g;-><init>(I)V

    .line 33
    .line 34
    .line 35
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    invoke-interface {p0, v1, v0}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :catchall_0
    move-exception p0

    .line 44
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 45
    throw p0
.end method

.method public final h(Lu/l;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lu/m;->b:Lu/k;

    .line 2
    .line 3
    iget-object p0, p0, Lu/k;->b:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ljava/util/HashSet;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final i()V
    .locals 2

    .line 1
    iget-object v0, p0, Lu/m;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget v1, p0, Lu/m;->q:I

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    add-int/lit8 v1, v1, -0x1

    .line 9
    .line 10
    iput v1, p0, Lu/m;->q:I

    .line 11
    .line 12
    monitor-exit v0

    .line 13
    return-void

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 17
    .line 18
    const-string v1, "Decrementing use count occurs more times than incrementing"

    .line 19
    .line 20
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    throw p0
.end method

.method public final j()Lh0/z1;
    .locals 10

    .line 1
    iget-object v0, p0, Lu/m;->g:Lh0/v1;

    .line 2
    .line 3
    iget v1, p0, Lu/m;->w:I

    .line 4
    .line 5
    iget-object v2, v0, Lh0/u1;->b:Lb0/n1;

    .line 6
    .line 7
    iput v1, v2, Lb0/n1;->d:I

    .line 8
    .line 9
    new-instance v1, Lb0/h1;

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    invoke-direct {v1, v2}, Lb0/h1;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sget-object v2, Landroid/hardware/camera2/CaptureRequest;->CONTROL_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 16
    .line 17
    const/4 v3, 0x1

    .line 18
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    invoke-virtual {v1, v2, v4}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iget-object v2, p0, Lu/m;->h:Lu/r0;

    .line 26
    .line 27
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    iget v4, v2, Lu/r0;->c:I

    .line 31
    .line 32
    const/4 v5, 0x3

    .line 33
    if-eq v4, v5, :cond_0

    .line 34
    .line 35
    const/4 v4, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move v4, v5

    .line 38
    :goto_0
    sget-object v6, Landroid/hardware/camera2/CaptureRequest;->CONTROL_AF_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 39
    .line 40
    iget-object v7, v2, Lu/r0;->a:Lu/m;

    .line 41
    .line 42
    iget-object v7, v7, Lu/m;->e:Lv/b;

    .line 43
    .line 44
    sget-object v8, Landroid/hardware/camera2/CameraCharacteristics;->CONTROL_AF_AVAILABLE_MODES:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 45
    .line 46
    invoke-virtual {v7, v8}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v7

    .line 50
    check-cast v7, [I

    .line 51
    .line 52
    const/4 v8, 0x0

    .line 53
    if-nez v7, :cond_2

    .line 54
    .line 55
    :cond_1
    move v4, v8

    .line 56
    goto :goto_1

    .line 57
    :cond_2
    invoke-static {v4, v7}, Lu/m;->l(I[I)Z

    .line 58
    .line 59
    .line 60
    move-result v9

    .line 61
    if-eqz v9, :cond_3

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_3
    const/4 v4, 0x4

    .line 65
    invoke-static {v4, v7}, Lu/m;->l(I[I)Z

    .line 66
    .line 67
    .line 68
    move-result v9

    .line 69
    if-eqz v9, :cond_4

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_4
    const/4 v4, 0x1

    .line 73
    invoke-static {v4, v7}, Lu/m;->l(I[I)Z

    .line 74
    .line 75
    .line 76
    move-result v7

    .line 77
    if-eqz v7, :cond_1

    .line 78
    .line 79
    :goto_1
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    invoke-virtual {v1, v6, v4}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    iget-object v4, v2, Lu/r0;->d:[Landroid/hardware/camera2/params/MeteringRectangle;

    .line 87
    .line 88
    array-length v6, v4

    .line 89
    if-eqz v6, :cond_5

    .line 90
    .line 91
    sget-object v6, Landroid/hardware/camera2/CaptureRequest;->CONTROL_AF_REGIONS:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 92
    .line 93
    invoke-virtual {v1, v6, v4}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    :cond_5
    iget-object v4, v2, Lu/r0;->e:[Landroid/hardware/camera2/params/MeteringRectangle;

    .line 97
    .line 98
    array-length v6, v4

    .line 99
    if-eqz v6, :cond_6

    .line 100
    .line 101
    sget-object v6, Landroid/hardware/camera2/CaptureRequest;->CONTROL_AE_REGIONS:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 102
    .line 103
    invoke-virtual {v1, v6, v4}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    :cond_6
    iget-object v2, v2, Lu/r0;->f:[Landroid/hardware/camera2/params/MeteringRectangle;

    .line 107
    .line 108
    array-length v4, v2

    .line 109
    if-eqz v4, :cond_7

    .line 110
    .line 111
    sget-object v4, Landroid/hardware/camera2/CaptureRequest;->CONTROL_AWB_REGIONS:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 112
    .line 113
    invoke-virtual {v1, v4, v2}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    :cond_7
    iget-object v2, p0, Lu/m;->i:Lh8/o;

    .line 117
    .line 118
    iget-object v2, v2, Lh8/o;->e:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast v2, Lu/k1;

    .line 121
    .line 122
    invoke-interface {v2, v1}, Lu/k1;->b(Lb0/h1;)V

    .line 123
    .line 124
    .line 125
    iget-object v2, p0, Lu/m;->h:Lu/r0;

    .line 126
    .line 127
    iget-boolean v2, v2, Lu/r0;->g:Z

    .line 128
    .line 129
    if-eqz v2, :cond_8

    .line 130
    .line 131
    const/4 v2, 0x5

    .line 132
    goto :goto_2

    .line 133
    :cond_8
    move v2, v3

    .line 134
    :goto_2
    iget v4, p0, Lu/m;->r:I

    .line 135
    .line 136
    const/4 v6, 0x2

    .line 137
    if-eqz v4, :cond_a

    .line 138
    .line 139
    sget-object v4, Landroid/hardware/camera2/CaptureRequest;->FLASH_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 140
    .line 141
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    invoke-virtual {v1, v4, v5}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 149
    .line 150
    const/16 v5, 0x23

    .line 151
    .line 152
    if-lt v4, v5, :cond_b

    .line 153
    .line 154
    iget v4, p0, Lu/m;->r:I

    .line 155
    .line 156
    if-ne v4, v3, :cond_9

    .line 157
    .line 158
    invoke-static {}, Lu/f;->a()Landroid/hardware/camera2/CaptureRequest$Key;

    .line 159
    .line 160
    .line 161
    move-result-object v4

    .line 162
    iget v5, p0, Lu/m;->s:I

    .line 163
    .line 164
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 165
    .line 166
    .line 167
    move-result-object v5

    .line 168
    invoke-virtual {v1, v4, v5}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    goto :goto_3

    .line 172
    :cond_9
    iget v4, p0, Lu/m;->r:I

    .line 173
    .line 174
    if-ne v4, v6, :cond_b

    .line 175
    .line 176
    invoke-static {}, Lu/f;->a()Landroid/hardware/camera2/CaptureRequest$Key;

    .line 177
    .line 178
    .line 179
    move-result-object v4

    .line 180
    iget-object v5, p0, Lu/m;->e:Lv/b;

    .line 181
    .line 182
    invoke-virtual {v5}, Lv/b;->b()I

    .line 183
    .line 184
    .line 185
    move-result v5

    .line 186
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 187
    .line 188
    .line 189
    move-result-object v5

    .line 190
    invoke-virtual {v1, v4, v5}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    goto :goto_3

    .line 194
    :cond_a
    iget v4, p0, Lu/m;->t:I

    .line 195
    .line 196
    if-eqz v4, :cond_d

    .line 197
    .line 198
    if-eq v4, v3, :cond_f

    .line 199
    .line 200
    if-eq v4, v6, :cond_c

    .line 201
    .line 202
    :cond_b
    :goto_3
    move v5, v2

    .line 203
    goto :goto_5

    .line 204
    :cond_c
    :goto_4
    move v5, v3

    .line 205
    goto :goto_5

    .line 206
    :cond_d
    iget-object v2, p0, Lu/m;->u:Lk1/c0;

    .line 207
    .line 208
    iget-boolean v4, v2, Lk1/c0;->a:Z

    .line 209
    .line 210
    if-nez v4, :cond_c

    .line 211
    .line 212
    iget-boolean v2, v2, Lk1/c0;->b:Z

    .line 213
    .line 214
    if-eqz v2, :cond_e

    .line 215
    .line 216
    goto :goto_4

    .line 217
    :cond_e
    move v5, v6

    .line 218
    :cond_f
    :goto_5
    sget-object v2, Landroid/hardware/camera2/CaptureRequest;->CONTROL_AE_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 219
    .line 220
    iget-object v4, p0, Lu/m;->e:Lv/b;

    .line 221
    .line 222
    invoke-static {v4, v5}, Lu/m;->k(Lv/b;I)I

    .line 223
    .line 224
    .line 225
    move-result v4

    .line 226
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 227
    .line 228
    .line 229
    move-result-object v4

    .line 230
    invoke-virtual {v1, v2, v4}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    sget-object v2, Landroid/hardware/camera2/CaptureRequest;->CONTROL_AWB_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 234
    .line 235
    iget-object v4, p0, Lu/m;->e:Lv/b;

    .line 236
    .line 237
    sget-object v5, Landroid/hardware/camera2/CameraCharacteristics;->CONTROL_AWB_AVAILABLE_MODES:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 238
    .line 239
    invoke-virtual {v4, v5}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v4

    .line 243
    check-cast v4, [I

    .line 244
    .line 245
    const/4 v5, 0x0

    .line 246
    if-nez v4, :cond_11

    .line 247
    .line 248
    :cond_10
    move v3, v5

    .line 249
    goto :goto_6

    .line 250
    :cond_11
    invoke-static {v3, v4}, Lu/m;->l(I[I)Z

    .line 251
    .line 252
    .line 253
    move-result v6

    .line 254
    if-eqz v6, :cond_12

    .line 255
    .line 256
    goto :goto_6

    .line 257
    :cond_12
    invoke-static {v3, v4}, Lu/m;->l(I[I)Z

    .line 258
    .line 259
    .line 260
    move-result v4

    .line 261
    if-eqz v4, :cond_10

    .line 262
    .line 263
    :goto_6
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 264
    .line 265
    .line 266
    move-result-object v3

    .line 267
    invoke-virtual {v1, v2, v3}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 268
    .line 269
    .line 270
    iget-object v2, p0, Lu/m;->l:Lb6/f;

    .line 271
    .line 272
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 273
    .line 274
    .line 275
    sget-object v3, Landroid/hardware/camera2/CaptureRequest;->CONTROL_AE_EXPOSURE_COMPENSATION:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 276
    .line 277
    iget-object v2, v2, Lb6/f;->e:Ljava/lang/Object;

    .line 278
    .line 279
    check-cast v2, Ld8/c;

    .line 280
    .line 281
    iget-object v2, v2, Ld8/c;->d:Ljava/lang/Object;

    .line 282
    .line 283
    monitor-enter v2

    .line 284
    :try_start_0
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 285
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 286
    .line 287
    .line 288
    move-result-object v2

    .line 289
    invoke-virtual {v1, v3, v2}, Lb0/h1;->d(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 290
    .line 291
    .line 292
    iget-object v2, p0, Lu/m;->n:La0/e;

    .line 293
    .line 294
    iget-object v3, v2, La0/e;->e:Ljava/lang/Object;

    .line 295
    .line 296
    monitor-enter v3

    .line 297
    :try_start_1
    iget-object v2, v2, La0/e;->f:Lb0/h1;

    .line 298
    .line 299
    iget-object v2, v2, Lb0/h1;->b:Lh0/j1;

    .line 300
    .line 301
    sget-object v4, Lh0/p0;->d:Lh0/p0;

    .line 302
    .line 303
    invoke-virtual {v2}, Lh0/n1;->d()Ljava/util/Set;

    .line 304
    .line 305
    .line 306
    move-result-object v5

    .line 307
    invoke-interface {v5}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 308
    .line 309
    .line 310
    move-result-object v5

    .line 311
    :goto_7
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 312
    .line 313
    .line 314
    move-result v6

    .line 315
    if-eqz v6, :cond_13

    .line 316
    .line 317
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v6

    .line 321
    check-cast v6, Lh0/g;

    .line 322
    .line 323
    iget-object v7, v1, Lb0/h1;->b:Lh0/j1;

    .line 324
    .line 325
    invoke-virtual {v2, v6}, Lh0/n1;->f(Lh0/g;)Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v8

    .line 329
    invoke-virtual {v7, v6, v4, v8}, Lh0/j1;->m(Lh0/g;Lh0/p0;Ljava/lang/Object;)V

    .line 330
    .line 331
    .line 332
    goto :goto_7

    .line 333
    :cond_13
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 334
    new-instance v2, Lt/a;

    .line 335
    .line 336
    iget-object v1, v1, Lb0/h1;->b:Lh0/j1;

    .line 337
    .line 338
    invoke-static {v1}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 339
    .line 340
    .line 341
    move-result-object v1

    .line 342
    const/4 v3, 0x0

    .line 343
    invoke-direct {v2, v1, v3}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 344
    .line 345
    .line 346
    iget-object v0, v0, Lh0/u1;->b:Lb0/n1;

    .line 347
    .line 348
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 349
    .line 350
    .line 351
    invoke-static {v2}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    .line 352
    .line 353
    .line 354
    move-result-object v1

    .line 355
    iput-object v1, v0, Lb0/n1;->g:Ljava/lang/Object;

    .line 356
    .line 357
    iget-object v0, p0, Lu/m;->g:Lh0/v1;

    .line 358
    .line 359
    iget-wide v1, p0, Lu/m;->x:J

    .line 360
    .line 361
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 362
    .line 363
    .line 364
    move-result-object v1

    .line 365
    iget-object v0, v0, Lh0/u1;->b:Lb0/n1;

    .line 366
    .line 367
    const-string v2, "CameraControlSessionUpdateId"

    .line 368
    .line 369
    iget-object v0, v0, Lb0/n1;->i:Ljava/lang/Object;

    .line 370
    .line 371
    check-cast v0, Lh0/k1;

    .line 372
    .line 373
    iget-object v0, v0, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 374
    .line 375
    invoke-virtual {v0, v2, v1}, Landroid/util/ArrayMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 376
    .line 377
    .line 378
    iget-object p0, p0, Lu/m;->g:Lh0/v1;

    .line 379
    .line 380
    invoke-virtual {p0}, Lh0/v1;->c()Lh0/z1;

    .line 381
    .line 382
    .line 383
    move-result-object p0

    .line 384
    return-object p0

    .line 385
    :catchall_0
    move-exception p0

    .line 386
    :try_start_2
    monitor-exit v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 387
    throw p0

    .line 388
    :catchall_1
    move-exception p0

    .line 389
    :try_start_3
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 390
    throw p0
.end method

.method public final m(Z)V
    .locals 11

    .line 1
    const-string v0, "Camera2CameraControlImp"

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "setActive: isActive = "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-static {v0, v1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget-object v0, p0, Lu/m;->h:Lu/r0;

    .line 21
    .line 22
    iget-boolean v1, v0, Lu/r0;->b:Z

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    const/4 v3, 0x0

    .line 26
    if-ne p1, v1, :cond_0

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_0
    iput-boolean p1, v0, Lu/r0;->b:Z

    .line 30
    .line 31
    iget-boolean v1, v0, Lu/r0;->b:Z

    .line 32
    .line 33
    if-nez v1, :cond_3

    .line 34
    .line 35
    iget-object v1, v0, Lu/r0;->a:Lu/m;

    .line 36
    .line 37
    iget-object v4, v1, Lu/m;->b:Lu/k;

    .line 38
    .line 39
    iget-object v4, v4, Lu/k;->b:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v4, Ljava/util/HashSet;

    .line 42
    .line 43
    const/4 v5, 0x0

    .line 44
    invoke-virtual {v4, v5}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    iget-object v4, v1, Lu/m;->b:Lu/k;

    .line 48
    .line 49
    iget-object v4, v4, Lu/k;->b:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v4, Ljava/util/HashSet;

    .line 52
    .line 53
    invoke-virtual {v4, v2}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    iget-object v4, v0, Lu/r0;->d:[Landroid/hardware/camera2/params/MeteringRectangle;

    .line 57
    .line 58
    array-length v4, v4

    .line 59
    if-lez v4, :cond_2

    .line 60
    .line 61
    const/4 v4, 0x2

    .line 62
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    iget-boolean v5, v0, Lu/r0;->b:Z

    .line 67
    .line 68
    if-nez v5, :cond_1

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    new-instance v5, Lb0/n1;

    .line 72
    .line 73
    invoke-direct {v5}, Lb0/n1;-><init>()V

    .line 74
    .line 75
    .line 76
    const/4 v6, 0x1

    .line 77
    iput-boolean v6, v5, Lb0/n1;->e:Z

    .line 78
    .line 79
    iget v6, v0, Lu/r0;->c:I

    .line 80
    .line 81
    iput v6, v5, Lb0/n1;->d:I

    .line 82
    .line 83
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 84
    .line 85
    .line 86
    move-result-object v6

    .line 87
    sget-object v7, Landroid/hardware/camera2/CaptureRequest;->CONTROL_AF_TRIGGER:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 88
    .line 89
    invoke-static {v7}, Lt/a;->X(Landroid/hardware/camera2/CaptureRequest$Key;)Lh0/g;

    .line 90
    .line 91
    .line 92
    move-result-object v7

    .line 93
    invoke-virtual {v6, v7, v4}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    new-instance v4, Lt/a;

    .line 97
    .line 98
    invoke-static {v6}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 99
    .line 100
    .line 101
    move-result-object v6

    .line 102
    const/4 v7, 0x0

    .line 103
    invoke-direct {v4, v6, v7}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v5, v4}, Lb0/n1;->i(Lh0/q0;)V

    .line 107
    .line 108
    .line 109
    iget-object v4, v0, Lu/r0;->a:Lu/m;

    .line 110
    .line 111
    invoke-virtual {v5}, Lb0/n1;->j()Lh0/o0;

    .line 112
    .line 113
    .line 114
    move-result-object v5

    .line 115
    invoke-static {v5}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 116
    .line 117
    .line 118
    move-result-object v5

    .line 119
    invoke-virtual {v4, v5}, Lu/m;->o(Ljava/util/List;)V

    .line 120
    .line 121
    .line 122
    :cond_2
    :goto_0
    sget-object v4, Lu/r0;->h:[Landroid/hardware/camera2/params/MeteringRectangle;

    .line 123
    .line 124
    iput-object v4, v0, Lu/r0;->d:[Landroid/hardware/camera2/params/MeteringRectangle;

    .line 125
    .line 126
    iput-object v4, v0, Lu/r0;->e:[Landroid/hardware/camera2/params/MeteringRectangle;

    .line 127
    .line 128
    iput-object v4, v0, Lu/r0;->f:[Landroid/hardware/camera2/params/MeteringRectangle;

    .line 129
    .line 130
    invoke-virtual {v1}, Lu/m;->p()J

    .line 131
    .line 132
    .line 133
    :cond_3
    :goto_1
    iget-object v0, p0, Lu/m;->i:Lh8/o;

    .line 134
    .line 135
    iget-boolean v1, v0, Lh8/o;->a:Z

    .line 136
    .line 137
    if-ne v1, p1, :cond_4

    .line 138
    .line 139
    goto :goto_3

    .line 140
    :cond_4
    iput-boolean p1, v0, Lh8/o;->a:Z

    .line 141
    .line 142
    if-nez p1, :cond_6

    .line 143
    .line 144
    iget-object v1, v0, Lh8/o;->c:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast v1, Ld3/a;

    .line 147
    .line 148
    monitor-enter v1

    .line 149
    :try_start_0
    iget-object v4, v0, Lh8/o;->c:Ljava/lang/Object;

    .line 150
    .line 151
    check-cast v4, Ld3/a;

    .line 152
    .line 153
    invoke-virtual {v4}, Ld3/a;->j()V

    .line 154
    .line 155
    .line 156
    iget-object v4, v0, Lh8/o;->c:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v4, Ld3/a;

    .line 159
    .line 160
    new-instance v5, Ll0/a;

    .line 161
    .line 162
    invoke-virtual {v4}, Ld3/a;->e()F

    .line 163
    .line 164
    .line 165
    move-result v6

    .line 166
    invoke-virtual {v4}, Ld3/a;->c()F

    .line 167
    .line 168
    .line 169
    move-result v7

    .line 170
    invoke-virtual {v4}, Ld3/a;->d()F

    .line 171
    .line 172
    .line 173
    move-result v8

    .line 174
    invoke-virtual {v4}, Ld3/a;->b()F

    .line 175
    .line 176
    .line 177
    move-result v4

    .line 178
    invoke-direct {v5, v6, v7, v8, v4}, Ll0/a;-><init>(FFFF)V

    .line 179
    .line 180
    .line 181
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 182
    iget-object v1, v0, Lh8/o;->d:Ljava/lang/Object;

    .line 183
    .line 184
    check-cast v1, Landroidx/lifecycle/i0;

    .line 185
    .line 186
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 187
    .line 188
    .line 189
    move-result-object v4

    .line 190
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 191
    .line 192
    .line 193
    move-result-object v6

    .line 194
    if-ne v4, v6, :cond_5

    .line 195
    .line 196
    invoke-virtual {v1, v5}, Landroidx/lifecycle/i0;->j(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    goto :goto_2

    .line 200
    :cond_5
    invoke-virtual {v1, v5}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    :goto_2
    iget-object v1, v0, Lh8/o;->e:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v1, Lu/k1;

    .line 206
    .line 207
    invoke-interface {v1}, Lu/k1;->f()V

    .line 208
    .line 209
    .line 210
    iget-object v0, v0, Lh8/o;->b:Ljava/lang/Object;

    .line 211
    .line 212
    check-cast v0, Lu/m;

    .line 213
    .line 214
    invoke-virtual {v0}, Lu/m;->p()J

    .line 215
    .line 216
    .line 217
    goto :goto_3

    .line 218
    :catchall_0
    move-exception p0

    .line 219
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 220
    throw p0

    .line 221
    :cond_6
    :goto_3
    iget-object v0, p0, Lu/m;->k:Lb6/f;

    .line 222
    .line 223
    iget-boolean v1, v0, Lb6/f;->d:Z

    .line 224
    .line 225
    if-ne v1, p1, :cond_7

    .line 226
    .line 227
    goto :goto_4

    .line 228
    :cond_7
    iput-boolean p1, v0, Lb6/f;->d:Z

    .line 229
    .line 230
    :goto_4
    iget-object v0, p0, Lu/m;->j:Lu/i1;

    .line 231
    .line 232
    const-string v1, "Camera is not active."

    .line 233
    .line 234
    iget v4, v0, Lu/i1;->e:I

    .line 235
    .line 236
    iget-boolean v5, v0, Lu/i1;->d:Z

    .line 237
    .line 238
    if-ne v5, p1, :cond_8

    .line 239
    .line 240
    goto/16 :goto_7

    .line 241
    .line 242
    :cond_8
    iput-boolean p1, v0, Lu/i1;->d:Z

    .line 243
    .line 244
    if-nez p1, :cond_c

    .line 245
    .line 246
    iget-boolean v5, v0, Lu/i1;->g:Z

    .line 247
    .line 248
    if-eqz v5, :cond_b

    .line 249
    .line 250
    iput-boolean v3, v0, Lu/i1;->g:Z

    .line 251
    .line 252
    iget-object v5, v0, Lu/i1;->a:Lu/m;

    .line 253
    .line 254
    iput v3, v5, Lu/m;->r:I

    .line 255
    .line 256
    new-instance v6, Lb0/n1;

    .line 257
    .line 258
    invoke-direct {v6}, Lb0/n1;-><init>()V

    .line 259
    .line 260
    .line 261
    iget v7, v5, Lu/m;->w:I

    .line 262
    .line 263
    iput v7, v6, Lb0/n1;->d:I

    .line 264
    .line 265
    const/4 v7, 0x1

    .line 266
    iput-boolean v7, v6, Lb0/n1;->e:Z

    .line 267
    .line 268
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 269
    .line 270
    .line 271
    move-result-object v8

    .line 272
    sget-object v9, Landroid/hardware/camera2/CaptureRequest;->CONTROL_AE_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 273
    .line 274
    iget-object v10, v5, Lu/m;->e:Lv/b;

    .line 275
    .line 276
    invoke-static {v10, v7}, Lu/m;->k(Lv/b;I)I

    .line 277
    .line 278
    .line 279
    move-result v7

    .line 280
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 281
    .line 282
    .line 283
    move-result-object v7

    .line 284
    invoke-static {v9}, Lt/a;->X(Landroid/hardware/camera2/CaptureRequest$Key;)Lh0/g;

    .line 285
    .line 286
    .line 287
    move-result-object v9

    .line 288
    invoke-virtual {v8, v9, v7}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    sget-object v7, Landroid/hardware/camera2/CaptureRequest;->FLASH_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 292
    .line 293
    const/4 v9, 0x0

    .line 294
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 295
    .line 296
    .line 297
    move-result-object v9

    .line 298
    invoke-static {v7}, Lt/a;->X(Landroid/hardware/camera2/CaptureRequest$Key;)Lh0/g;

    .line 299
    .line 300
    .line 301
    move-result-object v7

    .line 302
    invoke-virtual {v8, v7, v9}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 303
    .line 304
    .line 305
    new-instance v7, Lt/a;

    .line 306
    .line 307
    invoke-static {v8}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 308
    .line 309
    .line 310
    move-result-object v8

    .line 311
    const/4 v9, 0x0

    .line 312
    invoke-direct {v7, v8, v9}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 313
    .line 314
    .line 315
    invoke-virtual {v6, v7}, Lb0/n1;->i(Lh0/q0;)V

    .line 316
    .line 317
    .line 318
    invoke-virtual {v6}, Lb0/n1;->j()Lh0/o0;

    .line 319
    .line 320
    .line 321
    move-result-object v6

    .line 322
    invoke-static {v6}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 323
    .line 324
    .line 325
    move-result-object v6

    .line 326
    invoke-virtual {v5, v6}, Lu/m;->o(Ljava/util/List;)V

    .line 327
    .line 328
    .line 329
    invoke-virtual {v5}, Lu/m;->p()J

    .line 330
    .line 331
    .line 332
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 333
    .line 334
    .line 335
    const/4 v5, 0x1

    .line 336
    xor-int/2addr v5, v5

    .line 337
    iget-object v6, v0, Lu/i1;->b:Landroidx/lifecycle/i0;

    .line 338
    .line 339
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 340
    .line 341
    .line 342
    move-result-object v5

    .line 343
    invoke-static {}, Llp/k1;->c()Z

    .line 344
    .line 345
    .line 346
    move-result v7

    .line 347
    if-eqz v7, :cond_9

    .line 348
    .line 349
    invoke-virtual {v6, v5}, Landroidx/lifecycle/i0;->j(Ljava/lang/Object;)V

    .line 350
    .line 351
    .line 352
    goto :goto_5

    .line 353
    :cond_9
    invoke-virtual {v6, v5}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    .line 354
    .line 355
    .line 356
    :goto_5
    iget-object v5, v0, Lu/i1;->c:Landroidx/lifecycle/i0;

    .line 357
    .line 358
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 359
    .line 360
    .line 361
    move-result-object v4

    .line 362
    invoke-static {}, Llp/k1;->c()Z

    .line 363
    .line 364
    .line 365
    move-result v6

    .line 366
    if-eqz v6, :cond_a

    .line 367
    .line 368
    invoke-virtual {v5, v4}, Landroidx/lifecycle/i0;->j(Ljava/lang/Object;)V

    .line 369
    .line 370
    .line 371
    goto :goto_6

    .line 372
    :cond_a
    invoke-virtual {v5, v4}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    .line 373
    .line 374
    .line 375
    :cond_b
    :goto_6
    iget-object v4, v0, Lu/i1;->f:Ly4/h;

    .line 376
    .line 377
    if-eqz v4, :cond_c

    .line 378
    .line 379
    new-instance v5, Lb0/l;

    .line 380
    .line 381
    invoke-direct {v5, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 382
    .line 383
    .line 384
    invoke-virtual {v4, v5}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 385
    .line 386
    .line 387
    iput-object v2, v0, Lu/i1;->f:Ly4/h;

    .line 388
    .line 389
    :cond_c
    :goto_7
    iget-object v0, p0, Lu/m;->l:Lb6/f;

    .line 390
    .line 391
    iget-boolean v1, v0, Lb6/f;->d:Z

    .line 392
    .line 393
    if-ne p1, v1, :cond_d

    .line 394
    .line 395
    goto :goto_8

    .line 396
    :cond_d
    iput-boolean p1, v0, Lb6/f;->d:Z

    .line 397
    .line 398
    if-nez p1, :cond_e

    .line 399
    .line 400
    iget-object v0, v0, Lb6/f;->e:Ljava/lang/Object;

    .line 401
    .line 402
    check-cast v0, Ld8/c;

    .line 403
    .line 404
    iget-object v0, v0, Ld8/c;->d:Ljava/lang/Object;

    .line 405
    .line 406
    monitor-enter v0

    .line 407
    :try_start_2
    monitor-exit v0

    .line 408
    goto :goto_8

    .line 409
    :catchall_1
    move-exception p0

    .line 410
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 411
    throw p0

    .line 412
    :cond_e
    :goto_8
    iget-object v0, p0, Lu/m;->n:La0/e;

    .line 413
    .line 414
    iget-object v1, v0, La0/e;->d:Lj0/h;

    .line 415
    .line 416
    new-instance v2, La0/b;

    .line 417
    .line 418
    const/4 v4, 0x0

    .line 419
    invoke-direct {v2, v0, p1, v4}, La0/b;-><init>(Ljava/lang/Object;ZI)V

    .line 420
    .line 421
    .line 422
    invoke-virtual {v1, v2}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 423
    .line 424
    .line 425
    if-nez p1, :cond_f

    .line 426
    .line 427
    iget-object p0, p0, Lu/m;->p:Lt1/j0;

    .line 428
    .line 429
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 430
    .line 431
    check-cast p0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 432
    .line 433
    invoke-virtual {p0, v3}, Ljava/util/concurrent/atomic/AtomicInteger;->set(I)V

    .line 434
    .line 435
    .line 436
    const-string p0, "VideoUsageControl"

    .line 437
    .line 438
    const-string p1, "resetDirectly: mVideoUsage reset!"

    .line 439
    .line 440
    invoke-static {p0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 441
    .line 442
    .line 443
    :cond_f
    return-void
.end method

.method public final n(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lu/m;->k:Lb6/f;

    .line 2
    .line 3
    iget-object p0, p0, Lb6/f;->e:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter p0

    .line 6
    if-nez p1, :cond_0

    .line 7
    .line 8
    :try_start_0
    monitor-exit p0

    .line 9
    return-void

    .line 10
    :catchall_0
    move-exception p1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    monitor-exit p0

    .line 13
    return-void

    .line 14
    :goto_0
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    throw p1
.end method

.method public final o(Ljava/util/List;)V
    .locals 14

    .line 1
    iget-object p0, p0, Lu/m;->f:Lro/f;

    .line 2
    .line 3
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lu/y;

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    check-cast p1, Ljava/util/List;

    .line 11
    .line 12
    new-instance v0, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const/4 v2, 0x0

    .line 26
    if-eqz v1, :cond_b

    .line 27
    .line 28
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    check-cast v1, Lh0/o0;

    .line 33
    .line 34
    new-instance v3, Ljava/util/HashSet;

    .line 35
    .line 36
    invoke-direct {v3}, Ljava/util/HashSet;-><init>()V

    .line 37
    .line 38
    .line 39
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 40
    .line 41
    .line 42
    new-instance v4, Ljava/util/ArrayList;

    .line 43
    .line 44
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 45
    .line 46
    .line 47
    invoke-static {}, Lh0/k1;->a()Lh0/k1;

    .line 48
    .line 49
    .line 50
    iget-object v5, v1, Lh0/o0;->a:Ljava/util/ArrayList;

    .line 51
    .line 52
    invoke-interface {v3, v5}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 53
    .line 54
    .line 55
    iget-object v5, v1, Lh0/o0;->b:Lh0/n1;

    .line 56
    .line 57
    invoke-static {v5}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    iget v9, v1, Lh0/o0;->c:I

    .line 62
    .line 63
    iget-object v6, v1, Lh0/o0;->d:Ljava/util/List;

    .line 64
    .line 65
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 66
    .line 67
    .line 68
    iget-boolean v11, v1, Lh0/o0;->e:Z

    .line 69
    .line 70
    iget-object v6, v1, Lh0/o0;->f:Lh0/j2;

    .line 71
    .line 72
    new-instance v7, Landroid/util/ArrayMap;

    .line 73
    .line 74
    invoke-direct {v7}, Landroid/util/ArrayMap;-><init>()V

    .line 75
    .line 76
    .line 77
    iget-object v8, v6, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 78
    .line 79
    invoke-virtual {v8}, Landroid/util/ArrayMap;->keySet()Ljava/util/Set;

    .line 80
    .line 81
    .line 82
    move-result-object v8

    .line 83
    invoke-interface {v8}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 84
    .line 85
    .line 86
    move-result-object v8

    .line 87
    :goto_1
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 88
    .line 89
    .line 90
    move-result v10

    .line 91
    if-eqz v10, :cond_0

    .line 92
    .line 93
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v10

    .line 97
    check-cast v10, Ljava/lang/String;

    .line 98
    .line 99
    iget-object v12, v6, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 100
    .line 101
    invoke-virtual {v12, v10}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v12

    .line 105
    invoke-virtual {v7, v10, v12}, Landroid/util/ArrayMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_0
    new-instance v6, Lh0/k1;

    .line 110
    .line 111
    invoke-direct {v6, v7}, Lh0/j2;-><init>(Landroid/util/ArrayMap;)V

    .line 112
    .line 113
    .line 114
    iget v7, v1, Lh0/o0;->c:I

    .line 115
    .line 116
    const/4 v8, 0x5

    .line 117
    if-ne v7, v8, :cond_1

    .line 118
    .line 119
    iget-object v7, v1, Lh0/o0;->g:Lh0/s;

    .line 120
    .line 121
    if-eqz v7, :cond_1

    .line 122
    .line 123
    move-object v13, v7

    .line 124
    goto :goto_2

    .line 125
    :cond_1
    move-object v13, v2

    .line 126
    :goto_2
    iget-object v2, v1, Lh0/o0;->a:Ljava/util/ArrayList;

    .line 127
    .line 128
    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 129
    .line 130
    .line 131
    move-result-object v2

    .line 132
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 133
    .line 134
    .line 135
    move-result v2

    .line 136
    if-eqz v2, :cond_9

    .line 137
    .line 138
    iget-boolean v1, v1, Lh0/o0;->e:Z

    .line 139
    .line 140
    if-eqz v1, :cond_9

    .line 141
    .line 142
    invoke-virtual {v3}, Ljava/util/HashSet;->isEmpty()Z

    .line 143
    .line 144
    .line 145
    move-result v1

    .line 146
    const-string v2, "Camera2CameraImpl"

    .line 147
    .line 148
    if-nez v1, :cond_2

    .line 149
    .line 150
    const-string v1, "The capture config builder already has surface inside."

    .line 151
    .line 152
    invoke-static {v2, v1}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    goto/16 :goto_0

    .line 156
    .line 157
    :cond_2
    iget-object v1, p0, Lu/y;->d:Lb81/c;

    .line 158
    .line 159
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 160
    .line 161
    .line 162
    new-instance v7, Ljava/util/ArrayList;

    .line 163
    .line 164
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 165
    .line 166
    .line 167
    iget-object v1, v1, Lb81/c;->f:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast v1, Ljava/util/LinkedHashMap;

    .line 170
    .line 171
    invoke-virtual {v1}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 176
    .line 177
    .line 178
    move-result-object v1

    .line 179
    :cond_3
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 180
    .line 181
    .line 182
    move-result v8

    .line 183
    if-eqz v8, :cond_4

    .line 184
    .line 185
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v8

    .line 189
    check-cast v8, Ljava/util/Map$Entry;

    .line 190
    .line 191
    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v10

    .line 195
    check-cast v10, Lh0/l2;

    .line 196
    .line 197
    iget-boolean v12, v10, Lh0/l2;->f:Z

    .line 198
    .line 199
    if-eqz v12, :cond_3

    .line 200
    .line 201
    iget-boolean v10, v10, Lh0/l2;->e:Z

    .line 202
    .line 203
    if-eqz v10, :cond_3

    .line 204
    .line 205
    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v8

    .line 209
    check-cast v8, Lh0/l2;

    .line 210
    .line 211
    iget-object v8, v8, Lh0/l2;->a:Lh0/z1;

    .line 212
    .line 213
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    goto :goto_3

    .line 217
    :cond_4
    invoke-static {v7}, Ljava/util/Collections;->unmodifiableCollection(Ljava/util/Collection;)Ljava/util/Collection;

    .line 218
    .line 219
    .line 220
    move-result-object v1

    .line 221
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 222
    .line 223
    .line 224
    move-result-object v1

    .line 225
    :cond_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 226
    .line 227
    .line 228
    move-result v7

    .line 229
    if-eqz v7, :cond_8

    .line 230
    .line 231
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v7

    .line 235
    check-cast v7, Lh0/z1;

    .line 236
    .line 237
    iget-object v7, v7, Lh0/z1;->g:Lh0/o0;

    .line 238
    .line 239
    iget-object v8, v7, Lh0/o0;->a:Ljava/util/ArrayList;

    .line 240
    .line 241
    invoke-static {v8}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 242
    .line 243
    .line 244
    move-result-object v8

    .line 245
    invoke-interface {v8}, Ljava/util/List;->isEmpty()Z

    .line 246
    .line 247
    .line 248
    move-result v10

    .line 249
    if-nez v10, :cond_5

    .line 250
    .line 251
    invoke-virtual {v7}, Lh0/o0;->b()I

    .line 252
    .line 253
    .line 254
    move-result v10

    .line 255
    if-eqz v10, :cond_6

    .line 256
    .line 257
    invoke-virtual {v7}, Lh0/o0;->b()I

    .line 258
    .line 259
    .line 260
    move-result v10

    .line 261
    if-eqz v10, :cond_6

    .line 262
    .line 263
    sget-object v12, Lh0/o2;->a1:Lh0/g;

    .line 264
    .line 265
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 266
    .line 267
    .line 268
    move-result-object v10

    .line 269
    invoke-virtual {v5, v12, v10}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 270
    .line 271
    .line 272
    :cond_6
    invoke-virtual {v7}, Lh0/o0;->c()I

    .line 273
    .line 274
    .line 275
    move-result v10

    .line 276
    if-eqz v10, :cond_7

    .line 277
    .line 278
    invoke-virtual {v7}, Lh0/o0;->c()I

    .line 279
    .line 280
    .line 281
    move-result v7

    .line 282
    if-eqz v7, :cond_7

    .line 283
    .line 284
    sget-object v10, Lh0/o2;->b1:Lh0/g;

    .line 285
    .line 286
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 287
    .line 288
    .line 289
    move-result-object v7

    .line 290
    invoke-virtual {v5, v10, v7}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 291
    .line 292
    .line 293
    :cond_7
    invoke-interface {v8}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 294
    .line 295
    .line 296
    move-result-object v7

    .line 297
    :goto_4
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 298
    .line 299
    .line 300
    move-result v8

    .line 301
    if-eqz v8, :cond_5

    .line 302
    .line 303
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v8

    .line 307
    check-cast v8, Lh0/t0;

    .line 308
    .line 309
    invoke-virtual {v3, v8}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 310
    .line 311
    .line 312
    goto :goto_4

    .line 313
    :cond_8
    invoke-virtual {v3}, Ljava/util/HashSet;->isEmpty()Z

    .line 314
    .line 315
    .line 316
    move-result v1

    .line 317
    if-eqz v1, :cond_9

    .line 318
    .line 319
    const-string v1, "Unable to find a repeating surface to attach to CaptureConfig"

    .line 320
    .line 321
    invoke-static {v2, v1}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 322
    .line 323
    .line 324
    goto/16 :goto_0

    .line 325
    .line 326
    :cond_9
    move-object v1, v6

    .line 327
    new-instance v6, Lh0/o0;

    .line 328
    .line 329
    new-instance v7, Ljava/util/ArrayList;

    .line 330
    .line 331
    invoke-direct {v7, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 332
    .line 333
    .line 334
    invoke-static {v5}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 335
    .line 336
    .line 337
    move-result-object v8

    .line 338
    new-instance v10, Ljava/util/ArrayList;

    .line 339
    .line 340
    invoke-direct {v10, v4}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 341
    .line 342
    .line 343
    sget-object v2, Lh0/j2;->b:Lh0/j2;

    .line 344
    .line 345
    new-instance v2, Landroid/util/ArrayMap;

    .line 346
    .line 347
    invoke-direct {v2}, Landroid/util/ArrayMap;-><init>()V

    .line 348
    .line 349
    .line 350
    iget-object v1, v1, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 351
    .line 352
    invoke-virtual {v1}, Landroid/util/ArrayMap;->keySet()Ljava/util/Set;

    .line 353
    .line 354
    .line 355
    move-result-object v3

    .line 356
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 357
    .line 358
    .line 359
    move-result-object v3

    .line 360
    :goto_5
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 361
    .line 362
    .line 363
    move-result v4

    .line 364
    if-eqz v4, :cond_a

    .line 365
    .line 366
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 367
    .line 368
    .line 369
    move-result-object v4

    .line 370
    check-cast v4, Ljava/lang/String;

    .line 371
    .line 372
    invoke-virtual {v1, v4}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object v5

    .line 376
    invoke-virtual {v2, v4, v5}, Landroid/util/ArrayMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    goto :goto_5

    .line 380
    :cond_a
    new-instance v12, Lh0/j2;

    .line 381
    .line 382
    invoke-direct {v12, v2}, Lh0/j2;-><init>(Landroid/util/ArrayMap;)V

    .line 383
    .line 384
    .line 385
    invoke-direct/range {v6 .. v13}, Lh0/o0;-><init>(Ljava/util/ArrayList;Lh0/n1;ILjava/util/ArrayList;ZLh0/j2;Lh0/s;)V

    .line 386
    .line 387
    .line 388
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 389
    .line 390
    .line 391
    goto/16 :goto_0

    .line 392
    .line 393
    :cond_b
    const-string p1, "Issue capture request"

    .line 394
    .line 395
    invoke-virtual {p0, p1, v2}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 396
    .line 397
    .line 398
    iget-object p0, p0, Lu/y;->o:Lu/p0;

    .line 399
    .line 400
    invoke-virtual {p0, v0}, Lu/p0;->k(Ljava/util/List;)V

    .line 401
    .line 402
    .line 403
    return-void
.end method

.method public final p()J
    .locals 2

    .line 1
    iget-object v0, p0, Lu/m;->v:Ljava/util/concurrent/atomic/AtomicLong;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicLong;->getAndIncrement()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iput-wide v0, p0, Lu/m;->x:J

    .line 8
    .line 9
    iget-object v0, p0, Lu/m;->f:Lro/f;

    .line 10
    .line 11
    iget-object v0, v0, Lro/f;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lu/y;

    .line 14
    .line 15
    invoke-virtual {v0}, Lu/y;->M()V

    .line 16
    .line 17
    .line 18
    iget-wide v0, p0, Lu/m;->x:J

    .line 19
    .line 20
    return-wide v0
.end method
