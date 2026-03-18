.class public abstract Llp/w0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lh0/o0;Landroid/hardware/camera2/CaptureRequest$Builder;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lh0/o0;->a()Landroid/util/Range;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object v0, Lh0/k;->h:Landroid/util/Range;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    sget-object v0, Landroid/hardware/camera2/CaptureRequest;->CONTROL_AE_TARGET_FPS_RANGE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 14
    .line 15
    invoke-virtual {p1, v0, p0}, Landroid/hardware/camera2/CaptureRequest$Builder;->set(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v0, "applyAeFpsRange: expectedFrameRateRange = "

    .line 21
    .line 22
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    const-string p1, "Camera2CaptureRequestBuilder"

    .line 33
    .line 34
    invoke-static {p1, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public static b(Landroid/hardware/camera2/CaptureRequest$Builder;Lh0/n1;)V
    .locals 4

    .line 1
    invoke-static {p1}, La0/i;->d(Lh0/q0;)La0/i;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p1}, La0/i;->c()La0/j;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-interface {p1}, Lh0/t1;->d()Ljava/util/Set;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, Lh0/g;

    .line 28
    .line 29
    iget-object v2, v1, Lh0/g;->c:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v2, Landroid/hardware/camera2/CaptureRequest$Key;

    .line 32
    .line 33
    :try_start_0
    invoke-interface {p1, v1}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-virtual {p0, v2, v1}, Landroid/hardware/camera2/CaptureRequest$Builder;->set(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :catch_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 42
    .line 43
    const-string v3, "CaptureRequest.Key is not supported: "

    .line 44
    .line 45
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    const-string v2, "Camera2CaptureRequestBuilder"

    .line 56
    .line 57
    invoke-static {v2, v1}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    return-void
.end method

.method public static c(Landroid/hardware/camera2/CaptureRequest$Builder;ILk1/c0;)V
    .locals 1

    .line 1
    const/4 v0, 0x3

    .line 2
    if-ne p1, v0, :cond_0

    .line 3
    .line 4
    iget-boolean v0, p2, Lk1/c0;->a:Z

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    new-instance p1, Ljava/util/HashMap;

    .line 9
    .line 10
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 11
    .line 12
    .line 13
    sget-object p2, Landroid/hardware/camera2/CaptureRequest;->CONTROL_CAPTURE_INTENT:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {p1, p2, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    invoke-static {p1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v0, 0x4

    .line 29
    if-ne p1, v0, :cond_1

    .line 30
    .line 31
    iget-boolean p1, p2, Lk1/c0;->b:Z

    .line 32
    .line 33
    if-eqz p1, :cond_2

    .line 34
    .line 35
    new-instance p1, Ljava/util/HashMap;

    .line 36
    .line 37
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 38
    .line 39
    .line 40
    sget-object p2, Landroid/hardware/camera2/CaptureRequest;->CONTROL_CAPTURE_INTENT:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 41
    .line 42
    const/4 v0, 0x2

    .line 43
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-virtual {p1, p2, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    invoke-static {p1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    goto :goto_0

    .line 55
    :cond_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    :cond_2
    sget-object p1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 59
    .line 60
    :goto_0
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 69
    .line 70
    .line 71
    move-result p2

    .line 72
    if-eqz p2, :cond_3

    .line 73
    .line 74
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p2

    .line 78
    check-cast p2, Ljava/util/Map$Entry;

    .line 79
    .line 80
    invoke-interface {p2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    check-cast v0, Landroid/hardware/camera2/CaptureRequest$Key;

    .line 85
    .line 86
    invoke-interface {p2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    invoke-virtual {p0, v0, p2}, Landroid/hardware/camera2/CaptureRequest$Builder;->set(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_3
    return-void
.end method

.method public static d(Lh0/o0;Landroid/hardware/camera2/CameraDevice;Ljava/util/HashMap;ZLk1/c0;)Landroid/hardware/camera2/CaptureRequest;
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    goto :goto_1

    .line 5
    :cond_0
    iget-object v1, p0, Lh0/o0;->a:Ljava/util/ArrayList;

    .line 6
    .line 7
    iget v2, p0, Lh0/o0;->c:I

    .line 8
    .line 9
    iget-object v3, p0, Lh0/o0;->b:Lh0/n1;

    .line 10
    .line 11
    iget-object v4, v3, Lh0/n1;->d:Ljava/util/TreeMap;

    .line 12
    .line 13
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    new-instance v5, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 20
    .line 21
    .line 22
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v6

    .line 30
    if-eqz v6, :cond_2

    .line 31
    .line 32
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v6

    .line 36
    check-cast v6, Lh0/t0;

    .line 37
    .line 38
    invoke-virtual {p2, v6}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    check-cast v6, Landroid/view/Surface;

    .line 43
    .line 44
    if-eqz v6, :cond_1

    .line 45
    .line 46
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 51
    .line 52
    const-string p1, "DeferrableSurface not in configuredSurfaceMap"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-virtual {v5}, Ljava/util/ArrayList;->isEmpty()Z

    .line 59
    .line 60
    .line 61
    move-result p2

    .line 62
    if-eqz p2, :cond_3

    .line 63
    .line 64
    :goto_1
    return-object v0

    .line 65
    :cond_3
    iget-object p2, p0, Lh0/o0;->g:Lh0/s;

    .line 66
    .line 67
    const/4 v1, 0x2

    .line 68
    const/4 v6, 0x1

    .line 69
    const/4 v7, 0x5

    .line 70
    const-string v8, "Camera2CaptureRequestBuilder"

    .line 71
    .line 72
    if-ne v2, v7, :cond_4

    .line 73
    .line 74
    if-eqz p2, :cond_4

    .line 75
    .line 76
    invoke-interface {p2}, Lh0/s;->f()Landroid/hardware/camera2/CaptureResult;

    .line 77
    .line 78
    .line 79
    move-result-object v9

    .line 80
    instance-of v9, v9, Landroid/hardware/camera2/TotalCaptureResult;

    .line 81
    .line 82
    if-eqz v9, :cond_4

    .line 83
    .line 84
    const-string p3, "createReprocessCaptureRequest"

    .line 85
    .line 86
    invoke-static {v8, p3}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-interface {p2}, Lh0/s;->f()Landroid/hardware/camera2/CaptureResult;

    .line 90
    .line 91
    .line 92
    move-result-object p2

    .line 93
    check-cast p2, Landroid/hardware/camera2/TotalCaptureResult;

    .line 94
    .line 95
    invoke-virtual {p1, p2}, Landroid/hardware/camera2/CameraDevice;->createReprocessCaptureRequest(Landroid/hardware/camera2/TotalCaptureResult;)Landroid/hardware/camera2/CaptureRequest$Builder;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    goto :goto_3

    .line 100
    :cond_4
    const-string p2, "createCaptureRequest"

    .line 101
    .line 102
    invoke-static {v8, p2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    if-ne v2, v7, :cond_6

    .line 106
    .line 107
    if-eqz p3, :cond_5

    .line 108
    .line 109
    move p2, v6

    .line 110
    goto :goto_2

    .line 111
    :cond_5
    move p2, v1

    .line 112
    :goto_2
    invoke-virtual {p1, p2}, Landroid/hardware/camera2/CameraDevice;->createCaptureRequest(I)Landroid/hardware/camera2/CaptureRequest$Builder;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    goto :goto_3

    .line 117
    :cond_6
    invoke-virtual {p1, v2}, Landroid/hardware/camera2/CameraDevice;->createCaptureRequest(I)Landroid/hardware/camera2/CaptureRequest$Builder;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    :goto_3
    invoke-static {p1, v2, p4}, Llp/w0;->c(Landroid/hardware/camera2/CaptureRequest$Builder;ILk1/c0;)V

    .line 122
    .line 123
    .line 124
    invoke-static {p0, p1}, Llp/w0;->a(Lh0/o0;Landroid/hardware/camera2/CaptureRequest$Builder;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p0}, Lh0/o0;->b()I

    .line 128
    .line 129
    .line 130
    move-result p2

    .line 131
    if-eq p2, v6, :cond_9

    .line 132
    .line 133
    invoke-virtual {p0}, Lh0/o0;->c()I

    .line 134
    .line 135
    .line 136
    move-result p2

    .line 137
    if-ne p2, v6, :cond_7

    .line 138
    .line 139
    goto :goto_4

    .line 140
    :cond_7
    invoke-virtual {p0}, Lh0/o0;->b()I

    .line 141
    .line 142
    .line 143
    move-result p2

    .line 144
    if-ne p2, v1, :cond_8

    .line 145
    .line 146
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    goto :goto_5

    .line 151
    :cond_8
    invoke-virtual {p0}, Lh0/o0;->c()I

    .line 152
    .line 153
    .line 154
    move-result p2

    .line 155
    if-ne p2, v1, :cond_a

    .line 156
    .line 157
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    goto :goto_5

    .line 162
    :cond_9
    :goto_4
    const/4 p2, 0x0

    .line 163
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    :cond_a
    :goto_5
    if-eqz v0, :cond_b

    .line 168
    .line 169
    sget-object p2, Landroid/hardware/camera2/CaptureRequest;->CONTROL_VIDEO_STABILIZATION_MODE:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 170
    .line 171
    invoke-virtual {p1, p2, v0}, Landroid/hardware/camera2/CaptureRequest$Builder;->set(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    :cond_b
    new-instance p2, Ljava/lang/StringBuilder;

    .line 175
    .line 176
    const-string p3, "applyVideoStabilization: mode = "

    .line 177
    .line 178
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object p2

    .line 188
    invoke-static {v8, p2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    sget-object p2, Lh0/o0;->h:Lh0/g;

    .line 192
    .line 193
    invoke-virtual {v4, p2}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result p3

    .line 197
    if-eqz p3, :cond_c

    .line 198
    .line 199
    sget-object p3, Landroid/hardware/camera2/CaptureRequest;->JPEG_ORIENTATION:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 200
    .line 201
    invoke-virtual {v3, p2}, Lh0/n1;->f(Lh0/g;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object p2

    .line 205
    check-cast p2, Ljava/lang/Integer;

    .line 206
    .line 207
    invoke-virtual {p1, p3, p2}, Landroid/hardware/camera2/CaptureRequest$Builder;->set(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    :cond_c
    sget-object p2, Lh0/o0;->i:Lh0/g;

    .line 211
    .line 212
    invoke-virtual {v4, p2}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 213
    .line 214
    .line 215
    move-result p3

    .line 216
    if-eqz p3, :cond_d

    .line 217
    .line 218
    sget-object p3, Landroid/hardware/camera2/CaptureRequest;->JPEG_QUALITY:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 219
    .line 220
    invoke-virtual {v3, p2}, Lh0/n1;->f(Lh0/g;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object p2

    .line 224
    check-cast p2, Ljava/lang/Integer;

    .line 225
    .line 226
    invoke-virtual {p2}, Ljava/lang/Integer;->byteValue()B

    .line 227
    .line 228
    .line 229
    move-result p2

    .line 230
    invoke-static {p2}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 231
    .line 232
    .line 233
    move-result-object p2

    .line 234
    invoke-virtual {p1, p3, p2}, Landroid/hardware/camera2/CaptureRequest$Builder;->set(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V

    .line 235
    .line 236
    .line 237
    :cond_d
    invoke-static {p1, v3}, Llp/w0;->b(Landroid/hardware/camera2/CaptureRequest$Builder;Lh0/n1;)V

    .line 238
    .line 239
    .line 240
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 241
    .line 242
    .line 243
    move-result-object p2

    .line 244
    :goto_6
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 245
    .line 246
    .line 247
    move-result p3

    .line 248
    if-eqz p3, :cond_e

    .line 249
    .line 250
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object p3

    .line 254
    check-cast p3, Landroid/view/Surface;

    .line 255
    .line 256
    invoke-virtual {p1, p3}, Landroid/hardware/camera2/CaptureRequest$Builder;->addTarget(Landroid/view/Surface;)V

    .line 257
    .line 258
    .line 259
    goto :goto_6

    .line 260
    :cond_e
    iget-object p0, p0, Lh0/o0;->f:Lh0/j2;

    .line 261
    .line 262
    invoke-virtual {p1, p0}, Landroid/hardware/camera2/CaptureRequest$Builder;->setTag(Ljava/lang/Object;)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {p1}, Landroid/hardware/camera2/CaptureRequest$Builder;->build()Landroid/hardware/camera2/CaptureRequest;

    .line 266
    .line 267
    .line 268
    move-result-object p0

    .line 269
    return-object p0
.end method

.method public static e(Lh0/o0;Landroid/hardware/camera2/CameraDevice;Lk1/c0;)Landroid/hardware/camera2/CaptureRequest;
    .locals 3

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "template type = "

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget v1, p0, Lh0/o0;->c:I

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const-string v2, "Camera2CaptureRequestBuilder"

    .line 22
    .line 23
    invoke-static {v2, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p1, v1}, Landroid/hardware/camera2/CameraDevice;->createCaptureRequest(I)Landroid/hardware/camera2/CaptureRequest$Builder;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-static {p1, v1, p2}, Llp/w0;->c(Landroid/hardware/camera2/CaptureRequest$Builder;ILk1/c0;)V

    .line 31
    .line 32
    .line 33
    invoke-static {p0, p1}, Llp/w0;->a(Lh0/o0;Landroid/hardware/camera2/CaptureRequest$Builder;)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lh0/o0;->b:Lh0/n1;

    .line 37
    .line 38
    invoke-static {p1, p0}, Llp/w0;->b(Landroid/hardware/camera2/CaptureRequest$Builder;Lh0/n1;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p1}, Landroid/hardware/camera2/CaptureRequest$Builder;->build()Landroid/hardware/camera2/CaptureRequest;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method

.method public static f(Lzg/h;Lai/d;)Lhh/e;
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "station"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v2, v0, Lzg/h;->e:Lzg/g;

    .line 11
    .line 12
    iget-object v3, v0, Lzg/h;->g:Lzg/q;

    .line 13
    .line 14
    iget-object v4, v0, Lzg/h;->n:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v5, v0, Lzg/h;->j:Ljava/lang/String;

    .line 17
    .line 18
    const-string v6, "downloadChargingStationImageUseCase"

    .line 19
    .line 20
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v6, v0, Lzg/h;->l:Ljava/lang/String;

    .line 24
    .line 25
    if-eqz v6, :cond_1

    .line 26
    .line 27
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 28
    .line 29
    .line 30
    move-result v9

    .line 31
    if-nez v9, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v9, 0x0

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    :goto_0
    const/4 v9, 0x1

    .line 37
    :goto_1
    xor-int/lit8 v24, v9, 0x1

    .line 38
    .line 39
    if-eqz v5, :cond_3

    .line 40
    .line 41
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 42
    .line 43
    .line 44
    move-result v10

    .line 45
    if-nez v10, :cond_2

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/4 v10, 0x0

    .line 49
    goto :goto_3

    .line 50
    :cond_3
    :goto_2
    const/4 v10, 0x1

    .line 51
    :goto_3
    xor-int/lit8 v25, v10, 0x1

    .line 52
    .line 53
    if-eqz v4, :cond_5

    .line 54
    .line 55
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 56
    .line 57
    .line 58
    move-result v11

    .line 59
    if-nez v11, :cond_4

    .line 60
    .line 61
    goto :goto_4

    .line 62
    :cond_4
    const/4 v11, 0x0

    .line 63
    goto :goto_5

    .line 64
    :cond_5
    :goto_4
    const/4 v11, 0x1

    .line 65
    :goto_5
    xor-int/lit8 v28, v11, 0x1

    .line 66
    .line 67
    if-eqz v3, :cond_6

    .line 68
    .line 69
    const/4 v12, 0x1

    .line 70
    :goto_6
    move v13, v11

    .line 71
    goto :goto_7

    .line 72
    :cond_6
    const/4 v12, 0x0

    .line 73
    goto :goto_6

    .line 74
    :goto_7
    iget-object v11, v0, Lzg/h;->i:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v14, v0, Lzg/h;->h:Ljava/lang/String;

    .line 77
    .line 78
    iget-object v15, v0, Lzg/h;->p:Ljava/lang/Boolean;

    .line 79
    .line 80
    sget-object v7, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 81
    .line 82
    invoke-static {v15, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v7

    .line 86
    const-string v15, "<this>"

    .line 87
    .line 88
    invoke-static {v2, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 92
    .line 93
    .line 94
    move-result v15

    .line 95
    packed-switch v15, :pswitch_data_0

    .line 96
    .line 97
    .line 98
    new-instance v0, La8/r0;

    .line 99
    .line 100
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 101
    .line 102
    .line 103
    throw v0

    .line 104
    :pswitch_0
    sget-object v15, Lgh/a;->f:Lgh/a;

    .line 105
    .line 106
    goto :goto_8

    .line 107
    :pswitch_1
    sget-object v15, Lgh/a;->h:Lgh/a;

    .line 108
    .line 109
    goto :goto_8

    .line 110
    :pswitch_2
    sget-object v15, Lgh/a;->g:Lgh/a;

    .line 111
    .line 112
    goto :goto_8

    .line 113
    :pswitch_3
    sget-object v15, Lgh/a;->e:Lgh/a;

    .line 114
    .line 115
    goto :goto_8

    .line 116
    :pswitch_4
    sget-object v15, Lgh/a;->d:Lgh/a;

    .line 117
    .line 118
    :goto_8
    const-string v17, ""

    .line 119
    .line 120
    if-nez v5, :cond_7

    .line 121
    .line 122
    move-object/from16 v5, v17

    .line 123
    .line 124
    :cond_7
    iget-object v8, v0, Lzg/h;->k:Ljava/lang/String;

    .line 125
    .line 126
    if-nez v8, :cond_8

    .line 127
    .line 128
    move-object/from16 v16, v17

    .line 129
    .line 130
    :goto_9
    const/16 v19, 0x0

    .line 131
    .line 132
    goto :goto_a

    .line 133
    :cond_8
    move-object/from16 v16, v8

    .line 134
    .line 135
    goto :goto_9

    .line 136
    :goto_a
    if-nez v6, :cond_9

    .line 137
    .line 138
    move-object/from16 v6, v17

    .line 139
    .line 140
    :cond_9
    move-object/from16 v20, v4

    .line 141
    .line 142
    iget-object v4, v0, Lzg/h;->m:Ljava/lang/String;

    .line 143
    .line 144
    if-nez v4, :cond_a

    .line 145
    .line 146
    move-object/from16 v18, v17

    .line 147
    .line 148
    :goto_b
    const/16 v21, 0x1

    .line 149
    .line 150
    goto :goto_c

    .line 151
    :cond_a
    move-object/from16 v18, v4

    .line 152
    .line 153
    goto :goto_b

    .line 154
    :goto_c
    if-nez v20, :cond_b

    .line 155
    .line 156
    move-object/from16 v20, v17

    .line 157
    .line 158
    :cond_b
    move-object/from16 v22, v4

    .line 159
    .line 160
    sget-object v4, Lzg/g;->e:Lzg/g;

    .line 161
    .line 162
    if-ne v2, v4, :cond_c

    .line 163
    .line 164
    move-object/from16 v19, v20

    .line 165
    .line 166
    move/from16 v20, v21

    .line 167
    .line 168
    goto :goto_d

    .line 169
    :cond_c
    move-object/from16 v33, v20

    .line 170
    .line 171
    move/from16 v20, v19

    .line 172
    .line 173
    move-object/from16 v19, v33

    .line 174
    .line 175
    :goto_d
    sget-object v4, Lzg/g;->g:Lzg/g;

    .line 176
    .line 177
    if-ne v2, v4, :cond_d

    .line 178
    .line 179
    goto :goto_e

    .line 180
    :cond_d
    const/16 v21, 0x0

    .line 181
    .line 182
    :goto_e
    sget-object v4, Lzg/g;->f:Lzg/g;

    .line 183
    .line 184
    move-object/from16 v27, v22

    .line 185
    .line 186
    if-ne v2, v4, :cond_e

    .line 187
    .line 188
    const/16 v22, 0x1

    .line 189
    .line 190
    goto :goto_f

    .line 191
    :cond_e
    const/16 v22, 0x0

    .line 192
    .line 193
    :goto_f
    sget-object v4, Lzg/g;->i:Lzg/g;

    .line 194
    .line 195
    if-ne v2, v4, :cond_f

    .line 196
    .line 197
    const/16 v23, 0x1

    .line 198
    .line 199
    :goto_10
    const/4 v2, 0x0

    .line 200
    goto :goto_11

    .line 201
    :cond_f
    const/16 v23, 0x0

    .line 202
    .line 203
    goto :goto_10

    .line 204
    :goto_11
    if-eqz v27, :cond_10

    .line 205
    .line 206
    const/16 v27, 0x1

    .line 207
    .line 208
    goto :goto_12

    .line 209
    :cond_10
    move/from16 v27, v2

    .line 210
    .line 211
    :goto_12
    if-eqz v8, :cond_11

    .line 212
    .line 213
    const/16 v26, 0x1

    .line 214
    .line 215
    :goto_13
    const/4 v4, 0x1

    .line 216
    goto :goto_14

    .line 217
    :cond_11
    move/from16 v26, v2

    .line 218
    .line 219
    goto :goto_13

    .line 220
    :goto_14
    if-eqz v9, :cond_13

    .line 221
    .line 222
    if-eqz v10, :cond_13

    .line 223
    .line 224
    if-nez v13, :cond_12

    .line 225
    .line 226
    goto :goto_15

    .line 227
    :cond_12
    move/from16 v29, v2

    .line 228
    .line 229
    goto :goto_16

    .line 230
    :cond_13
    :goto_15
    move/from16 v29, v4

    .line 231
    .line 232
    :goto_16
    iget-boolean v2, v0, Lzg/h;->v:Z

    .line 233
    .line 234
    iget-object v4, v0, Lzg/h;->d:Ljava/util/List;

    .line 235
    .line 236
    check-cast v4, Ljava/lang/Iterable;

    .line 237
    .line 238
    new-instance v8, Ljava/util/ArrayList;

    .line 239
    .line 240
    const/16 v9, 0xa

    .line 241
    .line 242
    invoke-static {v4, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 243
    .line 244
    .line 245
    move-result v9

    .line 246
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 247
    .line 248
    .line 249
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 250
    .line 251
    .line 252
    move-result-object v4

    .line 253
    :goto_17
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 254
    .line 255
    .line 256
    move-result v9

    .line 257
    if-eqz v9, :cond_14

    .line 258
    .line 259
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v9

    .line 263
    check-cast v9, Ljava/lang/String;

    .line 264
    .line 265
    invoke-virtual {v1, v9}, Lai/d;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object v9

    .line 269
    check-cast v9, Lkc/e;

    .line 270
    .line 271
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    goto :goto_17

    .line 275
    :cond_14
    new-instance v1, Lzg/i2;

    .line 276
    .line 277
    iget-object v0, v0, Lzg/h;->f:Ljava/lang/String;

    .line 278
    .line 279
    const/4 v4, 0x0

    .line 280
    if-eqz v3, :cond_15

    .line 281
    .line 282
    iget-object v9, v3, Lzg/q;->d:Ljava/lang/String;

    .line 283
    .line 284
    goto :goto_18

    .line 285
    :cond_15
    move-object v9, v4

    .line 286
    :goto_18
    if-nez v9, :cond_16

    .line 287
    .line 288
    move-object/from16 v9, v17

    .line 289
    .line 290
    :cond_16
    if-eqz v3, :cond_17

    .line 291
    .line 292
    iget-object v4, v3, Lzg/q;->e:Ljava/lang/String;

    .line 293
    .line 294
    :cond_17
    if-nez v4, :cond_18

    .line 295
    .line 296
    move-object/from16 v4, v17

    .line 297
    .line 298
    :cond_18
    invoke-direct {v1, v12, v0, v9, v4}, Lzg/i2;-><init>(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    new-instance v10, Lhh/e;

    .line 302
    .line 303
    move-object/from16 v32, v1

    .line 304
    .line 305
    move/from16 v30, v2

    .line 306
    .line 307
    move-object/from16 v17, v6

    .line 308
    .line 309
    move v13, v7

    .line 310
    move-object/from16 v31, v8

    .line 311
    .line 312
    move-object v12, v14

    .line 313
    move-object v14, v15

    .line 314
    move-object v15, v5

    .line 315
    invoke-direct/range {v10 .. v32}, Lhh/e;-><init>(Ljava/lang/String;Ljava/lang/String;ZLgh/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZZZZZZZLjava/util/ArrayList;Lzg/i2;)V

    .line 316
    .line 317
    .line 318
    return-object v10

    .line 319
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_3
        :pswitch_1
        :pswitch_0
        :pswitch_4
        :pswitch_3
    .end packed-switch
.end method
