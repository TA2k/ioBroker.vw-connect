.class public final Lh0/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/StringBuilder;

.field public final b:Ljava/lang/Object;

.field public c:I

.field public final d:Lz/a;

.field public final e:Ljava/util/HashMap;

.field public f:I


# direct methods
.method public constructor <init>(Lz/a;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lh0/k0;->a:Ljava/lang/StringBuilder;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lh0/k0;->b:Ljava/lang/Object;

    .line 17
    .line 18
    new-instance v1, Ljava/util/HashMap;

    .line 19
    .line 20
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v1, p0, Lh0/k0;->e:Ljava/util/HashMap;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    iput v1, p0, Lh0/k0;->c:I

    .line 27
    .line 28
    monitor-enter v0

    .line 29
    :try_start_0
    iput-object p1, p0, Lh0/k0;->d:Lz/a;

    .line 30
    .line 31
    iget p1, p0, Lh0/k0;->c:I

    .line 32
    .line 33
    iput p1, p0, Lh0/k0;->f:I

    .line 34
    .line 35
    monitor-exit v0

    .line 36
    return-void

    .line 37
    :catchall_0
    move-exception p0

    .line 38
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    throw p0
.end method

.method public static c(Lu/y;Lh0/a0;)V
    .locals 2

    .line 1
    invoke-static {}, Lab/a;->a()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "CX:State["

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, "]"

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    invoke-static {p0}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    int-to-long v0, p1

    .line 35
    invoke-static {p0, v0, v1}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 36
    .line 37
    .line 38
    :cond_0
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lh0/j0;
    .locals 3

    .line 1
    iget-object p0, p0, Lh0/k0;->e:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Lb0/k;

    .line 22
    .line 23
    invoke-interface {v1}, Lb0/k;->a()Lh0/z;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Lh0/z;

    .line 28
    .line 29
    invoke-interface {v2}, Lh0/z;->f()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {p1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_0

    .line 38
    .line 39
    invoke-virtual {p0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p0, Lh0/j0;

    .line 44
    .line 45
    return-object p0

    .line 46
    :cond_1
    const/4 p0, 0x0

    .line 47
    return-object p0
.end method

.method public final b()V
    .locals 12

    .line 1
    const/4 v0, 0x3

    .line 2
    const-string v1, "CameraStateRegistry"

    .line 3
    .line 4
    invoke-static {v0, v1}, Ljp/v1;->h(ILjava/lang/String;)Z

    .line 5
    .line 6
    .line 7
    move-result v2

    .line 8
    const-string v3, "-------------------------------------------------------------------\n"

    .line 9
    .line 10
    const-string v4, "%-45s%-22s\n"

    .line 11
    .line 12
    const/4 v5, 0x0

    .line 13
    iget-object v6, p0, Lh0/k0;->a:Ljava/lang/StringBuilder;

    .line 14
    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 18
    .line 19
    .line 20
    const-string v2, "Recalculating open cameras:\n"

    .line 21
    .line 22
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    sget-object v2, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 26
    .line 27
    const-string v7, "Camera"

    .line 28
    .line 29
    const-string v8, "State"

    .line 30
    .line 31
    filled-new-array {v7, v8}, [Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v7

    .line 35
    invoke-static {v2, v4, v7}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    :cond_0
    iget-object v2, p0, Lh0/k0;->e:Ljava/util/HashMap;

    .line 46
    .line 47
    invoke-virtual {v2}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    move v7, v5

    .line 56
    :cond_1
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v8

    .line 60
    if-eqz v8, :cond_4

    .line 61
    .line 62
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v8

    .line 66
    check-cast v8, Ljava/util/Map$Entry;

    .line 67
    .line 68
    invoke-static {v0, v1}, Ljp/v1;->h(ILjava/lang/String;)Z

    .line 69
    .line 70
    .line 71
    move-result v9

    .line 72
    if-eqz v9, :cond_3

    .line 73
    .line 74
    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v9

    .line 78
    check-cast v9, Lh0/j0;

    .line 79
    .line 80
    iget-object v9, v9, Lh0/j0;->a:Lh0/a0;

    .line 81
    .line 82
    if-eqz v9, :cond_2

    .line 83
    .line 84
    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v9

    .line 88
    check-cast v9, Lh0/j0;

    .line 89
    .line 90
    iget-object v9, v9, Lh0/j0;->a:Lh0/a0;

    .line 91
    .line 92
    invoke-virtual {v9}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v9

    .line 96
    goto :goto_1

    .line 97
    :cond_2
    const-string v9, "UNKNOWN"

    .line 98
    .line 99
    :goto_1
    sget-object v10, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 100
    .line 101
    invoke-interface {v8}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v11

    .line 105
    check-cast v11, Lb0/k;

    .line 106
    .line 107
    invoke-virtual {v11}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v11

    .line 111
    filled-new-array {v11, v9}, [Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v9

    .line 115
    invoke-static {v10, v4, v9}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v9

    .line 119
    invoke-virtual {v6, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    :cond_3
    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v8

    .line 126
    check-cast v8, Lh0/j0;

    .line 127
    .line 128
    iget-object v8, v8, Lh0/j0;->a:Lh0/a0;

    .line 129
    .line 130
    if-eqz v8, :cond_1

    .line 131
    .line 132
    iget-boolean v8, v8, Lh0/a0;->d:Z

    .line 133
    .line 134
    if-eqz v8, :cond_1

    .line 135
    .line 136
    add-int/lit8 v7, v7, 0x1

    .line 137
    .line 138
    goto :goto_0

    .line 139
    :cond_4
    invoke-static {v0, v1}, Ljp/v1;->h(ILjava/lang/String;)Z

    .line 140
    .line 141
    .line 142
    move-result v0

    .line 143
    if-eqz v0, :cond_5

    .line 144
    .line 145
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    sget-object v0, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 149
    .line 150
    iget v0, p0, Lh0/k0;->c:I

    .line 151
    .line 152
    const-string v2, " (Max allowed: "

    .line 153
    .line 154
    const-string v3, ")"

    .line 155
    .line 156
    const-string v4, "Open count: "

    .line 157
    .line 158
    invoke-static {v7, v0, v4, v2, v3}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    invoke-static {v1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    :cond_5
    iget v0, p0, Lh0/k0;->c:I

    .line 173
    .line 174
    sub-int/2addr v0, v7

    .line 175
    invoke-static {v0, v5}, Ljava/lang/Math;->max(II)I

    .line 176
    .line 177
    .line 178
    move-result v0

    .line 179
    iput v0, p0, Lh0/k0;->f:I

    .line 180
    .line 181
    return-void
.end method

.method public final d(Lu/y;)Z
    .locals 12

    .line 1
    const-string v0, "tryOpenCamera("

    .line 2
    .line 3
    const-string v1, " --> "

    .line 4
    .line 5
    iget-object v2, p0, Lh0/k0;->b:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v2

    .line 8
    :try_start_0
    iget-object v3, p0, Lh0/k0;->e:Ljava/util/HashMap;

    .line 9
    .line 10
    invoke-virtual {v3, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    check-cast v3, Lh0/j0;

    .line 15
    .line 16
    const-string v4, "Camera must first be registered with registerCamera()"

    .line 17
    .line 18
    invoke-static {v3, v4}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v4, "CameraStateRegistry"

    .line 22
    .line 23
    const/4 v5, 0x3

    .line 24
    invoke-static {v5, v4}, Ljp/v1;->h(ILjava/lang/String;)Z

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    const/4 v6, 0x1

    .line 29
    const/4 v7, 0x0

    .line 30
    if-eqz v4, :cond_1

    .line 31
    .line 32
    iget-object v4, p0, Lh0/k0;->a:Ljava/lang/StringBuilder;

    .line 33
    .line 34
    invoke-virtual {v4, v7}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 35
    .line 36
    .line 37
    iget-object v4, p0, Lh0/k0;->a:Ljava/lang/StringBuilder;

    .line 38
    .line 39
    sget-object v8, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 40
    .line 41
    iget v8, p0, Lh0/k0;->f:I

    .line 42
    .line 43
    iget-object v9, v3, Lh0/j0;->a:Lh0/a0;

    .line 44
    .line 45
    if-eqz v9, :cond_0

    .line 46
    .line 47
    iget-boolean v9, v9, Lh0/a0;->d:Z

    .line 48
    .line 49
    if-eqz v9, :cond_0

    .line 50
    .line 51
    move v9, v6

    .line 52
    goto :goto_0

    .line 53
    :catchall_0
    move-exception p0

    .line 54
    goto/16 :goto_5

    .line 55
    .line 56
    :cond_0
    move v9, v7

    .line 57
    :goto_0
    iget-object v10, v3, Lh0/j0;->a:Lh0/a0;

    .line 58
    .line 59
    new-instance v11, Ljava/lang/StringBuilder;

    .line 60
    .line 61
    invoke-direct {v11, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v11, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const-string v0, ") [Available Cameras: "

    .line 68
    .line 69
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {v11, v8}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v0, ", Already Open: "

    .line 76
    .line 77
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {v11, v9}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v0, " (Previous state: "

    .line 84
    .line 85
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v11, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    const-string v0, ")]"

    .line 92
    .line 93
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    :cond_1
    iget v0, p0, Lh0/k0;->f:I

    .line 104
    .line 105
    if-gtz v0, :cond_4

    .line 106
    .line 107
    iget-object v0, v3, Lh0/j0;->a:Lh0/a0;

    .line 108
    .line 109
    if-eqz v0, :cond_2

    .line 110
    .line 111
    iget-boolean v0, v0, Lh0/a0;->d:Z

    .line 112
    .line 113
    if-eqz v0, :cond_2

    .line 114
    .line 115
    move v0, v6

    .line 116
    goto :goto_1

    .line 117
    :cond_2
    move v0, v7

    .line 118
    :goto_1
    if-eqz v0, :cond_3

    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_3
    move v6, v7

    .line 122
    goto :goto_3

    .line 123
    :cond_4
    :goto_2
    sget-object v0, Lh0/a0;->j:Lh0/a0;

    .line 124
    .line 125
    iput-object v0, v3, Lh0/j0;->a:Lh0/a0;

    .line 126
    .line 127
    invoke-static {p1, v0}, Lh0/k0;->c(Lu/y;Lh0/a0;)V

    .line 128
    .line 129
    .line 130
    :goto_3
    const-string p1, "CameraStateRegistry"

    .line 131
    .line 132
    invoke-static {v5, p1}, Ljp/v1;->h(ILjava/lang/String;)Z

    .line 133
    .line 134
    .line 135
    move-result p1

    .line 136
    if-eqz p1, :cond_6

    .line 137
    .line 138
    iget-object p1, p0, Lh0/k0;->a:Ljava/lang/StringBuilder;

    .line 139
    .line 140
    sget-object v0, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 141
    .line 142
    if-eqz v6, :cond_5

    .line 143
    .line 144
    const-string v0, "SUCCESS"

    .line 145
    .line 146
    goto :goto_4

    .line 147
    :cond_5
    const-string v0, "FAIL"

    .line 148
    .line 149
    :goto_4
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    const-string p1, "CameraStateRegistry"

    .line 157
    .line 158
    iget-object v0, p0, Lh0/k0;->a:Ljava/lang/StringBuilder;

    .line 159
    .line 160
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    invoke-static {p1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    :cond_6
    if-eqz v6, :cond_7

    .line 168
    .line 169
    invoke-virtual {p0}, Lh0/k0;->b()V

    .line 170
    .line 171
    .line 172
    :cond_7
    monitor-exit v2

    .line 173
    return v6

    .line 174
    :goto_5
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 175
    throw p0
.end method

.method public final e(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 4

    .line 1
    iget-object v0, p0, Lh0/k0;->b:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lh0/k0;->d:Lz/a;

    .line 5
    .line 6
    invoke-virtual {v1}, Lz/a;->b()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    const/4 v2, 0x2

    .line 11
    const/4 v3, 0x1

    .line 12
    if-eq v1, v2, :cond_0

    .line 13
    .line 14
    monitor-exit v0

    .line 15
    return v3

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_7

    .line 18
    :cond_0
    invoke-virtual {p0, p1}, Lh0/k0;->a(Ljava/lang/String;)Lh0/j0;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    const/4 v1, 0x0

    .line 23
    if-eqz p1, :cond_1

    .line 24
    .line 25
    iget-object p1, p1, Lh0/j0;->a:Lh0/a0;

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    move-object p1, v1

    .line 29
    :goto_0
    if-eqz p2, :cond_2

    .line 30
    .line 31
    invoke-virtual {p0, p2}, Lh0/k0;->a(Ljava/lang/String;)Lh0/j0;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    goto :goto_1

    .line 36
    :cond_2
    move-object p0, v1

    .line 37
    :goto_1
    if-eqz p0, :cond_3

    .line 38
    .line 39
    iget-object v1, p0, Lh0/j0;->a:Lh0/a0;

    .line 40
    .line 41
    :cond_3
    sget-object p0, Lh0/a0;->k:Lh0/a0;

    .line 42
    .line 43
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result p2

    .line 47
    const/4 v2, 0x0

    .line 48
    if-nez p2, :cond_5

    .line 49
    .line 50
    sget-object p2, Lh0/a0;->l:Lh0/a0;

    .line 51
    .line 52
    invoke-virtual {p2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    if-eqz p1, :cond_4

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_4
    move p1, v2

    .line 60
    goto :goto_3

    .line 61
    :cond_5
    :goto_2
    move p1, v3

    .line 62
    :goto_3
    invoke-virtual {p0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    if-nez p0, :cond_7

    .line 67
    .line 68
    sget-object p0, Lh0/a0;->l:Lh0/a0;

    .line 69
    .line 70
    invoke-virtual {p0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    if-eqz p0, :cond_6

    .line 75
    .line 76
    goto :goto_4

    .line 77
    :cond_6
    move p0, v2

    .line 78
    goto :goto_5

    .line 79
    :cond_7
    :goto_4
    move p0, v3

    .line 80
    :goto_5
    if-eqz p1, :cond_8

    .line 81
    .line 82
    if-eqz p0, :cond_8

    .line 83
    .line 84
    goto :goto_6

    .line 85
    :cond_8
    move v3, v2

    .line 86
    :goto_6
    monitor-exit v0

    .line 87
    return v3

    .line 88
    :goto_7
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 89
    throw p0
.end method
