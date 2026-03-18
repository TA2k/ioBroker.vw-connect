.class public final Lcx/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/hardware/SensorEventListener;


# instance fields
.field public final a:Lcom/google/firebase/messaging/r;

.field public final b:Lgr/k;

.field public c:Landroid/hardware/SensorManager;

.field public d:Landroid/hardware/Sensor;


# direct methods
.method public constructor <init>(Lgr/k;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lcom/google/firebase/messaging/r;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v1, La0/j;

    .line 10
    .line 11
    const/16 v2, 0xd

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-direct {v1, v2, v3}, La0/j;-><init>(IZ)V

    .line 15
    .line 16
    .line 17
    iput-object v1, v0, Lcom/google/firebase/messaging/r;->c:Ljava/lang/Object;

    .line 18
    .line 19
    iput-object v0, p0, Lcx/b;->a:Lcom/google/firebase/messaging/r;

    .line 20
    .line 21
    iput-object p1, p0, Lcx/b;->b:Lgr/k;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final onAccuracyChanged(Landroid/hardware/Sensor;I)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onSensorChanged(Landroid/hardware/SensorEvent;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Landroid/hardware/SensorEvent;->values:[F

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    aget v4, v2, v3

    .line 9
    .line 10
    const/4 v5, 0x1

    .line 11
    aget v6, v2, v5

    .line 12
    .line 13
    const/4 v7, 0x2

    .line 14
    aget v2, v2, v7

    .line 15
    .line 16
    mul-float/2addr v4, v4

    .line 17
    mul-float/2addr v6, v6

    .line 18
    add-float/2addr v6, v4

    .line 19
    mul-float/2addr v2, v2

    .line 20
    add-float/2addr v2, v6

    .line 21
    float-to-double v8, v2

    .line 22
    const/16 v2, 0xa9

    .line 23
    .line 24
    int-to-double v10, v2

    .line 25
    cmpl-double v2, v8, v10

    .line 26
    .line 27
    if-lez v2, :cond_0

    .line 28
    .line 29
    move v2, v5

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move v2, v3

    .line 32
    :goto_0
    iget-wide v8, v1, Landroid/hardware/SensorEvent;->timestamp:J

    .line 33
    .line 34
    iget-object v1, v0, Lcx/b;->a:Lcom/google/firebase/messaging/r;

    .line 35
    .line 36
    iget-object v4, v1, Lcom/google/firebase/messaging/r;->c:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v4, La0/j;

    .line 39
    .line 40
    const-wide/32 v10, 0x1dcd6500

    .line 41
    .line 42
    .line 43
    sub-long v10, v8, v10

    .line 44
    .line 45
    :goto_1
    iget v6, v1, Lcom/google/firebase/messaging/r;->a:I

    .line 46
    .line 47
    const/4 v12, 0x4

    .line 48
    const/4 v13, 0x0

    .line 49
    if-lt v6, v12, :cond_3

    .line 50
    .line 51
    iget-object v12, v1, Lcom/google/firebase/messaging/r;->d:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v12, Lcx/a;

    .line 54
    .line 55
    if-eqz v12, :cond_3

    .line 56
    .line 57
    iget-wide v14, v12, Lcx/a;->a:J

    .line 58
    .line 59
    sub-long v14, v10, v14

    .line 60
    .line 61
    const-wide/16 v16, 0x0

    .line 62
    .line 63
    cmp-long v14, v14, v16

    .line 64
    .line 65
    if-lez v14, :cond_3

    .line 66
    .line 67
    iget-boolean v14, v12, Lcx/a;->b:Z

    .line 68
    .line 69
    if-eqz v14, :cond_1

    .line 70
    .line 71
    iget v14, v1, Lcom/google/firebase/messaging/r;->b:I

    .line 72
    .line 73
    sub-int/2addr v14, v5

    .line 74
    iput v14, v1, Lcom/google/firebase/messaging/r;->b:I

    .line 75
    .line 76
    :cond_1
    add-int/lit8 v6, v6, -0x1

    .line 77
    .line 78
    iput v6, v1, Lcom/google/firebase/messaging/r;->a:I

    .line 79
    .line 80
    iget-object v6, v12, Lcx/a;->c:Lcx/a;

    .line 81
    .line 82
    iput-object v6, v1, Lcom/google/firebase/messaging/r;->d:Ljava/lang/Object;

    .line 83
    .line 84
    if-nez v6, :cond_2

    .line 85
    .line 86
    iput-object v13, v1, Lcom/google/firebase/messaging/r;->e:Ljava/lang/Object;

    .line 87
    .line 88
    :cond_2
    iget-object v6, v4, La0/j;->e:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v6, Lcx/a;

    .line 91
    .line 92
    iput-object v6, v12, Lcx/a;->c:Lcx/a;

    .line 93
    .line 94
    iput-object v12, v4, La0/j;->e:Ljava/lang/Object;

    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_3
    iget-object v10, v4, La0/j;->e:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v10, Lcx/a;

    .line 100
    .line 101
    if-nez v10, :cond_4

    .line 102
    .line 103
    new-instance v10, Lcx/a;

    .line 104
    .line 105
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 106
    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_4
    iget-object v11, v10, Lcx/a;->c:Lcx/a;

    .line 110
    .line 111
    iput-object v11, v4, La0/j;->e:Ljava/lang/Object;

    .line 112
    .line 113
    :goto_2
    iput-wide v8, v10, Lcx/a;->a:J

    .line 114
    .line 115
    iput-boolean v2, v10, Lcx/a;->b:Z

    .line 116
    .line 117
    iput-object v13, v10, Lcx/a;->c:Lcx/a;

    .line 118
    .line 119
    iget-object v4, v1, Lcom/google/firebase/messaging/r;->e:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v4, Lcx/a;

    .line 122
    .line 123
    if-eqz v4, :cond_5

    .line 124
    .line 125
    iput-object v10, v4, Lcx/a;->c:Lcx/a;

    .line 126
    .line 127
    :cond_5
    iput-object v10, v1, Lcom/google/firebase/messaging/r;->e:Ljava/lang/Object;

    .line 128
    .line 129
    iget-object v4, v1, Lcom/google/firebase/messaging/r;->d:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v4, Lcx/a;

    .line 132
    .line 133
    if-nez v4, :cond_6

    .line 134
    .line 135
    iput-object v10, v1, Lcom/google/firebase/messaging/r;->d:Ljava/lang/Object;

    .line 136
    .line 137
    :cond_6
    add-int/2addr v6, v5

    .line 138
    iput v6, v1, Lcom/google/firebase/messaging/r;->a:I

    .line 139
    .line 140
    if-eqz v2, :cond_7

    .line 141
    .line 142
    iget v2, v1, Lcom/google/firebase/messaging/r;->b:I

    .line 143
    .line 144
    add-int/2addr v2, v5

    .line 145
    iput v2, v1, Lcom/google/firebase/messaging/r;->b:I

    .line 146
    .line 147
    :cond_7
    iget-object v2, v1, Lcom/google/firebase/messaging/r;->d:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v2, Lcx/a;

    .line 150
    .line 151
    if-eqz v2, :cond_9

    .line 152
    .line 153
    iget-wide v4, v2, Lcx/a;->a:J

    .line 154
    .line 155
    sub-long/2addr v8, v4

    .line 156
    const-wide/32 v4, 0xee6b280

    .line 157
    .line 158
    .line 159
    cmp-long v2, v8, v4

    .line 160
    .line 161
    if-ltz v2, :cond_9

    .line 162
    .line 163
    iget v2, v1, Lcom/google/firebase/messaging/r;->b:I

    .line 164
    .line 165
    shr-int/lit8 v4, v6, 0x1

    .line 166
    .line 167
    shr-int/lit8 v5, v6, 0x2

    .line 168
    .line 169
    add-int/2addr v4, v5

    .line 170
    if-lt v2, v4, :cond_9

    .line 171
    .line 172
    :goto_3
    iget-object v2, v1, Lcom/google/firebase/messaging/r;->d:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast v2, Lcx/a;

    .line 175
    .line 176
    if-eqz v2, :cond_8

    .line 177
    .line 178
    iget-object v4, v2, Lcx/a;->c:Lcx/a;

    .line 179
    .line 180
    iput-object v4, v1, Lcom/google/firebase/messaging/r;->d:Ljava/lang/Object;

    .line 181
    .line 182
    iget-object v4, v1, Lcom/google/firebase/messaging/r;->c:Ljava/lang/Object;

    .line 183
    .line 184
    check-cast v4, La0/j;

    .line 185
    .line 186
    iget-object v5, v4, La0/j;->e:Ljava/lang/Object;

    .line 187
    .line 188
    check-cast v5, Lcx/a;

    .line 189
    .line 190
    iput-object v5, v2, Lcx/a;->c:Lcx/a;

    .line 191
    .line 192
    iput-object v2, v4, La0/j;->e:Ljava/lang/Object;

    .line 193
    .line 194
    goto :goto_3

    .line 195
    :cond_8
    iput-object v13, v1, Lcom/google/firebase/messaging/r;->e:Ljava/lang/Object;

    .line 196
    .line 197
    iput v3, v1, Lcom/google/firebase/messaging/r;->a:I

    .line 198
    .line 199
    iput v3, v1, Lcom/google/firebase/messaging/r;->b:I

    .line 200
    .line 201
    iget-object v0, v0, Lcx/b;->b:Lgr/k;

    .line 202
    .line 203
    iget-object v0, v0, Lgr/k;->e:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v0, Lhi0/a;

    .line 206
    .line 207
    iget-object v0, v0, Lhi0/a;->b:Lei0/a;

    .line 208
    .line 209
    iget-object v0, v0, Lei0/a;->a:Lyy0/q1;

    .line 210
    .line 211
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 212
    .line 213
    invoke-virtual {v0, v1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    :cond_9
    return-void
.end method
