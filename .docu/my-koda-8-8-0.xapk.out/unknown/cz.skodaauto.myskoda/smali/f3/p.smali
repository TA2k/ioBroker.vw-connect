.class public final synthetic Lf3/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lf3/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lf3/s;


# direct methods
.method public synthetic constructor <init>(Lf3/s;I)V
    .locals 0

    .line 1
    iput p2, p0, Lf3/p;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf3/p;->e:Lf3/s;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final h(D)D
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p1

    .line 4
    .line 5
    iget v3, v0, Lf3/p;->d:I

    .line 6
    .line 7
    iget-object v0, v0, Lf3/p;->e:Lf3/s;

    .line 8
    .line 9
    packed-switch v3, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    iget-wide v6, v0, Lf3/s;->b:D

    .line 13
    .line 14
    iget-wide v8, v0, Lf3/s;->c:D

    .line 15
    .line 16
    iget-wide v10, v0, Lf3/s;->d:D

    .line 17
    .line 18
    iget-wide v12, v0, Lf3/s;->e:D

    .line 19
    .line 20
    iget-wide v14, v0, Lf3/s;->f:D

    .line 21
    .line 22
    const-wide/high16 v16, 0x3ff0000000000000L    # 1.0

    .line 23
    .line 24
    iget-wide v4, v0, Lf3/s;->g:D

    .line 25
    .line 26
    move-wide/from16 v18, v4

    .line 27
    .line 28
    iget-wide v3, v0, Lf3/s;->a:D

    .line 29
    .line 30
    mul-double/2addr v12, v10

    .line 31
    cmpl-double v0, v1, v12

    .line 32
    .line 33
    if-ltz v0, :cond_0

    .line 34
    .line 35
    sub-double v0, v1, v14

    .line 36
    .line 37
    div-double v4, v16, v3

    .line 38
    .line 39
    invoke-static {v0, v1, v4, v5}, Ljava/lang/Math;->pow(DD)D

    .line 40
    .line 41
    .line 42
    move-result-wide v0

    .line 43
    sub-double/2addr v0, v8

    .line 44
    div-double/2addr v0, v6

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    sub-double v0, v1, v18

    .line 47
    .line 48
    div-double/2addr v0, v10

    .line 49
    :goto_0
    return-wide v0

    .line 50
    :pswitch_0
    const-wide/high16 v16, 0x3ff0000000000000L    # 1.0

    .line 51
    .line 52
    iget-wide v3, v0, Lf3/s;->b:D

    .line 53
    .line 54
    iget-wide v5, v0, Lf3/s;->c:D

    .line 55
    .line 56
    iget-wide v7, v0, Lf3/s;->d:D

    .line 57
    .line 58
    iget-wide v9, v0, Lf3/s;->e:D

    .line 59
    .line 60
    iget-wide v11, v0, Lf3/s;->a:D

    .line 61
    .line 62
    mul-double/2addr v9, v7

    .line 63
    cmpl-double v0, v1, v9

    .line 64
    .line 65
    if-ltz v0, :cond_1

    .line 66
    .line 67
    div-double v7, v16, v11

    .line 68
    .line 69
    invoke-static {v1, v2, v7, v8}, Ljava/lang/Math;->pow(DD)D

    .line 70
    .line 71
    .line 72
    move-result-wide v0

    .line 73
    sub-double/2addr v0, v5

    .line 74
    div-double/2addr v0, v3

    .line 75
    goto :goto_1

    .line 76
    :cond_1
    div-double v0, v1, v7

    .line 77
    .line 78
    :goto_1
    return-wide v0

    .line 79
    :pswitch_1
    sget-object v3, Lf3/e;->a:[F

    .line 80
    .line 81
    invoke-static {v0, v1, v2}, Lf3/e;->d(Lf3/s;D)D

    .line 82
    .line 83
    .line 84
    move-result-wide v0

    .line 85
    return-wide v0

    .line 86
    :pswitch_2
    sget-object v3, Lf3/e;->a:[F

    .line 87
    .line 88
    invoke-static {v0, v1, v2}, Lf3/e;->b(Lf3/s;D)D

    .line 89
    .line 90
    .line 91
    move-result-wide v0

    .line 92
    return-wide v0

    .line 93
    :pswitch_3
    iget-wide v3, v0, Lf3/s;->b:D

    .line 94
    .line 95
    iget-wide v5, v0, Lf3/s;->c:D

    .line 96
    .line 97
    iget-wide v7, v0, Lf3/s;->d:D

    .line 98
    .line 99
    iget-wide v9, v0, Lf3/s;->e:D

    .line 100
    .line 101
    iget-wide v11, v0, Lf3/s;->f:D

    .line 102
    .line 103
    iget-wide v13, v0, Lf3/s;->g:D

    .line 104
    .line 105
    move-wide v15, v3

    .line 106
    iget-wide v3, v0, Lf3/s;->a:D

    .line 107
    .line 108
    cmpl-double v0, v1, v9

    .line 109
    .line 110
    if-ltz v0, :cond_2

    .line 111
    .line 112
    mul-double v0, v15, v1

    .line 113
    .line 114
    add-double/2addr v0, v5

    .line 115
    invoke-static {v0, v1, v3, v4}, Ljava/lang/Math;->pow(DD)D

    .line 116
    .line 117
    .line 118
    move-result-wide v0

    .line 119
    add-double/2addr v0, v11

    .line 120
    goto :goto_2

    .line 121
    :cond_2
    mul-double/2addr v7, v1

    .line 122
    add-double v0, v7, v13

    .line 123
    .line 124
    :goto_2
    return-wide v0

    .line 125
    :pswitch_4
    iget-wide v3, v0, Lf3/s;->b:D

    .line 126
    .line 127
    iget-wide v5, v0, Lf3/s;->c:D

    .line 128
    .line 129
    iget-wide v7, v0, Lf3/s;->d:D

    .line 130
    .line 131
    iget-wide v9, v0, Lf3/s;->e:D

    .line 132
    .line 133
    iget-wide v11, v0, Lf3/s;->a:D

    .line 134
    .line 135
    cmpl-double v0, v1, v9

    .line 136
    .line 137
    if-ltz v0, :cond_3

    .line 138
    .line 139
    mul-double/2addr v3, v1

    .line 140
    add-double/2addr v3, v5

    .line 141
    invoke-static {v3, v4, v11, v12}, Ljava/lang/Math;->pow(DD)D

    .line 142
    .line 143
    .line 144
    move-result-wide v0

    .line 145
    goto :goto_3

    .line 146
    :cond_3
    mul-double v0, v7, v1

    .line 147
    .line 148
    :goto_3
    return-wide v0

    .line 149
    :pswitch_5
    sget-object v3, Lf3/e;->a:[F

    .line 150
    .line 151
    invoke-static {v0, v1, v2}, Lf3/e;->c(Lf3/s;D)D

    .line 152
    .line 153
    .line 154
    move-result-wide v0

    .line 155
    return-wide v0

    .line 156
    :pswitch_6
    sget-object v3, Lf3/e;->a:[F

    .line 157
    .line 158
    invoke-static {v0, v1, v2}, Lf3/e;->a(Lf3/s;D)D

    .line 159
    .line 160
    .line 161
    move-result-wide v0

    .line 162
    return-wide v0

    .line 163
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
