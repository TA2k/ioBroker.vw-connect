.class public abstract Lo01/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lmw/b;)Lnx0/c;
    .locals 13

    .line 1
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {p0}, Lmw/b;->c()D

    .line 6
    .line 7
    .line 8
    move-result-wide v1

    .line 9
    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-virtual {v0, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    invoke-interface {p0}, Lmw/b;->d()D

    .line 17
    .line 18
    .line 19
    move-result-wide v1

    .line 20
    invoke-interface {p0}, Lmw/b;->b()D

    .line 21
    .line 22
    .line 23
    move-result-wide v3

    .line 24
    cmpg-double v1, v1, v3

    .line 25
    .line 26
    if-ltz v1, :cond_1

    .line 27
    .line 28
    invoke-interface {p0}, Lmw/b;->c()D

    .line 29
    .line 30
    .line 31
    move-result-wide v1

    .line 32
    invoke-interface {p0}, Lmw/b;->b()D

    .line 33
    .line 34
    .line 35
    move-result-wide v3

    .line 36
    invoke-interface {p0}, Lmw/b;->d()D

    .line 37
    .line 38
    .line 39
    move-result-wide v5

    .line 40
    invoke-interface {p0}, Lmw/b;->b()D

    .line 41
    .line 42
    .line 43
    move-result-wide v7

    .line 44
    div-double/2addr v5, v7

    .line 45
    invoke-static {v5, v6}, Ljava/lang/Math;->floor(D)D

    .line 46
    .line 47
    .line 48
    move-result-wide v5

    .line 49
    mul-double/2addr v5, v3

    .line 50
    add-double/2addr v5, v1

    .line 51
    invoke-static {v5, v6}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-virtual {v0, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    invoke-interface {p0}, Lmw/b;->d()D

    .line 59
    .line 60
    .line 61
    move-result-wide v1

    .line 62
    const/4 v3, 0x2

    .line 63
    int-to-double v3, v3

    .line 64
    invoke-interface {p0}, Lmw/b;->b()D

    .line 65
    .line 66
    .line 67
    move-result-wide v5

    .line 68
    mul-double/2addr v5, v3

    .line 69
    cmpl-double v1, v1, v5

    .line 70
    .line 71
    if-ltz v1, :cond_1

    .line 72
    .line 73
    invoke-interface {p0}, Lmw/b;->c()D

    .line 74
    .line 75
    .line 76
    move-result-wide v1

    .line 77
    invoke-interface {p0}, Lmw/b;->b()D

    .line 78
    .line 79
    .line 80
    move-result-wide v5

    .line 81
    invoke-interface {p0}, Lmw/b;->d()D

    .line 82
    .line 83
    .line 84
    move-result-wide v7

    .line 85
    div-double/2addr v7, v3

    .line 86
    invoke-interface {p0}, Lmw/b;->b()D

    .line 87
    .line 88
    .line 89
    move-result-wide v3

    .line 90
    div-double/2addr v7, v3

    .line 91
    invoke-static {v7, v8}, Ljava/lang/Math;->abs(D)D

    .line 92
    .line 93
    .line 94
    move-result-wide v3

    .line 95
    invoke-static {v7, v8}, Ljava/lang/Math;->signum(D)D

    .line 96
    .line 97
    .line 98
    move-result-wide v7

    .line 99
    const/4 p0, 0x1

    .line 100
    int-to-double v9, p0

    .line 101
    rem-double v9, v3, v9

    .line 102
    .line 103
    const-wide/high16 v11, 0x3fe0000000000000L    # 0.5

    .line 104
    .line 105
    cmpl-double p0, v9, v11

    .line 106
    .line 107
    if-ltz p0, :cond_0

    .line 108
    .line 109
    invoke-static {v3, v4}, Ljava/lang/Math;->ceil(D)D

    .line 110
    .line 111
    .line 112
    move-result-wide v3

    .line 113
    goto :goto_0

    .line 114
    :cond_0
    invoke-static {v3, v4}, Ljava/lang/Math;->floor(D)D

    .line 115
    .line 116
    .line 117
    move-result-wide v3

    .line 118
    :goto_0
    mul-double/2addr v7, v3

    .line 119
    mul-double/2addr v7, v5

    .line 120
    add-double/2addr v7, v1

    .line 121
    invoke-static {v7, v8}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    invoke-virtual {v0, p0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    :cond_1
    invoke-static {v0}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    return-object p0
.end method

.method public static final b(Lcq0/w;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    new-instance p0, La8/r0;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :pswitch_0
    const p0, 0x7f121176

    .line 20
    .line 21
    .line 22
    return p0

    .line 23
    :pswitch_1
    const p0, 0x7f121172

    .line 24
    .line 25
    .line 26
    return p0

    .line 27
    :pswitch_2
    const p0, 0x7f121173

    .line 28
    .line 29
    .line 30
    return p0

    .line 31
    :pswitch_3
    const p0, 0x7f121177

    .line 32
    .line 33
    .line 34
    return p0

    .line 35
    :pswitch_4
    const p0, 0x7f121179

    .line 36
    .line 37
    .line 38
    return p0

    .line 39
    :pswitch_5
    const p0, 0x7f121178

    .line 40
    .line 41
    .line 42
    return p0

    .line 43
    :pswitch_6
    const p0, 0x7f12117a

    .line 44
    .line 45
    .line 46
    return p0

    .line 47
    :pswitch_7
    const p0, 0x7f121174

    .line 48
    .line 49
    .line 50
    return p0

    .line 51
    :pswitch_8
    const p0, 0x7f121175

    .line 52
    .line 53
    .line 54
    return p0

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
