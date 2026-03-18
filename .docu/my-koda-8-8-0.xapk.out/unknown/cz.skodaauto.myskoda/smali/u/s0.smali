.class public final synthetic Lu/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lu/t0;


# direct methods
.method public synthetic constructor <init>(Lu/t0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lu/s0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lu/s0;->e:Lu/t0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lu/s0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu/s0;->e:Lu/t0;

    .line 7
    .line 8
    iget-object p0, p0, Lu/t0;->a:Lv/b;

    .line 9
    .line 10
    invoke-virtual {p0}, Lv/b;->c()Lrn/i;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    iget-object p0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Lro/f;

    .line 17
    .line 18
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Landroid/hardware/camera2/params/StreamConfigurationMap;

    .line 21
    .line 22
    invoke-virtual {p0}, Landroid/hardware/camera2/params/StreamConfigurationMap;->getHighSpeedVideoSizes()[Landroid/util/Size;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    if-eqz p0, :cond_0

    .line 27
    .line 28
    invoke-static {p0}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 34
    .line 35
    :goto_0
    return-object p0

    .line 36
    :pswitch_0
    iget-object p0, p0, Lu/s0;->e:Lu/t0;

    .line 37
    .line 38
    iget-object p0, p0, Lu/t0;->d:Llx0/q;

    .line 39
    .line 40
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    check-cast p0, Ljava/util/List;

    .line 45
    .line 46
    move-object v0, p0

    .line 47
    check-cast v0, Ljava/util/Collection;

    .line 48
    .line 49
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    const/4 v1, 0x0

    .line 54
    if-nez v0, :cond_1

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    move-object p0, v1

    .line 58
    :goto_1
    if-eqz p0, :cond_6

    .line 59
    .line 60
    check-cast p0, Ljava/lang/Iterable;

    .line 61
    .line 62
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-eqz v0, :cond_5

    .line 71
    .line 72
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    if-nez v1, :cond_2

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_2
    move-object v1, v0

    .line 84
    check-cast v1, Landroid/util/Size;

    .line 85
    .line 86
    invoke-static {v1}, Lo0/a;->a(Landroid/util/Size;)I

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    :cond_3
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    move-object v3, v2

    .line 95
    check-cast v3, Landroid/util/Size;

    .line 96
    .line 97
    invoke-static {v3}, Lo0/a;->a(Landroid/util/Size;)I

    .line 98
    .line 99
    .line 100
    move-result v3

    .line 101
    if-ge v1, v3, :cond_4

    .line 102
    .line 103
    move-object v0, v2

    .line 104
    move v1, v3

    .line 105
    :cond_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    if-nez v2, :cond_3

    .line 110
    .line 111
    :goto_2
    move-object v1, v0

    .line 112
    check-cast v1, Landroid/util/Size;

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_5
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 116
    .line 117
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 118
    .line 119
    .line 120
    throw p0

    .line 121
    :cond_6
    :goto_3
    return-object v1

    .line 122
    :pswitch_1
    iget-object p0, p0, Lu/s0;->e:Lu/t0;

    .line 123
    .line 124
    iget-object p0, p0, Lu/t0;->a:Lv/b;

    .line 125
    .line 126
    sget-object v0, Landroid/hardware/camera2/CameraCharacteristics;->REQUEST_AVAILABLE_CAPABILITIES:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 127
    .line 128
    invoke-virtual {p0, v0}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    check-cast p0, [I

    .line 133
    .line 134
    const/4 v0, 0x0

    .line 135
    if-eqz p0, :cond_8

    .line 136
    .line 137
    array-length v1, p0

    .line 138
    move v2, v0

    .line 139
    :goto_4
    if-ge v2, v1, :cond_8

    .line 140
    .line 141
    aget v3, p0, v2

    .line 142
    .line 143
    const/16 v4, 0x9

    .line 144
    .line 145
    if-ne v3, v4, :cond_7

    .line 146
    .line 147
    const/4 v0, 0x1

    .line 148
    goto :goto_5

    .line 149
    :cond_7
    add-int/lit8 v2, v2, 0x1

    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_8
    :goto_5
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    return-object p0

    .line 157
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
