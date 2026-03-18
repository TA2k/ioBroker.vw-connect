.class public final Lgp0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lla/u;

.field public final b:Las0/h;


# direct methods
.method public constructor <init>(Lla/u;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgp0/a;->a:Lla/u;

    .line 5
    .line 6
    new-instance p1, Las0/h;

    .line 7
    .line 8
    const/4 v0, 0x5

    .line 9
    invoke-direct {p1, v0}, Las0/h;-><init>(I)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lgp0/a;->b:Las0/h;

    .line 13
    .line 14
    return-void
.end method

.method public static a(Lhp0/d;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance p0, La8/r0;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    const-string p0, "Unknown"

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_1
    const-string p0, "PluggedInDark"

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_2
    const-string p0, "PluggedInLight"

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_3
    const-string p0, "ChargingDark"

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_4
    const-string p0, "ChargingLight"

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_5
    const-string p0, "DownscaledExteriorFront"

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_6
    const-string p0, "UnmodifiedInteriorBoot"

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_7
    const-string p0, "UnmodifiedInteriorFront"

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_8
    const-string p0, "UnmodifiedInteriorSide"

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_9
    const-string p0, "UnmodifiedExteriorRear"

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_a
    const-string p0, "UnmodifiedExteriorFront"

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_b
    const-string p0, "UnmodifiedExteriorSide"

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_c
    const-string p0, "Home"

    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
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


# virtual methods
.method public final b(Lua/a;Landroidx/collection/u;)V
    .locals 12

    .line 1
    invoke-virtual {p2}, Landroidx/collection/u;->h()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-virtual {p2}, Landroidx/collection/u;->h()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/16 v1, 0x3e7

    .line 13
    .line 14
    if-le v0, v1, :cond_1

    .line 15
    .line 16
    new-instance v0, Let/g;

    .line 17
    .line 18
    const/16 v1, 0xc

    .line 19
    .line 20
    invoke-direct {v0, v1, p0, p1}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-static {p2, v0}, Ljp/ye;->c(Landroidx/collection/u;Lay0/k;)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    const-string p0, "SELECT `id`,`composite_render_id`,`url`,`order` FROM `composite_render_layer` WHERE `composite_render_id` IN ("

    .line 28
    .line 29
    invoke-static {p0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {p2}, Landroidx/collection/u;->h()I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    invoke-static {v0, p0}, Ljp/cf;->d(ILjava/lang/StringBuilder;)V

    .line 38
    .line 39
    .line 40
    const-string v0, ")"

    .line 41
    .line 42
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    const-string v0, "toString(...)"

    .line 50
    .line 51
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-interface {p1, p0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-virtual {p2}, Landroidx/collection/u;->h()I

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    const/4 v0, 0x0

    .line 63
    const/4 v1, 0x1

    .line 64
    move v2, v0

    .line 65
    move v3, v1

    .line 66
    :goto_0
    if-ge v2, p1, :cond_2

    .line 67
    .line 68
    invoke-virtual {p2, v2}, Landroidx/collection/u;->d(I)J

    .line 69
    .line 70
    .line 71
    move-result-wide v4

    .line 72
    invoke-interface {p0, v3, v4, v5}, Lua/c;->bindLong(IJ)V

    .line 73
    .line 74
    .line 75
    add-int/2addr v3, v1

    .line 76
    add-int/lit8 v2, v2, 0x1

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_2
    :try_start_0
    const-string p1, "composite_render_id"

    .line 80
    .line 81
    invoke-static {p0, p1}, Ljp/af;->c(Lua/c;Ljava/lang/String;)I

    .line 82
    .line 83
    .line 84
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 85
    const/4 v2, -0x1

    .line 86
    if-ne p1, v2, :cond_3

    .line 87
    .line 88
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :cond_3
    :goto_1
    :try_start_1
    invoke-interface {p0}, Lua/c;->s0()Z

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    if-eqz v2, :cond_4

    .line 97
    .line 98
    invoke-interface {p0, p1}, Lua/c;->getLong(I)J

    .line 99
    .line 100
    .line 101
    move-result-wide v2

    .line 102
    invoke-virtual {p2, v2, v3}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    check-cast v2, Ljava/util/List;

    .line 107
    .line 108
    if-eqz v2, :cond_3

    .line 109
    .line 110
    invoke-interface {p0, v0}, Lua/c;->getLong(I)J

    .line 111
    .line 112
    .line 113
    move-result-wide v4

    .line 114
    invoke-interface {p0, v1}, Lua/c;->getLong(I)J

    .line 115
    .line 116
    .line 117
    move-result-wide v6

    .line 118
    const/4 v3, 0x2

    .line 119
    invoke-interface {p0, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v9

    .line 123
    const/4 v3, 0x3

    .line 124
    invoke-interface {p0, v3}, Lua/c;->getLong(I)J

    .line 125
    .line 126
    .line 127
    move-result-wide v10

    .line 128
    long-to-int v8, v10

    .line 129
    new-instance v3, Lgp0/d;

    .line 130
    .line 131
    invoke-direct/range {v3 .. v9}, Lgp0/d;-><init>(JJILjava/lang/String;)V

    .line 132
    .line 133
    .line 134
    invoke-interface {v2, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 135
    .line 136
    .line 137
    goto :goto_1

    .line 138
    :catchall_0
    move-exception v0

    .line 139
    move-object p1, v0

    .line 140
    goto :goto_2

    .line 141
    :cond_4
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 142
    .line 143
    .line 144
    return-void

    .line 145
    :goto_2
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 146
    .line 147
    .line 148
    throw p1
.end method
