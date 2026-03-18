.class public final Ltz/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 6

    .line 1
    check-cast p1, Lrd0/h;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    const/4 p1, 0x0

    .line 8
    const/4 v0, 0x4

    .line 9
    const/4 v1, 0x5

    .line 10
    const/4 v2, 0x6

    .line 11
    const/4 v3, 0x3

    .line 12
    const/4 v4, 0x1

    .line 13
    const/4 v5, 0x2

    .line 14
    packed-switch p0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    new-instance p0, La8/r0;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :pswitch_0
    move p0, v5

    .line 24
    goto :goto_0

    .line 25
    :pswitch_1
    move p0, v4

    .line 26
    goto :goto_0

    .line 27
    :pswitch_2
    move p0, v3

    .line 28
    goto :goto_0

    .line 29
    :pswitch_3
    move p0, v2

    .line 30
    goto :goto_0

    .line 31
    :pswitch_4
    move p0, v1

    .line 32
    goto :goto_0

    .line 33
    :pswitch_5
    move p0, v0

    .line 34
    goto :goto_0

    .line 35
    :pswitch_6
    move p0, p1

    .line 36
    :goto_0
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p2, Lrd0/h;

    .line 41
    .line 42
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 43
    .line 44
    .line 45
    move-result p2

    .line 46
    packed-switch p2, :pswitch_data_1

    .line 47
    .line 48
    .line 49
    new-instance p0, La8/r0;

    .line 50
    .line 51
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :pswitch_7
    move p1, v5

    .line 56
    goto :goto_1

    .line 57
    :pswitch_8
    move p1, v4

    .line 58
    goto :goto_1

    .line 59
    :pswitch_9
    move p1, v3

    .line 60
    goto :goto_1

    .line 61
    :pswitch_a
    move p1, v2

    .line 62
    goto :goto_1

    .line 63
    :pswitch_b
    move p1, v1

    .line 64
    goto :goto_1

    .line 65
    :pswitch_c
    move p1, v0

    .line 66
    :goto_1
    :pswitch_d
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    return p0

    .line 75
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

    .line 76
    .line 77
    .line 78
    .line 79
    .line 80
    .line 81
    .line 82
    .line 83
    .line 84
    .line 85
    .line 86
    .line 87
    .line 88
    .line 89
    .line 90
    .line 91
    .line 92
    .line 93
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
    .end packed-switch
.end method
