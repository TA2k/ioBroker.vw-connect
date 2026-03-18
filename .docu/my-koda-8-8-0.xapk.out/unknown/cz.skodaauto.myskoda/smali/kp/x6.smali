.class public abstract Lkp/x6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(ILjava/lang/CharSequence;)I
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, -0x1

    .line 3
    move v2, v0

    .line 4
    move v3, v2

    .line 5
    move v4, v1

    .line 6
    move v1, v3

    .line 7
    :goto_0
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 8
    .line 9
    .line 10
    move-result v5

    .line 11
    if-ge p0, v5, :cond_7

    .line 12
    .line 13
    invoke-interface {p1, p0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 14
    .line 15
    .line 16
    move-result v5

    .line 17
    const/16 v6, 0x2c

    .line 18
    .line 19
    if-eq v5, v6, :cond_6

    .line 20
    .line 21
    const/16 v6, 0x5b

    .line 22
    .line 23
    if-eq v5, v6, :cond_5

    .line 24
    .line 25
    const/16 v6, 0x5d

    .line 26
    .line 27
    if-eq v5, v6, :cond_4

    .line 28
    .line 29
    const/16 v6, 0x60

    .line 30
    .line 31
    if-eq v5, v6, :cond_7

    .line 32
    .line 33
    const/16 v6, 0x7b

    .line 34
    .line 35
    if-eq v5, v6, :cond_3

    .line 36
    .line 37
    const/16 v6, 0x7d

    .line 38
    .line 39
    if-eq v5, v6, :cond_2

    .line 40
    .line 41
    const/16 v6, 0x202f

    .line 42
    .line 43
    if-eq v5, v6, :cond_7

    .line 44
    .line 45
    const/16 v6, 0x205f

    .line 46
    .line 47
    if-eq v5, v6, :cond_7

    .line 48
    .line 49
    const/16 v6, 0x3000

    .line 50
    .line 51
    if-eq v5, v6, :cond_7

    .line 52
    .line 53
    const/16 v6, 0x2e

    .line 54
    .line 55
    if-eq v5, v6, :cond_6

    .line 56
    .line 57
    const/16 v6, 0x2f

    .line 58
    .line 59
    if-eq v5, v6, :cond_1

    .line 60
    .line 61
    const/16 v6, 0x3e

    .line 62
    .line 63
    if-eq v5, v6, :cond_7

    .line 64
    .line 65
    const/16 v6, 0x3f

    .line 66
    .line 67
    if-eq v5, v6, :cond_6

    .line 68
    .line 69
    const/16 v6, 0x2028

    .line 70
    .line 71
    if-eq v5, v6, :cond_7

    .line 72
    .line 73
    const/16 v6, 0x2029

    .line 74
    .line 75
    if-eq v5, v6, :cond_7

    .line 76
    .line 77
    packed-switch v5, :pswitch_data_0

    .line 78
    .line 79
    .line 80
    packed-switch v5, :pswitch_data_1

    .line 81
    .line 82
    .line 83
    packed-switch v5, :pswitch_data_2

    .line 84
    .line 85
    .line 86
    packed-switch v5, :pswitch_data_3

    .line 87
    .line 88
    .line 89
    packed-switch v5, :pswitch_data_4

    .line 90
    .line 91
    .line 92
    goto :goto_2

    .line 93
    :pswitch_0
    add-int/lit8 v1, v1, -0x1

    .line 94
    .line 95
    if-ltz v1, :cond_7

    .line 96
    .line 97
    :goto_1
    move v4, p0

    .line 98
    goto :goto_3

    .line 99
    :pswitch_1
    add-int/lit8 v1, v1, 0x1

    .line 100
    .line 101
    goto :goto_3

    .line 102
    :pswitch_2
    xor-int/lit8 v5, v0, 0x1

    .line 103
    .line 104
    if-eqz v0, :cond_0

    .line 105
    .line 106
    move v4, p0

    .line 107
    :cond_0
    move v0, v5

    .line 108
    goto :goto_3

    .line 109
    :cond_1
    add-int/lit8 v5, p0, -0x1

    .line 110
    .line 111
    if-ne v4, v5, :cond_6

    .line 112
    .line 113
    :goto_2
    goto :goto_1

    .line 114
    :cond_2
    add-int/lit8 v3, v3, -0x1

    .line 115
    .line 116
    if-ltz v3, :cond_7

    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_3
    add-int/lit8 v3, v3, 0x1

    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_4
    add-int/lit8 v2, v2, -0x1

    .line 123
    .line 124
    if-ltz v2, :cond_7

    .line 125
    .line 126
    goto :goto_1

    .line 127
    :cond_5
    add-int/lit8 v2, v2, 0x1

    .line 128
    .line 129
    :cond_6
    :goto_3
    :pswitch_3
    add-int/lit8 p0, p0, 0x1

    .line 130
    .line 131
    goto :goto_0

    .line 132
    :cond_7
    :pswitch_4
    return v4

    .line 133
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_3
        :pswitch_4
    .end packed-switch

    .line 134
    .line 135
    .line 136
    .line 137
    .line 138
    .line 139
    .line 140
    .line 141
    .line 142
    .line 143
    .line 144
    .line 145
    :pswitch_data_1
    .packed-switch 0x27
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    :pswitch_data_2
    .packed-switch 0x3a
        :pswitch_3
        :pswitch_3
        :pswitch_4
    .end packed-switch

    :pswitch_data_3
    .packed-switch 0x7f
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
    .end packed-switch

    :pswitch_data_4
    .packed-switch 0x2000
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
    .end packed-switch
.end method

.method public static b(Landroid/content/Context;)Landroid/content/pm/ResolveInfo;
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Landroid/content/Intent;

    .line 6
    .line 7
    const-string v1, "androidx.activity.result.contract.action.PICK_IMAGES"

    .line 8
    .line 9
    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const/high16 v1, 0x110000

    .line 13
    .line 14
    invoke-virtual {p0, v0, v1}, Landroid/content/pm/PackageManager;->resolveActivity(Landroid/content/Intent;I)Landroid/content/pm/ResolveInfo;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public static c(Lf/f;)Ljava/lang/String;
    .locals 1

    .line 1
    instance-of v0, p0, Lf/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const-string p0, "image/*"

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    instance-of p0, p0, Lf/d;

    .line 9
    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    return-object p0

    .line 14
    :cond_1
    new-instance p0, La8/r0;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 17
    .line 18
    .line 19
    throw p0
.end method
