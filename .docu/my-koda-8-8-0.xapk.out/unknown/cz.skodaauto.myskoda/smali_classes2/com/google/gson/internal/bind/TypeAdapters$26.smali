.class Lcom/google/gson/internal/bind/TypeAdapters$26;
.super Lcom/google/gson/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lcom/google/gson/y;"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final b(Lpu/a;)Ljava/lang/Object;
    .locals 11

    .line 1
    invoke-virtual {p1}, Lpu/a;->l0()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/16 v0, 0x9

    .line 6
    .line 7
    if-ne p0, v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p1}, Lpu/a;->W()V

    .line 10
    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    return-object p0

    .line 14
    :cond_0
    invoke-virtual {p1}, Lpu/a;->b()V

    .line 15
    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    move v1, p0

    .line 19
    move v2, v1

    .line 20
    move v3, v2

    .line 21
    move v4, v3

    .line 22
    move v5, v4

    .line 23
    move v6, v5

    .line 24
    :goto_0
    invoke-virtual {p1}, Lpu/a;->l0()I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/4 v7, 0x4

    .line 29
    if-eq v0, v7, :cond_7

    .line 30
    .line 31
    invoke-virtual {p1}, Lpu/a;->U()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {p1}, Lpu/a;->M()I

    .line 36
    .line 37
    .line 38
    move-result v8

    .line 39
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 43
    .line 44
    .line 45
    move-result v9

    .line 46
    const/4 v10, -0x1

    .line 47
    sparse-switch v9, :sswitch_data_0

    .line 48
    .line 49
    .line 50
    :goto_1
    move v7, v10

    .line 51
    goto :goto_2

    .line 52
    :sswitch_0
    const-string v7, "hourOfDay"

    .line 53
    .line 54
    invoke-virtual {v0, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-nez v0, :cond_1

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_1
    const/4 v7, 0x5

    .line 62
    goto :goto_2

    .line 63
    :sswitch_1
    const-string v9, "month"

    .line 64
    .line 65
    invoke-virtual {v0, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-nez v0, :cond_6

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :sswitch_2
    const-string v7, "year"

    .line 73
    .line 74
    invoke-virtual {v0, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    if-nez v0, :cond_2

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_2
    const/4 v7, 0x3

    .line 82
    goto :goto_2

    .line 83
    :sswitch_3
    const-string v7, "second"

    .line 84
    .line 85
    invoke-virtual {v0, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    if-nez v0, :cond_3

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_3
    const/4 v7, 0x2

    .line 93
    goto :goto_2

    .line 94
    :sswitch_4
    const-string v7, "minute"

    .line 95
    .line 96
    invoke-virtual {v0, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    if-nez v0, :cond_4

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_4
    const/4 v7, 0x1

    .line 104
    goto :goto_2

    .line 105
    :sswitch_5
    const-string v7, "dayOfMonth"

    .line 106
    .line 107
    invoke-virtual {v0, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    if-nez v0, :cond_5

    .line 112
    .line 113
    goto :goto_1

    .line 114
    :cond_5
    move v7, p0

    .line 115
    :cond_6
    :goto_2
    packed-switch v7, :pswitch_data_0

    .line 116
    .line 117
    .line 118
    goto :goto_0

    .line 119
    :pswitch_0
    move v4, v8

    .line 120
    goto :goto_0

    .line 121
    :pswitch_1
    move v2, v8

    .line 122
    goto :goto_0

    .line 123
    :pswitch_2
    move v1, v8

    .line 124
    goto :goto_0

    .line 125
    :pswitch_3
    move v6, v8

    .line 126
    goto :goto_0

    .line 127
    :pswitch_4
    move v5, v8

    .line 128
    goto :goto_0

    .line 129
    :pswitch_5
    move v3, v8

    .line 130
    goto :goto_0

    .line 131
    :cond_7
    invoke-virtual {p1}, Lpu/a;->h()V

    .line 132
    .line 133
    .line 134
    new-instance v0, Ljava/util/GregorianCalendar;

    .line 135
    .line 136
    invoke-direct/range {v0 .. v6}, Ljava/util/GregorianCalendar;-><init>(IIIIII)V

    .line 137
    .line 138
    .line 139
    return-object v0

    .line 140
    nop

    .line 141
    :sswitch_data_0
    .sparse-switch
        -0x4667c053 -> :sswitch_5
        -0x400459ec -> :sswitch_4
        -0x3604bb8c -> :sswitch_3
        0x38883d -> :sswitch_2
        0x6342280 -> :sswitch_1
        0x3ab9c2c1 -> :sswitch_0
    .end sparse-switch

    .line 142
    .line 143
    .line 144
    .line 145
    .line 146
    .line 147
    .line 148
    .line 149
    .line 150
    .line 151
    .line 152
    .line 153
    .line 154
    .line 155
    .line 156
    .line 157
    .line 158
    .line 159
    .line 160
    .line 161
    .line 162
    .line 163
    .line 164
    .line 165
    .line 166
    .line 167
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final c(Lpu/b;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p2, Ljava/util/Calendar;

    .line 2
    .line 3
    if-nez p2, :cond_0

    .line 4
    .line 5
    invoke-virtual {p1}, Lpu/b;->l()Lpu/b;

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    invoke-virtual {p1}, Lpu/b;->d()V

    .line 10
    .line 11
    .line 12
    const-string p0, "year"

    .line 13
    .line 14
    invoke-virtual {p1, p0}, Lpu/b;->j(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    invoke-virtual {p2, p0}, Ljava/util/Calendar;->get(I)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    int-to-long v0, p0

    .line 23
    invoke-virtual {p1, v0, v1}, Lpu/b;->T(J)V

    .line 24
    .line 25
    .line 26
    const-string p0, "month"

    .line 27
    .line 28
    invoke-virtual {p1, p0}, Lpu/b;->j(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const/4 p0, 0x2

    .line 32
    invoke-virtual {p2, p0}, Ljava/util/Calendar;->get(I)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    int-to-long v0, p0

    .line 37
    invoke-virtual {p1, v0, v1}, Lpu/b;->T(J)V

    .line 38
    .line 39
    .line 40
    const-string p0, "dayOfMonth"

    .line 41
    .line 42
    invoke-virtual {p1, p0}, Lpu/b;->j(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    const/4 p0, 0x5

    .line 46
    invoke-virtual {p2, p0}, Ljava/util/Calendar;->get(I)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    int-to-long v0, p0

    .line 51
    invoke-virtual {p1, v0, v1}, Lpu/b;->T(J)V

    .line 52
    .line 53
    .line 54
    const-string p0, "hourOfDay"

    .line 55
    .line 56
    invoke-virtual {p1, p0}, Lpu/b;->j(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const/16 p0, 0xb

    .line 60
    .line 61
    invoke-virtual {p2, p0}, Ljava/util/Calendar;->get(I)I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    int-to-long v0, p0

    .line 66
    invoke-virtual {p1, v0, v1}, Lpu/b;->T(J)V

    .line 67
    .line 68
    .line 69
    const-string p0, "minute"

    .line 70
    .line 71
    invoke-virtual {p1, p0}, Lpu/b;->j(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    const/16 p0, 0xc

    .line 75
    .line 76
    invoke-virtual {p2, p0}, Ljava/util/Calendar;->get(I)I

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    int-to-long v0, p0

    .line 81
    invoke-virtual {p1, v0, v1}, Lpu/b;->T(J)V

    .line 82
    .line 83
    .line 84
    const-string p0, "second"

    .line 85
    .line 86
    invoke-virtual {p1, p0}, Lpu/b;->j(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    const/16 p0, 0xd

    .line 90
    .line 91
    invoke-virtual {p2, p0}, Ljava/util/Calendar;->get(I)I

    .line 92
    .line 93
    .line 94
    move-result p0

    .line 95
    int-to-long v0, p0

    .line 96
    invoke-virtual {p1, v0, v1}, Lpu/b;->T(J)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {p1}, Lpu/b;->h()V

    .line 100
    .line 101
    .line 102
    return-void
.end method
