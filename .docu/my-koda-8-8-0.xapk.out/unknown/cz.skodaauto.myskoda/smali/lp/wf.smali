.class public abstract Llp/wf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/Object;
    .locals 2

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x22

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    invoke-static {p0, p1}, Lb/k;->b(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-virtual {p1, p0}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-class p1, Le/a;

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    if-eqz p1, :cond_1

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_1
    const/4 p0, 0x0

    .line 26
    return-object p0
.end method

.method public static final b(Ljava/lang/String;)Lon0/h;
    .locals 1

    .line 1
    const-string v0, "state"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    sparse-switch v0, :sswitch_data_0

    .line 11
    .line 12
    .line 13
    goto/16 :goto_0

    .line 14
    .line 15
    :sswitch_0
    const-string v0, "FAILED"

    .line 16
    .line 17
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-nez p0, :cond_0

    .line 22
    .line 23
    goto/16 :goto_0

    .line 24
    .line 25
    :cond_0
    sget-object p0, Lon0/h;->g:Lon0/h;

    .line 26
    .line 27
    return-object p0

    .line 28
    :sswitch_1
    const-string v0, "CREATED"

    .line 29
    .line 30
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-nez p0, :cond_1

    .line 35
    .line 36
    goto/16 :goto_0

    .line 37
    .line 38
    :cond_1
    sget-object p0, Lon0/h;->f:Lon0/h;

    .line 39
    .line 40
    return-object p0

    .line 41
    :sswitch_2
    const-string v0, "PARTIAL_PAYMENT"

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    if-nez p0, :cond_2

    .line 48
    .line 49
    goto/16 :goto_0

    .line 50
    .line 51
    :cond_2
    sget-object p0, Lon0/h;->h:Lon0/h;

    .line 52
    .line 53
    return-object p0

    .line 54
    :sswitch_3
    const-string v0, "PAYMENT_COMPLETE"

    .line 55
    .line 56
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    if-nez p0, :cond_3

    .line 61
    .line 62
    goto/16 :goto_0

    .line 63
    .line 64
    :cond_3
    sget-object p0, Lon0/h;->i:Lon0/h;

    .line 65
    .line 66
    return-object p0

    .line 67
    :sswitch_4
    const-string v0, "PROBLEM"

    .line 68
    .line 69
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    if-nez p0, :cond_4

    .line 74
    .line 75
    goto/16 :goto_0

    .line 76
    .line 77
    :cond_4
    sget-object p0, Lon0/h;->n:Lon0/h;

    .line 78
    .line 79
    return-object p0

    .line 80
    :sswitch_5
    const-string v0, "REJECTED"

    .line 81
    .line 82
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    if-nez p0, :cond_5

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_5
    sget-object p0, Lon0/h;->o:Lon0/h;

    .line 90
    .line 91
    return-object p0

    .line 92
    :sswitch_6
    const-string v0, "PAYMENT_PRE_AUTHORIZATION_RELEASED"

    .line 93
    .line 94
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result p0

    .line 98
    if-nez p0, :cond_6

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_6
    sget-object p0, Lon0/h;->l:Lon0/h;

    .line 102
    .line 103
    return-object p0

    .line 104
    :sswitch_7
    const-string v0, "PAYMENT_PRE_AUTHORIZATION_FAILED"

    .line 105
    .line 106
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    if-nez p0, :cond_7

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_7
    sget-object p0, Lon0/h;->j:Lon0/h;

    .line 114
    .line 115
    return-object p0

    .line 116
    :sswitch_8
    const-string v0, "PAYMENT_FAILED"

    .line 117
    .line 118
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    if-nez p0, :cond_8

    .line 123
    .line 124
    goto :goto_0

    .line 125
    :cond_8
    sget-object p0, Lon0/h;->m:Lon0/h;

    .line 126
    .line 127
    return-object p0

    .line 128
    :sswitch_9
    const-string v0, "PRODUCT_ACQUIRED"

    .line 129
    .line 130
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result p0

    .line 134
    if-nez p0, :cond_9

    .line 135
    .line 136
    goto :goto_0

    .line 137
    :cond_9
    sget-object p0, Lon0/h;->p:Lon0/h;

    .line 138
    .line 139
    return-object p0

    .line 140
    :sswitch_a
    const-string v0, "CANCELLED"

    .line 141
    .line 142
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    if-nez p0, :cond_a

    .line 147
    .line 148
    goto :goto_0

    .line 149
    :cond_a
    sget-object p0, Lon0/h;->e:Lon0/h;

    .line 150
    .line 151
    return-object p0

    .line 152
    :sswitch_b
    const-string v0, "PAYMENT_PRE_AUTHORIZATION_SUCCESSFUL"

    .line 153
    .line 154
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result p0

    .line 158
    if-nez p0, :cond_b

    .line 159
    .line 160
    goto :goto_0

    .line 161
    :cond_b
    sget-object p0, Lon0/h;->k:Lon0/h;

    .line 162
    .line 163
    return-object p0

    .line 164
    :sswitch_c
    const-string v0, "PRODUCT_PENDING"

    .line 165
    .line 166
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result p0

    .line 170
    if-nez p0, :cond_c

    .line 171
    .line 172
    goto :goto_0

    .line 173
    :cond_c
    sget-object p0, Lon0/h;->q:Lon0/h;

    .line 174
    .line 175
    return-object p0

    .line 176
    :sswitch_d
    const-string v0, "SESSION_COMPLETE"

    .line 177
    .line 178
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result p0

    .line 182
    if-nez p0, :cond_d

    .line 183
    .line 184
    :goto_0
    sget-object p0, Lon0/h;->n:Lon0/h;

    .line 185
    .line 186
    return-object p0

    .line 187
    :cond_d
    sget-object p0, Lon0/h;->r:Lon0/h;

    .line 188
    .line 189
    return-object p0

    .line 190
    nop

    .line 191
    :sswitch_data_0
    .sparse-switch
        -0x7341d71e -> :sswitch_d
        -0x587d29f9 -> :sswitch_c
        -0x47c387cb -> :sswitch_b
        -0x3d7fc6cf -> :sswitch_a
        -0x31180442 -> :sswitch_9
        -0x2ebe874a -> :sswitch_8
        -0x10fa90a8 -> :sswitch_7
        -0x5b7aa68 -> :sswitch_6
        0xa61047e -> :sswitch_5
        0x18584e7f -> :sswitch_4
        0x3ac8d772 -> :sswitch_3
        0x62c8c908 -> :sswitch_2
        0x681a0ac8 -> :sswitch_1
        0x7b29883d -> :sswitch_0
    .end sparse-switch
.end method

.method public static final c(Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;)Lon0/e;
    .locals 13

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getId()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v2

    .line 10
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getLocationId()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getState()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-static {v0}, Llp/wf;->b(Ljava/lang/String;)Lon0/h;

    .line 19
    .line 20
    .line 21
    move-result-object v5

    .line 22
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getPrice()Lcz/myskoda/api/bff_fueling/v2/FuelingSessionPriceDto;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    const/4 v1, 0x0

    .line 27
    if-eqz v0, :cond_2

    .line 28
    .line 29
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getPrice()Lcz/myskoda/api/bff_fueling/v2/FuelingSessionPriceDto;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    invoke-virtual {v0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionPriceDto;->getCurrency()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    move-object v0, v1

    .line 41
    :goto_0
    if-eqz v0, :cond_2

    .line 42
    .line 43
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getPrice()Lcz/myskoda/api/bff_fueling/v2/FuelingSessionPriceDto;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    if-eqz v0, :cond_2

    .line 48
    .line 49
    new-instance v4, Lon0/d;

    .line 50
    .line 51
    invoke-virtual {v0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionPriceDto;->getPricePerUnit()Ljava/lang/Double;

    .line 52
    .line 53
    .line 54
    move-result-object v6

    .line 55
    if-eqz v6, :cond_1

    .line 56
    .line 57
    invoke-virtual {v6}, Ljava/lang/Double;->doubleValue()D

    .line 58
    .line 59
    .line 60
    move-result-wide v6

    .line 61
    goto :goto_1

    .line 62
    :cond_1
    const-wide/16 v6, 0x0

    .line 63
    .line 64
    :goto_1
    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 65
    .line 66
    .line 67
    move-result-object v6

    .line 68
    invoke-virtual {v0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionPriceDto;->getTotal()D

    .line 69
    .line 70
    .line 71
    move-result-wide v7

    .line 72
    invoke-virtual {v0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionPriceDto;->getCurrency()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    invoke-direct {v4, v7, v8, v0, v6}, Lon0/d;-><init>(DLjava/lang/String;Ljava/lang/Double;)V

    .line 80
    .line 81
    .line 82
    move-object v6, v4

    .line 83
    goto :goto_2

    .line 84
    :cond_2
    move-object v6, v1

    .line 85
    :goto_2
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getQuantityUnit()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v10

    .line 89
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getQuantity()Ljava/lang/Double;

    .line 90
    .line 91
    .line 92
    move-result-object v11

    .line 93
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getFormattedCardName()Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v4

    .line 97
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getFuelName()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v7

    .line 101
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getDateTime()Ljava/time/OffsetDateTime;

    .line 102
    .line 103
    .line 104
    move-result-object v8

    .line 105
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getDateTime()Ljava/time/OffsetDateTime;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    if-eqz v0, :cond_3

    .line 110
    .line 111
    invoke-static {v0}, Lvo/a;->i(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    :cond_3
    move-object v9, v1

    .line 116
    new-instance v12, Lon0/l;

    .line 117
    .line 118
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getGasStation()Lcz/myskoda/api/bff_fueling/v2/GasStationSummaryDto;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    const-string v1, ""

    .line 123
    .line 124
    if-eqz v0, :cond_4

    .line 125
    .line 126
    invoke-virtual {v0}, Lcz/myskoda/api/bff_fueling/v2/GasStationSummaryDto;->getName()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    if-nez v0, :cond_5

    .line 131
    .line 132
    :cond_4
    move-object v0, v1

    .line 133
    :cond_5
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;->getGasStation()Lcz/myskoda/api/bff_fueling/v2/GasStationSummaryDto;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    if-eqz p0, :cond_7

    .line 138
    .line 139
    invoke-virtual {p0}, Lcz/myskoda/api/bff_fueling/v2/GasStationSummaryDto;->getFormattedAddress()Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    if-nez p0, :cond_6

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_6
    move-object v1, p0

    .line 147
    :cond_7
    :goto_3
    invoke-direct {v12, v0, v1}, Lon0/l;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    new-instance v1, Lon0/e;

    .line 151
    .line 152
    invoke-direct/range {v1 .. v12}, Lon0/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/h;Lon0/d;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Double;Lon0/l;)V

    .line 153
    .line 154
    .line 155
    return-object v1
.end method
