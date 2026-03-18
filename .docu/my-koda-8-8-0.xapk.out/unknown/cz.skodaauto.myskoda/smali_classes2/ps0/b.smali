.class public abstract Lps0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lcz/myskoda/api/bff_garage/v2/CompositeRenderDto;)Lhp0/e;
    .locals 10

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcz/myskoda/api/bff_garage/v2/CompositeRenderDto;->getLayers()Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Ljava/lang/Iterable;

    .line 11
    .line 12
    new-instance v1, Ljava/util/ArrayList;

    .line 13
    .line 14
    const/16 v2, 0xa

    .line 15
    .line 16
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 21
    .line 22
    .line 23
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-eqz v2, :cond_0

    .line 32
    .line 33
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    check-cast v2, Lcz/myskoda/api/bff_garage/v2/RenderDto;

    .line 38
    .line 39
    new-instance v3, Lhp0/a;

    .line 40
    .line 41
    invoke-virtual {v2}, Lcz/myskoda/api/bff_garage/v2/RenderDto;->getUrl()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    invoke-virtual {v2}, Lcz/myskoda/api/bff_garage/v2/RenderDto;->getOrder()I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    invoke-direct {v3, v4, v2}, Lhp0/a;-><init>(Ljava/lang/String;I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    invoke-virtual {p0}, Lcz/myskoda/api/bff_garage/v2/CompositeRenderDto;->getModifications()Lcz/myskoda/api/bff_garage/v2/RenderModificationsDto;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    if-eqz v0, :cond_8

    .line 61
    .line 62
    new-instance v2, Lhp0/c;

    .line 63
    .line 64
    invoke-virtual {v0}, Lcz/myskoda/api/bff_garage/v2/RenderModificationsDto;->getAdjustSpaceInPx()Lcz/myskoda/api/bff_garage/v2/AdjustSpaceInPxDto;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    invoke-virtual {v3}, Lcz/myskoda/api/bff_garage/v2/AdjustSpaceInPxDto;->getLeft()Ljava/lang/Integer;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    const/4 v4, 0x0

    .line 73
    if-eqz v3, :cond_1

    .line 74
    .line 75
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    goto :goto_1

    .line 80
    :cond_1
    move v3, v4

    .line 81
    :goto_1
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    invoke-virtual {v0}, Lcz/myskoda/api/bff_garage/v2/RenderModificationsDto;->getAdjustSpaceInPx()Lcz/myskoda/api/bff_garage/v2/AdjustSpaceInPxDto;

    .line 86
    .line 87
    .line 88
    move-result-object v5

    .line 89
    invoke-virtual {v5}, Lcz/myskoda/api/bff_garage/v2/AdjustSpaceInPxDto;->getRight()Ljava/lang/Integer;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    if-eqz v5, :cond_2

    .line 94
    .line 95
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    goto :goto_2

    .line 100
    :cond_2
    move v5, v4

    .line 101
    :goto_2
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    invoke-virtual {v0}, Lcz/myskoda/api/bff_garage/v2/RenderModificationsDto;->getAdjustSpaceInPx()Lcz/myskoda/api/bff_garage/v2/AdjustSpaceInPxDto;

    .line 106
    .line 107
    .line 108
    move-result-object v6

    .line 109
    invoke-virtual {v6}, Lcz/myskoda/api/bff_garage/v2/AdjustSpaceInPxDto;->getTop()Ljava/lang/Integer;

    .line 110
    .line 111
    .line 112
    move-result-object v6

    .line 113
    if-eqz v6, :cond_3

    .line 114
    .line 115
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 116
    .line 117
    .line 118
    move-result v6

    .line 119
    goto :goto_3

    .line 120
    :cond_3
    move v6, v4

    .line 121
    :goto_3
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 122
    .line 123
    .line 124
    move-result-object v6

    .line 125
    invoke-virtual {v0}, Lcz/myskoda/api/bff_garage/v2/RenderModificationsDto;->getAdjustSpaceInPx()Lcz/myskoda/api/bff_garage/v2/AdjustSpaceInPxDto;

    .line 126
    .line 127
    .line 128
    move-result-object v7

    .line 129
    invoke-virtual {v7}, Lcz/myskoda/api/bff_garage/v2/AdjustSpaceInPxDto;->getBottom()Ljava/lang/Integer;

    .line 130
    .line 131
    .line 132
    move-result-object v7

    .line 133
    if-eqz v7, :cond_4

    .line 134
    .line 135
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 136
    .line 137
    .line 138
    move-result v4

    .line 139
    :cond_4
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 140
    .line 141
    .line 142
    move-result-object v4

    .line 143
    invoke-virtual {v0}, Lcz/myskoda/api/bff_garage/v2/RenderModificationsDto;->getAnchorTo()Lcz/myskoda/api/bff_garage/v2/RenderModificationsDto$AnchorTo;

    .line 144
    .line 145
    .line 146
    move-result-object v7

    .line 147
    sget-object v8, Lps0/a;->a:[I

    .line 148
    .line 149
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 150
    .line 151
    .line 152
    move-result v7

    .line 153
    aget v7, v8, v7

    .line 154
    .line 155
    const/4 v8, 0x1

    .line 156
    if-eq v7, v8, :cond_7

    .line 157
    .line 158
    const/4 v8, 0x2

    .line 159
    if-eq v7, v8, :cond_6

    .line 160
    .line 161
    const/4 v8, 0x3

    .line 162
    if-ne v7, v8, :cond_5

    .line 163
    .line 164
    sget-object v7, Lhp0/b;->f:Lhp0/b;

    .line 165
    .line 166
    goto :goto_4

    .line 167
    :cond_5
    new-instance p0, La8/r0;

    .line 168
    .line 169
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 170
    .line 171
    .line 172
    throw p0

    .line 173
    :cond_6
    sget-object v7, Lhp0/b;->d:Lhp0/b;

    .line 174
    .line 175
    goto :goto_4

    .line 176
    :cond_7
    sget-object v7, Lhp0/b;->e:Lhp0/b;

    .line 177
    .line 178
    :goto_4
    invoke-virtual {v0}, Lcz/myskoda/api/bff_garage/v2/RenderModificationsDto;->getFlipHorizontal()Z

    .line 179
    .line 180
    .line 181
    move-result v8

    .line 182
    move-object v9, v6

    .line 183
    move-object v6, v4

    .line 184
    move-object v4, v5

    .line 185
    move-object v5, v9

    .line 186
    invoke-direct/range {v2 .. v8}, Lhp0/c;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Lhp0/b;Z)V

    .line 187
    .line 188
    .line 189
    goto :goto_5

    .line 190
    :cond_8
    const/4 v2, 0x0

    .line 191
    :goto_5
    invoke-virtual {p0}, Lcz/myskoda/api/bff_garage/v2/CompositeRenderDto;->getViewType()Ljava/lang/String;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    invoke-static {p0}, Lps0/b;->b(Ljava/lang/String;)Lhp0/d;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    new-instance v0, Lhp0/e;

    .line 200
    .line 201
    invoke-direct {v0, v1, v2, p0}, Lhp0/e;-><init>(Ljava/util/ArrayList;Lhp0/c;Lhp0/d;)V

    .line 202
    .line 203
    .line 204
    return-object v0
.end method

.method public static b(Ljava/lang/String;)Lhp0/d;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const-string v0, "toLowerCase(...)"

    .line 13
    .line 14
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    sparse-switch v0, :sswitch_data_0

    .line 22
    .line 23
    .line 24
    goto/16 :goto_0

    .line 25
    .line 26
    :sswitch_0
    const-string v0, "unmodified_exterior_front"

    .line 27
    .line 28
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-nez p0, :cond_0

    .line 33
    .line 34
    goto/16 :goto_0

    .line 35
    .line 36
    :cond_0
    sget-object p0, Lhp0/d;->g:Lhp0/d;

    .line 37
    .line 38
    return-object p0

    .line 39
    :sswitch_1
    const-string v0, "unmodified_interior_side"

    .line 40
    .line 41
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-nez p0, :cond_1

    .line 46
    .line 47
    goto/16 :goto_0

    .line 48
    .line 49
    :cond_1
    sget-object p0, Lhp0/d;->i:Lhp0/d;

    .line 50
    .line 51
    return-object p0

    .line 52
    :sswitch_2
    const-string v0, "unmodified_interior_boot"

    .line 53
    .line 54
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    if-nez p0, :cond_2

    .line 59
    .line 60
    goto/16 :goto_0

    .line 61
    .line 62
    :cond_2
    sget-object p0, Lhp0/d;->k:Lhp0/d;

    .line 63
    .line 64
    return-object p0

    .line 65
    :sswitch_3
    const-string v0, "charging_dark"

    .line 66
    .line 67
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    if-nez p0, :cond_3

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_3
    sget-object p0, Lhp0/d;->n:Lhp0/d;

    .line 75
    .line 76
    return-object p0

    .line 77
    :sswitch_4
    const-string v0, "charging_light"

    .line 78
    .line 79
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    if-nez p0, :cond_4

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_4
    sget-object p0, Lhp0/d;->m:Lhp0/d;

    .line 87
    .line 88
    return-object p0

    .line 89
    :sswitch_5
    const-string v0, "plugged_in_light"

    .line 90
    .line 91
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result p0

    .line 95
    if-nez p0, :cond_5

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_5
    sget-object p0, Lhp0/d;->o:Lhp0/d;

    .line 99
    .line 100
    return-object p0

    .line 101
    :sswitch_6
    const-string v0, "home"

    .line 102
    .line 103
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    if-nez p0, :cond_6

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_6
    sget-object p0, Lhp0/d;->e:Lhp0/d;

    .line 111
    .line 112
    return-object p0

    .line 113
    :sswitch_7
    const-string v0, "plugged_in_dark"

    .line 114
    .line 115
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    if-nez p0, :cond_7

    .line 120
    .line 121
    goto :goto_0

    .line 122
    :cond_7
    sget-object p0, Lhp0/d;->p:Lhp0/d;

    .line 123
    .line 124
    return-object p0

    .line 125
    :sswitch_8
    const-string v0, "unmodified_exterior_side"

    .line 126
    .line 127
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result p0

    .line 131
    if-nez p0, :cond_8

    .line 132
    .line 133
    goto :goto_0

    .line 134
    :cond_8
    sget-object p0, Lhp0/d;->f:Lhp0/d;

    .line 135
    .line 136
    return-object p0

    .line 137
    :sswitch_9
    const-string v0, "unmodified_exterior_rear"

    .line 138
    .line 139
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result p0

    .line 143
    if-nez p0, :cond_9

    .line 144
    .line 145
    goto :goto_0

    .line 146
    :cond_9
    sget-object p0, Lhp0/d;->h:Lhp0/d;

    .line 147
    .line 148
    return-object p0

    .line 149
    :sswitch_a
    const-string v0, "unmodified_interior_front"

    .line 150
    .line 151
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result p0

    .line 155
    if-nez p0, :cond_a

    .line 156
    .line 157
    goto :goto_0

    .line 158
    :cond_a
    sget-object p0, Lhp0/d;->j:Lhp0/d;

    .line 159
    .line 160
    return-object p0

    .line 161
    :sswitch_b
    const-string v0, "downscaled_exterior_front"

    .line 162
    .line 163
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result p0

    .line 167
    if-nez p0, :cond_b

    .line 168
    .line 169
    :goto_0
    sget-object p0, Lhp0/d;->q:Lhp0/d;

    .line 170
    .line 171
    return-object p0

    .line 172
    :cond_b
    sget-object p0, Lhp0/d;->l:Lhp0/d;

    .line 173
    .line 174
    return-object p0

    .line 175
    :sswitch_data_0
    .sparse-switch
        -0x6f9b2f75 -> :sswitch_b
        -0x660617a9 -> :sswitch_a
        -0x260e5298 -> :sswitch_9
        -0x260dcee5 -> :sswitch_8
        -0x183f57f7 -> :sswitch_7
        0x30f4df -> :sswitch_6
        0x10c88ee3 -> :sswitch_5
        0x2367a1c8 -> :sswitch_4
        0x43312484 -> :sswitch_3
        0x47063304 -> :sswitch_2
        0x470dd569 -> :sswitch_1
        0x63a102e5 -> :sswitch_0
    .end sparse-switch
.end method
