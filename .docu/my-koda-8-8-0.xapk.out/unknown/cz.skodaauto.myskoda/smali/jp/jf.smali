.class public abstract Ljp/jf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lz9/w;Ljava/lang/String;Lt2/b;)V
    .locals 10

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Lqe/b;

    .line 7
    .line 8
    const/4 v0, 0x3

    .line 9
    invoke-direct {v4, v0}, Lqe/b;-><init>(I)V

    .line 10
    .line 11
    .line 12
    new-instance v5, Lqe/b;

    .line 13
    .line 14
    const/4 v0, 0x4

    .line 15
    invoke-direct {v5, v0}, Lqe/b;-><init>(I)V

    .line 16
    .line 17
    .line 18
    new-instance v6, Lqe/b;

    .line 19
    .line 20
    const/4 v0, 0x5

    .line 21
    invoke-direct {v6, v0}, Lqe/b;-><init>(I)V

    .line 22
    .line 23
    .line 24
    new-instance v7, Lqe/b;

    .line 25
    .line 26
    const/4 v0, 0x6

    .line 27
    invoke-direct {v7, v0}, Lqe/b;-><init>(I)V

    .line 28
    .line 29
    .line 30
    new-instance v0, Lqe/c;

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    invoke-direct {v0, p2, v1}, Lqe/c;-><init>(Lt2/b;I)V

    .line 34
    .line 35
    .line 36
    new-instance v8, Lt2/b;

    .line 37
    .line 38
    const/4 p2, 0x1

    .line 39
    const v1, 0x388f1ff

    .line 40
    .line 41
    .line 42
    invoke-direct {v8, v0, p2, v1}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 43
    .line 44
    .line 45
    const/16 v9, 0x86

    .line 46
    .line 47
    const/4 v3, 0x0

    .line 48
    move-object v1, p0

    .line 49
    move-object v2, p1

    .line 50
    invoke-static/range {v1 .. v9}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 51
    .line 52
    .line 53
    return-void
.end method

.method public static final b(Ljava/lang/String;)Lg40/c0;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "WEBSHOP"

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    sget-object p0, Lg40/c0;->d:Lg40/c0;

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    const-string v0, "POWERPASS"

    .line 18
    .line 19
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    sget-object p0, Lg40/c0;->e:Lg40/c0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 29
    .line 30
    const-string v1, "Unsupported IssuedVoucherCategory "

    .line 31
    .line 32
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw v0
.end method

.method public static final c(Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;)Lg40/a;
    .locals 16

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lg40/a;

    .line 9
    .line 10
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;->getId()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;->getName()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;->getDescription()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;->getDetailedDescription()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;->getPickupDatetime()Ljava/time/OffsetDateTime;

    .line 27
    .line 28
    .line 29
    move-result-object v6

    .line 30
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;->getRedemptionPageUrl()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v7

    .line 34
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;->getDealer()Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDealerDto;

    .line 35
    .line 36
    .line 37
    move-result-object v8

    .line 38
    const/4 v9, 0x0

    .line 39
    if-eqz v8, :cond_1

    .line 40
    .line 41
    new-instance v10, Lg40/z;

    .line 42
    .line 43
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDealerDto;->getName()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v11

    .line 47
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDealerDto;->getPhone()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v12

    .line 51
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDealerDto;->getEmail()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v13

    .line 55
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDealerDto;->getAddress()Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDealerAddressDto;

    .line 56
    .line 57
    .line 58
    move-result-object v8

    .line 59
    if-eqz v8, :cond_0

    .line 60
    .line 61
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDealerAddressDto;->getStreet()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v9

    .line 65
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDealerAddressDto;->getZipCode()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v14

    .line 69
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDealerAddressDto;->getCity()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v8

    .line 73
    new-instance v15, Lcq0/h;

    .line 74
    .line 75
    invoke-direct {v15, v9, v8, v14}, Lcq0/h;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    move-object v9, v15

    .line 79
    :cond_0
    invoke-direct {v10, v11, v12, v13, v9}, Lg40/z;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcq0/h;)V

    .line 80
    .line 81
    .line 82
    move-object v8, v10

    .line 83
    goto :goto_0

    .line 84
    :cond_1
    move-object v8, v9

    .line 85
    :goto_0
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;->getStatus()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v9

    .line 89
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v9}, Ljava/lang/String;->hashCode()I

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    const v10, -0x6ffa6fdc

    .line 97
    .line 98
    .line 99
    if-eq v0, v10, :cond_3

    .line 100
    .line 101
    const v10, 0x25a5f173

    .line 102
    .line 103
    .line 104
    if-eq v0, v10, :cond_2

    .line 105
    .line 106
    const v10, 0x6f8127dd

    .line 107
    .line 108
    .line 109
    if-ne v0, v10, :cond_4

    .line 110
    .line 111
    const-string v0, "WAITING_FOR_CONFIRMATION"

    .line 112
    .line 113
    invoke-virtual {v9, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    if-eqz v0, :cond_4

    .line 118
    .line 119
    sget-object v0, Lg40/b;->d:Lg40/b;

    .line 120
    .line 121
    :goto_1
    move-object v9, v0

    .line 122
    goto :goto_2

    .line 123
    :cond_2
    const-string v0, "CANCELLED_BY_DEALER"

    .line 124
    .line 125
    invoke-virtual {v9, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    if-eqz v0, :cond_4

    .line 130
    .line 131
    sget-object v0, Lg40/b;->f:Lg40/b;

    .line 132
    .line 133
    goto :goto_1

    .line 134
    :cond_3
    const-string v0, "WAITING_FOR_PICKUP"

    .line 135
    .line 136
    invoke-virtual {v9, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v0

    .line 140
    if-eqz v0, :cond_4

    .line 141
    .line 142
    sget-object v0, Lg40/b;->e:Lg40/b;

    .line 143
    .line 144
    goto :goto_1

    .line 145
    :goto_2
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;->getImageUrls()Ljava/util/List;

    .line 146
    .line 147
    .line 148
    move-result-object v10

    .line 149
    invoke-direct/range {v1 .. v10}, Lg40/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Lg40/z;Lg40/b;Ljava/util/List;)V

    .line 150
    .line 151
    .line 152
    return-object v1

    .line 153
    :cond_4
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 154
    .line 155
    const-string v1, "Unsupported ActiveRewardStatus "

    .line 156
    .line 157
    invoke-virtual {v1, v9}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    throw v0
.end method
