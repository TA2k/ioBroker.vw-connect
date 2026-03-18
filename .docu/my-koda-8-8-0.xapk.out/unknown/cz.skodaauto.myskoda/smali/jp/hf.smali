.class public abstract Ljp/hf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a()I
    .locals 1

    .line 1
    invoke-static {}, Landroid/content/res/Resources;->getSystem()Landroid/content/res/Resources;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget v0, v0, Landroid/util/DisplayMetrics;->widthPixels:I

    .line 10
    .line 11
    return v0
.end method

.method public static final b(Lg40/u;)Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardRequestDto;
    .locals 11

    .line 1
    iget-object v1, p0, Lg40/u;->a:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v3, p0, Lg40/u;->c:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v0, p0, Lg40/u;->g:Lg40/w;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    new-instance v4, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardVehicleInformationDto;

    .line 11
    .line 12
    iget-object v0, v0, Lg40/w;->a:Ljava/lang/String;

    .line 13
    .line 14
    invoke-direct {v4, v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardVehicleInformationDto;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object v7, v4

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move-object v7, v2

    .line 20
    :goto_0
    iget-object v5, p0, Lg40/u;->d:Ljava/time/LocalDate;

    .line 21
    .line 22
    iget-object v4, p0, Lg40/u;->f:Ljava/lang/String;

    .line 23
    .line 24
    iget-object v0, p0, Lg40/u;->e:Lg40/x;

    .line 25
    .line 26
    const/4 v6, 0x1

    .line 27
    if-eqz v0, :cond_6

    .line 28
    .line 29
    iget-object v2, v0, Lg40/x;->d:Ljava/lang/String;

    .line 30
    .line 31
    iget-object v8, v0, Lg40/x;->e:Lcq0/c;

    .line 32
    .line 33
    sget-object v9, Lcq0/c;->e:Lcq0/c;

    .line 34
    .line 35
    if-ne v8, v9, :cond_1

    .line 36
    .line 37
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 38
    .line 39
    .line 40
    move-result v9

    .line 41
    if-nez v9, :cond_1

    .line 42
    .line 43
    sget-object v8, Lcq0/c;->d:Lcq0/c;

    .line 44
    .line 45
    :cond_1
    new-instance v9, Lcz/myskoda/api/bff_loyalty_program/v2/CommunicationChannelDto;

    .line 46
    .line 47
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 48
    .line 49
    .line 50
    move-result v10

    .line 51
    if-eqz v10, :cond_3

    .line 52
    .line 53
    if-ne v10, v6, :cond_2

    .line 54
    .line 55
    const-string v10, "PHONE"

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_2
    new-instance p0, La8/r0;

    .line 59
    .line 60
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 61
    .line 62
    .line 63
    throw p0

    .line 64
    :cond_3
    const-string v10, "EMAIL"

    .line 65
    .line 66
    :goto_1
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 67
    .line 68
    .line 69
    move-result v8

    .line 70
    if-eqz v8, :cond_5

    .line 71
    .line 72
    if-ne v8, v6, :cond_4

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_4
    new-instance p0, La8/r0;

    .line 76
    .line 77
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_5
    iget-object v2, v0, Lg40/x;->c:Ljava/lang/String;

    .line 82
    .line 83
    :goto_2
    invoke-direct {v9, v10, v2}, Lcz/myskoda/api/bff_loyalty_program/v2/CommunicationChannelDto;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    new-instance v2, Lcz/myskoda/api/bff_loyalty_program/v2/CustomerInformationDto;

    .line 87
    .line 88
    iget-object v8, v0, Lg40/x;->a:Ljava/lang/String;

    .line 89
    .line 90
    iget-object v0, v0, Lg40/x;->b:Ljava/lang/String;

    .line 91
    .line 92
    invoke-direct {v2, v8, v0, v9}, Lcz/myskoda/api/bff_loyalty_program/v2/CustomerInformationDto;-><init>(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/CommunicationChannelDto;)V

    .line 93
    .line 94
    .line 95
    :cond_6
    iget-object p0, p0, Lg40/u;->b:Lg40/s0;

    .line 96
    .line 97
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    if-eqz p0, :cond_8

    .line 102
    .line 103
    if-ne p0, v6, :cond_7

    .line 104
    .line 105
    const-string p0, "VOUCHER"

    .line 106
    .line 107
    goto :goto_3

    .line 108
    :cond_7
    new-instance p0, La8/r0;

    .line 109
    .line 110
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 111
    .line 112
    .line 113
    throw p0

    .line 114
    :cond_8
    const-string p0, "PRODUCT"

    .line 115
    .line 116
    :goto_3
    new-instance v0, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardRequestDto;

    .line 117
    .line 118
    move-object v6, v2

    .line 119
    move-object v2, p0

    .line 120
    invoke-direct/range {v0 .. v7}, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardRequestDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Lcz/myskoda/api/bff_loyalty_program/v2/CustomerInformationDto;Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardVehicleInformationDto;)V

    .line 121
    .line 122
    .line 123
    return-object v0
.end method
