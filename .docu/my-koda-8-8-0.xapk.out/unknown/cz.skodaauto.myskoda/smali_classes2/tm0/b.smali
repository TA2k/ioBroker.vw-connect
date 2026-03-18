.class public final synthetic Ltm0/b;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Ltm0/b;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Ltm0/b;

    .line 2
    .line 3
    const-string v4, "toModel(Lcz/myskoda/api/bff/v1/SoftwareUpdateStatusDto;)Lcz/skodaauto/myskoda/library/onlineremoteupdate/model/SoftwareUpdateStatus;"

    .line 4
    .line 5
    const/4 v5, 0x1

    .line 6
    const/4 v1, 0x1

    .line 7
    const-class v2, Ltm0/d;

    .line 8
    .line 9
    const-string v3, "toModel"

    .line 10
    .line 11
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Ltm0/b;->d:Ltm0/b;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Lcz/myskoda/api/bff/v1/SoftwareUpdateStatusDto;

    .line 2
    .line 3
    const-string p0, "p0"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lwm0/a;

    .line 9
    .line 10
    invoke-virtual {p1}, Lcz/myskoda/api/bff/v1/SoftwareUpdateStatusDto;->getStatus()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string v1, "<this>"

    .line 15
    .line 16
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    sparse-switch v1, :sswitch_data_0

    .line 24
    .line 25
    .line 26
    goto :goto_1

    .line 27
    :sswitch_0
    const-string v1, "PRE_UPDATE_AVAILABLE"

    .line 28
    .line 29
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-nez p0, :cond_0

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_0
    sget-object p0, Lwm0/b;->d:Lwm0/b;

    .line 37
    .line 38
    :goto_0
    move-object v1, p0

    .line 39
    goto :goto_2

    .line 40
    :sswitch_1
    const-string v1, "UPDATE_PRECONDITION_FAILED"

    .line 41
    .line 42
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-nez p0, :cond_1

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    sget-object p0, Lwm0/b;->j:Lwm0/b;

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :sswitch_2
    const-string v1, "UPDATE_IN_PROGRESS"

    .line 53
    .line 54
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    if-nez p0, :cond_2

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_2
    sget-object p0, Lwm0/b;->f:Lwm0/b;

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :sswitch_3
    const-string v1, "UPDATE_AVAILABLE"

    .line 65
    .line 66
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    if-nez p0, :cond_3

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_3
    sget-object p0, Lwm0/b;->e:Lwm0/b;

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :sswitch_4
    const-string v1, "UPDATE_SUCCESSFUL"

    .line 77
    .line 78
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    if-nez p0, :cond_4

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_4
    sget-object p0, Lwm0/b;->g:Lwm0/b;

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :sswitch_5
    const-string v1, "UPDATE_FAILED"

    .line 89
    .line 90
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result p0

    .line 94
    if-nez p0, :cond_5

    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_5
    sget-object p0, Lwm0/b;->h:Lwm0/b;

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :sswitch_6
    const-string v1, "NO_UPDATE_AVAILABLE"

    .line 101
    .line 102
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result p0

    .line 106
    if-nez p0, :cond_6

    .line 107
    .line 108
    :goto_1
    sget-object p0, Lwm0/b;->i:Lwm0/b;

    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_6
    sget-object p0, Lwm0/b;->i:Lwm0/b;

    .line 112
    .line 113
    goto :goto_0

    .line 114
    :goto_2
    invoke-virtual {p1}, Lcz/myskoda/api/bff/v1/SoftwareUpdateStatusDto;->getCarCapturedTimestamp()Ljava/time/OffsetDateTime;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    invoke-virtual {p1}, Lcz/myskoda/api/bff/v1/SoftwareUpdateStatusDto;->getReleaseNotesUrl()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v3

    .line 122
    invoke-virtual {p1}, Lcz/myskoda/api/bff/v1/SoftwareUpdateStatusDto;->getCurrentSoftwareVersion()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v4

    .line 126
    invoke-virtual {p1}, Lcz/myskoda/api/bff/v1/SoftwareUpdateStatusDto;->getUpdateDurationInSeconds()Ljava/lang/Integer;

    .line 127
    .line 128
    .line 129
    move-result-object v5

    .line 130
    invoke-direct/range {v0 .. v5}, Lwm0/a;-><init>(Lwm0/b;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)V

    .line 131
    .line 132
    .line 133
    return-object v0

    .line 134
    nop

    .line 135
    :sswitch_data_0
    .sparse-switch
        -0x6c50f28f -> :sswitch_6
        -0x10d6eb8d -> :sswitch_5
        0x58217d0 -> :sswitch_4
        0x51b71ab3 -> :sswitch_3
        0x51f4f991 -> :sswitch_2
        0x5569d40e -> :sswitch_1
        0x7f38bcef -> :sswitch_0
    .end sparse-switch
.end method
