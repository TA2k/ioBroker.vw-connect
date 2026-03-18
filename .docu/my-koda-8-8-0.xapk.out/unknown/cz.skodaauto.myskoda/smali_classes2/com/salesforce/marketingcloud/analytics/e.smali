.class public final Lcom/salesforce/marketingcloud/analytics/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final a:Lcom/salesforce/marketingcloud/registration/f;

.field private final b:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

.field private final c:Z

.field private final d:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;ZLcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)V
    .locals 1

    .line 1
    const-string v0, "registrationMeta"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    .line 10
    .line 11
    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/e;->b:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    .line 12
    .line 13
    iput-boolean p3, p0, Lcom/salesforce/marketingcloud/analytics/e;->c:Z

    .line 14
    .line 15
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/e;->d:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 16
    .line 17
    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/analytics/e;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;ZLcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/analytics/e;
    .locals 0

    and-int/lit8 p6, p5, 0x1

    if-eqz p6, :cond_0

    .line 3
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    :cond_0
    and-int/lit8 p6, p5, 0x2

    if-eqz p6, :cond_1

    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/e;->b:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    :cond_1
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_2

    iget-boolean p3, p0, Lcom/salesforce/marketingcloud/analytics/e;->c:Z

    :cond_2
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_3

    iget-object p4, p0, Lcom/salesforce/marketingcloud/analytics/e;->d:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/e;->a(Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;ZLcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)Lcom/salesforce/marketingcloud/analytics/e;

    move-result-object p0

    return-object p0
.end method

.method private final a()Lcom/salesforce/marketingcloud/registration/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    return-object p0
.end method

.method private final b()Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/e;->b:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    .line 2
    .line 3
    return-object p0
.end method

.method private final c()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/analytics/e;->c:Z

    .line 2
    .line 3
    return p0
.end method

.method private final d()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/e;->d:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 2
    .line 3
    return-object p0
.end method


# virtual methods
.method public final a(Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;ZLcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)Lcom/salesforce/marketingcloud/analytics/e;
    .locals 0

    .line 2
    const-string p0, "registrationMeta"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p0, Lcom/salesforce/marketingcloud/analytics/e;

    invoke-direct {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/e;-><init>(Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;ZLcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)V

    return-object p0
.end method

.method public final e()Lorg/json/JSONObject;
    .locals 4

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    .line 7
    .line 8
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/registration/f;->f()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const-string v2, "deviceID"

    .line 13
    .line 14
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 15
    .line 16
    .line 17
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    .line 18
    .line 19
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/registration/f;->d()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    const-string v2, "etAppId"

    .line 24
    .line 25
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    .line 29
    .line 30
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/registration/f;->g()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    const-string v2, "hwid"

    .line 35
    .line 36
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    .line 40
    .line 41
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/registration/f;->h()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    const-string v2, "platform"

    .line 46
    .line 47
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 48
    .line 49
    .line 50
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    .line 51
    .line 52
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/registration/f;->i()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    const-string v2, "platform_Version"

    .line 57
    .line 58
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 59
    .line 60
    .line 61
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    .line 62
    .line 63
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/registration/f;->j()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    const-string v2, "sdk_Version"

    .line 68
    .line 69
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 70
    .line 71
    .line 72
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    .line 73
    .line 74
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/registration/f;->e()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    const-string v2, "app_Version"

    .line 79
    .line 80
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 81
    .line 82
    .line 83
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    invoke-virtual {v1}, Ljava/util/Locale;->toString()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    const-string v2, "locale"

    .line 92
    .line 93
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 94
    .line 95
    .line 96
    invoke-static {}, Lcom/salesforce/marketingcloud/util/j;->b()I

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    const-string v2, "timeZone"

    .line 101
    .line 102
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 103
    .line 104
    .line 105
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->c:Z

    .line 106
    .line 107
    const-string v2, "location_Enabled"

    .line 108
    .line 109
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 110
    .line 111
    .line 112
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->b:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    .line 113
    .line 114
    if-eqz v1, :cond_0

    .line 115
    .line 116
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->isPushEnabled()Z

    .line 117
    .line 118
    .line 119
    move-result v2

    .line 120
    const-string v3, "backgroundRefreshEnabled"

    .line 121
    .line 122
    invoke-virtual {v0, v3, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 123
    .line 124
    .line 125
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->isPushEnabled()Z

    .line 126
    .line 127
    .line 128
    move-result v1

    .line 129
    const-string v2, "push_Enabled"

    .line 130
    .line 131
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 132
    .line 133
    .line 134
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/e;->d:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 135
    .line 136
    if-eqz p0, :cond_1

    .line 137
    .line 138
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->toJson()Lorg/json/JSONObject;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    const-string v1, "identity"

    .line 143
    .line 144
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 145
    .line 146
    .line 147
    :cond_1
    return-object v0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/salesforce/marketingcloud/analytics/e;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcom/salesforce/marketingcloud/analytics/e;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->b:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/analytics/e;->b:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->c:Z

    .line 36
    .line 37
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/analytics/e;->c:Z

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/e;->d:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 43
    .line 44
    iget-object p1, p1, Lcom/salesforce/marketingcloud/analytics/e;->d:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 45
    .line 46
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-nez p0, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    return v0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/registration/f;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/e;->b:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    if-nez v2, :cond_0

    .line 14
    .line 15
    move v2, v3

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    :goto_0
    add-int/2addr v0, v2

    .line 22
    mul-int/2addr v0, v1

    .line 23
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/analytics/e;->c:Z

    .line 24
    .line 25
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/e;->d:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 30
    .line 31
    if-nez p0, :cond_1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    :goto_1
    add-int/2addr v0, v3

    .line 39
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/e;->a:Lcom/salesforce/marketingcloud/registration/f;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/e;->b:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    .line 4
    .line 5
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/analytics/e;->c:Z

    .line 6
    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/e;->d:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 8
    .line 9
    new-instance v3, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v4, "EventMetaData(registrationMeta="

    .line 12
    .line 13
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, ", pushMessageManager="

    .line 20
    .line 21
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, ", locationEnabled="

    .line 28
    .line 29
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", identity="

    .line 36
    .line 37
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p0, ")"

    .line 44
    .line 45
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
