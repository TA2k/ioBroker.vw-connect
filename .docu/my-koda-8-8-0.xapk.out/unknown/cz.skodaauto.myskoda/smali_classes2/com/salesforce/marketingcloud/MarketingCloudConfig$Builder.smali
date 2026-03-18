.class public final Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/MarketingCloudConfig;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Builder"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder$a;
    }
.end annotation


# static fields
.field private static final ACCESS_TOKEN_LENGTH:I = 0x18

.field private static final APP_ID_REGEX:Lly0/n;

.field public static final Companion:Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder$a;

.field private static final INITIAL_PI_VALUE:Ljava/lang/String; = ""

.field private static final TSE_ERROR_MSG:Ljava/lang/String; = "An App Endpoint (the Marketing Cloud Server URL) is required in order to configure the SDK. See http://salesforce-marketingcloud.github.io/MarketingCloudSDK-Android for more information."


# instance fields
.field private accessToken:Ljava/lang/String;

.field private analyticsEnabled:Z

.field private applicationId:Ljava/lang/String;

.field private delayRegistrationUntilContactKeyIsSet:Z

.field private geofencingEnabled:Z

.field private inboxEnabled:Z

.field private legacyEncryptionDependencyForciblyRemoved:Z

.field private markMessageReadOnInboxNotificationOpen:Z

.field private marketingCloudServerUrl:Ljava/lang/String;

.field private mid:Ljava/lang/String;

.field private notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

.field private piAnalyticsEnabled:Z

.field private predictiveIntelligenceServerUrl:Ljava/lang/String;

.field private proximityEnabled:Z

.field private proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

.field private senderId:Ljava/lang/String;

.field private urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

.field private useLegacyPiIdentifier:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->Companion:Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder$a;

    .line 8
    .line 9
    new-instance v0, Lly0/n;

    .line 10
    .line 11
    const-string v1, "[0-9a-f]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89aAbB][a-f0-9]{3}-[a-f0-9]{12}"

    .line 12
    .line 13
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->APP_ID_REGEX:Lly0/n;

    .line 17
    .line 18
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->markMessageReadOnInboxNotificationOpen:Z

    .line 3
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->useLegacyPiIdentifier:Z

    .line 4
    const-string v0, ""

    iput-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)V
    .locals 1

    const-string v0, "config"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iget-object v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId:Ljava/lang/String;

    iput-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->applicationId:Ljava/lang/String;

    .line 7
    iget-object v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken:Ljava/lang/String;

    iput-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->accessToken:Ljava/lang/String;

    .line 8
    iget-object v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->senderId:Ljava/lang/String;

    iput-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->senderId:Ljava/lang/String;

    .line 9
    iget-object v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->marketingCloudServerUrl:Ljava/lang/String;

    iput-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->marketingCloudServerUrl:Ljava/lang/String;

    .line 10
    iget-object v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->mid:Ljava/lang/String;

    iput-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->mid:Ljava/lang/String;

    .line 11
    iget-boolean v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled:Z

    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->analyticsEnabled:Z

    .line 12
    iget-boolean v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->geofencingEnabled:Z

    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->geofencingEnabled:Z

    .line 13
    iget-boolean v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->inboxEnabled:Z

    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->inboxEnabled:Z

    .line 14
    iget-boolean v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->piAnalyticsEnabled:Z

    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->piAnalyticsEnabled:Z

    .line 15
    iget-boolean v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled:Z

    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->proximityEnabled:Z

    .line 16
    iget-boolean v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->markMessageReadOnInboxNotificationOpen:Z

    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->markMessageReadOnInboxNotificationOpen:Z

    .line 17
    iget-boolean v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet:Z

    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->delayRegistrationUntilContactKeyIsSet:Z

    .line 18
    iget-boolean v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->useLegacyPiIdentifier:Z

    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->useLegacyPiIdentifier:Z

    .line 19
    iget-object v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    iput-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    .line 20
    iget-object v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    iput-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    .line 21
    iget-object v0, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    iput-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 22
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->getPredictiveIntelligenceServerUrl$sdk_release()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 23
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->getLegacyEncryptionDependencyForciblyRemoved$sdk_release()Z

    move-result p1

    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->legacyEncryptionDependencyForciblyRemoved:Z

    return-void
.end method

.method private final checkNotEmpty(Ljava/lang/String;Lay0/a;)Ljava/lang/String;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lay0/a;",
            ")",
            "Ljava/lang/String;"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-static {p1}, Landroid/text/TextUtils;->getTrimmedLength(Ljava/lang/CharSequence;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-interface {p2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p1

    .line 24
    :cond_1
    :goto_0
    return-object p1
.end method

.method private final checkNotNullOrEmpty(Ljava/lang/String;Lay0/a;)Ljava/lang/String;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lay0/a;",
            ")",
            "Ljava/lang/String;"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-static {p1}, Landroid/text/TextUtils;->getTrimmedLength(Ljava/lang/CharSequence;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    return-object p1

    .line 10
    :cond_0
    invoke-interface {p2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p1
.end method


# virtual methods
.method public final build(Landroid/content/Context;)Lcom/salesforce/marketingcloud/MarketingCloudConfig;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "null"

    .line 4
    .line 5
    const-string v2, "context"

    .line 6
    .line 7
    move-object/from16 v3, p1

    .line 8
    .line 9
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v3}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    const/4 v4, 0x0

    .line 17
    :try_start_0
    invoke-virtual {v3}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    invoke-virtual {v3, v2, v4}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    iget-object v3, v3, Landroid/content/pm/PackageInfo;->versionName:Ljava/lang/String;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    .line 27
    if-nez v3, :cond_0

    .line 28
    .line 29
    :catch_0
    move-object/from16 v21, v1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    move-object/from16 v21, v3

    .line 33
    .line 34
    :goto_0
    iget-object v1, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->applicationId:Ljava/lang/String;

    .line 35
    .line 36
    if-eqz v1, :cond_f

    .line 37
    .line 38
    sget-object v3, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 39
    .line 40
    const-string v5, "ENGLISH"

    .line 41
    .line 42
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1, v3}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v5

    .line 49
    const-string v6, "toLowerCase(...)"

    .line 50
    .line 51
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    sget-object v7, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->APP_ID_REGEX:Lly0/n;

    .line 55
    .line 56
    invoke-virtual {v7, v5}, Lly0/n;->d(Ljava/lang/CharSequence;)Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-eqz v5, :cond_e

    .line 61
    .line 62
    iget-object v5, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->accessToken:Ljava/lang/String;

    .line 63
    .line 64
    if-eqz v5, :cond_d

    .line 65
    .line 66
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 67
    .line 68
    .line 69
    move-result v7

    .line 70
    const/16 v8, 0x18

    .line 71
    .line 72
    if-ne v7, v8, :cond_c

    .line 73
    .line 74
    iget-object v7, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->marketingCloudServerUrl:Ljava/lang/String;

    .line 75
    .line 76
    const-string v8, "An App Endpoint (the Marketing Cloud Server URL) is required in order to configure the SDK. See http://salesforce-marketingcloud.github.io/MarketingCloudSDK-Android for more information."

    .line 77
    .line 78
    if-eqz v7, :cond_b

    .line 79
    .line 80
    invoke-static {v7}, Landroid/text/TextUtils;->getTrimmedLength(Ljava/lang/CharSequence;)I

    .line 81
    .line 82
    .line 83
    move-result v9

    .line 84
    if-eqz v9, :cond_b

    .line 85
    .line 86
    invoke-static {v7}, Landroid/webkit/URLUtil;->isNetworkUrl(Ljava/lang/String;)Z

    .line 87
    .line 88
    .line 89
    move-result v9

    .line 90
    if-eqz v9, :cond_a

    .line 91
    .line 92
    iget-object v8, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 93
    .line 94
    const-string v9, ""

    .line 95
    .line 96
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v8

    .line 100
    if-eqz v8, :cond_4

    .line 101
    .line 102
    iget-object v8, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->mid:Ljava/lang/String;

    .line 103
    .line 104
    if-eqz v8, :cond_2

    .line 105
    .line 106
    invoke-virtual {v8, v3}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    const-string v6, "-"

    .line 114
    .line 115
    const/4 v9, 0x6

    .line 116
    invoke-static {v3, v6, v4, v4, v9}, Lly0/p;->K(Ljava/lang/CharSequence;Ljava/lang/String;IZI)I

    .line 117
    .line 118
    .line 119
    move-result v3

    .line 120
    const/4 v6, -0x1

    .line 121
    if-eq v3, v6, :cond_1

    .line 122
    .line 123
    invoke-virtual {v8, v4, v3}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 124
    .line 125
    .line 126
    move-result-object v3

    .line 127
    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v3

    .line 131
    goto :goto_1

    .line 132
    :cond_1
    move-object v3, v8

    .line 133
    :goto_1
    iput-object v3, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->mid:Ljava/lang/String;

    .line 134
    .line 135
    const-string v4, ".collect.igodigital.com/c2/"

    .line 136
    .line 137
    const-string v6, "/process_batch.json"

    .line 138
    .line 139
    const-string v9, "https://"

    .line 140
    .line 141
    invoke-static {v9, v8, v4, v3, v6}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    if-nez v3, :cond_3

    .line 146
    .line 147
    :cond_2
    const-string v3, "https://app.igodigital.com/api/v1/collect/process_batch"

    .line 148
    .line 149
    :cond_3
    iput-object v3, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 150
    .line 151
    :cond_4
    iget-object v6, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->senderId:Ljava/lang/String;

    .line 152
    .line 153
    if-eqz v6, :cond_6

    .line 154
    .line 155
    invoke-static {v6}, Landroid/text/TextUtils;->getTrimmedLength(Ljava/lang/CharSequence;)I

    .line 156
    .line 157
    .line 158
    move-result v3

    .line 159
    if-eqz v3, :cond_5

    .line 160
    .line 161
    goto :goto_2

    .line 162
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 163
    .line 164
    const-string v1, "The senderId cannot be empty."

    .line 165
    .line 166
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    throw v0

    .line 170
    :cond_6
    :goto_2
    iget-object v8, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->mid:Ljava/lang/String;

    .line 171
    .line 172
    if-eqz v8, :cond_8

    .line 173
    .line 174
    invoke-static {v8}, Landroid/text/TextUtils;->getTrimmedLength(Ljava/lang/CharSequence;)I

    .line 175
    .line 176
    .line 177
    move-result v3

    .line 178
    if-eqz v3, :cond_7

    .line 179
    .line 180
    goto :goto_3

    .line 181
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 182
    .line 183
    const-string v1, "MID must not be empty."

    .line 184
    .line 185
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    throw v0

    .line 189
    :cond_8
    :goto_3
    iget-boolean v9, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->analyticsEnabled:Z

    .line 190
    .line 191
    iget-boolean v10, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->geofencingEnabled:Z

    .line 192
    .line 193
    iget-boolean v11, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->inboxEnabled:Z

    .line 194
    .line 195
    iget-boolean v12, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->piAnalyticsEnabled:Z

    .line 196
    .line 197
    iget-boolean v13, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->proximityEnabled:Z

    .line 198
    .line 199
    iget-boolean v14, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->markMessageReadOnInboxNotificationOpen:Z

    .line 200
    .line 201
    iget-boolean v15, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->delayRegistrationUntilContactKeyIsSet:Z

    .line 202
    .line 203
    iget-boolean v3, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->useLegacyPiIdentifier:Z

    .line 204
    .line 205
    iget-object v4, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    .line 206
    .line 207
    if-eqz v4, :cond_9

    .line 208
    .line 209
    move-object/from16 v16, v1

    .line 210
    .line 211
    iget-object v1, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 212
    .line 213
    move-object/from16 v19, v1

    .line 214
    .line 215
    iget-object v1, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 216
    .line 217
    move-object/from16 v22, v1

    .line 218
    .line 219
    iget-object v1, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    .line 220
    .line 221
    iget-boolean v0, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->legacyEncryptionDependencyForciblyRemoved:Z

    .line 222
    .line 223
    move-object/from16 v17, v4

    .line 224
    .line 225
    move-object/from16 v4, v16

    .line 226
    .line 227
    move/from16 v16, v3

    .line 228
    .line 229
    new-instance v3, Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 230
    .line 231
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    move/from16 v23, v0

    .line 235
    .line 236
    move-object/from16 v18, v1

    .line 237
    .line 238
    move-object/from16 v20, v2

    .line 239
    .line 240
    invoke-direct/range {v3 .. v23}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZZZZLcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;Lcom/salesforce/marketingcloud/UrlHandler;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 241
    .line 242
    .line 243
    return-object v3

    .line 244
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 245
    .line 246
    const-string v1, "notificationCustomizationOptions == null"

    .line 247
    .line 248
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    throw v0

    .line 252
    :cond_a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 253
    .line 254
    invoke-direct {v0, v8}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 255
    .line 256
    .line 257
    throw v0

    .line 258
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 259
    .line 260
    invoke-direct {v0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 261
    .line 262
    .line 263
    throw v0

    .line 264
    :cond_c
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 265
    .line 266
    const-string v1, "The accessToken must be 24 characters."

    .line 267
    .line 268
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 269
    .line 270
    .line 271
    throw v0

    .line 272
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 273
    .line 274
    const-string v1, "accessToken == null"

    .line 275
    .line 276
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 277
    .line 278
    .line 279
    throw v0

    .line 280
    :cond_e
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 281
    .line 282
    const-string v1, "The applicationId is not a valid UUID."

    .line 283
    .line 284
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    throw v0

    .line 288
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 289
    .line 290
    const-string v1, "applicationId == null"

    .line 291
    .line 292
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    throw v0
.end method

.method public final setAccessToken(Ljava/lang/String;)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 1

    .line 1
    const-string v0, "accessToken"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->accessToken:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setAnalyticsEnabled(Z)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->analyticsEnabled:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public final setApplicationId(Ljava/lang/String;)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 1

    .line 1
    const-string v0, "applicationId"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->applicationId:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setDelayRegistrationUntilContactKeyIsSet(Z)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->delayRegistrationUntilContactKeyIsSet:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public final setGeofencingEnabled(Z)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->geofencingEnabled:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public final setInboxEnabled(Z)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->inboxEnabled:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public final setLegacyEncryptionDependencyForciblyRemoved(Z)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->legacyEncryptionDependencyForciblyRemoved:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public final setMarkMessageReadOnInboxNotificationOpen(Z)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->markMessageReadOnInboxNotificationOpen:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public final setMarketingCloudServerUrl(Ljava/lang/String;)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 1

    .line 1
    const-string v0, "marketingCloudServerUrl"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->marketingCloudServerUrl:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setMid(Ljava/lang/String;)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 1

    .line 1
    const-string v0, "mid"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->mid:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setNotificationCustomizationOptions(Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 1

    .line 1
    const-string v0, "options"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setPiAnalyticsEnabled(Z)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->piAnalyticsEnabled:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public final setPredictiveIntelligenceServerUrl(Ljava/lang/String;)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 1

    .line 1
    const-string v0, "url"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setProximityEnabled(Z)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->proximityEnabled:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public final setProximityNotificationOptions(Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 1

    .line 1
    const-string v0, "options"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setSenderId(Ljava/lang/String;)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 1

    .line 1
    const-string v0, "senderId"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->senderId:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setUrlHandler(Lcom/salesforce/marketingcloud/UrlHandler;)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 1

    .line 1
    const-string v0, "urlHandler"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 7
    .line 8
    return-object p0
.end method

.method public final setUseLegacyPiIdentifier(Z)Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;->useLegacyPiIdentifier:Z

    .line 2
    .line 3
    return-object p0
.end method
