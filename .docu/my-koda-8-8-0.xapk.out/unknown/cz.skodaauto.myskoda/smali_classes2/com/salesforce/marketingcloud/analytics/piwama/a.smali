.class Lcom/salesforce/marketingcloud/analytics/piwama/a;
.super Lcom/salesforce/marketingcloud/analytics/piwama/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final w:[Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/analytics/piwama/a;->w:[Ljava/lang/Object;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/piwama/j;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public a(Lorg/json/JSONObject;)Lorg/json/JSONObject;
    .locals 4

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    const-string v1, "YXBpX2tleQ=="

    .line 7
    .line 8
    invoke-static {v1}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->base64Decode(Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const-string v2, "849f26e2-2df6-11e4-ab12-14109fdc48df"

    .line 13
    .line 14
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 15
    .line 16
    .line 17
    const-string v1, "app_id"

    .line 18
    .line 19
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->b:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 20
    .line 21
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a:Lcom/salesforce/marketingcloud/storage/h;

    .line 29
    .line 30
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    const-string v2, "et_user_id_cache"

    .line 35
    .line 36
    const/4 v3, 0x0

    .line 37
    invoke-interface {v1, v2, v3}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    if-nez v2, :cond_0

    .line 46
    .line 47
    const-string v2, "user_id"

    .line 48
    .line 49
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 50
    .line 51
    .line 52
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a:Lcom/salesforce/marketingcloud/storage/h;

    .line 53
    .line 54
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    const-string v2, "et_session_id_cache"

    .line 59
    .line 60
    invoke-interface {v1, v2, v3}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-nez v2, :cond_1

    .line 69
    .line 70
    const-string v2, "session_id"

    .line 71
    .line 72
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 73
    .line 74
    .line 75
    :cond_1
    new-instance v1, Lorg/json/JSONObject;

    .line 76
    .line 77
    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 78
    .line 79
    .line 80
    const-string v2, "app_name"

    .line 81
    .line 82
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/j;->b:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 83
    .line 84
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appPackageName()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-virtual {v1, v2, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 89
    .line 90
    .line 91
    const-string p0, "user_info"

    .line 92
    .line 93
    invoke-virtual {v1, p0, p1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 94
    .line 95
    .line 96
    const-string p0, "payload"

    .line 97
    .line 98
    invoke-virtual {v0, p0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 99
    .line 100
    .line 101
    return-object v0

    .line 102
    :catch_0
    move-exception p0

    .line 103
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    .line 104
    .line 105
    const/4 v0, 0x0

    .line 106
    new-array v0, v0, [Ljava/lang/Object;

    .line 107
    .line 108
    const-string v1, "Failed to construct PiWama payload JSON Object."

    .line 109
    .line 110
    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    new-instance p0, Lorg/json/JSONObject;

    .line 114
    .line 115
    invoke-direct {p0}, Lorg/json/JSONObject;-><init>()V

    .line 116
    .line 117
    .line 118
    return-object p0
.end method

.method public b()[Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/piwama/a;->w:[Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method
