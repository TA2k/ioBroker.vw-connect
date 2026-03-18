.class public abstract Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$PushTokenRefreshListener;,
        Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$SilentPushListener;
    }
.end annotation


# static fields
.field public static final d:Ljava/lang/String; = "com.salesforce.marketingcloud.messages.push.TOKEN_REFRESHED"

.field public static final e:Ljava/lang/String; = "com.salesforce.marketingcloud.push.TOKEN_REFRESH_SUCCESSFUL"

.field public static final f:Ljava/lang/String; = "com.salesforce.marketingcloud.push.TOKEN_SENDER_ID"

.field public static final g:Ljava/lang/String; = "com.salesforce.marketingcloud.notifications.PUSH_ENABLED"

.field public static final h:Ljava/lang/String; = "com.salesforce.marketingcloud.push.TOKEN"

.field static final i:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "PushMessageManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->i:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static isMarketingCloudPush(Lcom/google/firebase/messaging/v;)Z
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    if-eqz p0, :cond_0

    .line 2
    invoke-virtual {p0}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    move-result-object p0

    invoke-static {p0}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->isMarketingCloudPush(Ljava/util/Map;)Z

    move-result p0

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static isMarketingCloudPush(Ljava/util/Map;)Z
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)Z"
        }
    .end annotation

    if-eqz p0, :cond_0

    .line 1
    const-string v0, "_sid"

    invoke-interface {p0, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/String;

    const-string v0, "SFMC"

    invoke-virtual {v0, p0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result p0

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method


# virtual methods
.method public abstract disablePush()V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract enablePush()V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract getPushDebugInfo()Lorg/json/JSONObject;
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract getPushToken()Ljava/lang/String;
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract handleMessage(Lcom/google/firebase/messaging/v;)Z
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract handleMessage(Ljava/util/Map;)Z
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)Z"
        }
    .end annotation
.end method

.method public abstract isPushEnabled()Z
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract registerSilentPushListener(Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$SilentPushListener;)V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract registerTokenRefreshListener(Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$PushTokenRefreshListener;)V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract setPushToken(Ljava/lang/String;)V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract unregisterSilentPushListener(Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$SilentPushListener;)V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method

.method public abstract unregisterTokenRefreshListener(Lcom/salesforce/marketingcloud/messages/push/PushMessageManager$PushTokenRefreshListener;)V
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation
.end method
