.class public Lcom/salesforce/marketingcloud/messages/push/MCFirebaseMessagingService;
.super Lcom/google/firebase/messaging/FirebaseMessagingService;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field private static final a:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "MCFirebaseMessagingService"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/messages/push/MCFirebaseMessagingService;->a:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/google/firebase/messaging/FirebaseMessagingService;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static a()Lcom/salesforce/marketingcloud/MarketingCloudSdk;
    .locals 4

    const-wide/16 v0, 0xbb8

    const-wide/16 v2, 0x32

    .line 14
    invoke-static {v0, v1, v2, v3}, Lcom/salesforce/marketingcloud/util/j;->a(JJ)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getInstance()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    move-result-object v0

    if-eqz v0, :cond_0

    .line 15
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getInstance()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    move-result-object v0

    return-object v0

    .line 16
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/messages/push/MCFirebaseMessagingService;->a:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "MarketingCloudSdk#init must be called in your application\'s onCreate"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 v0, 0x0

    return-object v0
.end method

.method public static a(Landroid/content/Context;)V
    .locals 2

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/messages/push/MCFirebaseMessagingService;->a()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    move-result-object v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/MCFirebaseMessagingService;->a:Ljava/lang/String;

    new-array v0, v1, [Ljava/lang/Object;

    const-string v1, "Marketing Cloud SDK init failed.  Unable to update push token."

    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 3
    :cond_0
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getMarketingCloudConfig()Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    move-result-object v0

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->senderId()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 4
    invoke-static {p0, v0}, Lcom/salesforce/marketingcloud/MCService;->b(Landroid/content/Context;Ljava/lang/String;)V

    return-void

    .line 5
    :cond_1
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/MCFirebaseMessagingService;->a:Ljava/lang/String;

    new-array v0, v1, [Ljava/lang/Object;

    const-string v1, "Received new token intent but senderId was not set."

    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static a(Lcom/google/firebase/messaging/v;)V
    .locals 4

    const/4 v0, 0x0

    if-nez p0, :cond_0

    .line 6
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/MCFirebaseMessagingService;->a:Ljava/lang/String;

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "RemoteMessage was null."

    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 7
    :cond_0
    invoke-virtual {p0}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    move-result-object v1

    if-eqz v1, :cond_1

    invoke-virtual {p0}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    move-result-object v1

    const-string v2, "_m"

    invoke-interface {v1, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    .line 8
    invoke-virtual {p0}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    move-result-object v1

    invoke-interface {v1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    goto :goto_0

    .line 9
    :cond_1
    const-string v1, "Unknown Message"

    .line 10
    :goto_0
    sget-object v2, Lcom/salesforce/marketingcloud/messages/push/MCFirebaseMessagingService;->a:Ljava/lang/String;

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v3, "onMessageReceived() for MessageID: \'%s\'"

    invoke-static {v2, v3, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    invoke-static {}, Lcom/salesforce/marketingcloud/messages/push/MCFirebaseMessagingService;->a()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    move-result-object v1

    if-nez v1, :cond_2

    .line 12
    new-array p0, v0, [Ljava/lang/Object;

    const-string v0, "Marketing Cloud SDK init failed.  Push message ignored."

    invoke-static {v2, v0, p0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 13
    :cond_2
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getPushMessageManager()Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    move-result-object v0

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->handleMessage(Lcom/google/firebase/messaging/v;)Z

    return-void
.end method


# virtual methods
.method public onMessageReceived(Lcom/google/firebase/messaging/v;)V
    .locals 2

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/messages/push/MCFirebaseMessagingService;->a:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    new-array v0, v0, [Ljava/lang/Object;

    .line 5
    .line 6
    const-string v1, "onMessageReceived()"

    .line 7
    .line 8
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Lcom/salesforce/marketingcloud/messages/push/MCFirebaseMessagingService;->a(Lcom/google/firebase/messaging/v;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public onNewToken(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/messages/push/MCFirebaseMessagingService;->a(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method
