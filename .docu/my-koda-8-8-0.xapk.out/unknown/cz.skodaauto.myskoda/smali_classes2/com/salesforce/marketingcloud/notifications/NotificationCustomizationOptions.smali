.class public Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation


# static fields
.field static final TAG:Ljava/lang/String;


# instance fields
.field final channelIdProvider:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;

.field final launchIntentProvider:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;

.field final notificationBuilder:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;

.field final smallIconResId:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "NotificationCustomizationOptions"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->TAG:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->smallIconResId:I

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->launchIntentProvider:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->channelIdProvider:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;

    .line 9
    .line 10
    iput-object p4, p0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->notificationBuilder:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;

    .line 11
    .line 12
    return-void
.end method

.method private static classNameOrNull(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    const-string p0, "null"

    .line 13
    .line 14
    return-object p0
.end method

.method public static create(I)Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;
    .locals 2

    .line 3
    new-instance v0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1, v1, v1}, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;-><init>(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;)V

    return-object v0
.end method

.method public static create(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;)Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;
    .locals 3

    if-eqz p1, :cond_0

    .line 4
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1f

    if-lt v0, v1, :cond_0

    .line 5
    sget-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->TAG:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "Make sure FLAG_IMMUTABLE or FLAG_MUTABLE for Pending Intent is set because of Targeting S+ (version 31 and above) "

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 6
    :cond_0
    new-instance v0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, p2, v1}, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;-><init>(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;)V

    return-object v0
.end method

.method public static create(Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;)Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;
    .locals 3

    if-eqz p0, :cond_0

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2, v2, p0}, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;-><init>(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;)V

    return-object v0

    .line 2
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string v0, "The provided NotificationManager.NotificationBuilder cannot be null."

    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method


# virtual methods
.method public getNotificationBuilder()Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->notificationBuilder:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->notificationBuilder:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationBuilder;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lcom/salesforce/marketingcloud/util/j;->a:Ljava/util/Locale;

    .line 6
    .line 7
    invoke-static {v0}, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->classNameOrNull(Ljava/lang/Object;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string v0, "{notificationBuilder="

    .line 12
    .line 13
    const-string v1, "}"

    .line 14
    .line 15
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/util/j;->a:Ljava/util/Locale;

    .line 21
    .line 22
    iget v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->smallIconResId:I

    .line 23
    .line 24
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->launchIntentProvider:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;

    .line 29
    .line 30
    invoke-static {v2}, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->classNameOrNull(Ljava/lang/Object;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->channelIdProvider:Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;

    .line 35
    .line 36
    invoke-static {p0}, Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;->classNameOrNull(Ljava/lang/Object;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    filled-new-array {v1, v2, p0}, [Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    const-string v1, "{smallIconResId=%d, launchIntentProvider=%s, channelIdProvider=%s}"

    .line 45
    .line 46
    invoke-static {v0, v1, p0}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0
.end method
