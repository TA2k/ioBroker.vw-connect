.class public final Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final create(I)Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;
    .locals 1

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;->access$getInstance$cp()Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    move-result-object p0

    if-nez p0, :cond_0

    .line 2
    new-instance p0, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0, v0}, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;-><init>(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;Lkotlin/jvm/internal/g;)V

    invoke-static {p0}, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;->access$setInstance$cp(Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;)V

    .line 3
    :cond_0
    invoke-static {}, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;->access$getInstance$cp()Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    move-result-object p0

    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    return-object p0
.end method

.method public final create(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;)Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;
    .locals 1

    const-string p0, "channelIdProvider"

    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-static {}, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;->access$getInstance$cp()Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    move-result-object p0

    if-nez p0, :cond_0

    .line 5
    new-instance p0, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    const/4 v0, 0x0

    invoke-direct {p0, p1, p2, v0}, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;-><init>(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;Lkotlin/jvm/internal/g;)V

    invoke-static {p0}, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;->access$setInstance$cp(Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;)V

    .line 6
    :cond_0
    invoke-static {}, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;->access$getInstance$cp()Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    move-result-object p0

    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    return-object p0
.end method
