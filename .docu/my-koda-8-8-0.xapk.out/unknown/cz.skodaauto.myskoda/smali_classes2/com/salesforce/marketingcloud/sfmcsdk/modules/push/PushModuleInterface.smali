.class public abstract Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleInterface;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008&\u0018\u00002\u00020\u0001B\u0005\u00a2\u0006\u0002\u0010\u0002R\u0012\u0010\u0003\u001a\u00020\u0004X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0005\u0010\u0006R\u0012\u0010\u0007\u001a\u00020\u0008X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\t\u0010\nR\u0012\u0010\u000b\u001a\u00020\u000cX\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\r\u0010\u000eR\u0012\u0010\u000f\u001a\u00020\u0010X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0011\u0010\u0012R\u0012\u0010\u0013\u001a\u00020\u0014X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0015\u0010\u0016R\u0012\u0010\u0017\u001a\u00020\u0018X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0019\u0010\u001aR\u0012\u0010\u001b\u001a\u00020\u001cX\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001d\u0010\u001eR\u0012\u0010\u001f\u001a\u00020 X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008!\u0010\"R\u0012\u0010#\u001a\u00020$X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008%\u0010&\u00a8\u0006\'"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleInterface;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;",
        "()V",
        "analyticsManager",
        "Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;",
        "getAnalyticsManager",
        "()Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;",
        "eventManager",
        "Lcom/salesforce/marketingcloud/events/EventManager;",
        "getEventManager",
        "()Lcom/salesforce/marketingcloud/events/EventManager;",
        "inAppMessageManager",
        "Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager;",
        "getInAppMessageManager",
        "()Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager;",
        "inboxMessageManager",
        "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;",
        "getInboxMessageManager",
        "()Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;",
        "initializationStatus",
        "Lcom/salesforce/marketingcloud/InitializationStatus;",
        "getInitializationStatus",
        "()Lcom/salesforce/marketingcloud/InitializationStatus;",
        "notificationManager",
        "Lcom/salesforce/marketingcloud/notifications/NotificationManager;",
        "getNotificationManager",
        "()Lcom/salesforce/marketingcloud/notifications/NotificationManager;",
        "pushMessageManager",
        "Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;",
        "getPushMessageManager",
        "()Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;",
        "regionMessageManager",
        "Lcom/salesforce/marketingcloud/messages/RegionMessageManager;",
        "getRegionMessageManager",
        "()Lcom/salesforce/marketingcloud/messages/RegionMessageManager;",
        "registrationManager",
        "Lcom/salesforce/marketingcloud/registration/RegistrationManager;",
        "getRegistrationManager",
        "()Lcom/salesforce/marketingcloud/registration/RegistrationManager;",
        "sfmcsdk_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public abstract getAnalyticsManager()Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;
.end method

.method public abstract getEventManager()Lcom/salesforce/marketingcloud/events/EventManager;
.end method

.method public abstract getInAppMessageManager()Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager;
.end method

.method public abstract getInboxMessageManager()Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;
.end method

.method public abstract getInitializationStatus()Lcom/salesforce/marketingcloud/InitializationStatus;
.end method

.method public abstract getNotificationManager()Lcom/salesforce/marketingcloud/notifications/NotificationManager;
.end method

.method public abstract getPushMessageManager()Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;
.end method

.method public abstract getRegionMessageManager()Lcom/salesforce/marketingcloud/messages/RegionMessageManager;
.end method

.method public abstract getRegistrationManager()Lcom/salesforce/marketingcloud/registration/RegistrationManager;
.end method
