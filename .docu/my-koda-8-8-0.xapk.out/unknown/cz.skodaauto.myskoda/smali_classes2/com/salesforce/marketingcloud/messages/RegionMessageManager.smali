.class public interface abstract Lcom/salesforce/marketingcloud/messages/RegionMessageManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/RegionMessageManager$ProximityMessageResponseListener;,
        Lcom/salesforce/marketingcloud/messages/RegionMessageManager$GeofenceMessageResponseListener;,
        Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener;
    }
.end annotation


# static fields
.field public static final BUNDLE_KEY_MESSAGING_ENABLED:Ljava/lang/String; = "com.salesforce.marketingcloud.messaging.ENABLED"


# virtual methods
.method public abstract disableGeofenceMessaging()V
.end method

.method public abstract disableProximityMessaging()V
.end method

.method public abstract enableGeofenceMessaging()Z
.end method

.method public abstract enableProximityMessaging()Z
.end method

.method public abstract isGeofenceMessagingEnabled()Z
.end method

.method public abstract isProximityMessagingEnabled()Z
.end method

.method public abstract registerGeofenceMessageResponseListener(Lcom/salesforce/marketingcloud/messages/RegionMessageManager$GeofenceMessageResponseListener;)V
.end method

.method public abstract registerProximityMessageResponseListener(Lcom/salesforce/marketingcloud/messages/RegionMessageManager$ProximityMessageResponseListener;)V
.end method

.method public abstract registerRegionTransitionEventListener(Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener;)V
.end method

.method public abstract unregisterGeofenceMessageResponseListener(Lcom/salesforce/marketingcloud/messages/RegionMessageManager$GeofenceMessageResponseListener;)V
.end method

.method public abstract unregisterProximityMessageResponseListener(Lcom/salesforce/marketingcloud/messages/RegionMessageManager$ProximityMessageResponseListener;)V
.end method

.method public abstract unregisterRegionTransitionEventListener(Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener;)V
.end method
