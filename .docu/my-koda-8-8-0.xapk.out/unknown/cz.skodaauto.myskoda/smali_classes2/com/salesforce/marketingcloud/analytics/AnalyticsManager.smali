.class public interface abstract Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation


# static fields
.field public static final TAG:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "AnalyticsManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public abstract areAnalyticsEnabled()Z
.end method

.method public abstract arePiAnalyticsEnabled()Z
.end method

.method public abstract disableAnalytics()V
.end method

.method public abstract disablePiAnalytics()V
.end method

.method public abstract enableAnalytics()V
.end method

.method public abstract enablePiAnalytics()V
.end method

.method public abstract getPiIdentifier()Ljava/lang/String;
.end method

.method public abstract setPiIdentifier(Ljava/lang/String;)V
.end method

.method public abstract trackCartContents(Lcom/salesforce/marketingcloud/analytics/PiCart;)V
.end method

.method public abstract trackCartConversion(Lcom/salesforce/marketingcloud/analytics/PiOrder;)V
.end method

.method public abstract trackInboxOpenEvent(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
.end method

.method public abstract trackPageView(Ljava/lang/String;)V
.end method

.method public abstract trackPageView(Ljava/lang/String;Ljava/lang/String;)V
.end method

.method public abstract trackPageView(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
.end method

.method public abstract trackPageView(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
.end method
