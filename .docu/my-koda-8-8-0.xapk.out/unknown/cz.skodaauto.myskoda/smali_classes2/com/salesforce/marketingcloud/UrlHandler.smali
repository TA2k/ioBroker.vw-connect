.class public interface abstract Lcom/salesforce/marketingcloud/UrlHandler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/UrlHandler$a;
    }
.end annotation


# static fields
.field public static final ACTION:Ljava/lang/String; = "action"

.field public static final APP_OPEN:Ljava/lang/String; = "app_open"

.field public static final CLOUD_PAGE:Ljava/lang/String; = "cloud_page"

.field public static final DEEPLINK:Ljava/lang/String; = "deeplink"

.field public static final URL:Ljava/lang/String; = "url"


# virtual methods
.method public abstract handleUrl(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Landroid/app/PendingIntent;
.end method
