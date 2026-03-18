.class public interface abstract Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;
    }
.end annotation


# virtual methods
.method public abstract setInAppMessageListener(Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;)V
.end method

.method public abstract setStatusBarColor(I)V
.end method

.method public abstract setTypeface(Landroid/graphics/Typeface;)V
.end method

.method public abstract showMessage(Ljava/lang/String;)V
.end method
