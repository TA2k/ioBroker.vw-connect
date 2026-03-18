.class public interface abstract Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/messages/RegionMessageManager;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x609
    name = "RegionTransitionEventListener"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener$a;
    }
.end annotation


# static fields
.field public static final TRANSITION_ENTERED:I = 0x1

.field public static final TRANSITION_EXITED:I = 0x2


# virtual methods
.method public abstract onTransitionEvent(ILcom/salesforce/marketingcloud/messages/Region;)V
.end method
