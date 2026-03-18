.class public interface abstract Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008f\u0018\u00002\u00020\u0001J%\u0010\u0008\u001a\u00020\u00072\u000c\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u00022\u0006\u0010\u0006\u001a\u00020\u0005H&\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u0017\u0010\n\u001a\u00020\u00072\u0006\u0010\u0006\u001a\u00020\u0005H&\u00a2\u0006\u0004\u0008\n\u0010\u000b\u00a8\u0006\u000c"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManager;",
        "",
        "Ljava/util/EnumSet;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;",
        "behaviorTypes",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;",
        "listener",
        "Llx0/b0;",
        "registerForBehaviors",
        "(Ljava/util/EnumSet;Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;)V",
        "unregisterForAllBehaviors",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;)V",
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


# virtual methods
.method public abstract registerForBehaviors(Ljava/util/EnumSet;Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/EnumSet<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;",
            ">;",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;",
            ")V"
        }
    .end annotation
.end method

.method public abstract unregisterForAllBehaviors(Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;)V
.end method
