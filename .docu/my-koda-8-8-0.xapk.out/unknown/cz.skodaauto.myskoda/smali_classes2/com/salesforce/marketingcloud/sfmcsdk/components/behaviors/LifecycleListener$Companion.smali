.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0000\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\u0008\u0002\u00a2\u0006\u0002\u0010\u0002J\u000e\u0010\u000b\u001a\u00020\u00062\u0006\u0010\u000c\u001a\u00020\rR\u000e\u0010\u0003\u001a\u00020\u0004X\u0082T\u00a2\u0006\u0002\n\u0000R \u0010\u0005\u001a\u0004\u0018\u00010\u00068\u0000@\u0000X\u0081\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0007\u0010\u0008\"\u0004\u0008\t\u0010\n\u00a8\u0006\u000e"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener$Companion;",
        "",
        "()V",
        "TAG",
        "",
        "instance",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;",
        "getInstance$sfmcsdk_release",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;",
        "setInstance$sfmcsdk_release",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;)V",
        "getInstance",
        "context",
        "Landroid/content/Context;",
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
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final getInstance(Landroid/content/Context;)Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;
    .locals 2

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener$Companion;->getInstance$sfmcsdk_release()Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-direct {v0, p1, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;-><init>(Landroid/content/Context;Lkotlin/jvm/internal/g;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener$Companion;->setInstance$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener$Companion;->getInstance$sfmcsdk_release()Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const-string p1, "null cannot be cast to non-null type com.salesforce.marketingcloud.sfmcsdk.components.behaviors.LifecycleListener"

    .line 26
    .line 27
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    return-object p0
.end method

.method public final getInstance$sfmcsdk_release()Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;
    .locals 0

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;->access$getInstance$cp()Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final setInstance$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;->access$setInstance$cp(Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/LifecycleListener;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method
