.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "BehaviorRunnable"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0018\u00002\u00020\u0001B%\u0012\u000c\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u0002\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u0012\u0006\u0010\u0008\u001a\u00020\u0007\u00a2\u0006\u0004\u0008\t\u0010\nJ\u000f\u0010\u000c\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008\u000c\u0010\rR\u001a\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u00028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0004\u0010\u000eR\u0014\u0010\u0006\u001a\u00020\u00058\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0006\u0010\u000fR\u0016\u0010\u0011\u001a\u0004\u0018\u00010\u00108\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0011\u0010\u0012\u00a8\u0006\u0013"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable;",
        "Ljava/lang/Runnable;",
        "",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;",
        "listeners",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;",
        "behaviorType",
        "Landroid/os/Bundle;",
        "data",
        "<init>",
        "(Ljava/util/Set;Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;Landroid/os/Bundle;)V",
        "Llx0/b0;",
        "run",
        "()V",
        "Ljava/util/Set;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;",
        "behavior",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;",
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


# instance fields
.field private final behavior:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;

.field private final behaviorType:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

.field private final listeners:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/util/Set;Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;Landroid/os/Bundle;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "+",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;",
            ">;",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;",
            "Landroid/os/Bundle;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "listeners"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "behaviorType"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "data"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable;->listeners:Ljava/util/Set;

    .line 20
    .line 21
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable;->behaviorType:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 22
    .line 23
    invoke-virtual {p2, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->toBehavior$sfmcsdk_release(Landroid/os/Bundle;)Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable;->behavior:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;

    .line 28
    .line 29
    return-void
.end method

.method public static final synthetic access$getBehaviorType$p(Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable;)Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable;->behaviorType:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 2
    .line 3
    return-object p0
.end method


# virtual methods
.method public run()V
    .locals 6

    .line 1
    const-string v0, "~$BehaviorManager"

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable;->behavior:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;

    .line 4
    .line 5
    if-eqz v1, :cond_1

    .line 6
    .line 7
    sget-object v2, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

    .line 8
    .line 9
    invoke-static {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorTypeKt;->toEvent(Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;)Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    filled-new-array {v3}, [Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    invoke-virtual {v2, v3}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->track([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    .line 18
    .line 19
    .line 20
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable;->listeners:Ljava/util/Set;

    .line 21
    .line 22
    check-cast v2, Ljava/lang/Iterable;

    .line 23
    .line 24
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    :cond_0
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    if-eqz v3, :cond_1

    .line 33
    .line 34
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    check-cast v3, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;

    .line 39
    .line 40
    if-eqz v3, :cond_0

    .line 41
    .line 42
    :try_start_0
    sget-object v4, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 43
    .line 44
    new-instance v5, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable$run$1$1$1$1;

    .line 45
    .line 46
    invoke-direct {v5, p0, v3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable$run$1$1$1$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable;Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v4, v0, v5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->d(Ljava/lang/String;Lay0/a;)V

    .line 50
    .line 51
    .line 52
    invoke-interface {v3, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;->onBehavior(Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :catch_0
    move-exception v3

    .line 57
    sget-object v4, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 58
    .line 59
    new-instance v5, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable$run$1$1$1$2;

    .line 60
    .line 61
    invoke-direct {v5, v3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl$Companion$BehaviorRunnable$run$1$1$1$2;-><init>(Ljava/lang/Exception;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v4, v0, v3, v5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_1
    return-void
.end method
