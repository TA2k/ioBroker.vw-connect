.class public final Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutorsKt$namedRunnable$1;
.super Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/NamedRunnable;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutorsKt;->namedRunnable(Ljava/util/concurrent/ExecutorService;Ljava/lang/String;Lay0/a;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0011\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003*\u0001\u0000\u0008\n\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H\u0014\u00a2\u0006\u0004\u0008\u0003\u0010\u0004\u00a8\u0006\u0005"
    }
    d2 = {
        "com/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutorsKt$namedRunnable$1",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/NamedRunnable;",
        "Llx0/b0;",
        "execute",
        "()V",
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
.field final synthetic $block:Lay0/a;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/a;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/String;Lay0/a;[Ljava/lang/Object;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lay0/a;",
            "[",
            "Ljava/lang/Object;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutorsKt$namedRunnable$1;->$block:Lay0/a;

    .line 2
    .line 3
    invoke-direct {p0, p1, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/NamedRunnable;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public execute()V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutorsKt$namedRunnable$1;->$block:Lay0/a;

    .line 2
    .line 3
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-void
.end method
