.class public interface abstract Lcom/salesforce/marketingcloud/sfmcsdk/InitializationStatus;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/InitializationStatus$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0004\u0008f\u0018\u0000 \u00062\u00020\u0001:\u0001\u0006R\u0012\u0010\u0002\u001a\u00020\u0003X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0004\u0010\u0005\u00a8\u0006\u0007"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/InitializationStatus;",
        "",
        "status",
        "",
        "getStatus",
        "()I",
        "Companion",
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


# static fields
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationStatus$Companion;

.field public static final FAILURE:I = -0x1

.field public static final SUCCESS:I = 0x1


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationStatus$Companion;->$$INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationStatus$Companion;

    .line 2
    .line 3
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationStatus;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationStatus$Companion;

    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public abstract getStatus()I
.end method
