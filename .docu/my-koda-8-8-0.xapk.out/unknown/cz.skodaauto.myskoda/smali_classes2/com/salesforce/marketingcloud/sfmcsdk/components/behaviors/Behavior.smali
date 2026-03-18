.class public abstract Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppBackgrounded;,
        Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppForegrounded;,
        Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppVersionChanged;,
        Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$Companion;,
        Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$ScreenEntry;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u00086\u0018\u0000 \u00122\u00020\u0001:\u0005\u000f\u0010\u0011\u0012\u0013B/\u0008\u0004\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0010\u0004\u001a\u0004\u0018\u00010\u0005\u0012\u0008\u0010\u0006\u001a\u0004\u0018\u00010\u0005\u0012\n\u0008\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u0005\u00a2\u0006\u0002\u0010\u0008R\u0013\u0010\u0006\u001a\u0004\u0018\u00010\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\t\u0010\nR\u0013\u0010\u0004\u001a\u0004\u0018\u00010\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000b\u0010\nR\u0013\u0010\u0007\u001a\u0004\u0018\u00010\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000c\u0010\nR\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u000e\u0082\u0001\u0004\u0014\u0015\u0016\u0017\u00a8\u0006\u0018"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;",
        "",
        "timestamp",
        "",
        "appVersion",
        "",
        "appName",
        "previousVersion",
        "(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        "getAppName",
        "()Ljava/lang/String;",
        "getAppVersion",
        "getPreviousVersion",
        "getTimestamp",
        "()J",
        "AppBackgrounded",
        "AppForegrounded",
        "AppVersionChanged",
        "Companion",
        "ScreenEntry",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppBackgrounded;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppForegrounded;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppVersionChanged;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$ScreenEntry;",
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
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$Companion;

.field public static final KEY_TIME:Ljava/lang/String; = "timestamp"


# instance fields
.field private final appName:Ljava/lang/String;

.field private final appVersion:Ljava/lang/String;

.field private final previousVersion:Ljava/lang/String;

.field private final timestamp:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$Companion;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-wide p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;->timestamp:J

    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;->appVersion:Ljava/lang/String;

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;->appName:Ljava/lang/String;

    .line 6
    iput-object p5, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;->previousVersion:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 7

    and-int/lit8 p6, p6, 0x8

    if-eqz p6, :cond_0

    const/4 p5, 0x0

    :cond_0
    move-object v5, p5

    const/4 v6, 0x0

    move-object v0, p0

    move-wide v1, p1

    move-object v3, p3

    move-object v4, p4

    .line 7
    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/internal/g;)V

    return-void
.end method

.method public synthetic constructor <init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct/range {p0 .. p5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method


# virtual methods
.method public final getAppName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;->appName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAppVersion()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;->appVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPreviousVersion()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;->previousVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTimestamp()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;->timestamp:J

    .line 2
    .line 3
    return-wide v0
.end method
