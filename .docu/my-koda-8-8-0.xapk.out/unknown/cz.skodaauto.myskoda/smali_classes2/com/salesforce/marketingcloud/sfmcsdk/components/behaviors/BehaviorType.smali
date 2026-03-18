.class public final enum Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType$Companion;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010 \n\u0002\u0008\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0008\u0086\u0081\u0002\u0018\u0000 \u001f2\u0008\u0012\u0004\u0012\u00020\u00000\u0001:\u0001\u001fB+\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0005\u0012\u0010\u0008\u0002\u0010\u0006\u001a\n\u0012\u0004\u0012\u00020\u0000\u0018\u00010\u0007\u00a2\u0006\u0002\u0010\u0008J\u0017\u0010\u0015\u001a\u0004\u0018\u00010\u00162\u0006\u0010\u0017\u001a\u00020\u0018H\u0000\u00a2\u0006\u0002\u0008\u0019J\u0008\u0010\u001a\u001a\u00020\u0003H\u0016R\"\u0010\u0006\u001a\n\u0012\u0004\u0012\u00020\u0000\u0018\u00010\u0007X\u0080\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\t\u0010\n\"\u0004\u0008\u000b\u0010\u000cR\u001a\u0010\u0002\u001a\u00020\u0003X\u0080\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\r\u0010\u000e\"\u0004\u0008\u000f\u0010\u0010R\u001a\u0010\u0004\u001a\u00020\u0005X\u0080\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0011\u0010\u0012\"\u0004\u0008\u0013\u0010\u0014j\u0002\u0008\u001bj\u0002\u0008\u001cj\u0002\u0008\u001dj\u0002\u0008\u001e\u00a8\u0006 "
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;",
        "",
        "intentFilter",
        "",
        "sticky",
        "",
        "behaviorTypesToClear",
        "",
        "(Ljava/lang/String;ILjava/lang/String;ZLjava/util/List;)V",
        "getBehaviorTypesToClear$sfmcsdk_release",
        "()Ljava/util/List;",
        "setBehaviorTypesToClear$sfmcsdk_release",
        "(Ljava/util/List;)V",
        "getIntentFilter$sfmcsdk_release",
        "()Ljava/lang/String;",
        "setIntentFilter$sfmcsdk_release",
        "(Ljava/lang/String;)V",
        "getSticky$sfmcsdk_release",
        "()Z",
        "setSticky$sfmcsdk_release",
        "(Z)V",
        "toBehavior",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;",
        "data",
        "Landroid/os/Bundle;",
        "toBehavior$sfmcsdk_release",
        "toString",
        "SCREEN_ENTRY",
        "APPLICATION_FOREGROUNDED",
        "APPLICATION_BACKGROUNDED",
        "APP_VERSION_CHANGED",
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
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

.field public static final enum APPLICATION_BACKGROUNDED:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

.field public static final enum APPLICATION_FOREGROUNDED:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

.field public static final enum APP_VERSION_CHANGED:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType$Companion;

.field public static final enum SCREEN_ENTRY:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;


# instance fields
.field private behaviorTypesToClear:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "+",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;",
            ">;"
        }
    .end annotation
.end field

.field private intentFilter:Ljava/lang/String;

.field private sticky:Z


# direct methods
.method private static final synthetic $values()[Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->SCREEN_ENTRY:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->APPLICATION_FOREGROUNDED:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 4
    .line 5
    sget-object v2, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->APPLICATION_BACKGROUNDED:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 6
    .line 7
    sget-object v3, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->APP_VERSION_CHANGED:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 11

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 2
    .line 3
    const/4 v6, 0x4

    .line 4
    const/4 v7, 0x0

    .line 5
    const-string v1, "SCREEN_ENTRY"

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const-string v3, "com.salesforce.marketingcloud.sfmcsdk.sdk.SCREEN_ENTRY"

    .line 9
    .line 10
    const/4 v4, 0x1

    .line 11
    const/4 v5, 0x0

    .line 12
    invoke-direct/range {v0 .. v7}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;-><init>(Ljava/lang/String;ILjava/lang/String;ZLjava/util/List;ILkotlin/jvm/internal/g;)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->SCREEN_ENTRY:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 16
    .line 17
    new-instance v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 18
    .line 19
    const/4 v7, 0x4

    .line 20
    const/4 v8, 0x0

    .line 21
    const-string v2, "APPLICATION_FOREGROUNDED"

    .line 22
    .line 23
    const/4 v3, 0x1

    .line 24
    const-string v4, "com.salesforce.marketingcloud.sfmcsdk.sdk.APPLICATION_FOREGROUNDED"

    .line 25
    .line 26
    const/4 v5, 0x1

    .line 27
    const/4 v6, 0x0

    .line 28
    invoke-direct/range {v1 .. v8}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;-><init>(Ljava/lang/String;ILjava/lang/String;ZLjava/util/List;ILkotlin/jvm/internal/g;)V

    .line 29
    .line 30
    .line 31
    sput-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->APPLICATION_FOREGROUNDED:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 32
    .line 33
    new-instance v2, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 34
    .line 35
    filled-new-array {v1, v0}, [Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 40
    .line 41
    .line 42
    move-result-object v7

    .line 43
    const/4 v8, 0x2

    .line 44
    const/4 v9, 0x0

    .line 45
    const-string v3, "APPLICATION_BACKGROUNDED"

    .line 46
    .line 47
    const/4 v4, 0x2

    .line 48
    const-string v5, "com.salesforce.marketingcloud.sfmcsdk.sdk.APPLICATION_BACKGROUNDED"

    .line 49
    .line 50
    const/4 v6, 0x0

    .line 51
    invoke-direct/range {v2 .. v9}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;-><init>(Ljava/lang/String;ILjava/lang/String;ZLjava/util/List;ILkotlin/jvm/internal/g;)V

    .line 52
    .line 53
    .line 54
    sput-object v2, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->APPLICATION_BACKGROUNDED:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 55
    .line 56
    new-instance v3, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 57
    .line 58
    const/4 v9, 0x4

    .line 59
    const/4 v10, 0x0

    .line 60
    const-string v4, "APP_VERSION_CHANGED"

    .line 61
    .line 62
    const/4 v5, 0x3

    .line 63
    const-string v6, "com.salesforce.marketingcloud.sfmcsdk.sdk.APP_VERSION_CHANGED"

    .line 64
    .line 65
    const/4 v7, 0x1

    .line 66
    const/4 v8, 0x0

    .line 67
    invoke-direct/range {v3 .. v10}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;-><init>(Ljava/lang/String;ILjava/lang/String;ZLjava/util/List;ILkotlin/jvm/internal/g;)V

    .line 68
    .line 69
    .line 70
    sput-object v3, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->APP_VERSION_CHANGED:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 71
    .line 72
    invoke-static {}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->$values()[Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->$VALUES:[Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 77
    .line 78
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->$ENTRIES:Lsx0/a;

    .line 83
    .line 84
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType$Companion;

    .line 85
    .line 86
    const/4 v1, 0x0

    .line 87
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 88
    .line 89
    .line 90
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType$Companion;

    .line 91
    .line 92
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;ZLjava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Z",
            "Ljava/util/List<",
            "+",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    iput-object p3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->intentFilter:Ljava/lang/String;

    .line 3
    iput-boolean p4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->sticky:Z

    .line 4
    iput-object p5, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->behaviorTypesToClear:Ljava/util/List;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;ILjava/lang/String;ZLjava/util/List;ILkotlin/jvm/internal/g;)V
    .locals 6

    and-int/lit8 p7, p6, 0x2

    if-eqz p7, :cond_0

    const/4 p4, 0x0

    :cond_0
    move v4, p4

    and-int/lit8 p4, p6, 0x4

    if-eqz p4, :cond_1

    const/4 p5, 0x0

    :cond_1
    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v3, p3

    move-object v5, p5

    .line 5
    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;-><init>(Ljava/lang/String;ILjava/lang/String;ZLjava/util/List;)V

    return-void
.end method

.method public static getEntries()Lsx0/a;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lsx0/a;"
        }
    .end annotation

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->$VALUES:[Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getBehaviorTypesToClear$sfmcsdk_release()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->behaviorTypesToClear:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getIntentFilter$sfmcsdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->intentFilter:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSticky$sfmcsdk_release()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->sticky:Z

    .line 2
    .line 3
    return p0
.end method

.method public final setBehaviorTypesToClear$sfmcsdk_release(Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "+",
            "Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->behaviorTypesToClear:Ljava/util/List;

    .line 2
    .line 3
    return-void
.end method

.method public final setIntentFilter$sfmcsdk_release(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->intentFilter:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method

.method public final setSticky$sfmcsdk_release(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->sticky:Z

    .line 2
    .line 3
    return-void
.end method

.method public final toBehavior$sfmcsdk_release(Landroid/os/Bundle;)Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;
    .locals 7

    .line 1
    const-string v0, "data"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "timestamp"

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 9
    .line 10
    .line 11
    move-result-wide v2

    .line 12
    const-string v0, "current_version"

    .line 13
    .line 14
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    const-string v0, "application_name"

    .line 19
    .line 20
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->intentFilter:Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    sparse-switch v0, :sswitch_data_0

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :sswitch_0
    const-string v0, "com.salesforce.marketingcloud.sfmcsdk.sdk.SCREEN_ENTRY"

    .line 35
    .line 36
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    if-nez p0, :cond_0

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    const-string p0, "screen_name"

    .line 44
    .line 45
    invoke-virtual {p1, p0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    if-eqz p0, :cond_3

    .line 50
    .line 51
    new-instance v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$ScreenEntry;

    .line 52
    .line 53
    move-object v6, v5

    .line 54
    move-object v5, v4

    .line 55
    move-wide v3, v2

    .line 56
    move-object v2, p0

    .line 57
    invoke-direct/range {v1 .. v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$ScreenEntry;-><init>(Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    return-object v1

    .line 61
    :sswitch_1
    const-string v0, "com.salesforce.marketingcloud.sfmcsdk.sdk.APP_VERSION_CHANGED"

    .line 62
    .line 63
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    if-nez p0, :cond_1

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_1
    new-instance v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppVersionChanged;

    .line 71
    .line 72
    const-string p0, "previous_version"

    .line 73
    .line 74
    invoke-virtual {p1, p0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v6

    .line 78
    invoke-direct/range {v1 .. v6}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppVersionChanged;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    return-object v1

    .line 82
    :sswitch_2
    const-string p1, "com.salesforce.marketingcloud.sfmcsdk.sdk.APPLICATION_FOREGROUNDED"

    .line 83
    .line 84
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    if-nez p0, :cond_2

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_2
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppForegrounded;

    .line 92
    .line 93
    invoke-direct {p0, v2, v3, v4, v5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppForegrounded;-><init>(JLjava/lang/String;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    return-object p0

    .line 97
    :sswitch_3
    const-string p1, "com.salesforce.marketingcloud.sfmcsdk.sdk.APPLICATION_BACKGROUNDED"

    .line 98
    .line 99
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result p0

    .line 103
    if-nez p0, :cond_4

    .line 104
    .line 105
    :cond_3
    :goto_0
    const/4 p0, 0x0

    .line 106
    return-object p0

    .line 107
    :cond_4
    new-instance p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppBackgrounded;

    .line 108
    .line 109
    invoke-direct {p0, v2, v3, v4, v5}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppBackgrounded;-><init>(JLjava/lang/String;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    return-object p0

    .line 113
    :sswitch_data_0
    .sparse-switch
        -0x79fdb1b6 -> :sswitch_3
        -0x60024ee1 -> :sswitch_2
        0x5f6c5c1 -> :sswitch_1
        0x1eee850d -> :sswitch_0
    .end sparse-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->intentFilter:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
