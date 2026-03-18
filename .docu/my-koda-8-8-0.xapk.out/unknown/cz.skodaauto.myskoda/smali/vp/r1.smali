.class public final enum Lvp/r1;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lvp/r1;

.field public static final enum f:Lvp/r1;

.field public static final enum g:Lvp/r1;

.field public static final enum h:Lvp/r1;

.field public static final synthetic i:[Lvp/r1;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lvp/r1;

    .line 2
    .line 3
    const-string v1, "AD_STORAGE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const-string v3, "ad_storage"

    .line 7
    .line 8
    invoke-direct {v0, v1, v2, v3}, Lvp/r1;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lvp/r1;->e:Lvp/r1;

    .line 12
    .line 13
    new-instance v1, Lvp/r1;

    .line 14
    .line 15
    const-string v2, "ANALYTICS_STORAGE"

    .line 16
    .line 17
    const/4 v3, 0x1

    .line 18
    const-string v4, "analytics_storage"

    .line 19
    .line 20
    invoke-direct {v1, v2, v3, v4}, Lvp/r1;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v1, Lvp/r1;->f:Lvp/r1;

    .line 24
    .line 25
    new-instance v2, Lvp/r1;

    .line 26
    .line 27
    const-string v3, "AD_USER_DATA"

    .line 28
    .line 29
    const/4 v4, 0x2

    .line 30
    const-string v5, "ad_user_data"

    .line 31
    .line 32
    invoke-direct {v2, v3, v4, v5}, Lvp/r1;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v2, Lvp/r1;->g:Lvp/r1;

    .line 36
    .line 37
    new-instance v3, Lvp/r1;

    .line 38
    .line 39
    const-string v4, "AD_PERSONALIZATION"

    .line 40
    .line 41
    const/4 v5, 0x3

    .line 42
    const-string v6, "ad_personalization"

    .line 43
    .line 44
    invoke-direct {v3, v4, v5, v6}, Lvp/r1;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 45
    .line 46
    .line 47
    sput-object v3, Lvp/r1;->h:Lvp/r1;

    .line 48
    .line 49
    filled-new-array {v0, v1, v2, v3}, [Lvp/r1;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sput-object v0, Lvp/r1;->i:[Lvp/r1;

    .line 54
    .line 55
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lvp/r1;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static values()[Lvp/r1;
    .locals 1

    .line 1
    sget-object v0, Lvp/r1;->i:[Lvp/r1;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lvp/r1;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lvp/r1;

    .line 8
    .line 9
    return-object v0
.end method
