.class public final Lrd0/w;
.super Lkr0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lrd0/w;

.field public static final c:Lrd0/w;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lrd0/w;

    .line 2
    .line 3
    const-string v1, "ChargingStart"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lkr0/c;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lrd0/w;->b:Lrd0/w;

    .line 9
    .line 10
    new-instance v0, Lrd0/w;

    .line 11
    .line 12
    const-string v1, "ChargingStop"

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lkr0/c;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lrd0/w;->c:Lrd0/w;

    .line 18
    .line 19
    return-void
.end method
