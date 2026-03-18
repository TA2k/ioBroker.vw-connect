.class public Lio/getlime/security/powerauth/core/ProtocolUpgradeData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final toVersion:I

.field public final v3CtrData:Ljava/lang/String;


# direct methods
.method private constructor <init>(Lio/getlime/security/powerauth/core/ProtocolVersion;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iget p1, p1, Lio/getlime/security/powerauth/core/ProtocolVersion;->numericValue:I

    .line 5
    .line 6
    iput p1, p0, Lio/getlime/security/powerauth/core/ProtocolUpgradeData;->toVersion:I

    .line 7
    .line 8
    iput-object p2, p0, Lio/getlime/security/powerauth/core/ProtocolUpgradeData;->v3CtrData:Ljava/lang/String;

    .line 9
    .line 10
    return-void
.end method
