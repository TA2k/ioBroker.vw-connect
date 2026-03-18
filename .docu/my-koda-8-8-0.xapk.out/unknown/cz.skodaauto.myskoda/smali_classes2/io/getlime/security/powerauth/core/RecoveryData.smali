.class public Lio/getlime/security/powerauth/core/RecoveryData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final puk:Ljava/lang/String;

.field public final recoveryCode:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lio/getlime/security/powerauth/core/RecoveryData;->recoveryCode:Ljava/lang/String;

    .line 6
    iput-object v0, p0, Lio/getlime/security/powerauth/core/RecoveryData;->puk:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lio/getlime/security/powerauth/core/RecoveryData;->recoveryCode:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lio/getlime/security/powerauth/core/RecoveryData;->puk:Ljava/lang/String;

    return-void
.end method
