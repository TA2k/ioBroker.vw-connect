.class public Lio/getlime/security/powerauth/core/ActivationStep2Param;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final activationId:Ljava/lang/String;

.field public final activationRecovery:Lio/getlime/security/powerauth/core/RecoveryData;

.field public final ctrData:Ljava/lang/String;

.field public final serverPublicKey:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/getlime/security/powerauth/core/RecoveryData;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/getlime/security/powerauth/core/ActivationStep2Param;->activationId:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lio/getlime/security/powerauth/core/ActivationStep2Param;->serverPublicKey:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lio/getlime/security/powerauth/core/ActivationStep2Param;->ctrData:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lio/getlime/security/powerauth/core/ActivationStep2Param;->activationRecovery:Lio/getlime/security/powerauth/core/RecoveryData;

    .line 11
    .line 12
    return-void
.end method
