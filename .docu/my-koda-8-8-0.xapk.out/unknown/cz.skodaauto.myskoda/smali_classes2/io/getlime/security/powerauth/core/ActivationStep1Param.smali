.class public Lio/getlime/security/powerauth/core/ActivationStep1Param;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final activationCode:Ljava/lang/String;

.field public final activationSignature:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/getlime/security/powerauth/core/ActivationStep1Param;->activationCode:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lio/getlime/security/powerauth/core/ActivationStep1Param;->activationSignature:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method
