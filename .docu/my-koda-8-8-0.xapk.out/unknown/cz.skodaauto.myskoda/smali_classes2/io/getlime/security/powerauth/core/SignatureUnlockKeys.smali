.class public Lio/getlime/security/powerauth/core/SignatureUnlockKeys;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final biometryUnlockKey:[B

.field public final possessionUnlockKey:[B

.field public final userPassword:Lio/getlime/security/powerauth/core/Password;


# direct methods
.method public constructor <init>([B[BLio/getlime/security/powerauth/core/Password;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/getlime/security/powerauth/core/SignatureUnlockKeys;->possessionUnlockKey:[B

    .line 5
    .line 6
    iput-object p2, p0, Lio/getlime/security/powerauth/core/SignatureUnlockKeys;->biometryUnlockKey:[B

    .line 7
    .line 8
    iput-object p3, p0, Lio/getlime/security/powerauth/core/SignatureUnlockKeys;->userPassword:Lio/getlime/security/powerauth/core/Password;

    .line 9
    .line 10
    return-void
.end method
