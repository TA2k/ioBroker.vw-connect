.class public Lio/getlime/security/powerauth/core/SessionSetup;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final configuration:Ljava/lang/String;

.field public final externalEncryptionKey:[B


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "PowerAuth2Module"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;[B)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/getlime/security/powerauth/core/SessionSetup;->configuration:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lio/getlime/security/powerauth/core/SessionSetup;->externalEncryptionKey:[B

    .line 7
    .line 8
    return-void
.end method
