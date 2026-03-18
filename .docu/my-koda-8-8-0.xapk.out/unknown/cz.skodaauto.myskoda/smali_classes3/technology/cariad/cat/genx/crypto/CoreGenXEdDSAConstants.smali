.class public final Ltechnology/cariad/cat/genx/crypto/CoreGenXEdDSAConstants;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0003\u0008\u00c0\u0002\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R\u000e\u0010\u0004\u001a\u00020\u0005X\u0080T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0005X\u0080T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\u0005X\u0080T\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u0008"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/crypto/CoreGenXEdDSAConstants;",
        "",
        "<init>",
        "()V",
        "CGXEd25519SignatureLength",
        "",
        "CGXEd25519PublicKeyLength",
        "CGXEd25519PrivateKeyLength",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final CGXEd25519PrivateKeyLength:I = 0x20

.field public static final CGXEd25519PublicKeyLength:I = 0x20

.field public static final CGXEd25519SignatureLength:I = 0x40

.field public static final INSTANCE:Ltechnology/cariad/cat/genx/crypto/CoreGenXEdDSAConstants;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/crypto/CoreGenXEdDSAConstants;

    .line 2
    .line 3
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/crypto/CoreGenXEdDSAConstants;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/genx/crypto/CoreGenXEdDSAConstants;->INSTANCE:Ltechnology/cariad/cat/genx/crypto/CoreGenXEdDSAConstants;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
