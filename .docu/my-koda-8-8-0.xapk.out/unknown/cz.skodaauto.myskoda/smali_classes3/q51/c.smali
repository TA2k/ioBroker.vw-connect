.class public final Lq51/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lq51/a;

.field public final b:Ljavax/crypto/Cipher;

.field public final c:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;


# direct methods
.method public constructor <init>(Lq51/a;Ljavax/crypto/Cipher;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;)V
    .locals 1

    .line 1
    const-string v0, "contentInformation"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "cipher"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lq51/c;->a:Lq51/a;

    .line 15
    .line 16
    iput-object p2, p0, Lq51/c;->b:Ljavax/crypto/Cipher;

    .line 17
    .line 18
    iput-object p3, p0, Lq51/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 19
    .line 20
    return-void
.end method
