.class public final Lcr/d;
.super Lbp/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ler/p;

.field public final e:Laq/k;

.field public final synthetic f:Lcr/e;


# direct methods
.method public constructor <init>(Lcr/e;Laq/k;)V
    .locals 1

    .line 1
    iput-object p1, p0, Lcr/d;->f:Lcr/e;

    .line 2
    .line 3
    const/4 p1, 0x3

    .line 4
    invoke-direct {p0, p1}, Lbp/j;-><init>(I)V

    .line 5
    .line 6
    .line 7
    const-string p1, "com.google.android.play.core.integrity.protocol.IIntegrityServiceCallback"

    .line 8
    .line 9
    invoke-virtual {p0, p0, p1}, Landroid/os/Binder;->attachInterface(Landroid/os/IInterface;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    new-instance p1, Ler/p;

    .line 13
    .line 14
    const-string v0, "OnRequestIntegrityTokenCallback"

    .line 15
    .line 16
    invoke-direct {p1, v0}, Ler/p;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lcr/d;->d:Ler/p;

    .line 20
    .line 21
    iput-object p2, p0, Lcr/d;->e:Laq/k;

    .line 22
    .line 23
    return-void
.end method
