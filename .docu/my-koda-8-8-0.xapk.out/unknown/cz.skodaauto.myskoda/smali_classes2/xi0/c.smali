.class public final Lxi0/c;
.super Lxi0/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "Mandatory legal document is not consented"

    .line 2
    .line 3
    invoke-direct {p0, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lxi0/c;->d:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p2, p0, Lxi0/c;->e:Ljava/lang/String;

    .line 9
    .line 10
    return-void
.end method
