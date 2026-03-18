.class public final Lmi0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Loi0/e;


# instance fields
.field public final a:Lve0/u;

.field public b:Lpi0/b;


# direct methods
.method public constructor <init>(Lve0/u;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmi0/a;->a:Lve0/u;

    .line 5
    .line 6
    new-instance p1, Lpi0/b;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    sget-object v1, Lpi0/a;->g:Lpi0/a;

    .line 10
    .line 11
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 12
    .line 13
    invoke-direct {p1, v2, v0, v1}, Lpi0/b;-><init>(Ljava/util/List;ILpi0/a;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lmi0/a;->b:Lpi0/b;

    .line 17
    .line 18
    return-void
.end method
