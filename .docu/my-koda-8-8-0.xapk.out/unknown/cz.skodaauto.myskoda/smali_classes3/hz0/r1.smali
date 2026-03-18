.class public final Lhz0/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhz0/b;
.implements Lhz0/e;


# instance fields
.field public final a:Lbn/c;


# direct methods
.method public constructor <init>(Lbn/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhz0/r1;->a:Lbn/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final e()Lbn/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/r1;->a:Lbn/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l()Lhz0/b;
    .locals 2

    .line 1
    new-instance p0, Lhz0/r1;

    .line 2
    .line 3
    new-instance v0, Lbn/c;

    .line 4
    .line 5
    const/4 v1, 0x3

    .line 6
    invoke-direct {v0, v1}, Lbn/c;-><init>(I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lhz0/r1;-><init>(Lbn/c;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public final q(Ljz0/k;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/r1;->a:Lbn/c;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lbn/c;->f(Ljz0/k;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
