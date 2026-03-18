.class public final Lhz0/d1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljz0/r;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljz0/r;

    .line 5
    .line 6
    sget-object v1, Lhz0/c1;->d:Lhz0/c1;

    .line 7
    .line 8
    invoke-interface {v1}, Lhy0/c;->getName()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-direct {v0, v1, v2}, Ljz0/r;-><init>(Lhy0/l;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lhz0/d1;->a:Ljz0/r;

    .line 16
    .line 17
    return-void
.end method
