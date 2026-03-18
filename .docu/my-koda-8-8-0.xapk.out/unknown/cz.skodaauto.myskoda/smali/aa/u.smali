.class public final Laa/u;
.super Lz9/u;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lz9/g;


# instance fields
.field public final i:Lx4/p;

.field public final j:Lt2/b;


# direct methods
.method public constructor <init>(Laa/v;)V
    .locals 3

    .line 1
    sget-object v0, Laa/e;->a:Lt2/b;

    .line 2
    .line 3
    new-instance v1, Lx4/p;

    .line 4
    .line 5
    const/4 v2, 0x7

    .line 6
    invoke-direct {v1, v2}, Lx4/p;-><init>(I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, p1}, Lz9/u;-><init>(Lz9/j0;)V

    .line 10
    .line 11
    .line 12
    iput-object v1, p0, Laa/u;->i:Lx4/p;

    .line 13
    .line 14
    iput-object v0, p0, Laa/u;->j:Lt2/b;

    .line 15
    .line 16
    return-void
.end method
