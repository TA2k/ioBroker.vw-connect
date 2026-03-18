.class public final Lvp/s2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:Lvp/r2;

.field public final synthetic e:Lvp/r2;

.field public final synthetic f:J

.field public final synthetic g:Z

.field public final synthetic h:Lvp/u2;


# direct methods
.method public constructor <init>(Lvp/u2;Lvp/r2;Lvp/r2;JZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lvp/s2;->d:Lvp/r2;

    .line 5
    .line 6
    iput-object p3, p0, Lvp/s2;->e:Lvp/r2;

    .line 7
    .line 8
    iput-wide p4, p0, Lvp/s2;->f:J

    .line 9
    .line 10
    iput-boolean p6, p0, Lvp/s2;->g:Z

    .line 11
    .line 12
    iput-object p1, p0, Lvp/s2;->h:Lvp/u2;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 7

    .line 1
    iget-boolean v5, p0, Lvp/s2;->g:Z

    .line 2
    .line 3
    const/4 v6, 0x0

    .line 4
    iget-object v0, p0, Lvp/s2;->h:Lvp/u2;

    .line 5
    .line 6
    iget-object v1, p0, Lvp/s2;->d:Lvp/r2;

    .line 7
    .line 8
    iget-object v2, p0, Lvp/s2;->e:Lvp/r2;

    .line 9
    .line 10
    iget-wide v3, p0, Lvp/s2;->f:J

    .line 11
    .line 12
    invoke-virtual/range {v0 .. v6}, Lvp/u2;->k0(Lvp/r2;Lvp/r2;JZLandroid/os/Bundle;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
