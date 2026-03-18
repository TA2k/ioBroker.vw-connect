.class public final Lvp/i3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final d:J

.field public final e:J

.field public final synthetic f:Lb81/d;


# direct methods
.method public constructor <init>(Lb81/d;JJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Lvp/i3;->f:Lb81/d;

    .line 8
    .line 9
    iput-wide p2, p0, Lvp/i3;->d:J

    .line 10
    .line 11
    iput-wide p4, p0, Lvp/i3;->e:J

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/i3;->f:Lb81/d;

    .line 2
    .line 3
    iget-object v0, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lvp/k3;

    .line 6
    .line 7
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lvp/g1;

    .line 10
    .line 11
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 12
    .line 13
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Laq/p;

    .line 17
    .line 18
    const/16 v2, 0x1c

    .line 19
    .line 20
    invoke-direct {v1, p0, v2}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method
