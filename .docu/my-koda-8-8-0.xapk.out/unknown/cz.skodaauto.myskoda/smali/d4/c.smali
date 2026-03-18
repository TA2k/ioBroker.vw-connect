.class public final Ld4/c;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/x1;


# instance fields
.field public r:Z

.field public final s:Z

.field public t:Lay0/k;


# direct methods
.method public constructor <init>(ZZLay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Ld4/c;->r:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Ld4/c;->s:Z

    .line 7
    .line 8
    iput-object p3, p0, Ld4/c;->t:Lay0/k;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final J0()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ld4/c;->r:Z

    .line 2
    .line 3
    return p0
.end method

.method public final a0(Ld4/l;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ld4/c;->t:Lay0/k;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final w()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ld4/c;->s:Z

    .line 2
    .line 3
    return p0
.end method
