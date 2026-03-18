.class public final Lz1/f;
.super Lv3/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/l;
.implements La2/k;


# instance fields
.field public t:Lro/f;

.field public u:Le2/o0;

.field public v:Le2/p0;

.field public w:Le2/n0;

.field public x:Lvy0/x1;

.field public final y:Ll2/h0;

.field public z:Ld3/c;


# direct methods
.method public constructor <init>(Lro/f;Le2/o0;Le2/p0;Le2/n0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lv3/n;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz1/f;->t:Lro/f;

    .line 5
    .line 6
    iput-object p2, p0, Lz1/f;->u:Le2/o0;

    .line 7
    .line 8
    iput-object p3, p0, Lz1/f;->v:Le2/p0;

    .line 9
    .line 10
    iput-object p4, p0, Lz1/f;->w:Le2/n0;

    .line 11
    .line 12
    new-instance p1, Ly1/i;

    .line 13
    .line 14
    const/16 p2, 0xc

    .line 15
    .line 16
    invoke-direct {p1, p0, p2}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 17
    .line 18
    .line 19
    invoke-static {p1}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iput-object p1, p0, Lz1/f;->y:Ll2/h0;

    .line 24
    .line 25
    sget-object p1, Ld3/c;->e:Ld3/c;

    .line 26
    .line 27
    iput-object p1, p0, Lz1/f;->z:Ld3/c;

    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public final B()Lw1/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lz1/f;->y:Ll2/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lw1/c;

    .line 8
    .line 9
    return-object p0
.end method

.method public final B0(Lt3/y;)J
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lz1/f;->p(Lt3/y;)Ld3/c;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ld3/c;->d()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    return-wide p0
.end method

.method public final P0()V
    .locals 1

    .line 1
    iget-object v0, p0, Lz1/f;->t:Lro/f;

    .line 2
    .line 3
    iput-object p0, v0, Lro/f;->e:Ljava/lang/Object;

    .line 4
    .line 5
    return-void
.end method

.method public final Q0()V
    .locals 1

    .line 1
    iget-object p0, p0, Lz1/f;->t:Lro/f;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    iput-object v0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 5
    .line 6
    return-void
.end method

.method public final p(Lt3/y;)Ld3/c;
    .locals 1

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lz1/f;->z:Ld3/c;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    iget-object v0, p0, Lz1/f;->w:Le2/n0;

    .line 9
    .line 10
    invoke-virtual {v0, p1}, Le2/n0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    check-cast p1, Ld3/c;

    .line 15
    .line 16
    iput-object p1, p0, Lz1/f;->z:Ld3/c;

    .line 17
    .line 18
    return-object p1
.end method
