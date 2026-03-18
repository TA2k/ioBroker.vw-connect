.class public final Lz1/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements La2/k;


# instance fields
.field public final d:J

.field public final synthetic e:Lz1/e;


# direct methods
.method public constructor <init>(Lz1/e;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz1/d;->e:Lz1/e;

    .line 5
    .line 6
    iput-wide p2, p0, Lz1/d;->d:J

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final B()Lw1/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lz1/d;->e:Lz1/e;

    .line 2
    .line 3
    invoke-static {p0}, Lev/a;->e(Lv3/m;)Lw1/c;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final B0(Lt3/y;)J
    .locals 3

    .line 1
    iget-object v0, p0, Lz1/d;->e:Lz1/e;

    .line 2
    .line 3
    iget-object v0, v0, Lz1/e;->u:Ll2/j1;

    .line 4
    .line 5
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lt3/y;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-wide v1, p0, Lz1/d;->d:J

    .line 14
    .line 15
    invoke-interface {p1, v0, v1, v2}, Lt3/y;->Z(Lt3/y;J)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    return-wide p0

    .line 20
    :cond_0
    const-string p0, "Tried to open context menu before the anchor was placed."

    .line 21
    .line 22
    invoke-static {p0}, Lj1/b;->d(Ljava/lang/String;)Ljava/lang/Void;

    .line 23
    .line 24
    .line 25
    new-instance p0, La8/r0;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0
.end method

.method public final p(Lt3/y;)Ld3/c;
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Lz1/d;->B0(Lt3/y;)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    const-wide/16 v0, 0x0

    .line 6
    .line 7
    invoke-static {p0, p1, v0, v1}, Ljp/cf;->c(JJ)Ld3/c;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
