.class public final Lh8/c1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh8/y0;


# instance fields
.field public final d:Lh8/y0;

.field public final e:J


# direct methods
.method public constructor <init>(Lh8/y0;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh8/c1;->d:Lh8/y0;

    .line 5
    .line 6
    iput-wide p2, p0, Lh8/c1;->e:J

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/c1;->d:Lh8/y0;

    .line 2
    .line 3
    invoke-interface {p0}, Lh8/y0;->a()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final c()V
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/c1;->d:Lh8/y0;

    .line 2
    .line 3
    invoke-interface {p0}, Lh8/y0;->c()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d(Lb81/d;Lz7/e;I)I
    .locals 4

    .line 1
    iget-object v0, p0, Lh8/c1;->d:Lh8/y0;

    .line 2
    .line 3
    invoke-interface {v0, p1, p2, p3}, Lh8/y0;->d(Lb81/d;Lz7/e;I)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    const/4 p3, -0x4

    .line 8
    if-ne p1, p3, :cond_0

    .line 9
    .line 10
    iget-wide v0, p2, Lz7/e;->j:J

    .line 11
    .line 12
    iget-wide v2, p0, Lh8/c1;->e:J

    .line 13
    .line 14
    add-long/2addr v0, v2

    .line 15
    iput-wide v0, p2, Lz7/e;->j:J

    .line 16
    .line 17
    :cond_0
    return p1
.end method

.method public final l(J)I
    .locals 2

    .line 1
    iget-wide v0, p0, Lh8/c1;->e:J

    .line 2
    .line 3
    sub-long/2addr p1, v0

    .line 4
    iget-object p0, p0, Lh8/c1;->d:Lh8/y0;

    .line 5
    .line 6
    invoke-interface {p0, p1, p2}, Lh8/y0;->l(J)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method
