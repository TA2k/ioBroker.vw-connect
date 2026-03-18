.class public final Lrm/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lrm/e;


# instance fields
.field public final b:I


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lrm/a;->b:I

    .line 5
    .line 6
    if-lez p1, :cond_0

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 10
    .line 11
    const-string p1, "durationMillis must be > 0."

    .line 12
    .line 13
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    throw p0
.end method


# virtual methods
.method public final a(Lzl/i;Lmm/j;)Lrm/f;
    .locals 2

    .line 1
    instance-of v0, p2, Lmm/p;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance p0, Lrm/d;

    .line 6
    .line 7
    invoke-direct {p0, p1, p2}, Lrm/d;-><init>(Lzl/i;Lmm/j;)V

    .line 8
    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_0
    move-object v0, p2

    .line 12
    check-cast v0, Lmm/p;

    .line 13
    .line 14
    iget-object v0, v0, Lmm/p;->c:Lbm/h;

    .line 15
    .line 16
    sget-object v1, Lbm/h;->d:Lbm/h;

    .line 17
    .line 18
    if-ne v0, v1, :cond_1

    .line 19
    .line 20
    new-instance p0, Lrm/d;

    .line 21
    .line 22
    invoke-direct {p0, p1, p2}, Lrm/d;-><init>(Lzl/i;Lmm/j;)V

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_1
    new-instance v0, Lrm/b;

    .line 27
    .line 28
    iget p0, p0, Lrm/a;->b:I

    .line 29
    .line 30
    invoke-direct {v0, p1, p2, p0}, Lrm/b;-><init>(Lzl/i;Lmm/j;I)V

    .line 31
    .line 32
    .line 33
    return-object v0
.end method
