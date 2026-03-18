.class public abstract Lh2/sb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    const/16 v1, 0x8

    .line 5
    .line 6
    int-to-float v1, v1

    .line 7
    invoke-static {v0, v1}, Lkp/c9;->a(FF)J

    .line 8
    .line 9
    .line 10
    const/16 v0, 0xc8

    .line 11
    .line 12
    int-to-float v0, v0

    .line 13
    sput v0, Lh2/sb;->a:F

    .line 14
    .line 15
    return-void
.end method

.method public static a(Ll2/o;)Lh2/wb;
    .locals 3

    .line 1
    sget v0, Lh2/vb;->a:F

    .line 2
    .line 3
    sget-object v1, Lw3/h1;->h:Ll2/u2;

    .line 4
    .line 5
    check-cast p0, Ll2/t;

    .line 6
    .line 7
    invoke-virtual {p0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    check-cast v1, Lt4/c;

    .line 12
    .line 13
    invoke-interface {v1, v0}, Lt4/c;->Q(F)I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    invoke-virtual {p0, v0}, Ll2/t;->e(I)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    if-nez v1, :cond_0

    .line 26
    .line 27
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 28
    .line 29
    if-ne v2, v1, :cond_1

    .line 30
    .line 31
    :cond_0
    new-instance v2, Lh2/wb;

    .line 32
    .line 33
    invoke-direct {v2, v0}, Lh2/wb;-><init>(I)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    :cond_1
    check-cast v2, Lh2/wb;

    .line 40
    .line 41
    return-object v2
.end method
