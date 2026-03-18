.class public abstract Landroidx/collection/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[F


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    sget-object v0, Landroidx/collection/y0;->a:[J

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {v1}, Landroidx/collection/y0;->d(I)I

    .line 5
    .line 6
    .line 7
    move-result v2

    .line 8
    if-lez v2, :cond_0

    .line 9
    .line 10
    invoke-static {v2}, Landroidx/collection/y0;->c(I)I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    const/4 v3, 0x7

    .line 15
    invoke-static {v3, v2}, Ljava/lang/Math;->max(II)I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move v2, v1

    .line 21
    :goto_0
    if-nez v2, :cond_1

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_1
    add-int/lit8 v0, v2, 0xf

    .line 25
    .line 26
    and-int/lit8 v0, v0, -0x8

    .line 27
    .line 28
    shr-int/lit8 v0, v0, 0x3

    .line 29
    .line 30
    new-array v0, v0, [J

    .line 31
    .line 32
    const-wide v3, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 33
    .line 34
    .line 35
    .line 36
    .line 37
    invoke-static {v3, v4, v0}, Lmx0/n;->r(J[J)V

    .line 38
    .line 39
    .line 40
    :goto_1
    shr-int/lit8 v3, v2, 0x3

    .line 41
    .line 42
    and-int/lit8 v4, v2, 0x7

    .line 43
    .line 44
    shl-int/lit8 v4, v4, 0x3

    .line 45
    .line 46
    aget-wide v5, v0, v3

    .line 47
    .line 48
    const-wide/16 v7, 0xff

    .line 49
    .line 50
    shl-long/2addr v7, v4

    .line 51
    not-long v9, v7

    .line 52
    and-long v4, v5, v9

    .line 53
    .line 54
    or-long/2addr v4, v7

    .line 55
    aput-wide v4, v0, v3

    .line 56
    .line 57
    new-array v0, v2, [F

    .line 58
    .line 59
    new-array v0, v1, [F

    .line 60
    .line 61
    sput-object v0, Landroidx/collection/l;->a:[F

    .line 62
    .line 63
    return-void
.end method
