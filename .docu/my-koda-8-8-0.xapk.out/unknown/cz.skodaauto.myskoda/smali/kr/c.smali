.class public abstract Lkr/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[B


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    const/16 v0, 0x80

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    const/4 v1, -0x1

    .line 6
    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([BB)V

    .line 7
    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    move v2, v1

    .line 11
    :goto_0
    const/16 v3, 0xa

    .line 12
    .line 13
    if-ge v2, v3, :cond_0

    .line 14
    .line 15
    add-int/lit8 v3, v2, 0x30

    .line 16
    .line 17
    int-to-byte v4, v2

    .line 18
    aput-byte v4, v0, v3

    .line 19
    .line 20
    add-int/lit8 v2, v2, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    :goto_1
    const/16 v2, 0x1a

    .line 24
    .line 25
    if-ge v1, v2, :cond_1

    .line 26
    .line 27
    add-int/lit8 v2, v1, 0x41

    .line 28
    .line 29
    add-int/lit8 v3, v1, 0xa

    .line 30
    .line 31
    int-to-byte v3, v3

    .line 32
    aput-byte v3, v0, v2

    .line 33
    .line 34
    add-int/lit8 v2, v1, 0x61

    .line 35
    .line 36
    aput-byte v3, v0, v2

    .line 37
    .line 38
    add-int/lit8 v1, v1, 0x1

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    sput-object v0, Lkr/c;->a:[B

    .line 42
    .line 43
    return-void
.end method
