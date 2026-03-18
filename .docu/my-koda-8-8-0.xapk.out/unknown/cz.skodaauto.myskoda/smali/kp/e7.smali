.class public final enum Lkp/e7;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkp/b;


# static fields
.field public static final enum e:Lkp/e7;

.field public static final synthetic f:[Lkp/e7;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lkp/e7;

    .line 2
    .line 3
    const-string v1, "SOURCE_UNKNOWN"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lkp/e7;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lkp/e7;

    .line 10
    .line 11
    const-string v2, "BITMAP"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3, v3}, Lkp/e7;-><init>(Ljava/lang/String;II)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Lkp/e7;

    .line 18
    .line 19
    const-string v3, "BYTEARRAY"

    .line 20
    .line 21
    const/4 v4, 0x2

    .line 22
    invoke-direct {v2, v3, v4, v4}, Lkp/e7;-><init>(Ljava/lang/String;II)V

    .line 23
    .line 24
    .line 25
    new-instance v3, Lkp/e7;

    .line 26
    .line 27
    const-string v4, "BYTEBUFFER"

    .line 28
    .line 29
    const/4 v5, 0x3

    .line 30
    invoke-direct {v3, v4, v5, v5}, Lkp/e7;-><init>(Ljava/lang/String;II)V

    .line 31
    .line 32
    .line 33
    new-instance v4, Lkp/e7;

    .line 34
    .line 35
    const-string v5, "FILEPATH"

    .line 36
    .line 37
    const/4 v6, 0x4

    .line 38
    invoke-direct {v4, v5, v6, v6}, Lkp/e7;-><init>(Ljava/lang/String;II)V

    .line 39
    .line 40
    .line 41
    new-instance v5, Lkp/e7;

    .line 42
    .line 43
    const-string v6, "ANDROID_MEDIA_IMAGE"

    .line 44
    .line 45
    const/4 v7, 0x5

    .line 46
    invoke-direct {v5, v6, v7, v7}, Lkp/e7;-><init>(Ljava/lang/String;II)V

    .line 47
    .line 48
    .line 49
    sput-object v5, Lkp/e7;->e:Lkp/e7;

    .line 50
    .line 51
    filled-new-array/range {v0 .. v5}, [Lkp/e7;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Lkp/e7;->f:[Lkp/e7;

    .line 56
    .line 57
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lkp/e7;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static values()[Lkp/e7;
    .locals 1

    .line 1
    sget-object v0, Lkp/e7;->f:[Lkp/e7;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lkp/e7;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lkp/e7;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final h()I
    .locals 0

    .line 1
    iget p0, p0, Lkp/e7;->d:I

    .line 2
    .line 3
    return p0
.end method
