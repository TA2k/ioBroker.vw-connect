.class public final enum Lh0/c2;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lh0/c2;

.field public static final enum f:Lh0/c2;

.field public static final enum g:Lh0/c2;

.field public static final enum h:Lh0/c2;

.field public static final enum i:Lh0/c2;

.field public static final synthetic j:[Lh0/c2;


# instance fields
.field public final d:J


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lh0/c2;

    .line 2
    .line 3
    const-string v1, "DEFAULT"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lh0/c2;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lh0/c2;->e:Lh0/c2;

    .line 10
    .line 11
    new-instance v1, Lh0/c2;

    .line 12
    .line 13
    const-string v2, "PREVIEW"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3, v3}, Lh0/c2;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lh0/c2;->f:Lh0/c2;

    .line 20
    .line 21
    new-instance v2, Lh0/c2;

    .line 22
    .line 23
    const-string v3, "VIDEO_RECORD"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    const/4 v5, 0x3

    .line 27
    invoke-direct {v2, v3, v4, v5}, Lh0/c2;-><init>(Ljava/lang/String;II)V

    .line 28
    .line 29
    .line 30
    sput-object v2, Lh0/c2;->g:Lh0/c2;

    .line 31
    .line 32
    new-instance v3, Lh0/c2;

    .line 33
    .line 34
    const-string v6, "STILL_CAPTURE"

    .line 35
    .line 36
    invoke-direct {v3, v6, v5, v4}, Lh0/c2;-><init>(Ljava/lang/String;II)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Lh0/c2;->h:Lh0/c2;

    .line 40
    .line 41
    new-instance v4, Lh0/c2;

    .line 42
    .line 43
    const-string v5, "VIDEO_CALL"

    .line 44
    .line 45
    const/4 v6, 0x4

    .line 46
    const/4 v7, 0x5

    .line 47
    invoke-direct {v4, v5, v6, v7}, Lh0/c2;-><init>(Ljava/lang/String;II)V

    .line 48
    .line 49
    .line 50
    new-instance v5, Lh0/c2;

    .line 51
    .line 52
    const-string v8, "PREVIEW_VIDEO_STILL"

    .line 53
    .line 54
    invoke-direct {v5, v8, v7, v6}, Lh0/c2;-><init>(Ljava/lang/String;II)V

    .line 55
    .line 56
    .line 57
    sput-object v5, Lh0/c2;->i:Lh0/c2;

    .line 58
    .line 59
    new-instance v6, Lh0/c2;

    .line 60
    .line 61
    const-string v7, "CROPPED_RAW"

    .line 62
    .line 63
    const/4 v8, 0x6

    .line 64
    invoke-direct {v6, v7, v8, v8}, Lh0/c2;-><init>(Ljava/lang/String;II)V

    .line 65
    .line 66
    .line 67
    filled-new-array/range {v0 .. v6}, [Lh0/c2;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    sput-object v0, Lh0/c2;->j:[Lh0/c2;

    .line 72
    .line 73
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 74
    .line 75
    .line 76
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    int-to-long p1, p3

    .line 5
    iput-wide p1, p0, Lh0/c2;->d:J

    .line 6
    .line 7
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lh0/c2;
    .locals 1

    .line 1
    const-class v0, Lh0/c2;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lh0/c2;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lh0/c2;
    .locals 1

    .line 1
    sget-object v0, Lh0/c2;->j:[Lh0/c2;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lh0/c2;

    .line 8
    .line 9
    return-object v0
.end method
