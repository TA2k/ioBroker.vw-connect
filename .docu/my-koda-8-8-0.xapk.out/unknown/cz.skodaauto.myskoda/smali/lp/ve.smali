.class public final enum Llp/ve;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llp/a0;


# static fields
.field public static final enum e:Llp/ve;

.field public static final synthetic f:[Llp/ve;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    new-instance v0, Llp/ve;

    .line 2
    .line 3
    const-string v1, "TYPE_UNKNOWN"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Llp/ve;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Llp/ve;

    .line 10
    .line 11
    const-string v2, "LATIN"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3, v3}, Llp/ve;-><init>(Ljava/lang/String;II)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Llp/ve;->e:Llp/ve;

    .line 18
    .line 19
    new-instance v2, Llp/ve;

    .line 20
    .line 21
    const-string v3, "LATIN_AND_CHINESE"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4, v4}, Llp/ve;-><init>(Ljava/lang/String;II)V

    .line 25
    .line 26
    .line 27
    new-instance v3, Llp/ve;

    .line 28
    .line 29
    const-string v4, "LATIN_AND_DEVANAGARI"

    .line 30
    .line 31
    const/4 v5, 0x3

    .line 32
    invoke-direct {v3, v4, v5, v5}, Llp/ve;-><init>(Ljava/lang/String;II)V

    .line 33
    .line 34
    .line 35
    new-instance v4, Llp/ve;

    .line 36
    .line 37
    const-string v5, "LATIN_AND_JAPANESE"

    .line 38
    .line 39
    const/4 v6, 0x4

    .line 40
    invoke-direct {v4, v5, v6, v6}, Llp/ve;-><init>(Ljava/lang/String;II)V

    .line 41
    .line 42
    .line 43
    new-instance v5, Llp/ve;

    .line 44
    .line 45
    const-string v6, "LATIN_AND_KOREAN"

    .line 46
    .line 47
    const/4 v7, 0x5

    .line 48
    invoke-direct {v5, v6, v7, v7}, Llp/ve;-><init>(Ljava/lang/String;II)V

    .line 49
    .line 50
    .line 51
    new-instance v6, Llp/ve;

    .line 52
    .line 53
    const-string v7, "CREDIT_CARD"

    .line 54
    .line 55
    const/4 v8, 0x6

    .line 56
    invoke-direct {v6, v7, v8, v8}, Llp/ve;-><init>(Ljava/lang/String;II)V

    .line 57
    .line 58
    .line 59
    new-instance v7, Llp/ve;

    .line 60
    .line 61
    const-string v8, "DOCUMENT"

    .line 62
    .line 63
    const/4 v9, 0x7

    .line 64
    invoke-direct {v7, v8, v9, v9}, Llp/ve;-><init>(Ljava/lang/String;II)V

    .line 65
    .line 66
    .line 67
    new-instance v8, Llp/ve;

    .line 68
    .line 69
    const-string v9, "PIXEL_AI"

    .line 70
    .line 71
    const/16 v10, 0x8

    .line 72
    .line 73
    invoke-direct {v8, v9, v10, v10}, Llp/ve;-><init>(Ljava/lang/String;II)V

    .line 74
    .line 75
    .line 76
    filled-new-array/range {v0 .. v8}, [Llp/ve;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    sput-object v0, Llp/ve;->f:[Llp/ve;

    .line 81
    .line 82
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Llp/ve;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static values()[Llp/ve;
    .locals 1

    .line 1
    sget-object v0, Llp/ve;->f:[Llp/ve;

    .line 2
    .line 3
    invoke-virtual {v0}, [Llp/ve;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Llp/ve;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final h()I
    .locals 0

    .line 1
    iget p0, p0, Llp/ve;->d:I

    .line 2
    .line 3
    return p0
.end method
