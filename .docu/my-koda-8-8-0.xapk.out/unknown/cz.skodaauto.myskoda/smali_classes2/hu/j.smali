.class public final enum Lhu/j;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lbt/f;


# static fields
.field public static final enum e:Lhu/j;

.field public static final enum f:Lhu/j;

.field public static final enum g:Lhu/j;

.field public static final synthetic h:[Lhu/j;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lhu/j;

    .line 2
    .line 3
    const-string v1, "COLLECTION_UNKNOWN"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lhu/j;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lhu/j;

    .line 10
    .line 11
    const-string v2, "COLLECTION_SDK_NOT_INSTALLED"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3, v3}, Lhu/j;-><init>(Ljava/lang/String;II)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lhu/j;->e:Lhu/j;

    .line 18
    .line 19
    new-instance v2, Lhu/j;

    .line 20
    .line 21
    const-string v3, "COLLECTION_ENABLED"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4, v4}, Lhu/j;-><init>(Ljava/lang/String;II)V

    .line 25
    .line 26
    .line 27
    sput-object v2, Lhu/j;->f:Lhu/j;

    .line 28
    .line 29
    new-instance v3, Lhu/j;

    .line 30
    .line 31
    const-string v4, "COLLECTION_DISABLED"

    .line 32
    .line 33
    const/4 v5, 0x3

    .line 34
    invoke-direct {v3, v4, v5, v5}, Lhu/j;-><init>(Ljava/lang/String;II)V

    .line 35
    .line 36
    .line 37
    sput-object v3, Lhu/j;->g:Lhu/j;

    .line 38
    .line 39
    new-instance v4, Lhu/j;

    .line 40
    .line 41
    const-string v5, "COLLECTION_DISABLED_REMOTE"

    .line 42
    .line 43
    const/4 v6, 0x4

    .line 44
    invoke-direct {v4, v5, v6, v6}, Lhu/j;-><init>(Ljava/lang/String;II)V

    .line 45
    .line 46
    .line 47
    new-instance v5, Lhu/j;

    .line 48
    .line 49
    const-string v6, "COLLECTION_SAMPLED"

    .line 50
    .line 51
    const/4 v7, 0x5

    .line 52
    invoke-direct {v5, v6, v7, v7}, Lhu/j;-><init>(Ljava/lang/String;II)V

    .line 53
    .line 54
    .line 55
    filled-new-array/range {v0 .. v5}, [Lhu/j;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    sput-object v0, Lhu/j;->h:[Lhu/j;

    .line 60
    .line 61
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 62
    .line 63
    .line 64
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lhu/j;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lhu/j;
    .locals 1

    .line 1
    const-class v0, Lhu/j;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lhu/j;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lhu/j;
    .locals 1

    .line 1
    sget-object v0, Lhu/j;->h:[Lhu/j;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lhu/j;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getNumber()I
    .locals 0

    .line 1
    iget p0, p0, Lhu/j;->d:I

    .line 2
    .line 3
    return p0
.end method
