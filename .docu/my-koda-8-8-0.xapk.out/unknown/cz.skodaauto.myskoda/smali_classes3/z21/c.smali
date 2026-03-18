.class public final enum Lz21/c;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lnm0/b;

.field public static final enum e:Lz21/c;

.field public static final enum f:Lz21/c;

.field public static final enum g:Lz21/c;

.field public static final enum h:Lz21/c;

.field public static final enum i:Lz21/c;

.field public static final enum j:Lz21/c;

.field public static final synthetic k:[Lz21/c;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lz21/c;

    .line 2
    .line 3
    const-string v1, "MSL"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lz21/c;->e:Lz21/c;

    .line 10
    .line 11
    new-instance v1, Lz21/c;

    .line 12
    .line 13
    const-string v2, "MSL_1_5"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lz21/c;->f:Lz21/c;

    .line 20
    .line 21
    new-instance v2, Lz21/c;

    .line 22
    .line 23
    const-string v3, "MSL_1_6"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lz21/c;->g:Lz21/c;

    .line 30
    .line 31
    new-instance v3, Lz21/c;

    .line 32
    .line 33
    const-string v4, "SBO"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Lz21/c;->h:Lz21/c;

    .line 40
    .line 41
    new-instance v4, Lz21/c;

    .line 42
    .line 43
    const-string v5, "SBO_2_1"

    .line 44
    .line 45
    const/4 v6, 0x4

    .line 46
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v4, Lz21/c;->i:Lz21/c;

    .line 50
    .line 51
    new-instance v5, Lz21/c;

    .line 52
    .line 53
    const-string v6, "AUTOMATIC"

    .line 54
    .line 55
    const/4 v7, 0x5

    .line 56
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v5, Lz21/c;->j:Lz21/c;

    .line 60
    .line 61
    filled-new-array/range {v0 .. v5}, [Lz21/c;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Lz21/c;->k:[Lz21/c;

    .line 66
    .line 67
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 68
    .line 69
    .line 70
    new-instance v0, Lnm0/b;

    .line 71
    .line 72
    const/16 v1, 0x1b

    .line 73
    .line 74
    invoke-direct {v0, v1}, Lnm0/b;-><init>(I)V

    .line 75
    .line 76
    .line 77
    sput-object v0, Lz21/c;->d:Lnm0/b;

    .line 78
    .line 79
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lz21/c;
    .locals 1

    .line 1
    const-class v0, Lz21/c;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lz21/c;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lz21/c;
    .locals 1

    .line 1
    sget-object v0, Lz21/c;->k:[Lz21/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lz21/c;

    .line 8
    .line 9
    return-object v0
.end method
